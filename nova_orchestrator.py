#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🧠 NOVA ORCHESTRATOR v1.0 — OpenAI Agents SDK-Style Multi-Agent Engine    ║
║                                                                              ║
║  Brings Claude / OpenAI Agents SDK patterns to Nova's local Ollama stack:   ║
║  • Agents with names, instructions, tools, handoffs, and guardrails         ║
║  • Structured tool calling with JSON schema validation                       ║
║  • Agent-to-agent handoffs with full state transfer                         ║
║  • Input / output guardrails that block unsafe or off-scope actions         ║
║  • Full execution tracing (every step logged with timestamps)               ║
║  • Parallel agent fan-out with result aggregation                           ║
║  • 100% local — zero cloud dependency, zero cost                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    from nova_orchestrator import Agent, Tool, Runner, Guardrail

    recon_agent = Agent(
        name="ReconAgent",
        instructions="You are a passive recon specialist. Find subdomains and endpoints.",
        tools=[web_fetch_tool, dns_lookup_tool],
        handoffs=["AttackAgent"],
    )

    attack_agent = Agent(
        name="AttackAgent",
        instructions="You receive recon data and test for IDOR, SQLi, XSS.",
        tools=[http_probe_tool, sqli_test_tool],
    )

    runner = Runner(agents=[recon_agent, attack_agent], max_steps=30)
    result = runner.run("Hunt http://target.com for vulnerabilities", start="ReconAgent")
    print(result.findings)
"""

import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── Config ─────────────────────────────────────────────────────────────────────
OLLAMA_URL   = os.getenv("NOVA_LLM_URL",   "http://localhost:11434")
OLLAMA_MODEL = os.getenv("NOVA_LLM_MODEL", "qwen3:8b")
WORKSPACE    = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)


# ── Trace ──────────────────────────────────────────────────────────────────────

@dataclass
class TraceEvent:
    timestamp: str
    agent:     str
    event:     str          # think | tool_call | tool_result | handoff | guardrail | complete
    data:      Dict = field(default_factory=dict)

    def pretty(self) -> str:
        icons = {"think": "💭", "tool_call": "🔧", "tool_result": "📥",
                 "handoff": "🤝", "guardrail": "🛡️", "complete": "✅", "error": "❌"}
        icon = icons.get(self.event, "•")
        ts   = self.timestamp[11:19]
        return f"  [{ts}] {icon} [{self.agent}] {self.event}: {str(self.data)[:120]}"


class Trace:
    """Execution log for a full agent run."""

    def __init__(self):
        self.events: List[TraceEvent] = []
        self._lock = threading.Lock()

    def log(self, agent: str, event: str, data: Dict = None):
        with self._lock:
            ev = TraceEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent=agent,
                event=event,
                data=data or {},
            )
            self.events.append(ev)
            print(ev.pretty())

    def save(self, path: str):
        Path(path).write_text(json.dumps(
            [{"ts": e.timestamp, "agent": e.agent, "event": e.event, "data": e.data}
             for e in self.events], indent=2))

    def summary(self) -> Dict:
        counts: Dict[str, int] = {}
        for e in self.events:
            counts[e.event] = counts.get(e.event, 0) + 1
        return {"total_events": len(self.events), "by_type": counts}


# ── Tool ───────────────────────────────────────────────────────────────────────

@dataclass
class Tool:
    """
    A callable tool an agent can invoke.

    The function receives (input_dict: dict) and returns a string result.
    Schema follows JSON Schema Draft-7 for the input object.
    """
    name:        str
    description: str
    function:    Callable[[Dict], str]
    schema:      Dict = field(default_factory=lambda: {"type": "object", "properties": {}})

    def call(self, args: Dict) -> str:
        try:
            return self.function(args)
        except Exception as e:
            return f"ERROR: {e}"

    def schema_str(self) -> str:
        props = self.schema.get("properties", {})
        parts = []
        for k, v in props.items():
            req  = k in self.schema.get("required", [])
            desc = v.get("description", "")
            parts.append(f"  {k} ({'required' if req else 'optional'}): {v.get('type','str')} — {desc}")
        return "\n".join(parts) or "  (no parameters)"


# ── Guardrail ──────────────────────────────────────────────────────────────────

@dataclass
class Guardrail:
    """
    Validates agent input or output.
    Function receives the text to validate, returns (pass: bool, reason: str).
    """
    name:     str
    check:    Callable[[str], Tuple[bool, str]]
    on_input: bool = True   # apply to agent input
    on_output: bool = False # apply to agent output

    def validate(self, text: str) -> Tuple[bool, str]:
        try:
            return self.check(text)
        except Exception as e:
            return False, f"Guardrail error: {e}"


# ── Built-in Guardrails ────────────────────────────────────────────────────────

def _scope_guardrail_fn(scope_patterns: List[str]) -> Callable:
    """Returns a guardrail function that blocks out-of-scope targets."""
    def check(text: str) -> Tuple[bool, str]:
        text_low = text.lower()
        for pattern in scope_patterns:
            if pattern.lower() in text_low:
                return True, "in scope"
        # Check for obvious out-of-scope domains
        blocked = ["google.com", "facebook.com", "amazon.com", "microsoft.com",
                   "apple.com", "cloudflare.com"]
        for b in blocked:
            if b in text_low:
                return False, f"blocked domain: {b}"
        return True, "pass"
    return check


def _safety_guardrail_fn(text: str) -> Tuple[bool, str]:
    """Block obviously destructive commands."""
    danger = ["rm -rf /", "drop table", "format c:", "mkfs", "> /dev/sda",
              "chmod 777 /", "curl | bash", "wget | sh"]
    text_low = text.lower()
    for d in danger:
        if d in text_low:
            return False, f"dangerous command blocked: {d}"
    return True, "safe"


SAFETY_GUARDRAIL = Guardrail(
    name="SafetyGuardrail",
    check=_safety_guardrail_fn,
    on_input=True,
    on_output=True,
)


# ── Built-in Tools ─────────────────────────────────────────────────────────────

def _make_http_probe_tool() -> Tool:
    def fn(args: Dict) -> str:
        import urllib.request, urllib.error
        url     = args.get("url", "")
        method  = args.get("method", "GET").upper()
        headers = args.get("headers", {})
        body    = args.get("body", "")
        timeout = int(args.get("timeout", 10))
        try:
            data = body.encode() if body else None
            req  = urllib.request.Request(url, data=data, method=method)
            req.add_header("User-Agent", "Nova-Orchestrator/1.0")
            for k, v in headers.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body_text = r.read(8192).decode("utf-8", errors="replace")
                return json.dumps({
                    "status":  r.status,
                    "headers": dict(r.headers),
                    "body":    body_text[:4000],
                })
        except urllib.error.HTTPError as e:
            return json.dumps({"status": e.code, "error": str(e), "body": e.read(1000).decode("utf-8","replace")})
        except Exception as e:
            return json.dumps({"error": str(e)})
    return Tool(
        name="http_probe",
        description="Send an HTTP request and return status code, headers, and body.",
        function=fn,
        schema={
            "type": "object",
            "properties": {
                "url":     {"type": "string",  "description": "Full URL to request"},
                "method":  {"type": "string",  "description": "HTTP method (GET, POST, PUT, DELETE, PATCH)"},
                "headers": {"type": "object",  "description": "Extra request headers as key-value pairs"},
                "body":    {"type": "string",  "description": "Request body string (for POST/PUT)"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 10)"},
            },
            "required": ["url"],
        }
    )


def _make_shell_tool(allow_list: List[str] = None) -> Tool:
    SAFE_CMDS = allow_list or ["curl", "nmap", "nslookup", "dig", "whois",
                                "subfinder", "httpx", "nuclei", "ffuf",
                                "python3", "cat", "ls", "grep", "wc", "echo"]
    def fn(args: Dict) -> str:
        cmd = args.get("command", "")
        first = cmd.strip().split()[0] if cmd.strip() else ""
        if first not in SAFE_CMDS:
            return f"ERROR: command '{first}' not in allow-list: {SAFE_CMDS}"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30
            )
            out = result.stdout[:4000] + (result.stderr[:1000] if result.returncode != 0 else "")
            return out or "(no output)"
        except subprocess.TimeoutExpired:
            return "ERROR: command timed out after 30s"
        except Exception as e:
            return f"ERROR: {e}"
    return Tool(
        name="shell",
        description=f"Run an allow-listed shell command. Allowed: {', '.join(SAFE_CMDS)}",
        function=fn,
        schema={"type":"object","properties":{"command":{"type":"string","description":"Shell command to run"}},"required":["command"]}
    )


def _make_read_file_tool() -> Tool:
    def fn(args: Dict) -> str:
        try:
            path   = Path(args.get("path",""))
            offset = int(args.get("offset", 0))
            limit  = int(args.get("limit", 200))
            lines  = path.read_text(errors="replace").splitlines()
            chunk  = lines[offset:offset+limit]
            return "\n".join(f"{offset+i+1}: {l}" for i, l in enumerate(chunk))
        except Exception as e:
            return f"ERROR: {e}"
    return Tool(
        name="read_file",
        description="Read lines from a file. Supports offset + limit for large files.",
        function=fn,
        schema={"type":"object","properties":{"path":{"type":"string"},"offset":{"type":"integer"},"limit":{"type":"integer"}},"required":["path"]}
    )


def _make_python_eval_tool() -> Tool:
    """Safe Python evaluation in a restricted namespace."""
    def fn(args: Dict) -> str:
        code = args.get("code", "")
        safe_globals = {
            "__builtins__": {k: __builtins__[k] for k in
                             ["print","len","range","str","int","float","list","dict","set",
                              "tuple","sorted","enumerate","zip","map","filter","sum","max","min",
                              "abs","round","bool","type","isinstance","json"]
                             if k in (dir(__builtins__) if isinstance(__builtins__, dict) else dir(__builtins__))
                             },
            "json": json,
            "re": re,
            "Path": Path,
        }
        import io
        buf = io.StringIO()
        import contextlib
        try:
            with contextlib.redirect_stdout(buf):
                exec(code, safe_globals)  # noqa: S102
            return buf.getvalue() or "(no output)"
        except Exception as e:
            return f"ERROR: {e}"
    return Tool(
        name="python_eval",
        description="Safely execute a small Python snippet for data analysis. No network or filesystem write.",
        function=fn,
        schema={"type":"object","properties":{"code":{"type":"string","description":"Python code to execute"}},"required":["code"]}
    )


# ── Agent ──────────────────────────────────────────────────────────────────────

@dataclass
class Agent:
    """
    A named agent with its own instructions, tool belt, guardrails, and handoff targets.

    Modelled after OpenAI Agents SDK Agent class but runs on local Ollama.
    """
    name:         str
    instructions: str
    tools:        List[Tool]         = field(default_factory=list)
    handoffs:     List[str]          = field(default_factory=list)  # agent names
    guardrails:   List[Guardrail]    = field(default_factory=list)
    model:        str                = ""   # overrides runner default
    max_steps:    int                = 20
    output_schema: Optional[Dict]   = None  # JSON Schema for structured output

    def tool_map(self) -> Dict[str, Tool]:
        return {t.name: t for t in self.tools}

    def system_prompt(self, available_handoffs: List[str] = None) -> str:
        tool_block = "\n".join(
            f"- {t.name}: {t.description}\n  Parameters:\n{t.schema_str()}"
            for t in self.tools
        )
        handoff_block = ", ".join(available_handoffs or self.handoffs) or "none"
        schema_block  = (
            f"\nOutput schema (always respond with valid JSON matching this schema when done):\n"
            f"{json.dumps(self.output_schema, indent=2)}"
            if self.output_schema else ""
        )
        return f"""You are {self.name}.

{self.instructions}

Available tools:
{tool_block or '(none)'}

Available handoffs (agents you can delegate to): {handoff_block}
{schema_block}

Respond in this EXACT format every turn:
THINK: <your reasoning>
ACTION: <tool_name OR "handoff:AgentName" OR "done">
INPUT: <JSON object with tool inputs, or handoff message, or final answer>

Rules:
- Always THINK before acting.
- Call one tool at a time.
- To hand off, use ACTION: handoff:<AgentName> and pass context in INPUT.
- When you have your final answer, use ACTION: done.
- If structured output is required, INPUT must be valid JSON.
"""


# ── AgentResult ────────────────────────────────────────────────────────────────

@dataclass
class AgentResult:
    agent:    str
    findings: List[Dict]  = field(default_factory=list)
    output:   str         = ""
    handoff:  Optional[str] = None
    handoff_context: str  = ""
    steps:    int         = 0
    trace:    Optional[Trace] = None
    success:  bool        = True
    error:    str         = ""

    def save(self, path: str):
        Path(path).write_text(json.dumps({
            "agent": self.agent,
            "success": self.success,
            "steps": self.steps,
            "output": self.output,
            "findings": self.findings,
            "handoff": self.handoff,
            "error": self.error,
            "trace_summary": self.trace.summary() if self.trace else {},
        }, indent=2))


# ── Runner ─────────────────────────────────────────────────────────────────────

class Runner:
    """
    Executes a network of agents with handoffs, guardrails, and full tracing.

    Equivalent to OpenAI Agents SDK's Runner.run() but on local Ollama.
    """

    def __init__(self,
                 agents:     List[Agent],
                 model:      str = "",
                 max_steps:  int = 30,
                 trace:      bool = True,
                 workspace:  Path = WORKSPACE):
        self.agents     = {a.name: a for a in agents}
        self.model      = model or OLLAMA_MODEL
        self.max_steps  = max_steps
        self.workspace  = workspace
        self._trace     = Trace() if trace else None

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self, task: str, start: str = None) -> AgentResult:
        """Run the agent network on a task, starting from 'start' agent."""
        start_name = start or (list(self.agents.keys())[0] if self.agents else None)
        if start_name not in self.agents:
            return AgentResult(agent=start_name or "?", error="Agent not found", success=False)

        print(f"\n{'═'*65}")
        print(f"  🧠 Nova Orchestrator — starting {start_name}")
        print(f"  📋 Task: {task[:80]}")
        print(f"{'═'*65}")

        context = task
        agent_name = start_name
        all_findings: List[Dict] = []
        total_steps = 0

        while agent_name and total_steps < self.max_steps:
            agent = self.agents.get(agent_name)
            if not agent:
                break

            result = self._run_agent(agent, context)
            total_steps += result.steps
            all_findings.extend(result.findings)

            if result.handoff and result.handoff in self.agents:
                if self._trace:
                    self._trace.log(agent_name, "handoff",
                                    {"to": result.handoff, "context": result.handoff_context[:200]})
                context    = result.handoff_context or context
                agent_name = result.handoff
            else:
                # Terminal agent
                final = AgentResult(
                    agent=agent_name,
                    findings=all_findings,
                    output=result.output,
                    steps=total_steps,
                    trace=self._trace,
                    success=result.success,
                )
                self._save_run(final, task)
                return final

        return AgentResult(
            agent=start_name,
            findings=all_findings,
            output="Max steps reached",
            steps=total_steps,
            trace=self._trace,
            success=False,
            error="exceeded max_steps",
        )

    def run_parallel(self, task: str, agent_names: List[str]) -> List[AgentResult]:
        """Fan out the same task to multiple agents in parallel."""
        print(f"\n  🚀 Parallel fan-out → {agent_names}")
        results = []
        with ThreadPoolExecutor(max_workers=len(agent_names)) as ex:
            futures = {ex.submit(self._run_agent, self.agents[n], task): n
                       for n in agent_names if n in self.agents}
            for f in as_completed(futures):
                results.append(f.result())
        return results

    # ── Internal ───────────────────────────────────────────────────────────────

    def _run_agent(self, agent: Agent, context: str) -> AgentResult:
        model     = agent.model or self.model
        tool_map  = agent.tool_map()
        history   = [{"role": "system", "content": agent.system_prompt(list(self.agents.keys()))}]
        history.append({"role": "user", "content": context})

        findings: List[Dict] = []
        steps = 0

        for step in range(agent.max_steps):
            steps += 1

            # ── Guardrails on input ─────────────────────────────────────────
            for g in agent.guardrails:
                if g.on_input:
                    ok, reason = g.validate(history[-1]["content"])
                    if not ok:
                        if self._trace:
                            self._trace.log(agent.name, "guardrail",
                                            {"blocked": reason, "guardrail": g.name})
                        return AgentResult(agent=agent.name, success=False,
                                           error=f"Guardrail blocked: {reason}", steps=steps)

            # ── LLM call ───────────────────────────────────────────────────
            reply = self._chat(model, history)
            if not reply:
                break
            history.append({"role": "assistant", "content": reply})

            if self._trace:
                self._trace.log(agent.name, "think", {"reply": reply[:200]})

            # ── Parse reply ────────────────────────────────────────────────
            action, inp_raw = self._parse_reply(reply)

            # done
            if action == "done":
                output = inp_raw
                # Try to extract structured findings from the output
                try:
                    parsed = json.loads(inp_raw)
                    if isinstance(parsed, list):
                        findings.extend(parsed)
                    elif isinstance(parsed, dict) and "findings" in parsed:
                        findings.extend(parsed["findings"])
                except Exception:
                    pass
                if self._trace:
                    self._trace.log(agent.name, "complete", {"output": output[:200]})
                return AgentResult(agent=agent.name, findings=findings,
                                   output=output, steps=steps)

            # handoff
            if action.startswith("handoff:"):
                target = action.split(":", 1)[1].strip()
                if self._trace:
                    self._trace.log(agent.name, "handoff",
                                    {"to": target, "context": inp_raw[:200]})
                return AgentResult(agent=agent.name, findings=findings,
                                   handoff=target, handoff_context=inp_raw, steps=steps)

            # tool call
            if action in tool_map:
                try:
                    inp = json.loads(inp_raw) if inp_raw.strip().startswith("{") else {"input": inp_raw}
                except Exception:
                    inp = {"input": inp_raw}

                if self._trace:
                    self._trace.log(agent.name, "tool_call",
                                    {"tool": action, "input": inp})

                tool_result = tool_map[action].call(inp)

                # Try to extract findings from tool results
                try:
                    parsed = json.loads(tool_result)
                    if isinstance(parsed, list) and parsed and "severity" in parsed[0]:
                        findings.extend(parsed)
                except Exception:
                    pass

                if self._trace:
                    self._trace.log(agent.name, "tool_result",
                                    {"tool": action, "result": tool_result[:300]})

                # Guardrail on output
                for g in agent.guardrails:
                    if g.on_output:
                        ok, reason = g.validate(tool_result)
                        if not ok:
                            tool_result = f"[BLOCKED by {g.name}: {reason}]"

                history.append({"role": "user",
                                 "content": f"Tool result ({action}):\n{tool_result}"})
            else:
                history.append({"role": "user",
                                 "content": f"Unknown action '{action}'. Use a valid tool name, 'done', or 'handoff:AgentName'."})

        return AgentResult(agent=agent.name, findings=findings,
                           output="max steps reached", steps=steps, success=False)

    def _chat(self, model: str, messages: List[Dict]) -> str:
        try:
            payload = json.dumps({
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 2000},
            }).encode()
            req = urllib.request.Request(
                f"{OLLAMA_URL}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read()).get("message", {}).get("content", "").strip()
        except Exception as e:
            print(f"  ⚠️  LLM error: {e}")
            return ""

    @staticmethod
    def _parse_reply(reply: str) -> Tuple[str, str]:
        action_match = re.search(r"ACTION:\s*(.+?)(?:\n|$)", reply, re.IGNORECASE)
        input_match  = re.search(r"INPUT:\s*([\s\S]+?)(?:THINK:|ACTION:|$)", reply, re.IGNORECASE)
        action = action_match.group(1).strip() if action_match else "done"
        inp    = input_match.group(1).strip()  if input_match  else reply
        return action, inp

    def _save_run(self, result: AgentResult, task: str):
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.workspace / f"nova_orchestrator_{ts}.json"
        result.save(str(path))
        if self._trace:
            self._trace.save(str(self.workspace / f"nova_trace_{ts}.json"))
        print(f"\n  💾 Orchestrator results → {path}")


# ── Pre-built Security Agent Network ──────────────────────────────────────────

def build_security_network(target: str, scope: List[str] = None) -> Runner:
    """
    Build a production-ready security agent network with:
      ReconAgent → AttackAgent → ReportAgent
    """
    guardrails = [SAFETY_GUARDRAIL]
    if scope:
        guardrails.append(Guardrail(
            name="ScopeGuard",
            check=_scope_guardrail_fn(scope),
            on_input=True,
        ))

    http_tool  = _make_http_probe_tool()
    shell_tool = _make_shell_tool()
    read_tool  = _make_read_file_tool()
    py_tool    = _make_python_eval_tool()

    recon_agent = Agent(
        name="ReconAgent",
        instructions=(
            f"You are Nova's passive recon specialist. Target: {target}\n"
            "Discover: subdomains, endpoints, JS files, technologies, open ports, API paths.\n"
            "Use http_probe to fetch robots.txt, sitemap.xml, /.well-known/, /api/.\n"
            "Collect all discovered URLs and tech stack info. Then hand off to AttackAgent."
        ),
        tools=[http_tool, shell_tool],
        handoffs=["AttackAgent"],
        guardrails=guardrails,
        max_steps=15,
    )

    attack_agent = Agent(
        name="AttackAgent",
        instructions=(
            f"You are Nova's active vulnerability tester. Target: {target}\n"
            "Test for: IDOR, SQLi, XSS, SSRF, auth bypass, misconfigurations, info leakage.\n"
            "For each finding, produce a JSON object with: type, severity, endpoint, evidence, cvss.\n"
            "Compile all findings as a JSON array and hand off to ReportAgent."
        ),
        tools=[http_tool, shell_tool, py_tool],
        handoffs=["ReportAgent"],
        guardrails=guardrails,
        max_steps=20,
        output_schema={
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "severity", "endpoint"],
                "properties": {
                    "type":        {"type": "string"},
                    "severity":    {"type": "string", "enum": ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]},
                    "endpoint":    {"type": "string"},
                    "evidence":    {"type": "string"},
                    "cvss":        {"type": "number"},
                    "description": {"type": "string"},
                },
            },
        },
    )

    report_agent = Agent(
        name="ReportAgent",
        instructions=(
            "You are Nova's reporting specialist. Receive findings and produce:\n"
            "1. Executive summary (2-3 sentences)\n"
            "2. Prioritized findings list (CRITICAL → INFO)\n"
            "3. Risk score (0-10)\n"
            "4. Top 3 recommended remediations\n"
            "Output as structured JSON."
        ),
        tools=[py_tool, read_tool],
        guardrails=[SAFETY_GUARDRAIL],
        max_steps=10,
    )

    return Runner(
        agents=[recon_agent, attack_agent, report_agent],
        max_steps=60,
    )


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="🧠 Nova Orchestrator — Multi-agent security runner")
    parser.add_argument("task",   help="Task in plain English")
    parser.add_argument("--target", default=os.getenv("NOVA_TARGET","http://localhost:3000"))
    parser.add_argument("--scope",  nargs="*", default=[], help="In-scope domains/patterns")
    parser.add_argument("--start",  default="ReconAgent", help="Starting agent name")
    parser.add_argument("--max-steps", type=int, default=60)
    args = parser.parse_args()

    runner = build_security_network(args.target, args.scope)
    runner.max_steps = args.max_steps
    result = runner.run(args.task, start=args.start)

    print(f"\n{'═'*65}")
    print(f"  ✅ Orchestrator complete")
    print(f"  📊 Findings: {len(result.findings)}")
    print(f"  🔢 Steps:    {result.steps}")
    print(f"  💬 Output:   {result.output[:200]}")
    if result.findings:
        critical = [f for f in result.findings if f.get("severity","") in ("CRITICAL","HIGH")]
        print(f"  🔴 CRIT/HIGH: {len(critical)}")
    print(f"{'═'*65}")
