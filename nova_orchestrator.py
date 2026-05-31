#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🧠 NOVA ORCHESTRATOR v2.0 — Production Multi-Agent Engine                 ║
║                                                                              ║
║  Now as powerful as OpenAI Agents SDK + Anthropic Claude Agent SDK:         ║
║                                                                              ║
║  ✅ nova_llm_router   — OpenAI · Anthropic · Gemini · Ollama, auto-fallback ║
║  ✅ nova_hooks        — PreRun · PostRun · PreTool · PostTool · OnFinding   ║
║  ✅ nova_context      — Typed shared state, scope enforcement, audit trail   ║
║  ✅ nova_sessions     — Persistent memory across runs, deduped findings      ║
║  ✅ nova_retry        — Exponential backoff + per-tool circuit breaker       ║
║  ✅ nova_observability— Span-based tracing, token/cost attribution, HTML    ║
║  ✅ nova_skills       — 20+ parameterised prompt templates                   ║
║                                                                              ║
║  Usage:                                                                      ║
║    from nova_orchestrator import Agent, Tool, Runner, Guardrail             ║
║    from nova_orchestrator import build_security_network                     ║
║                                                                              ║
║    runner = build_security_network("https://target.com",                    ║
║                                    scope=["target.com"])                    ║
║    result = runner.run("Hunt for IDOR and SQLi")                            ║
║    print(result.findings)                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── Workspace ──────────────────────────────────────────────────────────────────
WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)

# ── Import new provider-layer modules (graceful degradation if missing) ────────

def _try_import(module: str, attr: str = None):
    try:
        import importlib
        mod = importlib.import_module(module)
        return getattr(mod, attr) if attr else mod
    except ImportError:
        return None

_llm_router_mod   = _try_import("nova_llm_router")
_hooks_mod        = _try_import("nova_hooks")
_context_mod      = _try_import("nova_context")
_sessions_mod     = _try_import("nova_sessions")
_retry_mod        = _try_import("nova_retry")
_obs_mod          = _try_import("nova_observability")
_skills_mod       = _try_import("nova_skills")

LLMRouter    = getattr(_llm_router_mod,  "LLMRouter",    None)
get_router   = getattr(_llm_router_mod,  "get_router",   None)
HookBus      = getattr(_hooks_mod,       "HookBus",      None)
get_bus      = getattr(_hooks_mod,       "get_bus",      None)
RunContext   = getattr(_context_mod,     "RunContext",   None)
SessionStore = getattr(_sessions_mod,    "SessionStore", None)
ResilientCaller = getattr(_retry_mod,   "ResilientCaller", None)
RetryPolicy  = getattr(_retry_mod,       "RetryPolicy",  None)
Tracer       = getattr(_obs_mod,         "Tracer",       None)
SkillLibrary = getattr(_skills_mod,      "SkillLibrary", None)

# ── Legacy LLM fallback (pure Ollama, no dependency) ──────────────────────────
_OLLAMA_URL   = os.getenv("NOVA_LLM_URL",   "http://localhost:11434")
_OLLAMA_MODEL = os.getenv("NOVA_LLM_MODEL", "qwen3:8b")

def _ollama_chat(model: str, messages: List[Dict], timeout: int = 120) -> str:
    import urllib.request
    payload = json.dumps({
        "model": model, "messages": messages,
        "stream": False, "options": {"temperature": 0.1, "num_predict": 2000}
    }).encode()
    req = urllib.request.Request(
        f"{_OLLAMA_URL}/api/chat", data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read()).get("message", {}).get("content", "").strip()


# ── Backward-compatible Trace (wraps nova_observability.Tracer if available) ──

class Trace:
    """
    Thin façade: delegates to nova_observability.Tracer when available,
    otherwise falls back to the original in-process event log.
    """
    def __init__(self, tracer=None):
        self._tracer = tracer        # nova_observability.Tracer instance or None
        self.events: List[Dict] = []
        self._lock = threading.Lock()

    def log(self, agent: str, event: str, data: Dict = None):
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.events.append({"ts": ts, "agent": agent, "event": event, "data": data or {}})
        icons = {"think": "💭", "tool_call": "🔧", "tool_result": "📥",
                 "handoff": "🤝", "guardrail": "🛡️", "complete": "✅", "error": "❌"}
        icon = icons.get(event, "•")
        print(f"  [{ts[11:19]}] {icon} [{agent}] {event}: {str(data or {})[:120]}")
        if self._tracer:
            try:
                self._tracer._root and self._tracer._root.add_event(
                    f"{agent}.{event}", data or {})
            except Exception:
                pass

    def save(self, path: str):
        Path(path).write_text(json.dumps(self.events, indent=2, default=str))
        if self._tracer:
            try:
                self._tracer.save(path.replace(".json", "_spans.json"))
                self._tracer.export_html(path.replace(".json", ".html"))
            except Exception:
                pass

    def summary(self) -> Dict:
        counts: Dict[str, int] = {}
        for e in self.events:
            counts[e["event"]] = counts.get(e["event"], 0) + 1
        return {"total_events": len(self.events), "by_type": counts}


# ── Tool ───────────────────────────────────────────────────────────────────────

@dataclass
class Tool:
    """
    A callable tool an agent can invoke.
    The function receives (input_dict: dict) → str.
    Schema follows JSON Schema Draft-7.
    """
    name:        str
    description: str
    function:    Callable[[Dict], str]
    schema:      Dict = field(default_factory=lambda: {"type": "object", "properties": {}})
    _caller:     Any  = field(default=None, init=False, repr=False)  # ResilientCaller

    def _ensure_caller(self):
        if self._caller is None and ResilientCaller:
            self._caller = ResilientCaller(
                name=self.name,
                policy=RetryPolicy(max_attempts=3, base_delay=1.0) if RetryPolicy else None,
                cb_threshold=3, cb_reset=60.0)

    def call(self, args: Dict, bus=None, agent_name: str = "") -> str:
        """Call the tool, firing PreTool/PostTool hooks and applying retry."""
        self._ensure_caller()

        # ── PreTool hook ───────────────────────────────────────────────────
        if bus:
            try:
                allow = bus.fire_pre_tool(self.name, args, agent=agent_name)
                if not allow:
                    return f"[BLOCKED] Tool '{self.name}' cancelled by hook."
            except Exception:
                pass

        t0 = time.monotonic()
        try:
            if self._caller:
                result = self._caller.call(self.function, args)
            else:
                result = self.function(args)
        except Exception as e:
            result = f"ERROR: {e}"
            if bus:
                try:
                    bus.fire_error(e, context={"tool": self.name, "args": args},
                                   agent=agent_name)
                except Exception:
                    pass
        elapsed_ms = (time.monotonic() - t0) * 1000

        # ── PostTool hook ──────────────────────────────────────────────────
        if bus:
            try:
                bus.fire_post_tool(self.name, args, result, elapsed_ms, agent=agent_name)
            except Exception:
                pass

        return result or ""

    def schema_str(self) -> str:
        props = self.schema.get("properties", {})
        parts = []
        for k, v in props.items():
            req  = k in self.schema.get("required", [])
            desc = v.get("description", "")
            parts.append(
                f"  {k} ({'required' if req else 'optional'}): {v.get('type','str')} — {desc}")
        return "\n".join(parts) or "  (no parameters)"


# ── Guardrail ──────────────────────────────────────────────────────────────────

@dataclass
class Guardrail:
    name:      str
    check:     Callable[[str], Tuple[bool, str]]
    on_input:  bool = True
    on_output: bool = False

    def validate(self, text: str) -> Tuple[bool, str]:
        try:
            return self.check(text)
        except Exception as e:
            return False, f"Guardrail error: {e}"


# ── Built-in Guardrails ────────────────────────────────────────────────────────

def _scope_guardrail_fn(scope_patterns: List[str]) -> Callable:
    def check(text: str) -> Tuple[bool, str]:
        text_low = text.lower()
        for p in scope_patterns:
            if p.lower().lstrip("*.") in text_low:
                return True, "in scope"
        blocked = ["google.com", "facebook.com", "amazon.com",
                   "microsoft.com", "apple.com", "cloudflare.com"]
        for b in blocked:
            if b in text_low:
                return False, f"blocked domain: {b}"
        return True, "pass"
    return check


def _safety_guardrail_fn(text: str) -> Tuple[bool, str]:
    danger = ["rm -rf /", "drop table", "format c:", "mkfs",
              "> /dev/sda", "chmod 777 /", "curl | bash", "wget | sh"]
    t = text.lower()
    for d in danger:
        if d in t:
            return False, f"dangerous command: {d}"
    return True, "safe"


SAFETY_GUARDRAIL = Guardrail(
    name="SafetyGuardrail", check=_safety_guardrail_fn,
    on_input=True, on_output=True)


# ── Built-in Tools ─────────────────────────────────────────────────────────────

def _make_http_probe_tool() -> Tool:
    import urllib.request as _ur, urllib.error as _ue
    def fn(args: Dict) -> str:
        url     = args.get("url", "")
        method  = args.get("method", "GET").upper()
        headers = args.get("headers", {})
        body    = args.get("body", "")
        timeout = int(args.get("timeout", 10))
        try:
            data = body.encode() if body else None
            req  = _ur.Request(url, data=data, method=method)
            req.add_header("User-Agent", "Nova-Orchestrator/2.0")
            for k, v in headers.items():
                req.add_header(k, v)
            with _ur.urlopen(req, timeout=timeout) as r:
                body_text = r.read(8192).decode("utf-8", errors="replace")
                return json.dumps({
                    "status": r.status, "headers": dict(r.headers),
                    "body": body_text[:4000]})
        except _ue.HTTPError as e:
            return json.dumps({"status": e.code, "error": str(e),
                               "body": e.read(1000).decode("utf-8", "replace")})
        except Exception as e:
            return json.dumps({"error": str(e)})
    return Tool(
        name="http_probe",
        description="Send an HTTP request and return status, headers, and body.",
        function=fn,
        schema={
            "type": "object",
            "properties": {
                "url":     {"type": "string",  "description": "Full URL"},
                "method":  {"type": "string",  "description": "HTTP method"},
                "headers": {"type": "object",  "description": "Extra headers"},
                "body":    {"type": "string",  "description": "Request body"},
                "timeout": {"type": "integer", "description": "Timeout seconds"},
            },
            "required": ["url"],
        })


def _make_shell_tool(allow_list: List[str] = None) -> Tool:
    SAFE = allow_list or [
        "curl", "nmap", "nslookup", "dig", "whois",
        "subfinder", "httpx", "nuclei", "ffuf", "gau", "katana",
        "python3", "cat", "ls", "grep", "wc", "echo", "jq",
    ]
    def fn(args: Dict) -> str:
        cmd   = args.get("command", "")
        first = cmd.strip().split()[0] if cmd.strip() else ""
        if first not in SAFE:
            return f"ERROR: '{first}' not in allow-list. Allowed: {SAFE}"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=60)
            out = (result.stdout[:4000]
                   + (result.stderr[:1000] if result.returncode != 0 else ""))
            return out or "(no output)"
        except subprocess.TimeoutExpired:
            return "ERROR: timed out after 60s"
        except Exception as e:
            return f"ERROR: {e}"
    return Tool(
        name="shell",
        description=f"Run an allow-listed shell command. Allowed: {', '.join(SAFE)}",
        function=fn,
        schema={"type": "object",
                "properties": {"command": {"type": "string", "description": "Shell command"}},
                "required": ["command"]})


def _make_read_file_tool() -> Tool:
    def fn(args: Dict) -> str:
        try:
            path   = Path(args.get("path", ""))
            offset = int(args.get("offset", 0))
            limit  = int(args.get("limit", 200))
            lines  = path.read_text(errors="replace").splitlines()
            chunk  = lines[offset: offset + limit]
            return "\n".join(f"{offset+i+1}: {l}" for i, l in enumerate(chunk))
        except Exception as e:
            return f"ERROR: {e}"
    return Tool(
        name="read_file",
        description="Read lines from a file (offset + limit for large files).",
        function=fn,
        schema={"type": "object",
                "properties": {
                    "path":   {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit":  {"type": "integer"}},
                "required": ["path"]})


def _make_python_eval_tool() -> Tool:
    def fn(args: Dict) -> str:
        import io, contextlib
        code = args.get("code", "")
        safe_globals: Dict[str, Any] = {"json": json, "re": re,
                                         "Path": Path, "__builtins__": {}}
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                exec(code, safe_globals)  # noqa: S102
            return buf.getvalue() or "(no output)"
        except Exception as e:
            return f"ERROR: {e}"
    return Tool(
        name="python_eval",
        description="Execute a small Python snippet for data analysis (no network/fs writes).",
        function=fn,
        schema={"type": "object",
                "properties": {"code": {"type": "string", "description": "Python code"}},
                "required": ["code"]})


# ── Agent ──────────────────────────────────────────────────────────────────────

@dataclass
class Agent:
    """
    Named agent with instructions, tool belt, guardrails, and handoff targets.
    Fully compatible with OpenAI Agents SDK patterns.
    """
    name:          str
    instructions:  str
    tools:         List[Tool]       = field(default_factory=list)
    handoffs:      List[str]        = field(default_factory=list)
    guardrails:    List[Guardrail]  = field(default_factory=list)
    model:         str              = ""
    max_steps:     int              = 20
    output_schema: Optional[Dict]  = None
    skill:         Optional[str]   = None   # nova_skills skill name for system prompt

    def tool_map(self) -> Dict[str, Tool]:
        return {t.name: t for t in self.tools}

    def system_prompt(self, available_handoffs: List[str] = None,
                      context: Any = None) -> str:
        # Use nova_skills to render the system prompt if a skill is named
        if self.skill and SkillLibrary:
            try:
                lib = SkillLibrary()
                skill_obj = lib.get(self.skill)
                # Skills that need context parameters fill what they can
                ctx_vars: Dict[str, str] = {}
                if context and hasattr(context, "target"):
                    ctx_vars["target"] = context.target
                for p in skill_obj.params:
                    if p not in ctx_vars:
                        ctx_vars[p] = f"<{p}>"   # placeholder
                try:
                    rendered = skill_obj.render(**ctx_vars)
                    base_system = rendered["system"]
                except Exception:
                    base_system = self.instructions
            except Exception:
                base_system = self.instructions
        else:
            base_system = self.instructions

        tool_block = "\n".join(
            f"- {t.name}: {t.description}\n  Parameters:\n{t.schema_str()}"
            for t in self.tools)
        handoff_block = ", ".join(available_handoffs or self.handoffs) or "none"
        schema_block  = (
            f"\nOutput schema (respond with valid JSON matching this schema when done):\n"
            f"{json.dumps(self.output_schema, indent=2)}"
            if self.output_schema else "")

        # Inject live context summary if available
        ctx_block = ""
        if context and hasattr(context, "summary"):
            try:
                s = context.summary()
                ctx_block = (
                    f"\nCurrent run context:"
                    f"\n  Target: {s.get('target')}"
                    f"\n  Findings so far: {s.get('findings_count', 0)}"
                    f"\n  Subdomains found: {s.get('subdomains_found', 0)}"
                    f"\n  Endpoints found: {s.get('endpoints_found', 0)}")
            except Exception:
                pass

        return f"""You are {self.name}.

{base_system}
{ctx_block}

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
- To hand off, use ACTION: handoff:<AgentName> and pass full context in INPUT.
- When finished, use ACTION: done and put your final answer in INPUT.
- If structured output is required, INPUT must be valid JSON matching the schema.
"""


# ── AgentResult ────────────────────────────────────────────────────────────────

@dataclass
class AgentResult:
    agent:           str
    findings:        List[Dict]      = field(default_factory=list)
    output:          str             = ""
    handoff:         Optional[str]  = None
    handoff_context: str            = ""
    steps:           int            = 0
    trace:           Optional[Trace] = None
    success:         bool           = True
    error:           str            = ""
    cost_usd:        float          = 0.0
    tokens_used:     int            = 0

    def save(self, path: str):
        Path(path).write_text(json.dumps({
            "agent": self.agent, "success": self.success,
            "steps": self.steps, "output": self.output,
            "findings": self.findings, "handoff": self.handoff,
            "error": self.error, "cost_usd": round(self.cost_usd, 6),
            "tokens_used": self.tokens_used,
            "trace_summary": self.trace.summary() if self.trace else {},
        }, indent=2))


# ── Runner ─────────────────────────────────────────────────────────────────────

class Runner:
    """
    Production multi-agent runner — wires LLMRouter, HookBus, RunContext,
    SessionStore, Tracer, and retry infrastructure into every run.

    Drop-in replacement for the v1.0 Runner with no API change.
    """

    def __init__(
        self,
        agents:      List[Agent],
        model:       str           = "",
        max_steps:   int           = 30,
        trace:       bool          = True,
        workspace:   Path          = WORKSPACE,
        # New in v2.0
        context:     Any           = None,    # RunContext instance
        session:     Any           = None,    # Session instance
        bus:         Any           = None,    # HookBus instance
        router:      Any           = None,    # LLMRouter instance
        tracer:      Any           = None,    # nova_observability.Tracer
        verbose:     bool          = True,
    ):
        self.agents    = {a.name: a for a in agents}
        self.model     = model or _OLLAMA_MODEL
        self.max_steps = max_steps
        self.workspace = workspace
        self.verbose   = verbose

        # ── Provider layer ─────────────────────────────────────────────────
        self._router  = router  or (get_router() if get_router else None)
        self._bus     = bus     or (get_bus(verbose=False) if get_bus else None)
        self._context = context or (RunContext(verbose=False) if RunContext else None)
        self._session = session

        # ── Observability ──────────────────────────────────────────────────
        _obs_tracer = tracer or (Tracer(verbose=verbose) if Tracer else None)
        self._trace = Trace(tracer=_obs_tracer) if trace else None

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self, task: str, start: str = None) -> AgentResult:
        """
        Run the agent network on a task, starting from `start` agent.
        Fires PreRun / PostRun hooks, records to session, traces every step.
        """
        start_name = start or (list(self.agents.keys())[0] if self.agents else None)
        if not start_name or start_name not in self.agents:
            return AgentResult(agent=start_name or "?",
                               error="Agent not found", success=False)

        if self.verbose:
            print(f"\n{'═'*65}")
            print(f"  🧠 Nova Orchestrator v2.0 — starting {start_name}")
            print(f"  📋 Task: {task[:80]}")
            if self._router:
                print(f"  🔀 Providers: {self._router.available_providers()}")
            print(f"{'═'*65}")

        # ── Session: start run record ──────────────────────────────────────
        _run_record = None
        if self._session:
            try:
                _run_record = self._session.start_run("orchestrate")
                self._session.add_message("user", task, agent=start_name)
            except Exception:
                pass

        # ── Hooks: PreRun ──────────────────────────────────────────────────
        if self._bus:
            try:
                self._bus.fire("PreRun",
                               {"agent": start_name, "task": task,
                                "target": getattr(self._context, "target", "")})
            except Exception:
                pass

        t_start        = time.monotonic()
        context_str    = task
        agent_name     = start_name
        all_findings:  List[Dict] = []
        total_steps    = 0
        total_cost     = 0.0
        total_tokens   = 0
        agent_chain:   List[str]  = []

        while agent_name and total_steps < self.max_steps:
            # Check cancellation
            if self._context and getattr(self._context, "cancelled", False):
                print("  ⛔ Run cancelled via context.")
                break

            agent = self.agents.get(agent_name)
            if not agent:
                break

            agent_chain.append(agent_name)

            # ── Tracer: agent span ─────────────────────────────────────────
            if self._trace and self._trace._tracer:
                span = self._trace._tracer._new_span(agent_name, "agent")
                span.set("task", context_str[:200])
            else:
                span = None

            result = self._run_agent(agent, context_str, span=span)
            total_steps   += result.steps
            total_cost    += result.cost_usd
            total_tokens  += result.tokens_used
            all_findings.extend(result.findings)

            # ── Context: add findings ──────────────────────────────────────
            if self._context:
                for f in result.findings:
                    try:
                        self._context.add_finding(f, agent=agent_name)
                    except Exception:
                        pass

            # ── Session: record messages + findings ────────────────────────
            if self._session:
                try:
                    for f in result.findings:
                        self._session.add_finding(f)
                    if result.output:
                        self._session.add_message(
                            "assistant", result.output[:500], agent=agent_name)
                except Exception:
                    pass

            if span:
                try:
                    span.set("findings_count", len(result.findings))
                    span.end(status="ok" if result.success else "error",
                             error=result.error or None)
                except Exception:
                    pass

            # ── Handoff or terminal ────────────────────────────────────────
            if result.handoff and result.handoff in self.agents:
                if self._trace:
                    self._trace.log(agent_name, "handoff",
                                    {"to": result.handoff,
                                     "ctx": result.handoff_context[:200]})
                if self._bus:
                    try:
                        self._bus.fire_handoff(
                            agent_name, result.handoff,
                            {"context": result.handoff_context[:400]})
                    except Exception:
                        pass
                if self._context:
                    try:
                        self._context.set_agent_output(agent_name, result.output)
                    except Exception:
                        pass
                context_str = result.handoff_context or context_str
                agent_name  = result.handoff
            else:
                # Terminal
                elapsed_ms = (time.monotonic() - t_start) * 1000

                # ── Hooks: PostRun ─────────────────────────────────────────
                if self._bus:
                    try:
                        self._bus.fire("PostRun", {
                            "agent": agent_name, "elapsed_ms": elapsed_ms,
                            "findings_count": len(all_findings),
                            "cost_usd": total_cost,
                        })
                    except Exception:
                        pass

                # ── Session: end run record ────────────────────────────────
                if self._session and _run_record:
                    try:
                        self._session.end_run(
                            _run_record,
                            findings_count=len(all_findings),
                            cost_usd=total_cost,
                            token_total=total_tokens,
                            agent_chain=agent_chain,
                            success=result.success,
                            error=result.error or None)
                        _store = SessionStore()
                        _store.save(self._session)
                    except Exception:
                        pass

                final = AgentResult(
                    agent=agent_name,
                    findings=all_findings,
                    output=result.output,
                    steps=total_steps,
                    trace=self._trace,
                    success=result.success,
                    cost_usd=total_cost,
                    tokens_used=total_tokens,
                )
                self._save_run(final, task)
                return final

        # Exceeded max steps / cancelled
        return AgentResult(
            agent=start_name, findings=all_findings,
            output="Max steps reached or cancelled",
            steps=total_steps, trace=self._trace,
            success=False, error="exceeded max_steps or cancelled",
            cost_usd=total_cost, tokens_used=total_tokens,
        )

    def run_parallel(self, task: str, agent_names: List[str]) -> List[AgentResult]:
        """Fan out the same task to multiple agents in parallel."""
        if self.verbose:
            print(f"\n  🚀 Parallel fan-out → {agent_names}")
        results = []
        with ThreadPoolExecutor(max_workers=len(agent_names)) as ex:
            futures = {
                ex.submit(self._run_agent, self.agents[n], task): n
                for n in agent_names if n in self.agents
            }
            for f in as_completed(futures):
                results.append(f.result())
        # Merge findings into context + session
        for r in results:
            if self._context:
                for f in r.findings:
                    try:
                        self._context.add_finding(f)
                    except Exception:
                        pass
            if self._session:
                for f in r.findings:
                    try:
                        self._session.add_finding(f)
                    except Exception:
                        pass
        return results

    # ── Internal ───────────────────────────────────────────────────────────────

    def _run_agent(self, agent: Agent, context: str,
                   span=None) -> AgentResult:
        model     = agent.model or self.model
        tool_map  = agent.tool_map()
        history   = [
            {"role": "system",
             "content": agent.system_prompt(
                 list(self.agents.keys()),
                 context=self._context)},
            {"role": "user", "content": context},
        ]

        findings:     List[Dict] = []
        steps         = 0
        total_cost    = 0.0
        total_tokens  = 0

        for step in range(agent.max_steps):
            steps += 1

            # ── Check cancellation ─────────────────────────────────────────
            if self._context and getattr(self._context, "cancelled", False):
                return AgentResult(agent=agent.name, findings=findings,
                                   output="cancelled", steps=steps, success=False,
                                   error="cancelled")

            # ── Input guardrails ───────────────────────────────────────────
            last_msg = history[-1]["content"]
            for g in agent.guardrails:
                if g.on_input:
                    ok, reason = g.validate(last_msg)
                    if not ok:
                        if self._trace:
                            self._trace.log(agent.name, "guardrail",
                                            {"blocked": reason, "guardrail": g.name})
                        if self._bus:
                            try:
                                self._bus.fire("OnGuardrailBlock",
                                               {"guardrail": g.name, "reason": reason},
                                               agent=agent.name)
                            except Exception:
                                pass
                        return AgentResult(
                            agent=agent.name, success=False,
                            error=f"Guardrail '{g.name}' blocked: {reason}",
                            steps=steps)

            # ── LLM call ──────────────────────────────────────────────────
            reply = ""
            llm_span = None
            if span and self._trace and self._trace._tracer:
                try:
                    llm_span = self._trace._tracer._new_span(
                        f"LLM:{model}", "llm", parent_id=span.span_id)
                except Exception:
                    pass

            if self._router:
                try:
                    from nova_llm_router import Message as LLMMessage
                    msgs = [LLMMessage(role=m["role"], content=m["content"])
                            for m in history]
                    resp = self._router.chat(
                        prompt="", messages=msgs)
                    reply = resp.content
                    total_cost   += resp.cost_usd
                    total_tokens += resp.prompt_tokens + resp.output_tokens
                    if llm_span:
                        llm_span.tokens_in  = resp.prompt_tokens
                        llm_span.tokens_out = resp.output_tokens
                        llm_span.cost_usd   = resp.cost_usd
                except Exception as e:
                    print(f"  ⚠️  LLMRouter error: {e}, falling back to Ollama")
            if not reply:
                try:
                    reply = _ollama_chat(model, history)
                except Exception as e:
                    print(f"  ⚠️  Ollama error: {e}")
                    break

            if llm_span:
                try:
                    llm_span.end(status="ok" if reply else "error")
                except Exception:
                    pass

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
                try:
                    parsed = json.loads(inp_raw)
                    if isinstance(parsed, list):
                        findings.extend(parsed)
                    elif isinstance(parsed, dict) and "findings" in parsed:
                        findings.extend(parsed["findings"])
                except Exception:
                    pass
                # Fire OnFinding for each new finding
                if self._bus:
                    for f in findings:
                        try:
                            self._bus.fire_finding(f, agent=agent.name)
                        except Exception:
                            pass
                if self._trace:
                    self._trace.log(agent.name, "complete",
                                    {"output": output[:200],
                                     "findings": len(findings)})
                return AgentResult(
                    agent=agent.name, findings=findings, output=output,
                    steps=steps, success=True,
                    cost_usd=total_cost, tokens_used=total_tokens)

            # handoff
            if action.startswith("handoff:"):
                target = action.split(":", 1)[1].strip()
                if self._trace:
                    self._trace.log(agent.name, "handoff",
                                    {"to": target, "context": inp_raw[:200]})
                return AgentResult(
                    agent=agent.name, findings=findings,
                    handoff=target, handoff_context=inp_raw,
                    steps=steps, success=True,
                    cost_usd=total_cost, tokens_used=total_tokens)

            # tool call
            if action in tool_map:
                try:
                    inp = (json.loads(inp_raw)
                           if inp_raw.strip().startswith("{")
                           else {"input": inp_raw})
                except Exception:
                    inp = {"input": inp_raw}

                if self._trace:
                    self._trace.log(agent.name, "tool_call",
                                    {"tool": action, "input": inp})

                # ── Tool span in tracer ────────────────────────────────────
                tool_span = None
                if span and self._trace and self._trace._tracer:
                    try:
                        tool_span = self._trace._tracer._new_span(
                            action, "tool", parent_id=span.span_id)
                        tool_span.set("args", inp)
                    except Exception:
                        pass

                tool_result = tool_map[action].call(
                    inp, bus=self._bus, agent_name=agent.name)

                if tool_span:
                    try:
                        tool_span.set("result_preview", str(tool_result)[:200])
                        tool_span.end(status="ok")
                    except Exception:
                        pass

                # Extract findings from tool output
                try:
                    parsed = json.loads(tool_result)
                    if (isinstance(parsed, list) and parsed
                            and isinstance(parsed[0], dict)
                            and "severity" in parsed[0]):
                        findings.extend(parsed)
                        if self._bus:
                            for f in parsed:
                                try:
                                    self._bus.fire_finding(f, agent=agent.name)
                                except Exception:
                                    pass
                except Exception:
                    pass

                if self._trace:
                    self._trace.log(agent.name, "tool_result",
                                    {"tool": action,
                                     "result": tool_result[:300]})

                # Output guardrails
                for g in agent.guardrails:
                    if g.on_output:
                        ok, reason = g.validate(tool_result)
                        if not ok:
                            tool_result = f"[BLOCKED by {g.name}: {reason}]"

                history.append({
                    "role": "user",
                    "content": f"Tool result ({action}):\n{tool_result}"})
            else:
                history.append({
                    "role": "user",
                    "content": (f"Unknown action '{action}'. "
                                f"Use a valid tool name, 'done', or 'handoff:AgentName'.")})

        return AgentResult(
            agent=agent.name, findings=findings,
            output="max steps reached", steps=steps, success=False,
            cost_usd=total_cost, tokens_used=total_tokens)

    @staticmethod
    def _parse_reply(reply: str) -> Tuple[str, str]:
        action_match = re.search(r"ACTION:\s*(.+?)(?:\n|$)", reply, re.IGNORECASE)
        input_match  = re.search(r"INPUT:\s*([\s\S]+?)(?:THINK:|ACTION:|$)",
                                 reply, re.IGNORECASE)
        action = action_match.group(1).strip() if action_match else "done"
        inp    = input_match.group(1).strip()  if input_match  else reply
        return action, inp

    def _save_run(self, result: AgentResult, task: str):
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.workspace / f"nova_orchestrator_{ts}.json"
        result.save(str(path))
        if self._trace:
            self._trace.save(str(self.workspace / f"nova_trace_{ts}.json"))
        if self.verbose:
            print(f"\n  💾 Results → {path}")
            print(f"  📊 Findings: {len(result.findings)} | "
                  f"Steps: {result.steps} | "
                  f"Cost: ${result.cost_usd:.5f} | "
                  f"Tokens: {result.tokens_used}")


# ── Pre-built Security Agent Network ──────────────────────────────────────────

def build_security_network(
    target:  str,
    scope:   List[str] = None,
    session: Any = None,
    verbose: bool = True,
) -> Runner:
    """
    Build a production-ready security agent network:
      ReconAgent → AttackAgent → ReportAgent

    All agents share:
      - RunContext (typed shared state with scope enforcement)
      - HookBus   (lifecycle events)
      - LLMRouter (multi-provider with auto-fallback)
      - Tracer    (span-based execution tracing)
    """
    scope = scope or [target.split("//")[-1].split("/")[0]]

    # ── Provider layer ─────────────────────────────────────────────────────
    router  = get_router() if get_router else None
    bus     = get_bus(verbose=False) if get_bus else None
    context = (RunContext(target=target, scope=scope, verbose=False)
               if RunContext else None)
    tracer  = Tracer(verbose=verbose) if Tracer else None

    # ── Wire standard logging hooks ────────────────────────────────────────
    if bus:
        try:
            from nova_hooks import attach_logging_hooks
            attach_logging_hooks(bus)
        except Exception:
            pass

        # Telegram alerts if configured
        tg_token   = os.getenv("NOVA_TELEGRAM_TOKEN")
        tg_chat_id = os.getenv("NOVA_TELEGRAM_CHAT_ID")
        if tg_token and tg_chat_id:
            try:
                from nova_hooks import attach_telegram_hooks
                attach_telegram_hooks(bus, tg_token, tg_chat_id)
            except Exception:
                pass

    # ── Guardrails ─────────────────────────────────────────────────────────
    guardrails = [SAFETY_GUARDRAIL]
    if scope:
        guardrails.append(Guardrail(
            name="ScopeGuard",
            check=_scope_guardrail_fn(scope),
            on_input=True))

    # ── Tools ──────────────────────────────────────────────────────────────
    http_tool  = _make_http_probe_tool()
    shell_tool = _make_shell_tool()
    read_tool  = _make_read_file_tool()
    py_tool    = _make_python_eval_tool()

    # ── Agents ─────────────────────────────────────────────────────────────
    recon_agent = Agent(
        name="ReconAgent",
        instructions=(
            f"You are Nova's passive recon specialist. Target: {target}\n"
            "Discover: subdomains, endpoints, JS files, technologies, open ports, API paths.\n"
            "Use http_probe to fetch robots.txt, sitemap.xml, /.well-known/, /api/.\n"
            "Use shell with subfinder, httpx, gau for deeper discovery.\n"
            "Collect all discovered URLs. Then hand off to AttackAgent with full recon data."
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
            "Test every endpoint from ReconAgent for:\n"
            "  - IDOR / BOLA (horizontal + vertical privilege escalation)\n"
            "  - SQL injection (error, blind boolean, time-based, union)\n"
            "  - XSS (reflected, stored, DOM)\n"
            "  - SSRF (cloud metadata, internal network)\n"
            "  - Authentication bypass, JWT flaws, session fixation\n"
            "  - Business logic flaws (negative prices, workflow skipping)\n"
            "  - Information disclosure, directory traversal\n"
            "For each confirmed finding produce JSON: "
            "{type, severity, endpoint, evidence, cvss, description}.\n"
            "Hand off ALL findings to ReportAgent."
        ),
        tools=[http_tool, shell_tool, py_tool],
        handoffs=["ReportAgent"],
        guardrails=guardrails,
        max_steps=25,
        output_schema={
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "severity", "endpoint"],
                "properties": {
                    "type":        {"type": "string"},
                    "severity":    {"type": "string",
                                   "enum": ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]},
                    "endpoint":    {"type": "string"},
                    "evidence":    {"type": "string"},
                    "cvss":        {"type": "number"},
                    "description": {"type": "string"},
                    "cve":         {"type": "string"},
                },
            },
        },
    )

    report_agent = Agent(
        name="ReportAgent",
        instructions=(
            "You are Nova's reporting specialist.\n"
            "Receive findings from AttackAgent and produce:\n"
            "1. Executive summary (3 sentences max)\n"
            "2. Prioritised findings list (CRITICAL → INFO) with CVSS scores\n"
            "3. Overall risk score (0-10)\n"
            "4. Top 3 recommended remediations with code-level guidance\n"
            "5. HackerOne submission readiness (yes/no + reason)\n"
            "Output structured JSON."
        ),
        tools=[py_tool, read_tool],
        guardrails=[SAFETY_GUARDRAIL],
        max_steps=10,
    )

    return Runner(
        agents=[recon_agent, attack_agent, report_agent],
        max_steps=60,
        context=context,
        session=session,
        bus=bus,
        router=router,
        tracer=tracer,
        verbose=verbose,
    )


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="🧠 Nova Orchestrator v2.0 — Production multi-agent security runner")
    parser.add_argument("task",        help="Task in plain English")
    parser.add_argument("--target",    default=os.getenv("NOVA_TARGET", "http://localhost:3000"))
    parser.add_argument("--scope",     nargs="*", default=[])
    parser.add_argument("--start",     default="ReconAgent")
    parser.add_argument("--max-steps", type=int, default=60)
    parser.add_argument("--session-id",help="Resume a previous session by ID")
    parser.add_argument("--quiet",     action="store_true")
    args = parser.parse_args()

    # ── Resume or create session ───────────────────────────────────────────
    session = None
    if SessionStore:
        store = SessionStore()
        if args.session_id:
            session = store.load(args.session_id)
            if session:
                print(f"  📂 Resumed session {args.session_id[:8]} "
                      f"({len(session.findings)} existing findings)")
            else:
                print(f"  ⚠️  Session {args.session_id} not found. Starting new.")
        if not session:
            session = store.create(target=args.target, mission="orchestrate")
            print(f"  📂 New session: {session.session_id[:8]}")

    runner = build_security_network(
        args.target, scope=args.scope or [args.target],
        session=session, verbose=not args.quiet)
    runner.max_steps = args.max_steps

    result = runner.run(args.task, start=args.start)

    print(f"\n{'═'*65}")
    print(f"  ✅ Orchestrator complete")
    print(f"  📊 Findings:  {len(result.findings)}")
    print(f"  🔢 Steps:     {result.steps}")
    print(f"  💰 Cost:      ${result.cost_usd:.5f}")
    print(f"  🔤 Tokens:    {result.tokens_used}")
    if result.findings:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_f  = sorted(result.findings,
                           key=lambda f: sev_order.get(f.get("severity","INFO").upper(), 4))
        for f in sorted_f[:10]:
            sev = f.get("severity","?").upper()
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                    "LOW": "🔵", "INFO": "⚪"}.get(sev, "•")
            print(f"  {icon} [{sev}] {f.get('type','?')} — {f.get('endpoint','?')}")
    if session:
        print(f"  📂 Session:   {session.session_id[:8]} "
              f"(total findings: {len(session.findings)})")
    print(f"{'═'*65}")
