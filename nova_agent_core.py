#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   🦅 NOVA AGENT CORE v1.0 — TRUE AGENTIC EXECUTION ENGINE      ║
║                                                                  ║
║   Closes the gap with Claude Code / Daybreak / OpenAI Codex     ║
║   by giving Nova a real ReAct agent loop:                       ║
║                                                                  ║
║   OBSERVE → THINK → ACT → OBSERVE → THINK → ACT → ...          ║
║                                                                  ║
║   The LLM decides what to do next — not hardcoded pipelines.    ║
║   Nova gets the same freedom frontier agents have:              ║
║     • Run any shell command                                     ║
║     • Use a real headless browser (Playwright)                  ║
║     • Make HTTP requests with full control                      ║
║     • Read and write files                                      ║
║     • Install missing tools on demand                           ║
║     • Chain observations into multi-step attack plans           ║
║                                                                  ║
║   Zero cloud. Zero API keys. Pure local intelligence.           ║
╚══════════════════════════════════════════════════════════════════╝

ReAct Loop:
  1. System prompt includes: task, tools, past findings (RAG), memory
  2. LLM outputs: {"thought": "...", "action": "tool_name", "args": {...}}
  3. Nova executes the tool
  4. Result added to conversation history
  5. LLM sees result, decides next action
  6. Repeat until LLM calls "mission_complete" or max_steps reached
"""

import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from nova_tool_kit import execute_tool, tools_summary_for_prompt, TOOL_SCHEMAS

try:
    from nova_model_router import get_router
    _ROUTER_AVAILABLE = True
except ImportError:
    _ROUTER_AVAILABLE = False

try:
    from nova_rag_builder import get_rag
    _RAG_AVAILABLE = True
except ImportError:
    _RAG_AVAILABLE = False

OLLAMA_URL    = os.getenv("NOVA_LLM_URL",   "http://localhost:11434")
OLLAMA_MODEL  = os.getenv("NOVA_LLM_MODEL", "")
MAX_STEPS     = int(os.getenv("NOVA_MAX_STEPS", "30"))
AGENT_TIMEOUT = int(os.getenv("NOVA_LLM_TIMEOUT", "120"))
WORKSPACE     = os.path.expanduser("~/nova_workspace")


# ── SYSTEM PROMPT ─────────────────────────────────────────────────

AGENT_SYSTEM_PROMPT = """You are Nova, an elite autonomous security researcher and bug bounty hunter.
You have full access to a Linux environment, a real Chromium browser, and a complete security tool stack.
You operate exactly like a senior human researcher: you use tools freely, chain observations into insights,
adapt your strategy based on what you find, and don't stop until you've fully exploited every attack surface.

You work in a ReAct loop:
  THINK: reason about what you know and what to try next
  ACT:   call exactly one tool
  OBSERVE: study the result and plan your next step

RULES:
1. Always output valid JSON with "thought", "action", and "args" fields.
2. Never guess — use tools to observe before concluding.
3. Chain your findings: a leaked JWT enables admin access; admin access enables data exfiltration.
4. Verify every finding before logging it — false positives waste bounty budget.
5. When you find something critical, immediately write it to a findings file.
6. Call mission_complete only when you have exhausted the attack surface or reached the objective.

OUTPUT FORMAT (always):
{
  "thought": "What I know so far and why I'm choosing this action",
  "action": "tool_name",
  "args": { ... }
}

{TOOLS}

{RAG_CONTEXT}
"""

# ── AGENT LOOP ────────────────────────────────────────────────────

class NovaAgent:
    """
    Nova's true agentic execution engine.

    The LLM drives the hunt — deciding what tools to call, in what order,
    based on what it observes. No hardcoded attack phases.
    """

    def __init__(
        self,
        target: str       = "http://localhost:3000",
        objective: str    = "Find and exploit all critical vulnerabilities",
        max_steps: int    = MAX_STEPS,
        nova_dir: str     = ".",
        session_id: str   = None,
    ):
        self.target     = target
        self.objective  = objective
        self.max_steps  = max_steps
        self.nova_dir   = nova_dir
        self.session_id = session_id or datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.history: List[Dict]  = []   # full conversation history
        self.findings: List[Dict] = []   # confirmed vulnerabilities
        self.step       = 0
        self.start_time = None
        self.done       = False

        # Model selection
        self.model = OLLAMA_MODEL
        if not self.model and _ROUTER_AVAILABLE:
            try:
                router = get_router()
                self.model = router.best_model_for("attack_planning") or ""
            except Exception:
                pass
        if not self.model:
            self.model = self._detect_model()

        # RAG context from past findings
        self.rag_context = self._load_rag()

        os.makedirs(WORKSPACE, exist_ok=True)
        self.findings_file = os.path.join(WORKSPACE, f"agent_findings_{self.session_id}.json")
        self.log_file      = os.path.join(WORKSPACE, f"agent_log_{self.session_id}.jsonl")

    def _detect_model(self) -> str:
        """Pick best available Ollama model."""
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                preferred = [
                    "deepseek-r1", "qwen3", "devstral", "qwen2.5-coder",
                    "llama3.1", "llama3", "mistral",
                ]
                for pref in preferred:
                    for m in models:
                        if pref in m:
                            return m
                if models:
                    return models[0]
        except Exception:
            pass
        return "llama3"

    def _load_rag(self) -> str:
        """Load relevant prior knowledge from RAG."""
        if not _RAG_AVAILABLE:
            return ""
        try:
            rag     = get_rag(nova_dir=self.nova_dir)
            entries = rag.query("attack_planning", top_k=5)
            if entries:
                return rag.format_context(entries, max_chars=1000)
        except Exception:
            pass
        return ""

    def _build_system_prompt(self) -> str:
        """Build the system prompt with tools and RAG context."""
        tools_text = tools_summary_for_prompt()
        rag_section = ""
        if self.rag_context:
            rag_section = f"\nPRIOR KNOWLEDGE FROM PAST HUNTS:\n{self.rag_context}\n"
        return (
            AGENT_SYSTEM_PROMPT
            .replace("{TOOLS}", tools_text)
            .replace("{RAG_CONTEXT}", rag_section)
        )

    # ── MAIN LOOP ─────────────────────────────────────────────────

    def run(self) -> Dict:
        """Execute the full agentic hunt."""
        self.start_time = time.time()
        self._banner()

        # Seed the conversation with the objective
        self.history = [{
            "role":    "user",
            "content": (
                f"Target: {self.target}\n"
                f"Objective: {self.objective}\n\n"
                "Begin the security assessment. Use tools freely. Think step by step. "
                "Start with reconnaissance to map the attack surface, then attack."
            ),
        }]

        while self.step < self.max_steps and not self.done:
            self.step += 1
            print(f"\n{'─'*60}")
            print(f"  🦅 NOVA AGENT — Step {self.step}/{self.max_steps}")
            print(f"  Findings so far: {len(self.findings)} | Model: {self.model}")

            # Ask LLM what to do next
            action = self._think()
            if not action:
                print("  ⚠️  LLM returned no action — retrying...")
                time.sleep(2)
                continue

            thought = action.get("thought", "")
            tool    = action.get("action", "")
            args    = action.get("args", {})

            print(f"\n  💭 THOUGHT: {thought[:120]}")
            print(f"  ⚡ ACTION:  {tool}({json.dumps(args, default=str)[:100]})")

            if not tool or tool not in {t["name"] for t in TOOL_SCHEMAS}:
                print(f"  ❌ Unknown tool: {tool}")
                self._add_observation({"error": f"Tool '{tool}' does not exist."})
                continue

            # Execute the tool
            result = execute_tool(tool, args)
            elapsed = result.get("_elapsed", 0)

            # Check for mission_complete signal
            if tool == "mission_complete" or result.get("done"):
                self.done = True
                print(f"\n  ✅ MISSION COMPLETE: {args.get('summary','')}")
                break

            # Log and feed result back
            self._log_step(action, result)
            obs_text = self._format_observation(tool, result)
            print(f"  📊 RESULT ({elapsed}s): {obs_text[:150]}")
            self._add_observation(result)

            # Extract any findings the LLM wrote to disk
            self._harvest_findings()

        elapsed_total = round(time.time() - self.start_time, 1)
        return self._wrap_up(elapsed_total)

    # ── LLM INTERFACE ─────────────────────────────────────────────

    def _think(self) -> Optional[Dict]:
        """Ask the LLM for the next action."""
        messages = [
            {"role": "system", "content": self._build_system_prompt()},
        ] + self.history

        for attempt in range(3):
            try:
                r = requests.post(
                    f"{OLLAMA_URL}/api/chat",
                    json={
                        "model":   self.model,
                        "messages": messages,
                        "stream":  False,
                        "options": {
                            "temperature": 0.2,
                            "num_predict": 800,
                        },
                    },
                    timeout=AGENT_TIMEOUT,
                )
                if r.status_code != 200:
                    time.sleep(2)
                    continue

                content = r.json().get("message", {}).get("content", "").strip()
                self.history.append({"role": "assistant", "content": content})
                return self._parse_action(content)

            except requests.exceptions.Timeout:
                print(f"  ⏱  LLM timeout (attempt {attempt+1}/3)")
                if attempt < 2:
                    time.sleep(3)
            except Exception as e:
                print(f"  ❌ LLM error: {e}")
                break

        return None

    def _parse_action(self, text: str) -> Optional[Dict]:
        """Parse LLM output into {thought, action, args}."""
        # Strip CoT <thinking> blocks first
        text = re.sub(r'<thinking>[\s\S]*?</thinking>', '', text).strip()
        # Strip markdown fences
        text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\s*```$', '', text)

        # Try direct JSON parse
        try:
            obj = json.loads(text)
            if "action" in obj:
                return obj
        except Exception:
            pass

        # Extract first JSON object
        m = re.search(r'\{[\s\S]*?"action"[\s\S]*?\}', text)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass

        # Fallback: extract fields with regex
        thought = re.search(r'"thought"\s*:\s*"([^"]+)"', text)
        action  = re.search(r'"action"\s*:\s*"([^"]+)"', text)
        if action:
            return {
                "thought": thought.group(1) if thought else "",
                "action":  action.group(1),
                "args":    {},
            }

        print(f"  ⚠️  Could not parse LLM output: {text[:200]}")
        return None

    def _add_observation(self, result: Dict):
        """Add tool result to conversation history."""
        # Keep observations concise to preserve context window
        obs = json.dumps(result, default=str)[:2000]
        self.history.append({
            "role":    "user",
            "content": f"Tool result:\n{obs}\n\nWhat is your next action?",
        })
        # Trim history if too long (keep system context + last 20 exchanges)
        if len(self.history) > 42:
            self.history = self.history[:1] + self.history[-40:]

    def _format_observation(self, tool: str, result: Dict) -> str:
        """Format a tool result for console display."""
        if not result.get("success", True):
            return f"❌ FAILED: {result.get('error','')}"
        if tool == "http_request":
            return f"HTTP {result.get('status_code','?')} — {len(result.get('body',''))} bytes"
        if tool == "bash_exec":
            out = result.get("stdout", result.get("combined", ""))
            return out[:100].replace("\n", " ")
        if tool == "browser_open":
            return f"Loaded: {result.get('title','?')} — {len(result.get('content',''))} chars"
        return str(result)[:100]

    # ── FINDINGS HARVESTING ───────────────────────────────────────

    def _harvest_findings(self):
        """Check if the LLM wrote any new findings to disk."""
        try:
            if os.path.exists(self.findings_file):
                with open(self.findings_file) as f:
                    fresh = json.load(f)
                if isinstance(fresh, list):
                    # Merge, avoid duplicates
                    existing_ids = {f.get("id") for f in self.findings}
                    for finding in fresh:
                        if finding.get("id") not in existing_ids:
                            self.findings.append(finding)
                            print(f"  🔴 NEW FINDING: {finding.get('type','?')} on {finding.get('endpoint','?')}")
        except Exception:
            pass

    # ── LOGGING ───────────────────────────────────────────────────

    def _log_step(self, action: Dict, result: Dict):
        """Append step to JSONL log."""
        try:
            entry = {
                "step":      self.step,
                "timestamp": datetime.utcnow().isoformat(),
                "action":    action,
                "result":    {k: v for k, v in result.items() if k != "html"},
            }
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            pass

    # ── WRAP-UP ───────────────────────────────────────────────────

    def _wrap_up(self, elapsed: float) -> Dict:
        """Generate final report and return results."""
        by_sev = {}
        for f in self.findings:
            s = f.get("severity", "medium")
            by_sev[s] = by_sev.get(s, 0) + 1

        print(f"""
╔══════════════════════════════════════════════════════════════╗
║   🦅 NOVA AGENT — MISSION COMPLETE                          ║
╠══════════════════════════════════════════════════════════════╣
║  Target:    {self.target[:50]:<50} ║
║  Duration:  {elapsed:<53.1f} ║
║  Steps:     {self.step:<53} ║
║  Findings:  {len(self.findings):<53} ║""")
        icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}
        for sev, count in by_sev.items():
            icon = icons.get(sev, "  ")
            print(f"║  {icon} {sev.capitalize():<10} {count:<45} ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print(f"\n  📁 Log: {self.log_file}")
        print(f"  📊 Findings: {self.findings_file}")

        result = {
            "session_id": self.session_id,
            "target":     self.target,
            "objective":  self.objective,
            "steps":      self.step,
            "duration_s": elapsed,
            "findings":   self.findings,
            "by_severity":by_sev,
            "log_file":   self.log_file,
        }

        report_file = os.path.join(WORKSPACE, f"agent_report_{self.session_id}.json")
        with open(report_file, "w") as f:
            json.dump(result, f, indent=2, default=str)

        return result

    def _banner(self):
        print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   🦅  NOVA AGENT CORE v1.0 — AGENTIC HUNT                      ║
║                                                                  ║
║   Target:    {self.target[:50]:<50} ║
║   Objective: {self.objective[:50]:<50} ║
║   Model:     {self.model[:50]:<50} ║
║   Max steps: {self.max_steps:<50} ║
╚══════════════════════════════════════════════════════════════════╝
""")


# ── CLI ENTRY POINT ───────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="🦅 Nova Agent — Autonomous agentic security assessment"
    )
    parser.add_argument("--target",    default="http://localhost:3000", help="Target URL")
    parser.add_argument("--objective", default="Find and exploit all critical vulnerabilities. Start with recon, then attack the highest-risk endpoints.", help="Mission objective")
    parser.add_argument("--steps",     type=int, default=MAX_STEPS, help=f"Max agent steps (default {MAX_STEPS})")
    parser.add_argument("--model",     default="", help="Force specific Ollama model")
    parser.add_argument("--dir",       default=".", help="Nova repo directory (for RAG)")
    args = parser.parse_args()

    if args.model:
        os.environ["NOVA_LLM_MODEL"] = args.model

    agent = NovaAgent(
        target    = args.target,
        objective = args.objective,
        max_steps = args.steps,
        nova_dir  = args.dir,
    )
    result = agent.run()
    print(f"\n✅ Done. {len(result['findings'])} findings in {result['duration_s']}s.")
