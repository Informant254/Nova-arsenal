#!/usr/bin/env python3
"""
NOVA AGENT CORE v2.0 — AUTONOMOUS REASONING ENGINE

Closed gaps vs Claude Code / Mythos / Daybreak:
  ✅ Pre-hunt strategic planning  (nova_planner)
  ✅ Rolling context compression  (nova_context_manager)
  ✅ Visual recon at hunt start   (nova_vision)
  ✅ CVE research before attacking (nova_web_researcher)
  ✅ Triple-verify before report   (nova_verify_engine)
  ✅ 20 parallel-capable tools    (nova_tool_kit v2)
"""

import json
import os
import sys
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import requests as _req
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

from nova_tool_kit import execute_tool, tools_summary_for_prompt, TOOL_SCHEMAS

# ── Optional gap-closing modules ─────────────────────────────────────────────
try:
    from nova_model_router import get_router
    _ROUTER = True
except ImportError:
    _ROUTER = False

try:
    from nova_rag_builder import get_rag_context
    _RAG = True
except ImportError:
    _RAG = False

try:
    from nova_planner import generate_plan, load_or_create_plan, HuntPlan
    _PLANNER = True
except ImportError:
    _PLANNER = False

try:
    from nova_context_manager import ContextManager
    _CTX_MGR = True
except ImportError:
    _CTX_MGR = False

try:
    from nova_repo_intelligence import update_index
    _REPO_INTEL = True
except ImportError:
    _REPO_INTEL = False

# ── CONFIG ────────────────────────────────────────────────────────────────────
OLLAMA_URL     = os.getenv("NOVA_LLM_URL",            "http://localhost:11434")
OLLAMA_MODEL   = os.getenv("NOVA_LLM_MODEL",          "")
MAX_STEPS      = int(os.getenv("NOVA_MAX_STEPS",      "40"))
AGENT_TIMEOUT  = int(os.getenv("NOVA_LLM_TIMEOUT",    "120"))
WORKSPACE      = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
REFLECT_EVERY  = int(os.getenv("NOVA_REFLECT_EVERY",  "5"))
HISTORY_LIMIT  = int(os.getenv("NOVA_HISTORY_LIMIT",  "30"))
AUTO_PLAN      = os.getenv("NOVA_AUTO_PLAN",  "true").lower() != "false"
AUTO_VISUAL    = os.getenv("NOVA_AUTO_VISUAL","true").lower() != "false"
AUTO_CVE       = os.getenv("NOVA_AUTO_CVE",  "true").lower() != "false"

# ── SYSTEM PROMPT ─────────────────────────────────────────────────────────────
AGENT_SYSTEM_PROMPT = """You are Nova — a senior offensive security researcher.
You think like a human expert: plan first, then probe systematically, verify before reporting.

You work in a strict ReAct loop:
  THINK:   reason about what you know and what to try next
  ACT:     call exactly ONE tool
  OBSERVE: study the result and update your plan

OUTPUT FORMAT — always emit valid JSON with exactly these three keys:
{
  "thought": "what I know so far and why I chose this action",
  "action":  "tool_name",
  "args":    { ... }
}

RULES:
1. Never guess — use tools to observe before concluding.
2. Chain findings: SQLi → credential dump → JWT forge → admin access → data exfil.
3. Verify EVERY finding with verify_finding before calling mission_complete.
4. When you find something critical, write it with file_write immediately.
5. If a tool fails, inspect the error and try a different approach.
6. Use visual_analyze at the start of every web hunt — you might see things source misses.
7. Use research_cve early — knowing the tech stack's CVEs guides your attack path.
8. Use plan_hunt if you don't have a plan yet — never hunt blind.
9. Use parallel_probe when testing multiple endpoints simultaneously.
10. Use verify_finding for ANY suspected sqli/xss/ssrf/idor/rce before reporting it.
11. Call mission_complete ONLY when you have verified findings or have exhausted the surface.
"""

class NovaAgent:
    def __init__(self, target: str,
                 objective: str = "Find and exploit all critical vulnerabilities.",
                 max_steps: int = None,
                 session_id: str = None,
                 plan_id: str = None):
        self.target     = target
        self.objective  = objective
        self.max_steps  = max_steps or MAX_STEPS
        self.session_id = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.findings   : List[Dict] = []
        self.is_done    = False
        self.plan       : Optional[Any] = None   # HuntPlan
        self.ctx        : Optional[Any] = None   # ContextManager
        self._plan_id   = plan_id
        self._verifications: List[Dict] = []

        WORKSPACE.mkdir(parents=True, exist_ok=True)
        self.log_path      = WORKSPACE / f"nova_run_{self.session_id}.log"
        self.findings_path = WORKSPACE / f"nova_findings_{self.session_id}.json"

        # Model selection
        self.model = OLLAMA_MODEL
        if not self.model and _ROUTER:
            try:
                self.model = get_router().best_model_for("attack_planning")
            except Exception:
                pass
        if not self.model:
            self.model = self._detect_model()

    # ── MODEL SELECTION ───────────────────────────────────────────────────────

    def _detect_model(self) -> str:
        preferred = ["xploiter","deepseek-r1","devstral","qwen3","qwen2.5","llama3"]
        if _REQUESTS_OK:
            try:
                r = _req.get(f"{OLLAMA_URL}/api/tags", timeout=5)
                if r.status_code == 200:
                    models = [m["name"] for m in r.json().get("models", [])]
                    for p in preferred:
                        for m in models:
                            if p in m: return m
                    if models: return models[0]
            except Exception:
                pass
        return "qwen3:8b"

    # ── PRE-HUNT SETUP ────────────────────────────────────────────────────────

    def _pre_hunt_plan(self):
        """Generate a strategic plan before the first tool call (Claude Code pattern)."""
        if not _PLANNER or not AUTO_PLAN:
            return
        print("  🗺️  Generating pre-hunt plan...")
        self.plan = load_or_create_plan(self.target, self.objective, self._plan_id)
        print(f"  ✅ Plan ready: {len(self.plan.phases)} phases")
        # Inject plan into context
        if self.ctx:
            self.ctx.set_plan(self.plan.to_agent_context())

    def _pre_hunt_visual(self):
        """Visual recon of the target before the ReAct loop (Mythos pattern)."""
        if not AUTO_VISUAL:
            return
        print("  👁️  Pre-hunt visual recon...")
        try:
            result = execute_tool("visual_analyze", {"url": self.target})
            if result.get("success"):
                vectors = result.get("attack_vectors", [])
                summary = result.get("summary", "")
                ctx_note = f"VISUAL RECON of {self.target}:\n{summary}\nAttack vectors: {json.dumps(vectors[:3])}"
                if self.ctx:
                    self.ctx.add("user", ctx_note)
                else:
                    self._fallback_history.append({"role": "user", "content": ctx_note})
                print(f"  ✅ Visual recon: {len(vectors)} vectors identified")
        except Exception as e:
            print(f"  ⚠️  Visual recon skipped: {e}")

    def _pre_hunt_cve(self):
        """Quick CVE check of the target's tech stack (Daybreak pattern)."""
        if not AUTO_CVE:
            return
        print("  🌐 Pre-hunt CVE research...")
        try:
            # First probe to detect tech stack
            probe = execute_tool("http_request", {"url": self.target, "timeout": 8})
            headers = probe.get("headers", {})
            powered_by = headers.get("X-Powered-By","") or headers.get("Server","")
            if not powered_by:
                return
            result = execute_tool("research_cve", {"query": powered_by, "include_pocs": True})
            if result.get("success") and result.get("cves"):
                top = result["cves"][:3]
                cve_note = (
                    f"CVE RESEARCH ({powered_by}): found {len(result['cves'])} CVEs. "
                    f"Top: {', '.join(c['cve_id'] for c in top)}"
                )
                if self.ctx:
                    self.ctx.add("user", cve_note)
                else:
                    self._fallback_history.append({"role": "user", "content": cve_note})
                print(f"  ✅ CVE research: {len(result['cves'])} CVEs found for {powered_by}")
        except Exception as e:
            print(f"  ⚠️  CVE research skipped: {e}")

    # ── CONTEXT MANAGEMENT ────────────────────────────────────────────────────

    def _init_context(self):
        """Initialize context manager or fallback list."""
        if _CTX_MGR:
            self.ctx = ContextManager(
                session_id=self.session_id,
                target=self.target,
                objective=self.objective,
                compress_every=8,
            )
            self.ctx.add("user", f"TARGET: {self.target}\nOBJECTIVE: {self.objective}")
        else:
            self._fallback_history = [
                {"role": "user", "content": f"TARGET: {self.target}\nOBJECTIVE: {self.objective}"}
            ]

    def _get_messages(self) -> List[Dict]:
        """Get full messages list for LLM call."""
        rag = ""
        if _RAG:
            try:
                rag = get_rag_context(self.target) or ""
            except Exception:
                pass

        system = AGENT_SYSTEM_PROMPT
        if rag:
            system += f"\n\nRAG CONTEXT (past hunt knowledge):\n{rag[:3000]}"
        system += f"\n\nAVAILABLE TOOLS:\n{tools_summary_for_prompt()}"

        if self.ctx:
            return self.ctx.get_messages(system)
        else:
            # Simple fallback — trim if over limit
            hist = self._fallback_history
            if len(hist) > HISTORY_LIMIT:
                hist = hist[:2] + hist[-10:]
            return [{"role": "system", "content": system}] + hist

    def _add_message(self, role: str, content: str):
        if self.ctx:
            self.ctx.add(role, content)
        else:
            self._fallback_history.append({"role": role, "content": content})

    # ── LLM CALL ─────────────────────────────────────────────────────────────

    def _call_ollama(self, messages: List[Dict]) -> str:
        payload = {
            "model":   self.model,
            "messages": messages,
            "stream":  False,
            "options": {"temperature": 0.1, "num_predict": 1024},
        }
        if _REQUESTS_OK:
            try:
                r = _req.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=AGENT_TIMEOUT)
                if r.status_code == 200:
                    return r.json().get("message",{}).get("content","")
            except Exception as e:
                print(f"  [!] Ollama error: {e}")
            return ""
        # urllib fallback
        import urllib.request
        try:
            data = json.dumps(payload).encode()
            req  = urllib.request.Request(
                f"{OLLAMA_URL}/api/chat", data=data,
                headers={"Content-Type":"application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=AGENT_TIMEOUT) as resp:
                return json.loads(resp.read()).get("message",{}).get("content","")
        except Exception as e:
            print(f"  [!] Ollama error: {e}")
            return ""

    # ── PARSING ───────────────────────────────────────────────────────────────

    def _parse_action(self, text: str) -> Optional[Dict]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```[a-zA-Z]*\n?","",cleaned)
            cleaned = re.sub(r"\n?```$","",cleaned).strip()
        try:
            return json.loads(cleaned)
        except Exception:
            pass
        m = re.search(r"\{[\s\S]+\}", text)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
        # Field-level fallback
        thought = re.search(r'"thought"\s*:\s*"([^"]+)"', text)
        action  = re.search(r'"action"\s*:\s*"([^"]+)"', text)
        args    = re.search(r'"args"\s*:\s*(\{[\s\S]+?\})', text)
        if action:
            a = {}
            if args:
                try: a = json.loads(args.group(1))
                except Exception: pass
            return {"thought": thought.group(1) if thought else "",
                    "action": action.group(1), "args": a}
        return None

    # ── OBSERVATION FORMATTING ────────────────────────────────────────────────

    def _format_obs(self, tool: str, result: Dict) -> str:
        status = "SUCCESS" if result.get("success") else "FAILED"
        out = f"TOOL '{tool}' → {status}\n"
        for key in ("stdout","body","content","result","context","summary"):
            v = result.get(key,"")
            if v: out += f"{key.upper()}:\n{str(v)[:3000]}\n"; break
        if result.get("error"):  out += f"ERROR: {result['error']}\n"
        if result.get("matches"): out += f"MATCHES:\n{json.dumps(result['matches'][:20],indent=2)}\n"
        if result.get("finding"): out += f"FINDING:\n{json.dumps(result['finding'],indent=2)[:1000]}\n"
        if result.get("cves"):    out += f"CVES: {len(result['cves'])} found\n"
        if result.get("plan"):    out += f"PLAN:\n{result.get('context','')[:1500]}\n"
        return out[:5000]

    # ── REFLECTION ────────────────────────────────────────────────────────────

    def _reflect(self, step: int):
        print(f"  🔄 Reflection @ step {step}...")
        prompt = ("Reflect on your last 5 steps. What worked, what failed? "
                  "What is your updated strategy? Output 3-5 bullet points.")
        messages = [
            {"role":"system","content":"You are Nova's self-correction engine. Be brief and precise."},
            {"role":"user","content": prompt},
        ]
        # Use last 6 messages for context
        if self.ctx:
            recent = self.ctx.ctx.verbatim[-6:]
            messages = [messages[0]] + recent + [messages[1]]
        resp = self._call_ollama(messages)
        if resp:
            self._add_message("user", f"SELF-REFLECTION:\n{resp}")

    # ── FINDING PINNING ───────────────────────────────────────────────────────

    def _maybe_pin_finding(self, tool: str, result: Dict):
        """If a tool returned a verified finding, pin it to context."""
        finding = result.get("finding",{})
        if finding and finding.get("confirmed") and self.ctx:
            self.ctx.pin(
                vuln_type=finding.get("vuln_type","unknown"),
                endpoint=finding.get("endpoint",""),
                severity=finding.get("severity","HIGH"),
                summary=f"CVSS {finding.get('cvss_score',0)} — {finding.get('confirmations',0)}/3 confirmed",
                confirmed=True,
                finding_id=finding.get("finding_id"),
            )
            self.findings.append(finding)

    # ── PLAN UPDATE ───────────────────────────────────────────────────────────

    def _update_plan_from_result(self, tool: str, result: Dict, step: int):
        """Mark plan phases complete when findings are verified."""
        if not self.plan:
            return
        if tool == "verify_finding" and result.get("finding",{}).get("confirmed"):
            # Mark inject/verify phase complete
            self.plan.mark_complete("inject", findings=[result["finding"]])
            if self.ctx:
                self.ctx.set_plan(self.plan.to_agent_context())

    # ── MAIN LOOP ─────────────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        start = time.time()
        print(f"\n{'─'*60}")
        print(f"  🦅 Nova Agent v2.0 — Session {self.session_id}")
        print(f"  🎯 Target:    {self.target}")
        print(f"  📋 Objective: {self.objective[:80]}")
        print(f"  🧠 Model:     {self.model}")
        print(f"{'─'*60}\n")

        # ── PRE-HUNT SETUP (Claude Code pattern) ──────────────────────────────
        self._init_context()

        if _REPO_INTEL:
            try:
                print("  🗂️  Building repo index...")
                update_index()
            except Exception:
                pass

        self._pre_hunt_plan()
        self._pre_hunt_visual()
        self._pre_hunt_cve()

        # ── REACT LOOP ────────────────────────────────────────────────────────
        step = 0
        while step < self.max_steps and not self.is_done:
            step += 1
            print(f"\n  ── Step {step}/{self.max_steps} ──")

            messages = self._get_messages()
            response = self._call_ollama(messages)

            if not response:
                print("  [!] Empty response — retrying...")
                time.sleep(2)
                self._add_message("user","Your previous response was empty. Please emit JSON.")
                continue

            self._add_message("assistant", response)
            parsed = self._parse_action(response)
            if not parsed:
                self._add_message("user",
                    "Your output was not valid JSON. Output EXACTLY: "
                    '{"thought":"...","action":"tool_name","args":{...}}')
                continue

            thought   = parsed.get("thought","")
            tool_name = parsed.get("action","")
            args      = parsed.get("args",{})

            print(f"  💭 {thought[:100]}")
            print(f"  🔧 {tool_name}({json.dumps(args)[:120]})")

            # ── mission_complete ───────────────────────────────────────────────
            if tool_name == "mission_complete":
                print(f"\n  ✅ Mission complete: {args.get('summary','')[:200]}")
                self.is_done = True
                break

            # ── execute tool ───────────────────────────────────────────────────
            result = execute_tool(tool_name, args)
            self._maybe_pin_finding(tool_name, result)
            self._update_plan_from_result(tool_name, result, step)

            obs = self._format_obs(tool_name, result)
            print(f"  📥 {obs[:180]}...")
            self._add_message("user", obs)

            # Periodic reflection
            if step % REFLECT_EVERY == 0:
                self._reflect(step)

            # Periodic context save
            if step % 10 == 0 and self.ctx:
                self.ctx.save()

        # ── POST-HUNT ─────────────────────────────────────────────────────────
        self._harvest_findings()
        if self.ctx:
            self.ctx.save()

        elapsed = time.time() - start
        summary = {
            "session_id":  self.session_id,
            "target":      self.target,
            "steps":       step,
            "duration_s":  round(elapsed, 1),
            "findings":    len(self.findings),
            "model":       self.model,
            "plan_phases": len(self.plan.phases) if self.plan else 0,
        }
        print(f"\n{'─'*60}")
        print(f"  🏁 Hunt complete — {step} steps, {len(self.findings)} findings, {round(elapsed)}s")
        if self.plan:
            print(f"  📊 {self.plan.progress_summary()}")
        print(f"{'─'*60}\n")
        return summary

    # ── FINDING HARVEST ───────────────────────────────────────────────────────

    def _harvest_findings(self):
        found = []
        try:
            for p in WORKSPACE.glob("nova_findings_*.json"):
                try:
                    data = json.loads(p.read_text())
                    if isinstance(data, list): found.extend(data)
                    elif isinstance(data, dict): found.append(data)
                except Exception:
                    pass
            # Deduplicate
            seen, deduped = set(), []
            for f in found:
                fid = f.get("id") or f.get("finding_id") or f.get("title") or str(f)[:50]
                if fid not in seen:
                    seen.add(fid)
                    deduped.append(f)
            self.findings = deduped
            self.findings_path.write_text(json.dumps(self.findings, indent=2, default=str))
            print(f"  📁 {len(self.findings)} finding(s) harvested")
        except Exception as e:
            print(f"  [!] Harvest error: {e}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Nova Agent v2.0")
    ap.add_argument("--target",    default="http://localhost:3000")
    ap.add_argument("--objective", default="Find and exploit all critical vulnerabilities.")
    ap.add_argument("--steps",     type=int, default=MAX_STEPS)
    ap.add_argument("--plan-id",   default=None)
    a = ap.parse_args()
    NovaAgent(target=a.target, objective=a.objective,
              max_steps=a.steps, plan_id=a.plan_id).run()
