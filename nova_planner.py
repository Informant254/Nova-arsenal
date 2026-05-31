#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🗺️  NOVA PLANNER v1.0 — PRE-HUNT STRATEGIC PLANNING              ║
║                                                                      ║
║   Closes the Claude Code planning gap.                               ║
║                                                                      ║
║   Claude Code ALWAYS plans before acting:                           ║
║   • Maps the full attack surface from available evidence            ║
║   • Generates ordered phases with dependencies                      ║
║   • Sets measurable success criteria per phase                      ║
║   • Tracks completion and adapts mid-hunt                           ║
║                                                                      ║
║   Nova now does the same — zero cloud, zero cost.                  ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import json
import os
import time
import hashlib
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

OLLAMA_URL   = os.getenv("NOVA_LLM_URL",   "http://localhost:11434")
OLLAMA_MODEL = os.getenv("NOVA_LLM_MODEL", "") or "qwen3:8b"
WORKSPACE    = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))

# ── DATA STRUCTURES ────────────────────────────────────────────────────────────

class Phase:
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETE  = "complete"
    FAILED    = "failed"
    SKIPPED   = "skipped"

    def __init__(self, id: str, name: str, objective: str, attack_types: List[str],
                 depends_on: List[str] = None, priority: int = 5,
                 success_criteria: List[str] = None, tools: List[str] = None):
        self.id              = id
        self.name            = name
        self.objective       = objective
        self.attack_types    = attack_types
        self.depends_on      = depends_on or []
        self.priority        = priority          # 1 (highest) → 10 (lowest)
        self.success_criteria = success_criteria or []
        self.tools           = tools or []
        self.status          = Phase.PENDING
        self.findings        = []
        self.started_at      = None
        self.completed_at    = None
        self.notes           = []

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "name": self.name, "objective": self.objective,
            "attack_types": self.attack_types, "depends_on": self.depends_on,
            "priority": self.priority, "success_criteria": self.success_criteria,
            "tools": self.tools, "status": self.status,
            "findings": self.findings, "started_at": self.started_at,
            "completed_at": self.completed_at, "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "Phase":
        p = cls(
            id=d["id"], name=d["name"], objective=d["objective"],
            attack_types=d.get("attack_types", []),
            depends_on=d.get("depends_on", []),
            priority=d.get("priority", 5),
            success_criteria=d.get("success_criteria", []),
            tools=d.get("tools", []),
        )
        p.status       = d.get("status", Phase.PENDING)
        p.findings     = d.get("findings", [])
        p.started_at   = d.get("started_at")
        p.completed_at = d.get("completed_at")
        p.notes        = d.get("notes", [])
        return p


class HuntPlan:
    def __init__(self, target: str, objective: str):
        self.id        = hashlib.md5(f"{target}{objective}{time.time()}".encode()).hexdigest()[:12]
        self.target    = target
        self.objective = objective
        self.phases: List[Phase] = []
        self.created_at = datetime.utcnow().isoformat()
        self.updated_at = self.created_at
        self.summary    = ""
        self.risk_score = 0.0

    # ── PHASE MANAGEMENT ──────────────────────────────────────────────────────

    def add_phase(self, phase: Phase):
        self.phases.append(phase)

    def next_phases(self) -> List[Phase]:
        """Return all phases that are ready to run (dependencies met)."""
        complete_ids = {p.id for p in self.phases if p.status == Phase.COMPLETE}
        return [
            p for p in self.phases
            if p.status == Phase.PENDING
            and all(dep in complete_ids for dep in p.depends_on)
        ]

    def mark_complete(self, phase_id: str, findings: List[Dict] = None, notes: str = ""):
        for p in self.phases:
            if p.id == phase_id:
                p.status       = Phase.COMPLETE
                p.completed_at = datetime.utcnow().isoformat()
                p.findings     = findings or []
                if notes:
                    p.notes.append(notes)
                self.updated_at = datetime.utcnow().isoformat()
                return

    def mark_failed(self, phase_id: str, reason: str = ""):
        for p in self.phases:
            if p.id == phase_id:
                p.status       = Phase.FAILED
                p.completed_at = datetime.utcnow().isoformat()
                if reason:
                    p.notes.append(f"FAILED: {reason}")
                self.updated_at = datetime.utcnow().isoformat()
                return

    def is_complete(self) -> bool:
        return all(p.status in (Phase.COMPLETE, Phase.FAILED, Phase.SKIPPED)
                   for p in self.phases)

    def progress_summary(self) -> str:
        total    = len(self.phases)
        done     = sum(1 for p in self.phases if p.status == Phase.COMPLETE)
        failed   = sum(1 for p in self.phases if p.status == Phase.FAILED)
        pending  = sum(1 for p in self.phases if p.status == Phase.PENDING)
        findings = sum(len(p.findings) for p in self.phases)
        return (f"Plan {self.id}: {done}/{total} phases complete, "
                f"{failed} failed, {pending} pending — {findings} findings so far")

    def to_agent_context(self) -> str:
        """Format the plan as agent system-prompt context."""
        lines = [
            f"HUNT PLAN  (target: {self.target})",
            f"OBJECTIVE: {self.objective}",
            f"PROGRESS:  {self.progress_summary()}",
            "",
            "PHASES:",
        ]
        for p in sorted(self.phases, key=lambda x: x.priority):
            icon = {"pending": "⬜", "running": "🔵", "complete": "✅",
                    "failed": "❌", "skipped": "⏭️"}.get(p.status, "?")
            lines.append(f"  {icon} [{p.id}] {p.name} (priority {p.priority})")
            lines.append(f"       Goal: {p.objective}")
            if p.depends_on:
                lines.append(f"       Depends on: {', '.join(p.depends_on)}")
            if p.success_criteria:
                lines.append(f"       Success: {'; '.join(p.success_criteria)}")
            if p.findings:
                lines.append(f"       Findings: {len(p.findings)}")
        next_up = self.next_phases()
        if next_up:
            lines.append(f"\nNEXT READY: {', '.join(p.name for p in next_up)}")
        return "\n".join(lines)

    # ── PERSISTENCE ───────────────────────────────────────────────────────────

    def save(self, path: Optional[Path] = None) -> Path:
        path = path or WORKSPACE / f"nova_plan_{self.id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "id": self.id, "target": self.target, "objective": self.objective,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "summary": self.summary, "risk_score": self.risk_score,
            "phases": [p.to_dict() for p in self.phases],
        }, indent=2))
        return path

    @classmethod
    def load(cls, path: Path) -> "HuntPlan":
        data = json.loads(path.read_text())
        plan = cls(data["target"], data["objective"])
        plan.id         = data["id"]
        plan.created_at = data["created_at"]
        plan.updated_at = data["updated_at"]
        plan.summary    = data.get("summary", "")
        plan.risk_score = data.get("risk_score", 0.0)
        plan.phases     = [Phase.from_dict(d) for d in data.get("phases", [])]
        return plan


# ── DEFAULT PLAN TEMPLATE ──────────────────────────────────────────────────────

def _default_plan(target: str, objective: str) -> HuntPlan:
    """Fallback plan when Ollama is unavailable."""
    plan = HuntPlan(target, objective)
    phases = [
        Phase("recon",   "Reconnaissance",        f"Map full attack surface of {target}",
              ["subdomain_enum","port_scan","tech_fingerprint"], priority=1,
              success_criteria=["≥5 endpoints discovered","tech stack identified"],
              tools=["bash_exec","http_request"]),
        Phase("passive", "Passive Analysis",       "Analyze source, JS, headers for secrets and patterns",
              ["source_analysis","secret_scan","js_analysis"],
              depends_on=["recon"], priority=2,
              success_criteria=["JS files reviewed","headers analyzed"],
              tools=["browser_source","grep_code","file_read"]),
        Phase("auth",    "Authentication Attack",  "Test login, JWT, session, registration flows",
              ["auth_bypass","jwt_forge","session_hijack"],
              depends_on=["recon"], priority=2,
              success_criteria=["admin access OR auth bypass confirmed"],
              tools=["http_request","browser_fill","bash_exec"]),
        Phase("inject",  "Injection Attacks",      "Test all params for SQLi, XSS, SSTI, SSRF",
              ["sqli","xss","ssrf","ssti"],
              depends_on=["recon"], priority=3,
              success_criteria=["≥1 injection confirmed"],
              tools=["http_request","bash_exec"]),
        Phase("access",  "Access Control",         "Test IDOR, privilege escalation, path traversal",
              ["idor","path_traversal","privilege_escalation"],
              depends_on=["auth"], priority=3,
              success_criteria=["access control boundary tested"],
              tools=["http_request","bash_exec"]),
        Phase("chain",   "Vulnerability Chaining", "Chain confirmed findings for maximum impact",
              ["exploit_chain","data_exfil"],
              depends_on=["inject","access"], priority=4,
              success_criteria=["chain demonstrated OR n/a"],
              tools=["http_request","browser_eval","bash_exec"]),
        Phase("verify",  "Verification",           "Triple-confirm every finding before reporting",
              ["verification"],
              depends_on=["chain"], priority=5,
              success_criteria=["all findings confirmed ×3"],
              tools=["http_request"]),
        Phase("report",  "Report Generation",      "Write professional findings report",
              ["reporting"],
              depends_on=["verify"], priority=6,
              success_criteria=["report written"],
              tools=["file_write"]),
    ]
    for p in phases:
        plan.add_phase(p)
    plan.summary = f"Default 8-phase hunt plan for {target}"
    return plan


# ── LLM PLANNER ────────────────────────────────────────────────────────────────

PLAN_SYSTEM = """You are Nova's strategic planning engine.
Given a target and objective, generate a precise attack plan as JSON.
Output ONLY valid JSON — no markdown, no explanation.

Schema:
{
  "summary": "one-line plan summary",
  "risk_score": 7.5,
  "phases": [
    {
      "id": "short-stable-id",
      "name": "Phase Name",
      "objective": "what to achieve",
      "attack_types": ["sqli", "xss"],
      "depends_on": [],
      "priority": 1,
      "success_criteria": ["measurable outcome"],
      "tools": ["bash_exec", "http_request"]
    }
  ]
}

Rules:
- Priority 1 = most critical, 10 = last
- depends_on lists phase IDs that must complete first
- 6-10 phases covering: recon → passive analysis → auth → injection → access control → chaining → verification → report
- success_criteria must be measurable
- tools from: bash_exec, http_request, browser_open, browser_source, browser_eval, browser_fill, file_read, file_write, grep_code, install_tool, visual_analyze, research_cve, verify_finding, self_review
"""

def _call_ollama(prompt: str, system: str, model: str, timeout: int = 60) -> Optional[str]:
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ],
        "stream": False, "format": "json",
        "options": {"temperature": 0.1, "num_predict": 2000},
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            f"{OLLAMA_URL.rstrip('/')}/api/chat",
            data=payload, headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
        return raw.get("message", {}).get("content", "").strip()
    except Exception:
        return None


def generate_plan(target: str, objective: str,
                  context: str = "", model: str = None) -> HuntPlan:
    """
    Generate a strategic hunt plan using local Ollama.
    Falls back to the default 8-phase template if Ollama is unavailable.
    """
    print(f"  🗺️  Generating hunt plan for {target}...")
    m = model or OLLAMA_MODEL

    prompt = json.dumps({
        "target": target,
        "objective": objective,
        "context": context[:2000] if context else "",
    })

    content = _call_ollama(prompt, PLAN_SYSTEM, m, timeout=60)
    if content:
        try:
            data = json.loads(content)
            plan = HuntPlan(target, objective)
            plan.summary    = data.get("summary", "")
            plan.risk_score = float(data.get("risk_score", 5.0))
            for pd in data.get("phases", []):
                plan.add_phase(Phase(
                    id=pd.get("id", f"phase_{len(plan.phases)}"),
                    name=pd.get("name", "Unknown"),
                    objective=pd.get("objective", ""),
                    attack_types=pd.get("attack_types", []),
                    depends_on=pd.get("depends_on", []),
                    priority=int(pd.get("priority", 5)),
                    success_criteria=pd.get("success_criteria", []),
                    tools=pd.get("tools", []),
                ))
            if plan.phases:
                print(f"  ✅ LLM plan: {len(plan.phases)} phases, risk score {plan.risk_score}")
                plan.save()
                return plan
        except Exception:
            pass

    print("  ⚡ Ollama offline — using default 8-phase plan")
    plan = _default_plan(target, objective)
    plan.save()
    return plan


def load_or_create_plan(target: str, objective: str,
                        plan_id: str = None) -> HuntPlan:
    """Load an existing plan or create a new one."""
    if plan_id:
        path = WORKSPACE / f"nova_plan_{plan_id}.json"
        if path.exists():
            print(f"  📋 Loaded existing plan: {plan_id}")
            return HuntPlan.load(path)
    return generate_plan(target, objective)


if __name__ == "__main__":
    import sys
    target    = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    objective = sys.argv[2] if len(sys.argv) > 2 else "Find all critical vulnerabilities"
    plan = generate_plan(target, objective)
    print("\n" + plan.to_agent_context())
    print(f"\nPlan saved: {WORKSPACE}/nova_plan_{plan.id}.json")
