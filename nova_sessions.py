#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🗂️  NOVA SESSIONS v1.0 — Persistent Session Management                   ║
║                                                                              ║
║  Persistent memory across Nova runs — mirrors OpenAI Agents SDK Sessions.  ║
║                                                                              ║
║  Each session stores:                                                        ║
║    • Conversation history (messages)                                         ║
║    • Run context snapshots                                                   ║
║    • Agent handoff chain                                                     ║
║    • Findings accumulated across all runs                                    ║
║    • Working memory (key-value scratch space)                                ║
║    • Token / cost accounting per run                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    from nova_sessions import SessionStore, Session

    store = SessionStore()
    session = store.create(target="https://example.com", mission="full_stack")

    # Attach messages during the run
    session.add_message("user", "Hunt example.com for IDOR")
    session.add_message("assistant", "Starting IDOR scan...")

    # Save after each run
    store.save(session)

    # Resume later
    session = store.load(session.session_id)
    history = session.messages          # full conversation
    findings = session.all_findings()  # deduplicated
"""

import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class SessionMessage:
    role:      str           # user | assistant | system | tool
    content:   str
    agent:     Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tokens:    int = 0


@dataclass
class RunRecord:
    run_id:        str
    started_at:    str
    ended_at:      Optional[str]
    mode:          str                  # hunt | recon | triage | etc.
    target:        str
    findings_count: int
    cost_usd:      float
    token_total:   int
    agent_chain:   List[str] = field(default_factory=list)
    success:       bool = True
    error:         Optional[str] = None


@dataclass
class Session:
    session_id:   str
    target:       str
    mission:      str
    created_at:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    messages:     List[SessionMessage] = field(default_factory=list)
    findings:     List[Dict] = field(default_factory=list)
    runs:         List[RunRecord] = field(default_factory=list)
    memory:       Dict[str, Any] = field(default_factory=dict)
    tags:         List[str] = field(default_factory=list)
    total_cost_usd: float = 0.0
    total_tokens:   int   = 0

    # ── Message management ─────────────────────────────────────────

    def add_message(self, role: str, content: str,
                    agent: Optional[str] = None, tokens: int = 0):
        self.messages.append(SessionMessage(
            role=role, content=content, agent=agent, tokens=tokens))
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def last_n_messages(self, n: int = 20) -> List[Dict]:
        """Return the last N messages as plain dicts for LLM context."""
        return [{"role": m.role, "content": m.content}
                for m in self.messages[-n:]]

    def context_window_messages(self, max_tokens: int = 6000) -> List[Dict]:
        """
        Return as many recent messages as fit within a rough token budget.
        Assumes ~4 chars per token.
        """
        budget   = max_tokens * 4
        selected = []
        for msg in reversed(self.messages):
            cost = len(msg.content)
            if cost > budget:
                break
            budget -= cost
            selected.append({"role": msg.role, "content": msg.content})
        return list(reversed(selected))

    # ── Findings management ────────────────────────────────────────

    def add_finding(self, finding: Dict):
        """Add a finding, deduplicating by (type, endpoint)."""
        key = (finding.get("type", ""), finding.get("endpoint", ""))
        for f in self.findings:
            if (f.get("type", ""), f.get("endpoint", "")) == key:
                return   # already recorded
        self.findings.append({**finding,
                              "recorded_at": datetime.now(timezone.utc).isoformat()})
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def all_findings(self, min_severity: Optional[str] = None) -> List[Dict]:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        results = self.findings
        if min_severity:
            threshold = order.get(min_severity.upper(), 99)
            results   = [f for f in results
                         if order.get(f.get("severity", "INFO").upper(), 99) <= threshold]
        return sorted(results, key=lambda f: order.get(
            f.get("severity", "INFO").upper(), 99))

    # ── Working memory ─────────────────────────────────────────────

    def remember(self, key: str, value: Any):
        self.memory[key] = value

    def recall(self, key: str, default: Any = None) -> Any:
        return self.memory.get(key, default)

    # ── Run tracking ───────────────────────────────────────────────

    def start_run(self, mode: str) -> RunRecord:
        run = RunRecord(
            run_id=_new_id(), started_at=datetime.now(timezone.utc).isoformat(),
            ended_at=None, mode=mode, target=self.target,
            findings_count=0, cost_usd=0.0, token_total=0)
        self.runs.append(run)
        return run

    def end_run(self, run: RunRecord, findings_count: int = 0,
                cost_usd: float = 0.0, token_total: int = 0,
                agent_chain: Optional[List[str]] = None,
                success: bool = True, error: Optional[str] = None):
        run.ended_at       = datetime.now(timezone.utc).isoformat()
        run.findings_count = findings_count
        run.cost_usd       = cost_usd
        run.token_total    = token_total
        run.agent_chain    = agent_chain or []
        run.success        = success
        run.error          = error
        self.total_cost_usd += cost_usd
        self.total_tokens   += token_total
        self.updated_at = datetime.now(timezone.utc).isoformat()

    # ── Serialisation ──────────────────────────────────────────────

    def to_dict(self) -> Dict:
        return {
            "session_id":    self.session_id,
            "target":        self.target,
            "mission":       self.mission,
            "created_at":    self.created_at,
            "updated_at":    self.updated_at,
            "total_cost_usd": self.total_cost_usd,
            "total_tokens":  self.total_tokens,
            "tags":          self.tags,
            "memory":        self.memory,
            "findings":      self.findings,
            "runs":          [asdict(r) for r in self.runs],
            "messages":      [asdict(m) for m in self.messages],
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "Session":
        s = cls(session_id=d["session_id"], target=d["target"],
                mission=d.get("mission", "unknown"),
                created_at=d.get("created_at", ""),
                updated_at=d.get("updated_at", ""))
        s.total_cost_usd = d.get("total_cost_usd", 0.0)
        s.total_tokens   = d.get("total_tokens", 0)
        s.tags           = d.get("tags", [])
        s.memory         = d.get("memory", {})
        s.findings       = d.get("findings", [])
        s.messages  = [SessionMessage(**m) for m in d.get("messages", [])]
        s.runs      = [RunRecord(**r) for r in d.get("runs", [])]
        return s

    def summary(self) -> Dict:
        return {
            "session_id":     self.session_id[:8],
            "target":         self.target,
            "mission":        self.mission,
            "runs":           len(self.runs),
            "messages":       len(self.messages),
            "findings":       len(self.findings),
            "total_cost_usd": round(self.total_cost_usd, 6),
            "total_tokens":   self.total_tokens,
            "updated_at":     self.updated_at,
        }


# ── Session store ──────────────────────────────────────────────────────────────

class SessionStore:
    """
    Filesystem-backed session store.
    Sessions are persisted as JSON files in ~/nova_workspace/sessions/.
    """

    def __init__(self, base_dir: Optional[str] = None):
        self._dir = Path(base_dir or Path.home() / "nova_workspace" / "sessions")
        self._dir.mkdir(parents=True, exist_ok=True)

    def create(self, target: str, mission: str = "hunt",
               tags: Optional[List[str]] = None) -> Session:
        sid = _new_id()
        s   = Session(session_id=sid, target=target, mission=mission)
        s.tags = tags or []
        self.save(s)
        return s

    def save(self, session: Session):
        path = self._dir / f"{session.session_id}.json"
        path.write_text(json.dumps(session.to_dict(), indent=2, default=str))

    def load(self, session_id: str) -> Optional[Session]:
        path = self._dir / f"{session_id}.json"
        if not path.exists():
            return None
        return Session.from_dict(json.loads(path.read_text()))

    def list_sessions(self, target: Optional[str] = None) -> List[Dict]:
        sessions = []
        for p in sorted(self._dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
            try:
                d = json.loads(p.read_text())
                s = Session.from_dict(d)
                if target and target not in s.target:
                    continue
                sessions.append(s.summary())
            except Exception:
                continue
        return sessions

    def delete(self, session_id: str):
        path = self._dir / f"{session_id}.json"
        if path.exists():
            path.unlink()

    def latest(self, target: Optional[str] = None) -> Optional[Session]:
        sessions = self.list_sessions(target=target)
        if not sessions:
            return None
        return self.load(sessions[0]["session_id"][:8] + sessions[0]["session_id"][8:])

    def find_by_target(self, target: str) -> List[Session]:
        results = []
        for p in self._dir.glob("*.json"):
            try:
                d = json.loads(p.read_text())
                if target in d.get("target", ""):
                    results.append(Session.from_dict(d))
            except Exception:
                continue
        return results


def _new_id() -> str:
    return hashlib.sha1(f"{time.time()}{time.monotonic()}".encode()).hexdigest()[:16]


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    store = SessionStore()

    # Create
    s = store.create(target="https://example.com", mission="full_stack")
    s.add_message("user", "Hunt example.com for all bugs")
    s.add_message("assistant", "Starting full-stack scan...")
    s.add_finding({"type": "SQLi", "severity": "HIGH", "endpoint": "/api/search"})
    s.add_finding({"type": "SQLi", "severity": "HIGH", "endpoint": "/api/search"})  # deduped

    run = s.start_run("full_stack")
    s.end_run(run, findings_count=1, cost_usd=0.002, token_total=800)
    store.save(s)

    print("Session summary:", json.dumps(s.summary(), indent=2))
    print("\nAll sessions:")
    for sess in store.list_sessions():
        print(" ", sess)
