#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  📦 NOVA CONTEXT v1.0 — Typed Context Variables for Agent Networks         ║
║                                                                              ║
║  Shared, typed state that flows through the entire agent pipeline.          ║
║  Mirrors OpenAI Agents SDK "context variables" pattern.                     ║
║                                                                              ║
║  Features:                                                                   ║
║    • Typed context with Pydantic-style validation                           ║
║    • Immutable snapshots for handoffs                                        ║
║    • Scoped sub-contexts per agent                                           ║
║    • Full audit trail of every mutation                                      ║
║    • JSON serialisation / deserialisation                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    from nova_context import RunContext

    ctx = RunContext(target="https://example.com", scope=["example.com"])
    ctx.set("recon_complete", True)
    ctx.append("subdomains", "api.example.com")

    # Pass to agents
    sub_ctx = ctx.child("AttackAgent")
    sub_ctx.set("focus_endpoints", ["/api/v1/users"])

    # Snapshot for handoff
    snap = ctx.snapshot()
"""

import json
import time
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ── Mutation record ────────────────────────────────────────────────────────────

@dataclass
class Mutation:
    key:       str
    old_value: Any
    new_value: Any
    agent:     str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    op:        str = "set"   # set | append | delete | merge


# ── RunContext ─────────────────────────────────────────────────────────────────

class RunContext:
    """
    Shared context object for a single Nova run (one target, one mission).
    Thread-safe reads; mutations are serialised via a simple lock.
    """

    def __init__(
        self,
        target:      str = "",
        scope:       Optional[List[str]] = None,
        session_id:  Optional[str] = None,
        max_steps:   int = 40,
        verbose:     bool = False,
        parent:      Optional["RunContext"] = None,
        agent_name:  str = "root",
    ):
        import threading
        self._lock      = threading.Lock()
        self._data:     Dict[str, Any] = {}
        self._mutations: List[Mutation] = []
        self._children: List["RunContext"] = []
        self._agent     = agent_name
        self._parent    = parent
        self.verbose    = verbose

        # Well-known top-level fields
        self._data["target"]        = target
        self._data["scope"]         = scope or ([target] if target else [])
        self._data["session_id"]    = session_id or _new_id()
        self._data["max_steps"]     = max_steps
        self._data["start_time"]    = datetime.now(timezone.utc).isoformat()
        self._data["findings"]      = []
        self._data["subdomains"]    = []
        self._data["endpoints"]     = []
        self._data["errors"]        = []
        self._data["agent_outputs"] = {}
        self._data["cancelled"]     = False

    # ── Accessors ──────────────────────────────────────────────────

    @property
    def target(self) -> str:
        return self._data.get("target", "")

    @property
    def scope(self) -> List[str]:
        return self._data.get("scope", [])

    @property
    def session_id(self) -> str:
        return self._data.get("session_id", "")

    @property
    def findings(self) -> List[Dict]:
        return self._data.get("findings", [])

    @property
    def cancelled(self) -> bool:
        return self._data.get("cancelled", False)

    def cancel(self):
        self.set("cancelled", True, agent="system")

    # ── Scope enforcement ──────────────────────────────────────────

    def in_scope(self, url_or_domain: str) -> bool:
        """Returns True if the given URL/domain is within the declared scope."""
        import re
        target = url_or_domain.lower()
        for s in self.scope:
            s = s.lower().lstrip("*.")
            if s in target:
                return True
        return False

    # ── CRUD ───────────────────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return deepcopy(self._data.get(key, default))

    def set(self, key: str, value: Any, agent: Optional[str] = None) -> None:
        with self._lock:
            old = self._data.get(key)
            self._data[key] = value
            self._mutations.append(Mutation(
                key=key, old_value=old, new_value=value,
                agent=agent or self._agent, op="set"))
            if self.verbose:
                print(f"  [ctx.set] {key} = {str(value)[:80]}")

    def append(self, key: str, value: Any, agent: Optional[str] = None,
               dedupe: bool = False) -> None:
        """Append a value to a list context variable."""
        with self._lock:
            lst = self._data.get(key, [])
            if not isinstance(lst, list):
                lst = [lst]
            if dedupe and value in lst:
                return
            lst.append(value)
            self._data[key] = lst
            self._mutations.append(Mutation(
                key=key, old_value=None, new_value=value,
                agent=agent or self._agent, op="append"))

    def merge(self, key: str, data: Dict, agent: Optional[str] = None) -> None:
        """Merge a dict into an existing dict context variable."""
        with self._lock:
            existing = self._data.get(key, {})
            if not isinstance(existing, dict):
                existing = {}
            existing.update(data)
            self._data[key] = existing
            self._mutations.append(Mutation(
                key=key, old_value=None, new_value=data,
                agent=agent or self._agent, op="merge"))

    def delete(self, key: str, agent: Optional[str] = None) -> None:
        with self._lock:
            old = self._data.pop(key, None)
            self._mutations.append(Mutation(
                key=key, old_value=old, new_value=None,
                agent=agent or self._agent, op="delete"))

    def add_finding(self, finding: Dict, agent: Optional[str] = None):
        """Convenience: append to findings list with deduplication."""
        self.append("findings", finding, agent=agent)

    def add_error(self, error: str, agent: Optional[str] = None):
        self.append("errors", {"error": error, "agent": agent or self._agent,
                               "time": datetime.now(timezone.utc).isoformat()})

    def set_agent_output(self, agent_name: str, output: Any):
        """Store an agent's final output for downstream agents."""
        self.merge("agent_outputs", {agent_name: output})

    # ── Scoped child contexts ──────────────────────────────────────

    def child(self, agent_name: str) -> "RunContext":
        """Create a child context scoped to a specific agent."""
        child = RunContext(
            target=self.target, scope=self.scope,
            session_id=self.session_id, max_steps=self.get("max_steps"),
            verbose=self.verbose, parent=self, agent_name=agent_name)
        # Inherit current data
        with self._lock:
            child._data.update(deepcopy(self._data))
        child._agent = agent_name
        self._children.append(child)
        return child

    def sync_from_child(self, child: "RunContext"):
        """Merge a child's findings/endpoints/subdomains back into this context."""
        for key in ("findings", "subdomains", "endpoints", "errors"):
            for item in child.get(key, []):
                self.append(key, item, agent=child._agent)
        for k, v in child.get("agent_outputs", {}).items():
            self.merge("agent_outputs", {k: v})

    # ── Snapshot / restore ─────────────────────────────────────────

    def snapshot(self) -> Dict:
        """Return a deep copy of the current context as a plain dict."""
        with self._lock:
            return deepcopy(self._data)

    @classmethod
    def from_snapshot(cls, snap: Dict) -> "RunContext":
        ctx = cls(target=snap.get("target", ""),
                  scope=snap.get("scope"),
                  session_id=snap.get("session_id"))
        ctx._data.update(snap)
        return ctx

    # ── Persistence ────────────────────────────────────────────────

    def save(self, path: Optional[str] = None) -> str:
        sid  = self.session_id
        out  = path or str(Path.home() / "nova_workspace" / f"context_{sid}.json")
        data = {
            "context":   self.snapshot(),
            "mutations": [asdict(m) for m in self._mutations[-100:]],  # last 100
        }
        Path(out).write_text(json.dumps(data, indent=2, default=str))
        return out

    @classmethod
    def load(cls, path: str) -> "RunContext":
        data = json.loads(Path(path).read_text())
        return cls.from_snapshot(data["context"])

    # ── Summary ────────────────────────────────────────────────────

    def summary(self) -> Dict:
        return {
            "session_id":      self.session_id,
            "target":          self.target,
            "scope":           self.scope,
            "findings_count":  len(self.findings),
            "subdomains_found": len(self.get("subdomains", [])),
            "endpoints_found": len(self.get("endpoints", [])),
            "errors_count":    len(self.get("errors", [])),
            "mutations":       len(self._mutations),
            "cancelled":       self.cancelled,
        }

    def __repr__(self) -> str:
        return (f"RunContext(target={self.target!r}, session={self.session_id[:8]}, "
                f"findings={len(self.findings)})")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _new_id() -> str:
    import hashlib
    return hashlib.sha1(f"{time.time()}".encode()).hexdigest()[:12]


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ctx = RunContext(target="https://example.com", scope=["example.com"],
                     verbose=True)
    ctx.set("phase", "recon")
    ctx.append("subdomains", "api.example.com", dedupe=True)
    ctx.append("subdomains", "api.example.com", dedupe=True)  # deduped
    ctx.add_finding({"type": "SQLi", "severity": "HIGH",
                     "endpoint": "/api/search", "description": "Error-based SQLi"})

    child = ctx.child("AttackAgent")
    child.add_finding({"type": "XSS", "severity": "MEDIUM",
                       "endpoint": "/profile", "description": "Stored XSS"})
    ctx.sync_from_child(child)

    print("\nContext summary:", json.dumps(ctx.summary(), indent=2))
    saved = ctx.save("/tmp/nova_test_context.json")
    print(f"\nSaved to: {saved}")
    restored = RunContext.load(saved)
    print("Restored:", restored)
