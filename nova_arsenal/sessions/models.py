"""Data models for concurrent work sessions and sub-agents."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class SessionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SubAgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class SubAgentRole(str, Enum):
    RECON = "recon"
    WEB = "web"
    EXPLOIT = "exploit"
    OSINT = "osint"
    RESEARCHER = "researcher"
    VALIDATOR = "validator"
    REPORTER = "reporter"


DEFAULT_PARALLEL_ROLES: List[SubAgentRole] = [
    SubAgentRole.RECON,
    SubAgentRole.WEB,
    SubAgentRole.OSINT,
    SubAgentRole.RESEARCHER,
    SubAgentRole.EXPLOIT,
    SubAgentRole.VALIDATOR,
    SubAgentRole.REPORTER,
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}" if prefix else uuid.uuid4().hex[:16]


@dataclass
class SessionEvent:
    event_type: str
    message: str
    agent_id: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "message": self.message,
            "agent_id": self.agent_id,
            "data": self.data,
            "ts": self.ts,
        }


@dataclass
class SubAgentSpec:
    role: SubAgentRole
    objective: str = ""
    max_steps: int = 8
    weight: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role.value,
            "objective": self.objective,
            "max_steps": self.max_steps,
            "weight": self.weight,
        }


@dataclass
class SubAgentResult:
    agent_id: str
    role: SubAgentRole
    status: SubAgentStatus = SubAgentStatus.PENDING
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    evidence: str = ""
    confidence: float = 0.0
    steps: int = 0
    duration_ms: float = 0.0
    error: str = ""
    reasoning: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "status": self.status.value,
            "findings": self.findings,
            "summary": self.summary,
            "evidence": self.evidence[:1000],
            "confidence": round(self.confidence, 3),
            "steps": self.steps,
            "duration_ms": round(self.duration_ms, 2),
            "error": self.error,
            "reasoning": self.reasoning[-20:],
        }


@dataclass
class TaskSession:
    """A multi-agent work session that runs sub-agents in parallel."""

    session_id: str = field(default_factory=lambda: _id("sess_"))
    goal: str = ""
    target: str = ""
    status: SessionStatus = SessionStatus.PENDING
    roles: List[SubAgentRole] = field(default_factory=lambda: list(DEFAULT_PARALLEL_ROLES))
    max_concurrent: int = 6
    authorized: bool = False
    authorization_ref: str = ""
    created_at: str = field(default_factory=_now)
    started_at: str = ""
    completed_at: str = ""
    agents: Dict[str, SubAgentResult] = field(default_factory=dict)
    events: List[SessionEvent] = field(default_factory=list)
    aggregated_findings: List[Dict[str, Any]] = field(default_factory=list)
    consensus: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def emit(self, event_type: str, message: str, agent_id: str = "", **data: Any) -> None:
        self.events.append(
            SessionEvent(
                event_type=event_type,
                message=message,
                agent_id=agent_id,
                data=data,
            )
        )
        # Cap event log
        if len(self.events) > 500:
            self.events = self.events[-400:]

    def to_dict(self, include_events: bool = True) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "session_id": self.session_id,
            "goal": self.goal,
            "target": self.target,
            "status": self.status.value,
            "roles": [r.value for r in self.roles],
            "max_concurrent": self.max_concurrent,
            "authorized": self.authorized,
            "authorization_ref": self.authorization_ref,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "agents": {k: v.to_dict() for k, v in self.agents.items()},
            "agent_count": len(self.agents),
            "findings_count": len(self.aggregated_findings),
            "aggregated_findings": self.aggregated_findings[:100],
            "consensus": self.consensus[:50],
            "summary": self.summary,
            "metadata": self.metadata,
        }
        if include_events:
            d["events"] = [e.to_dict() for e in self.events[-100:]]
            d["event_count"] = len(self.events)
        return d
