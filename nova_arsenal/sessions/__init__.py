"""
Concurrent work sessions with parallel sub-agents.

A *session* owns a goal/target and spawns specialized sub-agents that run
simultaneously (recon, web, exploit, osint, researcher, validator, reporter).
Results and events stream into the session for chat/UI polling.
"""

from .models import (
    SessionEvent,
    SessionStatus,
    SubAgentRole,
    SubAgentSpec,
    SubAgentStatus,
    SubAgentResult,
    TaskSession,
)
from .runtime import SessionManager, get_session_manager

__all__ = [
    "SessionEvent",
    "SessionStatus",
    "SubAgentRole",
    "SubAgentSpec",
    "SubAgentStatus",
    "SubAgentResult",
    "TaskSession",
    "SessionManager",
    "get_session_manager",
]
