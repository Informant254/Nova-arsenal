"""HTTP API for concurrent work sessions + sub-agents."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from nova_arsenal.auth.middleware import get_current_user, require_analyst
from nova_arsenal.db.models import User

from .models import DEFAULT_PARALLEL_ROLES, SubAgentRole
from .runtime import get_session_manager

router = APIRouter(prefix="/api/work-sessions", tags=["work-sessions"])


class CreateSessionRequest(BaseModel):
    goal: str = Field(..., min_length=1, description="What the multi-agent team should accomplish")
    target: str = Field(default="", description="Primary target host/domain/IP")
    roles: Optional[List[str]] = Field(
        default=None,
        description="Sub-agent roles",
    )
    max_concurrent: int = Field(default=6, ge=1, le=32)
    authorized: bool = False
    authorization_ref: str = ""
    auto_start: bool = False
    services: Optional[Dict[str, Any]] = None


class StartSessionRequest(BaseModel):
    force: bool = False


def _can_access(session, user: User) -> bool:
    if user.role.value == "admin":
        return True
    owner_id = (session.metadata or {}).get("owner_id")
    return owner_id == user.id


def _owned_session(session_id: str, user: User):
    session = get_session_manager().get(session_id)
    if not session or not _can_access(session, user):
        # Avoid revealing whether another user's session exists.
        raise HTTPException(404, f"Session {session_id} not found")
    return session


@router.get("/roles")
async def list_roles(
    _current_user: User = Depends(get_current_user),
):
    return {
        "roles": [r.value for r in SubAgentRole],
        "default": [r.value for r in DEFAULT_PARALLEL_ROLES],
        "description": {
            "recon": "Attack surface mapping + tool suggestions",
            "web": "Web review checklist",
            "osint": "Passive intelligence",
            "researcher": "Research and candidate analysis",
            "exploit": "Authorized exploit planning",
            "validator": "Promote/dedupe peer findings",
            "reporter": "Aggregate session report",
        },
    }


@router.post("")
async def create_session(
    body: CreateSessionRequest,
    current_user: User = Depends(require_analyst),
):
    if body.authorized and not body.authorization_ref.strip():
        raise HTTPException(
            400,
            "authorization_ref is required when authorized=true",
        )
    if body.auto_start and not body.authorized:
        raise HTTPException(
            403,
            "Starting a work session requires explicit authorization metadata",
        )

    mgr = get_session_manager()
    meta: Dict[str, Any] = {"owner_id": current_user.id}
    if body.services:
        meta["services"] = body.services

    session = mgr.create(
        goal=body.goal,
        target=body.target,
        roles=body.roles,
        max_concurrent=body.max_concurrent,
        authorized=body.authorized,
        authorization_ref=body.authorization_ref,
        metadata=meta,
    )
    if body.auto_start:
        session = await mgr.start(session.session_id, wait=False)
    return session.to_dict()


@router.get("")
async def list_sessions(
    current_user: User = Depends(get_current_user),
):
    manager = get_session_manager()
    sessions = manager.list_sessions()[:50]
    if current_user.role.value != "admin":
        sessions = [session for session in sessions if _can_access(session, current_user)]
    return {
        "sessions": [
            session.to_dict(include_events=False) for session in sessions
        ]
    }


@router.get("/{session_id}")
async def get_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
):
    return _owned_session(session_id, current_user).to_dict()


@router.post("/{session_id}/start")
async def start_session(
    session_id: str,
    current_user: User = Depends(require_analyst),
):
    session = _owned_session(session_id, current_user)
    if not session.authorized or not session.authorization_ref.strip():
        raise HTTPException(
            403,
            "Session start requires explicit authorization metadata",
        )
    session = await get_session_manager().start(session_id)
    return session.to_dict()


@router.post("/{session_id}/cancel")
async def cancel_session(
    session_id: str,
    current_user: User = Depends(require_analyst),
):
    _owned_session(session_id, current_user)
    session = await get_session_manager().cancel(session_id)
    return session.to_dict()


@router.get("/{session_id}/events")
async def session_events(
    session_id: str,
    after: int = 0,
    current_user: User = Depends(get_current_user),
):
    session = _owned_session(session_id, current_user)
    events = session.events[after:]
    return {
        "session_id": session_id,
        "status": session.status.value,
        "offset": after,
        "events": [event.to_dict() for event in events],
        "next_offset": after + len(events),
        "summary": session.summary,
    }


@router.get("/{session_id}/agents")
async def session_agents(
    session_id: str,
    current_user: User = Depends(get_current_user),
):
    session = _owned_session(session_id, current_user)
    return {
        "session_id": session_id,
        "agents": {key: value.to_dict() for key, value in session.agents.items()},
    }
