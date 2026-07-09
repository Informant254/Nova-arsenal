"""HTTP API for concurrent work sessions + sub-agents."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .models import DEFAULT_PARALLEL_ROLES, SubAgentRole
from .runtime import get_session_manager

router = APIRouter(prefix="/api/work-sessions", tags=["work-sessions"])


class CreateSessionRequest(BaseModel):
    goal: str = Field(..., min_length=1, description="What the multi-agent team should accomplish")
    target: str = Field(default="", description="Primary target host/domain/IP")
    roles: Optional[List[str]] = Field(
        default=None,
        description="Sub-agent roles (recon, web, exploit, osint, researcher, validator, reporter)",
    )
    max_concurrent: int = Field(default=6, ge=1, le=32)
    authorized: bool = False
    authorization_ref: str = ""
    auto_start: bool = True
    services: Optional[Dict[str, Any]] = None


class StartSessionRequest(BaseModel):
    force: bool = False


@router.get("/roles")
async def list_roles():
    return {
        "roles": [r.value for r in SubAgentRole],
        "default": [r.value for r in DEFAULT_PARALLEL_ROLES],
        "description": {
            "recon": "Attack surface mapping + tool suggestions",
            "web": "Web path / vuln checklist",
            "osint": "Passive intelligence",
            "researcher": "Zero-day candidate pipeline",
            "exploit": "Authorized exploit planning",
            "validator": "Promote/dedupe peer findings",
            "reporter": "Aggregate session report",
        },
    }


@router.post("")
async def create_session(body: CreateSessionRequest):
    mgr = get_session_manager()
    meta = {}
    if body.services:
        meta["services"] = body.services
    sess = mgr.create(
        goal=body.goal,
        target=body.target,
        roles=body.roles,
        max_concurrent=body.max_concurrent,
        authorized=body.authorized,
        authorization_ref=body.authorization_ref,
        metadata=meta,
    )
    if body.auto_start:
        # Don't block HTTP forever; run concurrently and return snapshot
        sess = await mgr.start(sess.session_id, wait=False)
    return sess.to_dict()


@router.get("")
async def list_sessions():
    mgr = get_session_manager()
    return {
        "sessions": [
            s.to_dict(include_events=False) for s in mgr.list_sessions()[:50]
        ]
    }


@router.get("/{session_id}")
async def get_session(session_id: str):
    sess = get_session_manager().get(session_id)
    if not sess:
        raise HTTPException(404, f"Session {session_id} not found")
    return sess.to_dict()


@router.post("/{session_id}/start")
async def start_session(session_id: str):
    mgr = get_session_manager()
    if not mgr.get(session_id):
        raise HTTPException(404, f"Session {session_id} not found")
    sess = await mgr.start(session_id)
    return sess.to_dict()


@router.post("/{session_id}/cancel")
async def cancel_session(session_id: str):
    mgr = get_session_manager()
    if not mgr.get(session_id):
        raise HTTPException(404, f"Session {session_id} not found")
    sess = await mgr.cancel(session_id)
    return sess.to_dict()


@router.get("/{session_id}/events")
async def session_events(session_id: str, after: int = 0):
    sess = get_session_manager().get(session_id)
    if not sess:
        raise HTTPException(404, f"Session {session_id} not found")
    events = sess.events[after:]
    return {
        "session_id": session_id,
        "status": sess.status.value,
        "offset": after,
        "events": [e.to_dict() for e in events],
        "next_offset": after + len(events),
        "summary": sess.summary,
    }


@router.get("/{session_id}/agents")
async def session_agents(session_id: str):
    sess = get_session_manager().get(session_id)
    if not sess:
        raise HTTPException(404, f"Session {session_id} not found")
    return {
        "session_id": session_id,
        "agents": {k: v.to_dict() for k, v in sess.agents.items()},
    }
