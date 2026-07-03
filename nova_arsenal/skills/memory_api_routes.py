"""
Nova Arsenal — Memory & Skill Authoring API Routes
=====================================================

Exposes session memory and the skill-authoring review workflow:

  GET  /api/memory/recap?days=7            -> "what were we working on"
  GET  /api/memory/targets                 -> full target history
  POST /api/memory/preferences             -> set a user preference
  GET  /api/memory/preferences             -> get all preferences

  GET  /api/skills/pending                 -> skills awaiting human review
  POST /api/skills/pending/{name}/approve  -> move a drafted skill live
  POST /api/skills/pending/{name}/reject   -> discard a drafted skill

Mounted the same way as skills/api_routes.py — included into
nova_arsenal/api/routes.py's top-level router, which already carries
prefix="/api", so this router has no prefix of its own.

User identity is now pulled from Nova's real auth system
(nova_arsenal.auth.middleware.get_current_user) instead of a raw
user_id query param — memory is scoped to whoever the JWT/API key/PAT
resolves to, same as every other authenticated route in the app.
Skill approval/rejection additionally requires analyst-or-higher role,
since approving a self-authored skill is what actually makes new code
loadable and executable.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from nova_arsenal.auth.middleware import get_current_user, require_analyst
from nova_arsenal.db.models import User

from .session_memory import SessionMemory
from .skill_author import SkillAuthor, SkillAuthoringError


router = APIRouter(tags=["memory", "skill-authoring"])

_author = SkillAuthor()


def _memory_for(user: User) -> SessionMemory:
    # SessionMemory takes a string user_id; the numeric User.id is the
    # stable, auth-verified identity to scope memory to (rather than
    # username/email, which a user could change).
    return SessionMemory(user_id=str(user.id))


class PreferencePayload(BaseModel):
    key: str
    value: str


class RejectPayload(BaseModel):
    reason: str = ""


@router.get("/memory/recap")
def get_recap(days: int = 7, current_user: User = Depends(get_current_user)):
    """The 'what were we working on' answer for the authenticated user."""
    mem = _memory_for(current_user)
    return mem.recap(days=days)


@router.get("/memory/targets")
def get_target_history(limit: int = 50, current_user: User = Depends(get_current_user)):
    mem = _memory_for(current_user)
    return [
        {
            "target_id": t.target_id,
            "platform": t.platform,
            "name": t.name,
            "status": t.status,
            "last_score": t.last_score,
            "notes": t.notes,
            "updated_at": t.updated_at,
        }
        for t in mem.target_history(limit=limit)
    ]


@router.post("/memory/preferences")
def set_preference(
    payload: PreferencePayload,
    current_user: User = Depends(get_current_user),
):
    mem = _memory_for(current_user)
    mem.set_preference(payload.key, payload.value)
    return {"user_id": current_user.id, "key": payload.key, "value": payload.value}


@router.get("/memory/preferences")
def get_preferences(current_user: User = Depends(get_current_user)):
    mem = _memory_for(current_user)
    return mem.all_preferences()


@router.get("/skills/pending")
def list_pending_skills(current_user: User = Depends(get_current_user)):
    """
    Self-authored skills awaiting human review before they can load.
    Any authenticated user can view the pending queue; only
    analyst/admin can approve or reject (see routes below) — visibility
    into what's pending shouldn't itself be gated, only the ability to
    make a skill live.
    """
    return _author.list_pending()


@router.post("/skills/pending/{name}/approve")
def approve_pending_skill(name: str, current_user: User = Depends(require_analyst)):
    """
    Requires analyst or admin role. This is the action that moves
    Nova-written code from an inert draft into something SkillRegistry
    will import and execute — not something a plain viewer role should
    be able to trigger.
    """
    try:
        path = _author.approve_skill(name)
    except SkillAuthoringError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "name": name,
        "status": "approved",
        "approved_by": current_user.username,
        "path": str(path),
    }


@router.post("/skills/pending/{name}/reject")
def reject_pending_skill(
    name: str,
    payload: RejectPayload,
    current_user: User = Depends(require_analyst),
):
    try:
        _author.reject_skill(name, reason=payload.reason)
    except SkillAuthoringError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "name": name,
        "status": "rejected",
        "rejected_by": current_user.username,
        "reason": payload.reason,
    }
