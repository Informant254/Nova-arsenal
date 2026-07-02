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
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .session_memory import SessionMemory
from .skill_author import SkillAuthor, SkillAuthoringError


router = APIRouter(tags=["memory", "skill-authoring"])

_author = SkillAuthor()


def _memory_for(user_id: str) -> SessionMemory:
    # TODO: wire to nova_arsenal/auth's actual user identity once this
    # is called from an authenticated request context rather than a
    # user_id query param.
    return SessionMemory(user_id=user_id)


class PreferencePayload(BaseModel):
    key: str
    value: str


class RejectPayload(BaseModel):
    reason: str = ""


@router.get("/memory/recap")
def get_recap(user_id: str, days: int = 7):
    """The 'what were we working on' answer for a returning user."""
    mem = _memory_for(user_id)
    return mem.recap(days=days)


@router.get("/memory/targets")
def get_target_history(user_id: str, limit: int = 50):
    mem = _memory_for(user_id)
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
def set_preference(user_id: str, payload: PreferencePayload):
    mem = _memory_for(user_id)
    mem.set_preference(payload.key, payload.value)
    return {"user_id": user_id, "key": payload.key, "value": payload.value}


@router.get("/memory/preferences")
def get_preferences(user_id: str):
    mem = _memory_for(user_id)
    return mem.all_preferences()


@router.get("/skills/pending")
def list_pending_skills():
    """Self-authored skills awaiting human review before they can load."""
    return _author.list_pending()


@router.post("/skills/pending/{name}/approve")
def approve_pending_skill(name: str):
    try:
        path = _author.approve_skill(name)
    except SkillAuthoringError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"name": name, "status": "approved", "path": str(path)}


@router.post("/skills/pending/{name}/reject")
def reject_pending_skill(name: str, payload: RejectPayload):
    try:
        _author.reject_skill(name, reason=payload.reason)
    except SkillAuthoringError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"name": name, "status": "rejected", "reason": payload.reason}
