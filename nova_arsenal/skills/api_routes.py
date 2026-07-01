"""
Nova Arsenal — Skills & Target Discovery API Routes
======================================================

Exposes the skills marketplace through Nova's existing FastAPI app:

  GET  /api/skills                    -> list discovered + loaded skills
  POST /api/skills/{name}/credentials -> set credentials for a skill (in-memory)
  GET  /api/targets                   -> aggregate targets across all ready platform connectors
  GET  /api/targets/recommend         -> Nova's ranked "most interesting target" reasoning

This is the piece that answers: "ask Nova to look up the most
interesting domain to handle and she reasons her way around it."

Wire this into nova_arsenal/api/routes.py with:
    from nova_arsenal.skills.api_routes import router as skills_router
    app.include_router(skills_router)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .skill_manifest import SkillRegistry
from .platform_connector import PlatformConnector, Target, TargetReasoner


router = APIRouter(prefix="/api", tags=["skills"])

# Single process-wide registry — discovered once at startup, credentials
# can be supplied later via the /skills/{name}/credentials endpoint.
_registry = SkillRegistry(skills_dir="skills")
_credentials_store: dict[str, dict[str, str]] = {}
_reasoner = TargetReasoner()


def _ensure_discovered() -> None:
    if not _registry.list_available():
        _registry.discover()


class CredentialsPayload(BaseModel):
    credentials: dict[str, str]


class SkillInfo(BaseModel):
    name: str
    version: str
    description: str
    type: str
    tags: list[str]
    requires_credentials: list[str]
    is_loaded: bool
    is_ready: bool
    missing_credentials: list[str]


class TargetOut(BaseModel):
    id: str
    platform: str
    kind: str
    name: str
    url: str
    scope_summary: str
    tags: list[str]
    difficulty: Optional[str]
    max_reward_usd: Optional[float]
    asset_types: list[str]


class TargetRecommendationOut(BaseModel):
    target: TargetOut
    score: float
    reasoning: str
    matched_strengths: list[str]
    estimated_effort: str


def _target_to_out(t: Target) -> TargetOut:
    return TargetOut(
        id=t.id,
        platform=t.platform,
        kind=t.kind.value if hasattr(t.kind, "value") else str(t.kind),
        name=t.name,
        url=t.url,
        scope_summary=t.scope_summary,
        tags=t.tags,
        difficulty=t.difficulty,
        max_reward_usd=t.max_reward_usd,
        asset_types=t.asset_types,
    )


@router.get("/skills", response_model=list[SkillInfo])
def list_skills():
    """List all discovered skills and their load/credential status."""
    _ensure_discovered()
    out = []
    for manifest in _registry.list_available():
        loaded = _registry.get(manifest.name)
        out.append(
            SkillInfo(
                name=manifest.name,
                version=manifest.version,
                description=manifest.description,
                type=manifest.type,
                tags=manifest.tags,
                requires_credentials=manifest.requires_credentials,
                is_loaded=loaded is not None,
                is_ready=loaded.is_ready if loaded else False,
                missing_credentials=loaded.missing_credentials if loaded else manifest.requires_credentials,
            )
        )
    return out


@router.post("/skills/{name}/credentials")
def set_skill_credentials(name: str, payload: CredentialsPayload):
    """
    Store credentials for a skill in-memory and (re)load it.

    NOTE: this stores credentials in process memory only — for production
    use, wire this to nova_arsenal/credentials/ instead so secrets are
    encrypted at rest rather than living in a plain dict.
    """
    _ensure_discovered()
    available = {m.name for m in _registry.list_available()}
    if name not in available:
        raise HTTPException(status_code=404, detail=f"Unknown skill: {name}")

    _credentials_store[name] = payload.credentials
    try:
        loaded = _registry.load(name, payload.credentials)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to load skill: {e}") from e

    return {
        "skill": name,
        "is_ready": loaded.is_ready,
        "missing_credentials": loaded.missing_credentials,
    }


@router.get("/targets", response_model=list[TargetOut])
def list_all_targets(limit: int = 50):
    """Aggregate targets across every ready (credentialed) platform connector."""
    _ensure_discovered()
    if not _registry.ready_skills():
        _registry.load_all(_credentials_store)

    all_targets: list[Target] = []
    for skill in _registry.skills_by_type("platform_connector"):
        if not skill.is_ready or skill.instance is None:
            continue
        connector: PlatformConnector = skill.instance
        try:
            all_targets.extend(connector.list_targets(limit=limit))
        except Exception as e:
            print(f"  [!] {connector.platform_name} list_targets error: {e}")

    return [_target_to_out(t) for t in all_targets]


@router.get("/targets/recommend", response_model=list[TargetRecommendationOut])
def recommend_targets(limit: int = 5):
    """
    Nova's reasoning endpoint — answers "what's the most interesting
    target to work on right now" by scoring every available target
    across every connected platform against Nova's known module strengths.

    This is the deterministic heuristic fallback (TargetReasoner). In the
    full agent loop, AgentRunner instead hands these candidate targets to
    the LLM router with persona_manager's "Strategic Planner" persona for
    richer reasoning text — this endpoint is what powers that context.
    """
    _ensure_discovered()
    if not _registry.ready_skills():
        _registry.load_all(_credentials_store)

    all_targets: list[Target] = []
    for skill in _registry.skills_by_type("platform_connector"):
        if not skill.is_ready or skill.instance is None:
            continue
        connector: PlatformConnector = skill.instance
        try:
            all_targets.extend(connector.list_targets(limit=50))
        except Exception as e:
            print(f"  [!] {connector.platform_name} list_targets error: {e}")

    if not all_targets:
        raise HTTPException(
            status_code=400,
            detail=(
                "No targets available — connect at least one platform skill first "
                "via POST /api/skills/{name}/credentials"
            ),
        )

    ranked = _reasoner.rank(all_targets)[:limit]

    return [
        TargetRecommendationOut(
            target=_target_to_out(r.target),
            score=r.score,
            reasoning=r.reasoning,
            matched_strengths=r.matched_strengths,
            estimated_effort=r.estimated_effort,
        )
        for r in ranked
    ]
