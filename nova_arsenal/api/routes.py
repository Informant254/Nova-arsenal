"""
Nova-Arsenal API Routes

FastAPI routes for the REST API.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nova_arsenal.auth.middleware import get_current_user, require_analyst, require_admin
from nova_arsenal.db import get_db
from nova_arsenal.db.models import Agent, AgentStatus, Finding, Scope, User

router = APIRouter(prefix="/api")


# Health routes
@router.get("/health")
async def health_check():
    """Basic health check."""
    return {"status": "healthy", "service": "nova-arsenal"}


@router.get("/health/detailed")
async def detailed_health_check():
    """Detailed health check with component status."""
    from nova_arsenal.llm import get_llm_router
    
    llm_router = get_llm_router()
    llm_health = await llm_router.health_check()
    
    return {
        "status": "healthy",
        "service": "nova-arsenal",
        "components": {
            "llm_providers": llm_health,
        },
    }


# Agent routes
@router.get("/agents")
async def list_agents(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all agents for the current user."""
    if current_user.role.value == "admin":
        result = await db.execute(select(Agent))
    else:
        result = await db.execute(
            select(Agent).where(Agent.owner_id == current_user.id)
        )
    
    agents = result.scalars().all()
    return {
        "agents": [
            {
                "id": agent.id,
                "name": agent.name,
                "target": agent.target,
                "status": agent.status.value,
                "created_at": agent.created_at.isoformat(),
            }
            for agent in agents
        ]
    }


@router.get("/agents/{agent_id}")
async def get_agent(
    agent_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get agent details."""
    result = await db.execute(
        select(Agent).where(Agent.id == agent_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )
    
    # Check access
    if current_user.role.value != "admin" and agent.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    
    return {
        "id": agent.id,
        "name": agent.name,
        "target": agent.target,
        "objective": agent.objective,
        "status": agent.status.value,
        "max_steps": agent.max_steps,
        "current_step": agent.current_step,
        "created_at": agent.created_at.isoformat(),
        "started_at": agent.started_at.isoformat() if agent.started_at else None,
        "completed_at": agent.completed_at.isoformat() if agent.completed_at else None,
    }


@router.post("/agents", status_code=status.HTTP_201_CREATED)
async def create_agent(
    target: str,
    objective: str = "Find and exploit all critical vulnerabilities",
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Create a new agent."""
    agent = Agent(
        name=f"Agent-{target}",
        target=target,
        objective=objective,
        owner_id=current_user.id,
        status=AgentStatus.IDLE,
    )
    db.add(agent)
    await db.flush()
    await db.refresh(agent)
    
    return {
        "id": agent.id,
        "name": agent.name,
        "target": agent.target,
        "status": agent.status.value,
    }


@router.delete("/agents/{agent_id}")
async def delete_agent(
    agent_id: int,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Delete an agent (admin only)."""
    result = await db.execute(
        select(Agent).where(Agent.id == agent_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )
    
    await db.delete(agent)
    return {"message": "Agent deleted"}


# Findings routes
@router.get("/findings")
async def list_findings(
    agent_id: int = None,
    severity: str = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List findings with optional filters."""
    query = select(Finding)
    
    if agent_id:
        query = query.where(Finding.agent_id == agent_id)
    if severity:
        query = query.where(Finding.severity == severity)
    
    result = await db.execute(query)
    findings = result.scalars().all()
    
    return {
        "findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "endpoint": finding.endpoint,
                "verified": finding.verified,
                "created_at": finding.created_at.isoformat(),
            }
            for finding in findings
        ]
    }


@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get finding details."""
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity.value,
        "description": finding.description,
        "evidence": finding.evidence,
        "endpoint": finding.endpoint,
        "cwe_id": finding.cwe_id,
        "cvss_score": finding.cvss_score,
        "verified": finding.verified,
        "remediation": finding.remediation,
        "created_at": finding.created_at.isoformat(),
        "verified_at": finding.verified_at.isoformat() if finding.verified_at else None,
    }


@router.post("/findings/{finding_id}/verify")
async def verify_finding(
    finding_id: int,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Mark a finding as verified."""
    from datetime import datetime
    
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    
    finding.verified = True
    finding.verified_at = datetime.utcnow()
    finding.verified_by = current_user.id
    
    return {"message": "Finding verified"}


# Scope routes
@router.get("/scope")
async def list_scope(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all scope entries."""
    result = await db.execute(select(Scope).where(Scope.is_active == True))
    scopes = result.scalars().all()
    
    return {
        "scope": [
            {
                "id": scope.id,
                "target": scope.target,
                "description": scope.description,
                "is_wildcard": scope.is_wildcard,
                "created_at": scope.created_at.isoformat(),
            }
            for scope in scopes
        ]
    }


@router.post("/scope", status_code=status.HTTP_201_CREATED)
async def add_scope(
    target: str,
    description: str = None,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Add a target to scope."""
    scope = Scope(
        target=target,
        description=description,
        owner_id=current_user.id,
        is_wildcard=target.startswith("*."),
    )
    db.add(scope)
    await db.flush()
    await db.refresh(scope)
    
    return {
        "id": scope.id,
        "target": scope.target,
        "is_wildcard": scope.is_wildcard,
    }


@router.delete("/scope/{scope_id}")
async def remove_scope(
    scope_id: int,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Remove a target from scope."""
    result = await db.execute(
        select(Scope).where(Scope.id == scope_id)
    )
    scope = result.scalar_one_or_none()
    
    if not scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scope entry not found",
        )
    
    scope.is_active = False
    return {"message": "Target removed from scope"}
