"""
Nova-Arsenal API Routes

FastAPI routes for the REST API.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nova_arsenal.auth.middleware import get_current_user, require_admin, require_analyst
from nova_arsenal.db import get_db
from nova_arsenal.db.crud import (
    complete_agent_run,
    create_agent_run,
    get_agent_run_history,
    persist_findings_batch,
)
from nova_arsenal.db.models import Agent, AgentStatus, Finding, Scope, User

router = APIRouter(prefix="/api")

# Skills marketplace — platform connectors (HackerOne, HackTheBox, ...)
# and Nova's target-recommendation reasoning endpoint.
from nova_arsenal.skills.api_routes import router as skills_router  # noqa: E402
router.include_router(skills_router)


# ââ Request/Response Models ââââââââââââââââââââââââââââââââââââââââââââââââ

class RunAgentRequest(BaseModel):
    target: str
    objective: str = "Find and exploit all critical vulnerabilities"
    max_steps: int = 40
    scope: list[str] | None = None
    sandbox_mode: str | None = None


class StepAgentRequest(BaseModel):
    instruction: str = ""


# ââ Active agent runner instances (live objects not persisted) ââââââââââââ

_active_runners: dict = {}  # agent_id -> AgentRunner instance (lazy import)


async def _event_bridge(agent_id: int, event_type: str, data: dict):
    """Bridge agent events to WebSocket."""
    from nova_arsenal.api.websocket.events import emit_agent_event
    await emit_agent_event(agent_id, event_type, data)


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
    from datetime import datetime, timezone

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
    finding.verified_at = datetime.now(timezone.utc)
    finding.verified_by = current_user.id

    return {"message": "Finding verified"}


# Scope routes
@router.get("/scope")
async def list_scope(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all scope entries."""
    result = await db.execute(select(Scope).where(Scope.is_active))
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


# ââ Autonomous Agent Runner Endpoints ââââââââââââââââââââââââââââââââââââââ

@router.post("/agents/{agent_id}/run", status_code=status.HTTP_202_ACCEPTED)
async def run_agent(
    agent_id: int,
    request: RunAgentRequest,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Start the fully autonomous agent loop."""
    from nova_arsenal.agent_runner import create_runner

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if current_user.role.value != "admin" and agent.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    if agent_id in _active_runners and _active_runners[agent_id]._running:
        raise HTTPException(status_code=409, detail="Agent is already running")

    runner = create_runner(
        target=request.target,
        objective=request.objective,
        max_steps=request.max_steps,
        scope=request.scope,
        sandbox_mode=request.sandbox_mode,
        on_event=lambda et, data: _event_bridge(agent_id, et, data),
    )

    _active_runners[agent_id] = runner

    # Update agent status
    agent.status = AgentStatus.RUNNING
    agent.started_at = datetime.now(timezone.utc)
    await db.commit()

    # Create a persistent run record
    run_record = await create_agent_run(db, agent_id)
    await db.commit()

    # Run in background
    async def _run_background():
        try:
            result = await runner.run()
            agent.status = AgentStatus.COMPLETED if result["status"] == "completed" else AgentStatus.FAILED
            agent.completed_at = datetime.now(timezone.utc)
            agent.current_step = result.get("steps_taken", 0)
            await db.commit()

            # Persist findings from runner to DB
            findings_data = [f.to_dict() for f in runner._findings]
            await persist_findings_batch(db, agent_id, findings_data)
            await db.commit()

            # Complete the run record
            await complete_agent_run(
                db, run_record.id,
                status=result["status"],
                steps_taken=result.get("steps_taken", 0),
                total_findings=len(findings_data),
                summary=result.get("summary", ""),
                result_dict=result,
            )
            await db.commit()
        except Exception as e:
            agent.status = AgentStatus.FAILED
            await db.commit()
            await complete_agent_run(
                db, run_record.id,
                status="failed",
                steps_taken=0,
                summary=str(e),
            )
            await db.commit()

    asyncio.create_task(_run_background())

    return {
        "message": "Agent started",
        "agent_id": agent_id,
        "target": request.target,
        "objective": request.objective,
    }


@router.post("/agents/{agent_id}/stop")
async def stop_agent(
    agent_id: int,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Stop a running agent."""
    if agent_id not in _active_runners:
        raise HTTPException(status_code=404, detail="No active runner for this agent")

    runner = _active_runners[agent_id]
    runner.stop()

    return {"message": "Agent stop requested", "agent_id": agent_id}


@router.post("/agents/{agent_id}/step")
async def step_agent(
    agent_id: int,
    request: StepAgentRequest,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Execute a single agent step (interactive mode)."""
    from nova_arsenal.agent_runner import create_runner

    if agent_id not in _active_runners:
        # Create a new runner
        result = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        runner = create_runner(
            target=agent.target,
            objective=agent.objective or "Find vulnerabilities",
            max_steps=agent.max_steps,
            on_event=lambda et, data: _event_bridge(agent_id, et, data),
        )
        _active_runners[agent_id] = runner

    runner = _active_runners[agent_id]
    action = await runner.step_once(request.instruction)

    return {
        "step": action.step,
        "command": action.command,
        "output": action.result.stdout if action.result else "",
        "exit_code": action.result.exit_code if action.result else None,
        "analysis": action.analysis,
    }


@router.get("/agents/{agent_id}/status")
async def agent_status(
    agent_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get real-time agent status."""
    if agent_id in _active_runners:
        runner = _active_runners[agent_id]
        state = runner.get_state()
        state["findings"] = [f.to_dict() for f in runner._findings]
        return state

    # Check DB for completed run results
    runs = await get_agent_run_history(db, agent_id, limit=1)
    if runs:
        latest = runs[0]
        return {
            "status": latest.status,
            "run_id": latest.id,
            "steps_taken": latest.steps_taken,
            "total_findings": latest.total_findings,
            "summary": latest.summary,
            "started_at": latest.started_at.isoformat(),
            "completed_at": latest.completed_at.isoformat() if latest.completed_at else None,
            "result": json.loads(latest.result_json) if latest.result_json else None,
        }

    # Check the agent DB record
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        return {
            "status": agent.status.value,
            "current_step": agent.current_step,
            "started_at": agent.started_at.isoformat() if agent.started_at else None,
            "completed_at": agent.completed_at.isoformat() if agent.completed_at else None,
        }

    return {"status": "idle"}


@router.get("/agents/{agent_id}/findings")
async def agent_findings(
    agent_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get findings from the agent (live or DB-persisted)."""
    # Live findings from active runner
    if agent_id in _active_runners:
        runner = _active_runners[agent_id]
        return {"findings": [f.to_dict() for f in runner._findings]}

    # Persisted findings from DB
    result = await db.execute(
        select(Finding).where(Finding.agent_id == agent_id).order_by(Finding.created_at.desc())
    )
    findings = result.scalars().all()
    return {
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "evidence": f.evidence,
                "endpoint": f.endpoint,
                "cwe_id": f.cwe_id,
                "cvss_score": f.cvss_score,
                "remediation": f.remediation,
                "verified": f.verified,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ]
    }


@router.get("/agents/{agent_id}/runs")
async def agent_run_history(
    agent_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get run history for an agent."""
    runs = await get_agent_run_history(db, agent_id, limit=20)
    return {
        "runs": [
            {
                "id": r.id,
                "status": r.status,
                "steps_taken": r.steps_taken,
                "total_findings": r.total_findings,
                "summary": r.summary,
                "started_at": r.started_at.isoformat(),
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            }
            for r in runs
        ]
    }


@router.get("/agents/{agent_id}/actions")
async def agent_actions(
    agent_id: int,
    current_user: User = Depends(get_current_user),
):
    """Get action history from the agent."""
    if agent_id in _active_runners:
        runner = _active_runners[agent_id]
        return {"actions": [a.to_dict() for a in runner._actions]}
    return {"actions": []}


@router.get("/kali/tools")
async def kali_tools(
    current_user: User = Depends(get_current_user),
):
    """List all Kali Linux tools known to the blueprint."""
    from nova_arsenal.kali_blueprint import KaliBlueprint

    bp = KaliBlueprint()
    return {
        "categories": bp.get_all_categories(),
        "tools": {
            name: {
                "name": t.name,
                "category": t.category,
                "description": t.description,
                "usage": t.usage,
                "examples": t.examples[:2],
            }
            for name, t in bp.tools.items()
        },
        "total": len(bp.tools),
    }


@router.get("/kali/context")
async def kali_context(
    current_user: User = Depends(get_current_user),
):
    """Get the full Kali Linux knowledge base context."""
    from nova_arsenal.kali_blueprint import KaliBlueprint

    bp = KaliBlueprint()
    return {"context": bp.get_full_context()}


@router.post("/code/generate")
async def generate_code(
    task: str,
    language: str = "python",
    target: str = "",
    current_user: User = Depends(require_analyst),
):
    """Generate code for a security task."""
    from nova_arsenal.code_generator import CodeGenerator, CodeLanguage

    gen = CodeGenerator()
    lang = CodeLanguage.PYTHON if language == "python" else CodeLanguage.BASH
    code = gen.generate(task=task, language=lang, target=target)

    return {
        "code": code.code,
        "language": code.language.value,
        "filename": code.filename,
        "description": code.description,
        "dependencies": code.dependencies,
    }


# ââ MCP Server Routes ââââââââââââââââââââââââââââââââââââââââââââââââââââââ

@router.get("/mcp/tools")
async def mcp_tools():
    """List MCP tools available from Nova."""
    from nova_arsenal.mcp import NovaMcpServer
    server = NovaMcpServer()
    server.register_all_tools()
    return {"tools": server.get_tool_list()}


@router.get("/mcp/resources")
async def mcp_resources():
    """List MCP resources available from Nova."""
    from nova_arsenal.mcp import NovaMcpServer
    server = NovaMcpServer()
    server.register_all_resources()
    return {"resources": server.get_resource_list()}


@router.post("/mcp/call")
async def mcp_call_tool(
    tool_name: str,
    arguments: dict = {},
):
    """Call an MCP tool."""
    from nova_arsenal.mcp import NovaMcpServer
    server = NovaMcpServer()
    server.register_all_tools()
    result = await server.handle_tool_call(tool_name, arguments)
    return {"result": result}


# ââ E2E Encryption Routes ââââââââââââââââââââââââââââââââââââââââââââââââââ

@router.post("/crypto/keypair")
async def generate_keypair(
    key_size: str = "rsa_4096",
):
    """Generate a new RSA keypair."""
    from nova_arsenal.crypto import KeyManager, KeySize
    km = KeyManager()
    size = KeySize.RSA_4096 if "4096" in key_size else KeySize.RSA_2048
    kp = km.generate_rsa_keypair(key_size=size)
    return {
        "key_id": km.get_active_key_id(),
        "public_key": kp.public_key_pem,
        "fingerprint": kp.fingerprint,
    }


@router.post("/crypto/encrypt")
async def encrypt_message(
    plaintext: str,
    recipient_public_key: str,
    sender_id: str = "nova",
    recipient_id: str = "",
):
    """Encrypt a message using E2E encryption (RSA+AES-GCM)."""
    from nova_arsenal.crypto import Cipher, KeyManager
    km = KeyManager()
    cipher = Cipher(km)
    envelope = cipher.encrypt(plaintext, recipient_public_key, sender_id, recipient_id)
    return envelope.to_dict()


@router.post("/crypto/decrypt")
async def decrypt_message(
    ciphertext: str,
    iv: str,
    encrypted_key: str,
    key_fingerprint: str,
    private_key_pem: str,
    algorithm: str = "AES-256-GCM+RSA-4096",
    sender_id: str = "",
):
    """Decrypt a message using E2E encryption."""
    from nova_arsenal.crypto import Cipher, KeyManager, SecureEnvelope
    km = KeyManager()
    cipher = Cipher(km)
    envelope = SecureEnvelope(
        ciphertext=ciphertext,
        iv=iv,
        encrypted_key=encrypted_key,
        key_fingerprint=key_fingerprint,
        algorithm=algorithm,
        sender_id=sender_id,
    )
    plaintext = cipher.decrypt(envelope, private_key_pem)
    return {"plaintext": plaintext}


# ââ CTF Solver Routes ââââââââââââââââââââââââââââââââââââââââââââââââââââââ

@router.post("/ctf/solve")
async def ctf_solve(
    challenge_name: str,
    challenge_type: str = "web",
    url: str = "",
    files: list[str] = [],
):
    """Solve a CTF challenge automatically."""
    from nova_arsenal.ctf_solver import ChallengeType, CtfSolver
    solver = CtfSolver()
    try:
        ctype = ChallengeType(challenge_type)
    except ValueError:
        ctype = ChallengeType.WEB
    challenge = solver.add_challenge(
        name=challenge_name,
        challenge_type=ctype,
        url=url,
        files=files,
    )
    flag = await solver.solve_challenge(challenge)
    stats = solver.get_stats()
    return {
        "solved": flag is not None,
        "flag": flag.flag if flag else None,
        "method": flag.method if flag else None,
        "confidence": flag.confidence if flag else None,
        "stats": stats,
    }


@router.get("/ctf/stats")
async def ctf_stats():
    """Get CTF solver stats."""
    from nova_arsenal.ctf_solver import CtfSolver
    solver = CtfSolver()
    return solver.get_stats()
