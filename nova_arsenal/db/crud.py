"""
Nova-Arsenal Database CRUD Operations

Reusable helpers for common database operations
used by chat, agent runner, scheduler, and API routes.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nova_arsenal.db.models import (
    AgentRunResult,
    ChatMessage,
    ChatSession,
    Finding,
    FindingSeverity,
    ScheduleEntryModel,
)

# ── Chat Session CRUD ─────────────────────────────────────────────────────────

async def get_or_create_chat_session(
    db: AsyncSession,
    session_id: str | None = None,
    user_id: int | None = None,
    title: str = "New Chat",
) -> ChatSession:
    if session_id:
        result = await db.execute(
            select(ChatSession).where(ChatSession.session_id == session_id)
        )
        session = result.scalar_one_or_none()
        if session:
            return session

    session = ChatSession(
        session_id=session_id or str(uuid.uuid4()),
        user_id=user_id,
        title=title,
    )
    db.add(session)
    await db.flush()
    await db.refresh(session)
    return session


async def add_chat_message(
    db: AsyncSession,
    session_id: str,
    role: str,
    content: str,
    metadata_dict: dict[str, Any] | None = None,
) -> ChatMessage:
    msg = ChatMessage(
        session_id=session_id,
        role=role,
        content=content,
        metadata_json=json.dumps(metadata_dict) if metadata_dict else None,
    )
    db.add(msg)

    await db.execute(
        select(ChatSession).where(ChatSession.session_id == session_id)
    )
    await db.flush()
    await db.refresh(msg)
    return msg


async def get_chat_messages(
    db: AsyncSession,
    session_id: str,
    limit: int = 100,
    offset: int = 0,
) -> list[ChatMessage]:
    result = await db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.timestamp)
        .offset(offset)
        .limit(limit)
    )
    return list(result.scalars().all())


async def delete_chat_session(db: AsyncSession, session_id: str) -> bool:
    result = await db.execute(
        select(ChatSession).where(ChatSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session:
        return False
    await db.delete(session)
    return True


async def list_chat_sessions(
    db: AsyncSession,
    user_id: int | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    query = select(ChatSession).order_by(ChatSession.updated_at.desc())
    if user_id is not None:
        query = query.where(ChatSession.user_id == user_id)
    result = await db.execute(query.limit(limit))
    sessions = result.scalars().all()
    return [
        {
            "session_id": s.session_id,
            "title": s.title,
            "created_at": s.created_at.isoformat(),
            "updated_at": s.updated_at.isoformat(),
            "message_count": len(s.messages) if s.messages else 0,
        }
        for s in sessions
    ]


# ── Agent Run Result CRUD ────────────────────────────────────────────────────

async def create_agent_run(
    db: AsyncSession,
    agent_id: int,
) -> AgentRunResult:
    run = AgentRunResult(
        agent_id=agent_id,
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    await db.flush()
    await db.refresh(run)
    return run


async def complete_agent_run(
    db: AsyncSession,
    run_id: int,
    status: str,
    steps_taken: int = 0,
    total_findings: int = 0,
    summary: str | None = None,
    result_dict: dict[str, Any] | None = None,
) -> AgentRunResult | None:
    result = await db.execute(
        select(AgentRunResult).where(AgentRunResult.id == run_id)
    )
    run = result.scalar_one_or_none()
    if not run:
        return None
    run.status = status
    run.steps_taken = steps_taken
    run.total_findings = total_findings
    run.summary = summary
    run.result_json = json.dumps(result_dict) if result_dict else None
    run.completed_at = datetime.now(timezone.utc)
    await db.flush()
    return run


async def get_agent_run_history(
    db: AsyncSession,
    agent_id: int,
    limit: int = 20,
) -> list[AgentRunResult]:
    result = await db.execute(
        select(AgentRunResult)
        .where(AgentRunResult.agent_id == agent_id)
        .order_by(AgentRunResult.started_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


# ── Finding CRUD ─────────────────────────────────────────────────────────────

async def persist_finding(
    db: AsyncSession,
    agent_id: int,
    title: str,
    severity: str,
    description: str,
    evidence: str = "",
    endpoint: str = "",
    cwe_id: str = "",
    cvss_score: float = 0.0,
    remediation: str = "",
    references: list[str] | None = None,
) -> Finding:
    try:
        sev = FindingSeverity(severity.lower())
    except ValueError:
        sev = FindingSeverity.INFO

    finding = Finding(
        agent_id=agent_id,
        title=title,
        severity=sev,
        description=description,
        evidence=evidence,
        endpoint=endpoint,
        cwe_id=cwe_id,
        cvss_score=cvss_score,
        remediation=remediation,
        references=json.dumps(references or []),
    )
    db.add(finding)
    await db.flush()
    await db.refresh(finding)
    return finding


async def persist_findings_batch(
    db: AsyncSession,
    agent_id: int,
    findings: list[dict[str, Any]],
) -> list[Finding]:
    persisted = []
    for f in findings:
        finding = await persist_finding(
            db=db,
            agent_id=agent_id,
            title=f.get("title", "Unknown Finding"),
            severity=f.get("severity", "info"),
            description=f.get("description", ""),
            evidence=f.get("evidence", ""),
            endpoint=f.get("endpoint", ""),
            cwe_id=f.get("cwe_id", ""),
            cvss_score=f.get("cvss_score", 0.0),
            remediation=f.get("remediation", ""),
            references=f.get("references"),
        )
        persisted.append(finding)
    return persisted


# ── Schedule Entry CRUD ──────────────────────────────────────────────────────

async def list_schedule_entries(db: AsyncSession) -> list[ScheduleEntryModel]:
    result = await db.execute(
        select(ScheduleEntryModel).order_by(ScheduleEntryModel.created_at.desc())
    )
    return list(result.scalars().all())


async def get_schedule_entry(db: AsyncSession, name: str) -> ScheduleEntryModel | None:
    result = await db.execute(
        select(ScheduleEntryModel).where(ScheduleEntryModel.name == name)
    )
    return result.scalar_one_or_none()


async def upsert_schedule_entry(
    db: AsyncSession,
    name: str,
    cron: str,
    target: str,
    task_type: str = "security_scan",
    objective: str | None = None,
    max_steps: int = 40,
    status: str = "active",
) -> ScheduleEntryModel:
    existing = await get_schedule_entry(db, name)
    if existing:
        existing.cron = cron
        existing.target = target
        existing.task_type = task_type
        existing.objective = objective
        existing.max_steps = max_steps
        existing.status = status
        existing.updated_at = datetime.now(timezone.utc)
        await db.flush()
        await db.refresh(existing)
        return existing

    entry = ScheduleEntryModel(
        name=name,
        cron=cron,
        target=target,
        task_type=task_type,
        objective=objective,
        max_steps=max_steps,
        status=status,
    )
    db.add(entry)
    await db.flush()
    await db.refresh(entry)
    return entry


async def delete_schedule_entry(db: AsyncSession, name: str) -> bool:
    entry = await get_schedule_entry(db, name)
    if not entry:
        return False
    await db.delete(entry)
    return True


async def update_entry_run_stats(
    db: AsyncSession,
    name: str,
    run_count: int,
    last_result: dict[str, Any] | None = None,
    next_run: datetime | None = None,
) -> ScheduleEntryModel | None:
    entry = await get_schedule_entry(db, name)
    if not entry:
        return None
    entry.run_count = run_count
    entry.last_result = json.dumps(last_result) if last_result else None
    if next_run:
        entry.next_run = next_run
    entry.updated_at = datetime.now(timezone.utc)
    await db.flush()
    return entry


__all__ = [
    "get_or_create_chat_session", "add_chat_message",
    "get_chat_messages", "delete_chat_session", "list_chat_sessions",
    "create_agent_run", "complete_agent_run", "get_agent_run_history",
    "persist_finding", "persist_findings_batch",
    "list_schedule_entries", "get_schedule_entry",
    "upsert_schedule_entry", "delete_schedule_entry",
    "update_entry_run_stats",
]
