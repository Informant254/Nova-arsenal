"""
Nova-Arsenal Chat Routes

Natural multi-turn conversation with streaming — talk to Nova like an assistant.
Security tools and agent actions are available when you ask, not forced on every message.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from nova_arsenal.auth.middleware import get_current_user
from nova_arsenal.db import get_db
from nova_arsenal.db.crud import (
    add_chat_message,
    delete_chat_session,
    get_chat_messages,
    get_chat_session,
    get_or_create_chat_session,
    list_chat_sessions,
)
from nova_arsenal.db.models import User
from nova_arsenal.db.session import get_session_factory
from nova_arsenal.kali_blueprint import KaliBlueprint
from nova_arsenal.llm.multi_router import MultiProviderRouter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/chat")

_blueprint: KaliBlueprint | None = None
_router: MultiProviderRouter | None = None


def get_blueprint() -> KaliBlueprint:
    global _blueprint
    if _blueprint is None:
        _blueprint = KaliBlueprint()
    return _blueprint


def get_router() -> MultiProviderRouter | None:
    return _router


def set_router(multi: MultiProviderRouter) -> None:
    global _router
    _router = multi


# ── Models ───────────────────────────────────────────────────────────────────


class ChatMessage(BaseModel):
    role: str
    content: str
    timestamp: str | None = None
    metadata: dict | None = None


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None
    target: str | None = None
    stream: bool = True


class ChatResponse(BaseModel):
    reply: str
    session_id: str
    intent: str
    metadata: dict | None = None


async def _require_owned_chat_session(
    db: AsyncSession,
    session_id: str,
    user_id: int,
):
    session = await get_chat_session(db, session_id)
    if not session or session.user_id != user_id:
        raise HTTPException(status_code=404, detail="Chat session not found")
    return session


# ── Intent (light routing only — conversation is default) ────────────────────

INTENT_PATTERNS = [
    (
        "security_task",
        [
            "scan ",
            "scan my",
            "pentest",
            "penetration test",
            "run nmap",
            "exploit ",
            "brute force",
            "start agent",
            "autonomous",
            "zero-day",
            "zeroday",
            "swarm scan",
            "recon on",
            "sub-agent",
            "subagent",
            "work session",
            "parallel agents",
            "multi-agent",
            "spawn agents",
        ],
    ),
    (
        "code_request",
        [
            "write code",
            "write a script",
            "generate code",
            "write me a",
            "create a payload",
            "python script",
            "bash script",
        ],
    ),
    (
        "tool_info",
        [
            "how to use nmap",
            "how does nmap",
            "how do i use",
            "what is sqlmap",
            "how to use sqlmap",
            "metasploit module",
        ],
    ),
]


def classify_intent(message: str) -> str:
    msg = message.lower().strip()
    for intent, patterns in INTENT_PATTERNS:
        for p in patterns:
            if p in msg:
                return intent
    # Default: normal conversation (like chatting with Grok)
    return "conversation"


# ── System prompts ───────────────────────────────────────────────────────────

NOVA_CONVERSATION_SYSTEM_PROMPT = """You are Nova — a sharp, friendly security research assistant.

Talk like a knowledgeable colleague in a continuous chat:
- Use natural, clear, complete sentences.
- Remember the conversation thread and refer back to earlier messages.
- Match the user's energy while staying precise on technical subjects.
- Security is your specialty, but general questions are fine.
- Prefer explanation, code review, threat modeling, remediation, and non-destructive validation.
- Treat any supplied target as context, never as proof of authorization.
- Do not provide destructive commands, credential theft, malware, exploit payloads, or instructions that bypass authorization.
- Never claim an action ran unless a tool actually ran and returned results.
- Be honest about limits.

You have deep knowledge of defensive security, secure coding, web/network security concepts, CTF learning, and threat modeling.
"""

NOVA_ACTION_SYSTEM_PROMPT = """You are Nova in action-assist mode inside a chat.

The user is asking for something operational.
- Stay conversational and explain the goal and risks clearly.
- Keep guidance non-destructive and defensive.
- Treat a supplied target as context, not proof of authorization.
- Do not provide exploit payloads, malware, credential-theft steps, destructive commands, or instructions for bypassing access controls.
- Prefer safe validation, remediation, code review, lab-only conceptual examples, and authorization checks.
- Never claim an action ran unless a tool actually ran and returned results.
"""


# ── History formatting ───────────────────────────────────────────────────────


def _truncate_middle(text: str, limit: int) -> str:
    """Keep both ends of oversized content instead of silently dropping context."""
    if len(text) <= limit:
        return text
    marker = "\n...[earlier content truncated]...\n"
    if limit <= len(marker) + 2:
        return text[:limit]
    remaining = limit - len(marker)
    head = int(remaining * 0.6)
    tail = remaining - head
    return text[:head] + marker + text[-tail:]


def _format_history(
    messages: list[dict],
    max_messages: int = 80,
    max_chars: int = 48_000,
) -> str:
    """Build bounded recent context for providers that accept a flat prompt.

    The newest turns are kept first within a character budget. A single
    oversized newest message is middle-truncated so both its opening context and
    ending request survive. This avoids sending arbitrarily large histories to
    providers with different context limits.
    """
    if not messages or max_chars <= 0:
        return ""

    recent = messages[-max_messages:]
    selected: list[str] = []
    used = 0

    for message in reversed(recent):
        role = message.get("role", "user")
        content = (message.get("content") or "").strip()
        if not content:
            continue

        label = "User" if role == "user" else "Nova"
        rendered = f"{label}: {content}"
        separator_cost = 2 if selected else 0

        if used + separator_cost + len(rendered) > max_chars:
            if not selected:
                prefix = f"{label}: "
                budget = max(0, max_chars - len(prefix))
                selected.append(prefix + _truncate_middle(content, budget))
            break

        selected.append(rendered)
        used += separator_cost + len(rendered)

    selected.reverse()
    if not selected:
        return ""

    prompt = "\n\n".join(selected)
    if selected[-1].startswith("User:"):
        prompt += "\n\nNova:"
    return prompt


def _system_for_intent(intent: str) -> str:
    if intent in ("security_task", "code_request"):
        return NOVA_ACTION_SYSTEM_PROMPT
    return NOVA_CONVERSATION_SYSTEM_PROMPT


# ── LLM access ───────────────────────────────────────────────────────────────


async def _resolve_llm():
    """Return the current multi-router and global router.

    Always prefer the router from get_llm_router() so config/account reloads are
    reflected immediately. The injected startup router remains only as a
    backwards-compatible fallback.
    """
    global_router = None
    multi = None
    try:
        from nova_arsenal.llm.router import get_llm_router

        global_router = get_llm_router()
        multi = global_router.multi_router
    except Exception as exc:  # noqa: BLE001
        logger.debug("global llm router unavailable: %s", exc)

    if multi is None:
        multi = get_router()
    return multi, global_router


async def _llm_chat(messages: list[dict], system_prompt: str) -> str:
    """Non-streaming completion with full conversation context."""
    prompt = _format_history(messages)
    last_user = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            last_user = m.get("content") or ""
            break
    if not prompt:
        prompt = last_user

    multi, global_router = await _resolve_llm()

    last_err: Exception | None = None

    # Multi-router first
    if multi and multi.list_providers():
        try:
            return await multi.complete(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.75,
                max_tokens=4096,
                preference="balanced",
            )
        except Exception as e:  # noqa: BLE001
            last_err = e
            logger.warning("multi-router chat failed: %s", e)

    # Global LLMRouter (BYOK + OAuth + Ollama)
    if global_router and global_router.list_providers():
        try:
            return await global_router.complete(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.75,
                max_tokens=4096,
            )
        except Exception as e:  # noqa: BLE001
            last_err = e
            logger.error("global llm chat failed: %s", e)

    # Always give a usable conversational fallback (never dead-end on DNS/tooling errors)
    base = _local_respond(last_user or prompt, system_prompt)
    if last_err:
        return (
            f"{base}\n\n---\n_Note: cloud/local model call failed "
            f"({type(last_err).__name__}: {last_err}). "
            "Fix with `nova-agent llm-status`, "
            "`login --provider openai --oauth`, or "
            "`login --provider ollama`._"
        )
    return base


async def _llm_stream(messages: list[dict], system_prompt: str) -> AsyncGenerator[str, None]:
    """Streaming tokens for a ChatGPT-like feel."""
    prompt = _format_history(messages)
    last_user = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            last_user = m.get("content") or ""
            break
    if not prompt:
        prompt = last_user

    multi, global_router = await _resolve_llm()

    # Prefer multi-router stream
    if multi and multi.list_providers():
        try:
            async for chunk in multi.stream(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.75,
                max_tokens=4096,
            ):
                if chunk:
                    yield chunk
            return
        except Exception as e:  # noqa: BLE001
            logger.warning("multi-router stream failed: %s", e)

    # Global router stream
    if global_router and global_router.list_providers():
        try:
            async for chunk in global_router.stream(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.75,
                max_tokens=4096,
            ):
                if chunk:
                    yield chunk
            return
        except Exception as e:  # noqa: BLE001
            logger.warning("global stream failed, falling back to complete: %s", e)
            try:
                full = await global_router.complete(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=0.75,
                    max_tokens=4096,
                )
                # Fake stream for UX
                for i in range(0, len(full), 24):
                    yield full[i : i + 24]
                    await asyncio.sleep(0.01)
                return
            except Exception as e2:  # noqa: BLE001
                yield (
                    f"I couldn't reach a language model ({e2}). "
                    "Sign in or set a key: `nova-agent login --provider openai --oauth` "
                    "or `nova-agent login --provider ollama`."
                )
                return

    # Offline local knowledge responder, streamed for feel
    text = _local_respond(last_user or prompt, system_prompt)
    for i in range(0, len(text), 28):
        yield text[i : i + 28]
        await asyncio.sleep(0.012)


def _local_respond(message: str, system_prompt: str) -> str:
    """Helpful offline replies when no LLM is configured."""
    bp = get_blueprint()
    msg_lower = (message or "").lower()

    for tool_name, tool in bp.tools.items():
        if tool_name in msg_lower:
            return (
                f"**{tool.name}** — {tool.description}\n"
                f"Category: {tool.category}\n\n"
                "I can explain what this tool is for, how to interpret its output, "
                "and how to use it safely in an authorized lab."
            )

    if any(w in msg_lower for w in ("hello", "hi ", "hey", "good morning", "good evening")):
        return (
            "Hey — I'm **Nova**. Talk to me like you would any AI assistant.\n\n"
            "I can chat about security, review code, explain tools, and help with "
            "defensive research. Examples:\n"
            "- “Explain SSRF simply”\n"
            "- “Review this authentication design”\n"
            "- “Help me interpret a vulnerability report”\n"
            "- “How should I structure an authorized lab?”\n\n"
            "What are you working on?"
        )

    if "what can you do" in msg_lower or msg_lower.strip() in {"help", "?"}:
        return (
            "I'm a conversational security research assistant.\n\n"
            "**Chat:** concepts, debugging, career, code review, CTF ideas\n"
            "**Tools:** conceptual guidance and output interpretation for common security tools\n"
            "**Research:** threat modeling, secure coding, remediation, and authorized lab analysis\n"
            "**Backends:** ChatGPT/Codex OAuth, API keys, or local Ollama\n\n"
            "Just keep talking — no special command language required."
        )

    suggestions = bp.suggest_tools(message)
    if suggestions and any(k in msg_lower for k in ("tool", "scan", "test", "vuln")):
        return (
            f"Relevant tools may include: **{', '.join(suggestions[:6])}**.\n\n"
            "I can explain their purpose, compare them, or help interpret results from an authorized lab."
        )

    return (
        f"I heard you: “{message}”\n\n"
        "I'm in **offline helper mode** (no LLM connected yet), so replies are limited.\n\n"
        "Connect a brain so we can chat freely:\n"
        "1. `nova-agent login --provider openai --oauth`  (ChatGPT sub)\n"
        "2. `nova-agent login --provider ollama`  (local free)\n"
        "3. Or set `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` in `.env`\n\n"
        "Then ask me anything again."
    )


# ── Streaming generator ──────────────────────────────────────────────────────


async def _stream_response(
    message: str,
    session_id: str,
    user_id: int,
    target: str | None = None,
) -> AsyncGenerator[str, None]:
    async with get_session_factory()() as db:
        try:
            session = await get_or_create_chat_session(
                db,
                session_id,
                user_id=user_id,
            )
            session_id = session.session_id

            await add_chat_message(db, session_id, "user", message)
            await db.commit()

            intent = classify_intent(message)
            yield f"data: {json.dumps({'type': 'intent', 'intent': intent, 'session_id': session_id})}\n\n"

            system_prompt = _system_for_intent(intent)
            if target:
                system_prompt += f"\n\nActive target context: {target}"

            history = await get_chat_messages(db, session_id, limit=50)
            session_history = [{"role": m.role, "content": m.content} for m in history]

            response_parts: list[str] = []
            async for chunk in _llm_stream(session_history, system_prompt):
                response_parts.append(chunk)
                yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"

            response = "".join(response_parts)
            bp = get_blueprint()
            metadata: dict[str, Any] = {
                "intent": intent,
                "suggestions": bp.suggest_tools(message)[:5],
                "tools_mentioned": [n for n in bp.tools if n.lower() in message.lower()][:10],
            }

            await add_chat_message(db, session_id, "assistant", response, metadata)
            await db.commit()
            yield f"data: {json.dumps({'type': 'done', 'metadata': metadata, 'session_id': session_id})}\n\n"

        except Exception as e:  # noqa: BLE001
            await db.rollback()
            logger.error("Stream error: %s", e)
            yield f"data: {json.dumps({'type': 'chunk', 'content': f'Sorry — chat error: {e}'})}\n\n"
            yield f"data: {json.dumps({'type': 'done', 'metadata': {'error': str(e)}})}\n\n"
        finally:
            await db.close()


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=ChatResponse)
@router.post("/", response_model=ChatResponse)
@router.post("/send", response_model=ChatResponse)
async def chat_send(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Send a message and get a full reply (non-streaming)."""
    session_id = request.session_id or str(uuid.uuid4())
    try:
        session = await get_or_create_chat_session(
            db,
            session_id,
            user_id=current_user.id,
        )
    except PermissionError:
        raise HTTPException(status_code=404, detail="Chat session not found")
    session_id = session.session_id

    await add_chat_message(db, session_id, "user", request.message)
    await db.commit()

    intent = classify_intent(request.message)
    system_prompt = _system_for_intent(intent)
    if request.target:
        system_prompt += f"\n\nActive target context: {request.target}"

    history = await get_chat_messages(db, session_id, limit=50)
    session_history = [{"role": m.role, "content": m.content} for m in history]

    response = await _llm_chat(session_history, system_prompt)

    bp = get_blueprint()
    metadata = {
        "intent": intent,
        "suggestions": bp.suggest_tools(request.message)[:5],
    }
    await add_chat_message(db, session_id, "assistant", response, metadata)
    await db.commit()

    return ChatResponse(
        reply=response,
        session_id=session_id,
        intent=intent,
        metadata=metadata,
    )


@router.post("/stream")
async def chat_stream(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Streaming SSE chat — authenticated, user-owned conversation."""
    session_id = request.session_id or str(uuid.uuid4())
    try:
        session = await get_or_create_chat_session(
            db,
            session_id,
            user_id=current_user.id,
        )
    except PermissionError:
        raise HTTPException(status_code=404, detail="Chat session not found")
    await db.commit()

    return StreamingResponse(
        _stream_response(
            request.message,
            session.session_id,
            current_user.id,
            request.target,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/sessions/{session_id}/history")
async def chat_history(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _require_owned_chat_session(db, session_id, current_user.id)
    messages = await get_chat_messages(db, session_id, limit=200)
    return {
        "session_id": session_id,
        "messages": [
            {
                "role": message.role,
                "content": message.content,
                "created_at": str(getattr(message, "timestamp", "")),
            }
            for message in messages
        ],
    }


@router.get("/sessions")
async def chat_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    sessions = await list_chat_sessions(db, user_id=current_user.id)
    return {"sessions": sessions}


@router.delete("/sessions/{session_id}")
async def chat_delete_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    deleted = await delete_chat_session(
        db,
        session_id,
        user_id=current_user.id,
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Chat session not found")
    await db.commit()
    return {"status": "deleted", "session_id": session_id}


@router.get("/tools/suggest")
async def tools_suggest(
    q: str = "",
    _current_user: User = Depends(get_current_user),
):
    bp = get_blueprint()
    return {"suggestions": bp.suggest_tools(q)[:10]}


@router.get("/tools/search")
async def tools_search(
    q: str = "",
    _current_user: User = Depends(get_current_user),
):
    bp = get_blueprint()
    q_l = q.lower()
    hits = []
    for name, tool in bp.tools.items():
        if q_l in name.lower() or q_l in (tool.description or "").lower():
            hits.append({"name": name, "description": tool.description})
        if len(hits) >= 20:
            break
    return {"results": hits}
