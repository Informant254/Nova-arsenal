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
from typing import Any, Optional

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from nova_arsenal.db import get_db
from nova_arsenal.db.crud import (
    add_chat_message,
    delete_chat_session,
    get_chat_messages,
    get_or_create_chat_session,
    list_chat_sessions,
)
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


# ── Intent (light routing only — conversation is default) ────────────────────

INTENT_PATTERNS = [
    ("security_task", [
        "scan ", "scan my", "pentest", "penetration test", "run nmap",
        "exploit ", "brute force", "start agent", "autonomous",
        "zero-day", "zeroday", "swarm scan", "recon on",
        "sub-agent", "subagent", "work session", "parallel agents",
        "multi-agent", "spawn agents",
    ]),
    ("code_request", [
        "write code", "write a script", "generate code", "write me a",
        "create a payload", "python script", "bash script",
    ]),
    ("tool_info", [
        "how to use nmap", "how does nmap", "how do i use",
        "what is sqlmap", "how to use sqlmap", "metasploit module",
    ]),
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

NOVA_CONVERSATION_SYSTEM_PROMPT = """You are Nova — a sharp, friendly autonomous security research assistant.

Talk like a knowledgeable colleague in a continuous chat (similar to ChatGPT / Claude / Grok):
- Natural, clear, complete sentences. No robot template dumps unless asked.
- Remember the conversation thread and refer back to earlier messages.
- Match the user's energy: casual when they are casual, precise when they go technical.
- You can discuss anything they bring up — security is your specialty, but general questions are fine.
- When they want action (scan, exploit, agent run), explain what you'll do, warn about authorization, and give concrete next steps or commands.
- Never claim you already attacked a system unless tools actually ran and returned results.
- Be honest about limits. Prefer ethical, authorized security work.

You have deep knowledge of: pentesting, Kali tools, web/network/AD security, CTFs, coding, and threat modeling.
If an LLM/backend is connected, reason carefully. If not, still be helpful with what you know.
"""

NOVA_ACTION_SYSTEM_PROMPT = """You are Nova in action-assist mode inside a chat.

The user wants something operational (scan, code, exploit, agent).
- Stay conversational — do NOT reply with only raw JSON unless they explicitly ask for JSON.
- Give a clear plan in plain language, then commands or code in fenced blocks.
- Always remind them to only test systems they are authorized to assess.
- If they gave a target, use it. If not, ask for one.
- Offer to go deeper (swarm, zero-day candidate pipeline, specific tools) when useful.
"""


# ── History formatting ───────────────────────────────────────────────────────

def _format_history(messages: list[dict], max_messages: int = 40) -> str:
    """Turn multi-turn history into a single prompt for providers that lack chat APIs."""
    recent = messages[-max_messages:] if messages else []
    lines: list[str] = []
    for m in recent:
        role = m.get("role", "user")
        content = (m.get("content") or "").strip()
        if not content:
            continue
        label = "User" if role == "user" else "Nova"
        lines.append(f"{label}: {content}")
    if not lines:
        return ""
    # Ensure the model continues as Nova
    if not lines[-1].startswith("User:"):
        return "\n\n".join(lines)
    return "\n\n".join(lines) + "\n\nNova:"


def _system_for_intent(intent: str) -> str:
    if intent in ("security_task", "code_request"):
        return NOVA_ACTION_SYSTEM_PROMPT
    return NOVA_CONVERSATION_SYSTEM_PROMPT


# ── LLM access ───────────────────────────────────────────────────────────────

async def _resolve_llm():
    """Return (multi_router_or_None, global_llm_router_or_None)."""
    multi = get_router()
    global_router = None
    try:
        from nova_arsenal.llm.router import get_llm_router

        global_router = get_llm_router()
    except Exception as exc:  # noqa: BLE001
        logger.debug("global llm router unavailable: %s", exc)
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
            lines = [
                f"**{tool.name}** — {tool.description}",
                f"Category: {tool.category}",
            ]
            if tool.usage:
                lines.append(f"Usage: `{tool.usage}`")
            if tool.examples:
                lines.append("\n**Examples:**")
                for ex in tool.examples[:3]:
                    lines.append(f"  `{ex}`")
            lines.append(
                "\n_Tip: connect an LLM (`nova-agent login --provider ollama` or ChatGPT OAuth) "
                "for freer conversation._"
            )
            return "\n".join(lines)

    if any(w in msg_lower for w in ("hello", "hi ", "hey", "good morning", "good evening")):
        return (
            "Hey — I'm **Nova**. Talk to me like you would any AI assistant.\n\n"
            "I can chat about security, write code, explain tools, or help plan "
            "authorized tests. Examples:\n"
            "- “Explain SSRF simply”\n"
            "- “How should I recon a web app?”\n"
            "- “Draft an nmap command for top ports”\n"
            "- “Sign me up for local Ollama” → run `nova-agent login --provider ollama`\n\n"
            "What are you working on?"
        )

    if "what can you do" in msg_lower or msg_lower.strip() in {"help", "?"}:
        return (
            "I'm a conversational security research assistant.\n\n"
            "**Chat:** concepts, debugging, career, code review, CTF ideas\n"
            "**Tools:** nmap, sqlmap, nuclei, hydra, Burp/Metasploit integration knowledge\n"
            "**Agent modes:** autonomous scans, swarm, zero-day *candidate* pipeline "
            "(authorized targets only)\n"
            "**Backends:** ChatGPT/Codex OAuth, API keys, or local Ollama\n\n"
            "Just keep talking — no special command language required."
        )

    suggestions = bp.suggest_tools(message)
    if suggestions and any(k in msg_lower for k in ("tool", "scan", "test", "vuln")):
        return (
            f"For that, common tools include: **{', '.join(suggestions[:6])}**.\n\n"
            "Tell me more about the target and goal and I'll walk you through it. "
            "For freer conversation, connect an LLM backend."
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
    target: str | None = None,
) -> AsyncGenerator[str, None]:
    async with get_session_factory()() as db:
        try:
            session = await get_or_create_chat_session(db, session_id)
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
                "tools_mentioned": [
                    n for n in bp.tools if n.lower() in message.lower()
                ][:10],
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
):
    """Send a message and get a full reply (non-streaming)."""
    session_id = request.session_id or str(uuid.uuid4())
    session = await get_or_create_chat_session(db, session_id)
    session_id = session.session_id

    await add_chat_message(db, session_id, "user", request.message)

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

    return ChatResponse(
        reply=response,
        session_id=session_id,
        intent=intent,
        metadata=metadata,
    )


@router.post("/stream")
async def chat_stream(request: ChatRequest):
    """Streaming SSE chat — ChatGPT-style token delivery."""
    session_id = request.session_id or str(uuid.uuid4())
    return StreamingResponse(
        _stream_response(request.message, session_id, request.target),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/sessions/{session_id}/history")
async def chat_history(session_id: str, db: AsyncSession = Depends(get_db)):
    messages = await get_chat_messages(db, session_id, limit=200)
    return {
        "session_id": session_id,
        "messages": [
            {"role": m.role, "content": m.content, "created_at": str(getattr(m, "created_at", ""))}
            for m in messages
        ],
    }


@router.get("/sessions")
async def chat_sessions(db: AsyncSession = Depends(get_db)):
    sessions = await list_chat_sessions(db)
    return {
        "sessions": [
            {
                "session_id": s.session_id,
                "created_at": str(getattr(s, "created_at", "")),
                "updated_at": str(getattr(s, "updated_at", "")),
            }
            for s in sessions
        ]
    }


@router.delete("/sessions/{session_id}")
async def chat_delete_session(session_id: str, db: AsyncSession = Depends(get_db)):
    await delete_chat_session(db, session_id)
    return {"status": "deleted", "session_id": session_id}


@router.get("/tools/suggest")
async def tools_suggest(q: str = ""):
    bp = get_blueprint()
    return {"suggestions": bp.suggest_tools(q)[:10]}


@router.get("/tools/search")
async def tools_search(q: str = ""):
    bp = get_blueprint()
    q_l = q.lower()
    hits = []
    for name, tool in bp.tools.items():
        if q_l in name.lower() or q_l in (tool.description or "").lower():
            hits.append({"name": name, "description": tool.description})
        if len(hits) >= 20:
            break
    return {"results": hits}
