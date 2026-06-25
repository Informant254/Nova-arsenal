"""
Nova-Arsenal Chat Routes

Conversational chat endpoint with SSE streaming.
Talk to Nova like you talk to a human — Nova understands intent and acts.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from nova_arsenal.kali_blueprint import KaliBlueprint
from nova_arsenal.llm.multi_router import MultiProviderRouter, TaskCategory

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/chat")

# ── Global state ─────────────────────────────────────────────────────────────

_blueprint: Optional[KaliBlueprint] = None
_router: Optional[MultiProviderRouter] = None
_sessions: Dict[str, List[Dict]] = {}  # session_id -> messages


def get_blueprint() -> KaliBlueprint:
    global _blueprint
    if _blueprint is None:
        _blueprint = KaliBlueprint()
    return _blueprint


def get_router() -> Optional[MultiProviderRouter]:
    global _router
    return _router


def set_router(router: MultiProviderRouter):
    global _router
    _router = router


# ── Models ───────────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str  # "user" or "assistant"
    content: str
    timestamp: Optional[str] = None
    metadata: Optional[Dict] = None


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    target: Optional[str] = None  # If the user mentions a target
    stream: bool = True


class ChatResponse(BaseModel):
    reply: str
    session_id: str
    intent: str
    metadata: Optional[Dict] = None


# ── Intent Classification ───────────────────────────────────────────────────

# Order matters: first match wins for phrase patterns
INTENT_PATTERNS = [
    ("conversation", [
        "hello", "hi ", "hey", "how are you", "thanks", "thank you",
        "good morning", "good evening", "who are you", "what can you do",
        "what's up", "how's it going",
    ]),
    ("code_request", [
        "write code", "create script", "write a script", "generate code",
        "python script", "bash script", "exploit code", "write me a",
        "build me", "make me", "code for",
    ]),
    ("tool_info", [
        "how to use ", "nmap", "sqlmap", "metasploit", "burp",
        "gobuster", "hashcat", "john ", "hydra", "nikto", "nuclei",
        "ffuf", "enum4linux", "crackmapexec", "aircrack", "nikto",
        "wpscan", "whatweb", "nuclei", "subfinder", "amass",
    ]),
    ("question", [
        "what is ", "how do ", "how to ", "explain ", "tell me about",
        "what does", "what are ", "why ", "when ",
    ]),
    ("security_task", [
        "scan ", "exploit", "penetration", "hack ", "attack ",
        "vulnerability", "brute force", "privilege escalation",
        "post exploitation", "recon ", "enumerate", "pentest",
        "red team", "reverse shell",
    ]),
]


def classify_intent(message: str) -> str:
    """Classify the user's intent from their message."""
    msg_lower = message.lower()

    # Hard priority: conversation greetings always win
    for pattern in INTENT_PATTERNS[0][1]:  # conversation patterns
        if pattern in msg_lower:
            return "conversation"

    # Hard priority: code requests always win
    for pattern in INTENT_PATTERNS[1][1]:  # code_request patterns
        if pattern in msg_lower:
            return "code_request"

    # Check if any tool name is mentioned — tool_info wins over question
    bp = get_blueprint()
    for tool_name in bp.tools:
        if tool_name.lower() in msg_lower:
            return "tool_info"

    # Then check remaining patterns in order
    for intent, patterns in INTENT_PATTERNS[2:]:  # skip conversation, code_request
        for pattern in patterns:
            if pattern in msg_lower:
                return intent

    return "conversation"


# ── System Prompts ───────────────────────────────────────────────────────────

NOVA_CONVERSATION_SYSTEM_PROMPT = """You are Nova, an elite autonomous security researcher and AI assistant.

You are conversational, helpful, and knowledgeable about:
- Cybersecurity (penetration testing, vulnerability assessment, exploit development)
- Kali Linux tools and how to use them
- Programming (Python, Bash, C, Go, Ruby, PowerShell)
- Operating systems, networking, cloud, containers
- Security frameworks (MITRE ATT&CK, OWASP, PTES)

PERSONALITY:
- Methodical and thorough, but friendly and approachable
- You explain things clearly when asked
- You suggest next steps proactively
- You know when to be cautious and respect scope boundaries
- You can be casual in conversation but precise in technical matters

CAPABILITIES:
- Answer questions about security, tools, techniques
- Explain how tools work and when to use them
- Generate code (exploits, scripts, payloads) when asked
- Analyze security situations and suggest approaches
- Run Kali Linux tools autonomously when given a task

RULES:
1. Never execute harmful commands against systems you don't have authorization for
2. Always remind users about scope and authorization
3. When generating code, include safety warnings
4. Be honest about limitations
5. If you're unsure, say so
"""


NOVA_TASK_SYSTEM_PROMPT = """You are Nova, an elite autonomous security researcher operating in Kali Linux.

You are about to execute a security task. Analyze the request and respond with a JSON action plan.

Respond with valid JSON:
{
    "action": "execute",
    "description": "what this does",
    "command": "the command to run",
    "phase": "recon|scanning|exploitation|post_exploitation|reporting"
}

If the request is ambiguous, ask for clarification.
If it's outside scope, explain why.
"""


# ── LLM Integration ──────────────────────────────────────────────────────────

async def _llm_chat(messages: List[Dict], system_prompt: str) -> str:
    """Send messages to the LLM and get a response."""
    router = get_router()

    if router and router.active_providers:
        try:
            full_messages = [{"role": "system", "content": system_prompt}] + messages
            response = await router.complete(
                prompt=messages[-1]["content"],
                system_prompt=system_prompt,
                temperature=0.7,
                max_tokens=2048,
            )
            return response
        except Exception as e:
            logger.error(f"LLM provider error: {e}")
            return f"I encountered an error connecting to my language model: {e}"

    # Fallback: intelligent local responses
    return _local_respond(messages[-1]["content"], system_prompt)


def _local_respond(message: str, system_prompt: str) -> str:
    """Local fallback responder when no LLM is configured."""
    bp = get_blueprint()
    msg_lower = message.lower()

    # Tool info requests — check every tool in the blueprint
    for tool_name, tool in bp.tools.items():
        if tool_name in msg_lower:
            lines = [
                f"**{tool.name}** — {tool.description}",
                f"Category: {tool.category}",
                f"Install: `{tool.install_path}`" if tool.install_path else "",
                f"Usage: `{tool.usage}`" if tool.usage else "",
            ]
            if tool.examples:
                lines.append("\n**Examples:**")
                for ex in tool.examples[:3]:
                    lines.append(f"  `{ex}`")
            if tool.flags:
                lines.append(f"\n**Key flags:** {', '.join(list(tool.flags.keys())[:10])}")
            if tool.notes:
                lines.append(f"\n_Note: {tool.notes}_")
            return "\n".join(l for l in lines if l)

    # Category suggestions
    if "what tools" in msg_lower or "recommend" in msg_lower or "suggest" in msg_lower:
        suggestions = bp.suggest_tools(message)
        if suggestions:
            return f"For that task, I'd suggest: **{', '.join(suggestions[:6])}**\n\nWould you like details on any of these?"

    # Attack chains
    for chain_name, chain in bp.attack_chains.items():
        if chain_name.replace("_", " ") in msg_lower or chain_name in msg_lower:
            steps = "\n".join(f"  {i+1}. `{s}`" for i, s in enumerate(chain["steps"]))
            tools = ", ".join(chain.get("tools", []))
            return f"**{chain_name.replace('_', ' ').title()}**\n\n{chain.get('description', '')}\n\n**Steps:**\n{steps}\n\n**Tools needed:** {tools}"

    # General greeting
    if any(w in msg_lower for w in ["hello", "hi", "hey", "good morning", "good evening"]):
        return ("Hey! I'm **Nova** — your autonomous security research assistant.\n\n"
                "I can:\n"
                "- **Answer questions** about security, tools, techniques\n"
                "- **Run Kali tools** — just tell me what to scan or test\n"
                "- **Write code** — exploits, scripts, payloads\n"
                "- **Autonomously pentest** — give me a target and I'll handle it\n\n"
                "What would you like to do?")

    # What can you do
    if "what can you do" in msg_lower or "help" in msg_lower:
        return ("I'm Nova, an autonomous security researcher. Here's what I can do:\n\n"
                "**Conversational:**\n"
                "- Explain security concepts\n"
                "- Describe how tools work\n"
                "- Discuss attack techniques and defenses\n\n"
                "**Action-oriented:**\n"
                "- Run Kali Linux tools (nmap, sqlmap, hydra, etc.)\n"
                "- Write custom exploits and scripts\n"
                "- Perform full penetration tests autonomously\n"
                "- Analyze findings and suggest next steps\n\n"
                "**Just talk to me naturally** — I'll understand what you need.")

    # Fallback
    return (f"I understand you're asking about: _{message}_\n\n"
            "I can help with security questions, tool usage, or run tasks autonomously. "
            "To get the best responses, make sure an LLM provider is configured in your settings.\n\n"
            "Try asking me about a specific tool, or give me a target to test!")


# ── Streaming Generator ──────────────────────────────────────────────────────

async def _stream_response(
    message: str,
    session_id: str,
    target: Optional[str] = None,
) -> AsyncGenerator[str, None]:
    """Generate a streaming SSE response."""
    session = _sessions.setdefault(session_id, [])
    session.append({"role": "user", "content": message, "timestamp": datetime.now(timezone.utc).isoformat()})

    # Classify intent
    intent = classify_intent(message)
    yield f"data: {json.dumps({'type': 'intent', 'intent': intent})}\n\n"

    # Route based on intent
    if intent in ("security_task", "code_request"):
        system_prompt = NOVA_TASK_SYSTEM_PROMPT
    else:
        system_prompt = NOVA_CONVERSATION_SYSTEM_PROMPT

    # Get LLM response
    router = get_router()
    if router and router.active_providers:
        try:
            full_messages = [{"role": "system", "content": system_prompt}] + [
                {"role": m["role"], "content": m["content"]} for m in session
            ]

            # Try streaming
            provider_name = router.route(message)
            provider = router.active_providers.get(provider_name)

            if provider and hasattr(provider, 'stream'):
                async for chunk in provider.stream(
                    prompt=message,
                    system_prompt=system_prompt,
                    temperature=0.7,
                    max_tokens=2048,
                ):
                    yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"
            else:
                # Fallback to non-streaming
                response = await _llm_chat(
                    [{"role": m["role"], "content": m["content"]} for m in session],
                    system_prompt,
                )
                # Simulate streaming by chunking
                for i in range(0, len(response), 40):
                    chunk = response[i:i+40]
                    yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"
                    await asyncio.sleep(0.02)

        except Exception as e:
            error_msg = f"Error: {e}"
            yield f"data: {json.dumps({'type': 'chunk', 'content': error_msg})}\n\n"
    else:
        # Local fallback
        response = _local_respond(message, system_prompt)
        for i in range(0, len(response), 30):
            chunk = response[i:i+30]
            yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"
            await asyncio.sleep(0.015)

    # Build metadata
    metadata = {
        "intent": intent,
        "tools_mentioned": [],
        "suggestions": [],
    }

    bp = get_blueprint()
    suggestions = bp.suggest_tools(message)
    if suggestions:
        metadata["suggestions"] = suggestions[:5]

    # Detect mentioned tools
    for tool_name in bp.tools:
        if tool_name.lower() in message.lower():
            metadata["tools_mentioned"].append(tool_name)

    # Store assistant response
    assistant_msg = {
        "role": "assistant",
        "content": response if 'response' in dir() else "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metadata": metadata,
    }
    session.append(assistant_msg)

    # Send done event
    yield f"data: {json.dumps({'type': 'done', 'metadata': metadata})}\n\n"


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/send", response_model=ChatResponse)
async def chat_send(request: ChatRequest):
    """Send a message and get a non-streaming response."""
    session_id = request.session_id or str(uuid.uuid4())

    # Classify intent
    intent = classify_intent(request.message)

    # Build context
    bp = get_blueprint()
    system_prompt = NOVA_CONVERSATION_SYSTEM_PROMPT

    if intent in ("security_task", "code_request"):
        system_prompt = NOVA_TASK_SYSTEM_PROMPT

    # Get response
    session = _sessions.setdefault(session_id, [])
    session.append({"role": "user", "content": request.message})

    response = await _llm_chat(
        [{"role": m["role"], "content": m["content"]} for m in session],
        system_prompt,
    )

    session.append({"role": "assistant", "content": response})

    metadata = {"intent": intent}
    suggestions = bp.suggest_tools(request.message)
    if suggestions:
        metadata["suggestions"] = suggestions[:5]

    return ChatResponse(
        reply=response,
        session_id=session_id,
        intent=intent,
        metadata=metadata,
    )


@router.post("/stream")
async def chat_stream(request: ChatRequest):
    """Send a message and get a streaming SSE response."""
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
async def chat_history(session_id: str):
    """Get chat history for a session."""
    session = _sessions.get(session_id, [])
    return {"session_id": session_id, "messages": session}


@router.delete("/sessions/{session_id}")
async def chat_clear(session_id: str):
    """Clear a chat session."""
    _sessions.pop(session_id, None)
    return {"status": "cleared", "session_id": session_id}


@router.get("/tools/suggest")
async def suggest_tools_endpoint(q: str):
    """Get tool suggestions for a task description."""
    bp = get_blueprint()
    suggestions = bp.suggest_tools(q)
    return {"query": q, "suggestions": suggestions}


@router.get("/tools/search")
async def search_tools(q: str):
    """Search tools by name or description."""
    bp = get_blueprint()
    results = []
    q_lower = q.lower()
    for tool in bp.get_all_tools():
        if q_lower in tool.name.lower() or q_lower in tool.description.lower():
            results.append({
                "name": tool.name,
                "category": tool.category,
                "description": tool.description,
                "usage": tool.usage,
            })
    return {"query": q, "results": results[:20]}
