"""
Cursor-inspired Priority-Based Prompt Builder (Qwythos-enhanced).

Port of Priompt's priority-scoped prompt assembly to Python.
Uses binary search on priority levels to fit the most important
content within a token limit.

Core algorithm (from Priompt lib.ts):
1. Build tree of scope nodes, each with absolute or relative priority
2. Compute all unique priority levels (pre-order traversal)
3. Binary search for highest cutoff that fits within token_limit
4. Render with chosen cutoff (include scopes with priority >= cutoff)

Qwythos enhancements:
- Structured chain-of-thought blocks (hypothesis→verification→conclusion)
- CoT node type that forces structured reasoning in agent responses
- Integration with data_generation.COT_FRAMEWORK
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

BASE_PRIORITY = 1_000_000_000

TOKEN_CHAR_ESTIMATE = 4  # ~4 chars per token for rough estimation


# ── Node Types ──────────────────────────────────────────────────────────────


@dataclass
class Scope:
    """A priority-scoped section of the prompt.
    
    If absolute_priority (or priority) is set, it takes precedence over
    relative_priority. relative_priority is relative to the parent's priority
    (should be negative to make content lower priority than parent).
    """
    children: List[Any] = field(default_factory=list)
    absolute_priority: Optional[int] = None
    relative_priority: Optional[int] = None
    name: Optional[str] = None
    priority: Optional[int] = None  # alias for absolute_priority

    def __post_init__(self) -> None:
        if self.priority is not None and self.absolute_priority is None:
            self.absolute_priority = self.priority


@dataclass
class First:
    """Mutually exclusive children - renders the first whose priority >= cutoff.
    
    Children must be Scope nodes. The first child with absolute_priority >= cutoff
    is rendered; others are skipped.
    """
    children: List[Scope] = field(default_factory=list)


@dataclass
class Empty:
    """Reserves token count without adding content."""
    token_count: int = 0


@dataclass
class Isolate:
    """Independently bounded subtree with its own token limit."""
    token_limit: int
    children: List[Any] = field(default_factory=list)
    _cached_output: Optional[Any] = None


@dataclass
class Text:
    """Leaf text content node."""
    content: str


@dataclass
class ChatMessage:
    """A chat message with a role and content."""
    role: str  # system, user, assistant, tool, function
    content: str
    name: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None


@dataclass
class ToolDefinition:
    """A tool/function definition with JSON schema."""
    name: str
    description: str
    parameters: Dict[str, Any]


class ThinkingProfile(Enum):
    """Nex-N2 inspired reasoning depth profiles for Adaptive Thinking."""
    DEFAULT = "default"         # Model decides autonomously
    FORCE_ON = "force_on"       # Always reason deeply
    FORCE_OFF = "force_off"     # Skip reasoning entirely
    SEARCH = "search"           # Early search strategy → late synthesis
    SWE = "swe"                 # Densest during bug-localization and fix-verification
    LONG_HORIZON = "long_horizon"  # Progressively deepening, peaking at result integration


@dataclass
class AdaptiveThinking:
    """Nex-N2 style Adaptive Thinking block.

    Controls reasoning depth dynamically per step.
    - enable_thinking=None: model autonomously decides whether to fill <think>
    - enable_thinking=True: always emit <think> tags
    - enable_thinking=False: emit empty <think></think> (no reasoning forced)

    Profiles provide task-specific reasoning patterns:
    - SEARCH: token savings from early synthesis after initial search strategy
    - SWE: dense reasoning during bug-localization and fix-verification
    - LONG_HORIZON: progressively deepening reasoning over many steps
    """
    enable_thinking: Optional[bool] = None
    profile: ThinkingProfile = ThinkingProfile.DEFAULT
    content: str = ""


@dataclass
class ChainOfThought:
    """A structured chain-of-thought block (Qwythos-style).
    
    Forces the model to produce reasoning in three distinct blocks:
    <hypothesis>, <verification>, <conclusion>.
    Each block must be substantive.
    """
    content: str = ""
    force_verification: bool = True
    force_conclusion: bool = True


PromptNode = Union[Scope, First, Empty, Isolate, Text, ChatMessage, ToolDefinition, ChainOfThought, AdaptiveThinking]


# ── Matcher for node types ──────────────────────────────────────────────────


def _is_scope(n: Any) -> bool:
    return isinstance(n, Scope)


def _is_first(n: Any) -> bool:
    return isinstance(n, First)


def _is_empty(n: Any) -> bool:
    return isinstance(n, Empty)


def _is_text(n: Any) -> bool:
    return isinstance(n, Text)


def _is_isolate(n: Any) -> bool:
    return isinstance(n, Isolate)


def _is_chat(n: Any) -> bool:
    return isinstance(n, ChatMessage)


def _is_tool_def(n: Any) -> bool:
    return isinstance(n, ToolDefinition)


def _is_cot(n: Any) -> bool:
    return isinstance(n, ChainOfThought)


def _is_adaptive_thinking(n: Any) -> bool:
    return isinstance(n, AdaptiveThinking)


ADAPTIVE_THINKING_PROMPT_TEMPLATE = """You have adaptive reasoning capabilities.
{profile_instruction}

{profile_hint}

Your reasoning will be enclosed in <think></think> tags.
{thinking_rule}"""


ADAPTIVE_THINKING_PROFILES = {
    ThinkingProfile.DEFAULT: {
        "instruction": "Reason deeply when the problem requires it, act directly when it doesn't.",
        "hint": "",
    },
    ThinkingProfile.FORCE_ON: {
        "instruction": "You MUST reason step-by-step before every response.",
        "hint": "",
    },
    ThinkingProfile.FORCE_OFF: {
        "instruction": "Respond directly without explicit reasoning.",
        "hint": "",
    },
    ThinkingProfile.SEARCH: {
        "instruction": "For search tasks: focus reasoning on search strategy decomposition early, then synthesize findings concisely.",
        "hint": "Concentrate reasoning where uncertainty is high and key decisions are needed.",
    },
    ThinkingProfile.SWE: {
        "instruction": "For software engineering: densest reasoning during bug-localization and fix-verification phases.",
        "hint": "Reason thoroughly to verify the fix before concluding.",
    },
    ThinkingProfile.LONG_HORIZON: {
        "instruction": "For long-horizon tasks: reasoning should deepen progressively, peaking at result integration.",
        "hint": "Track state across steps and adjust strategy as new information arrives.",
    },
}


COT_INSTRUCTION = """
You MUST structure ALL reasoning in the following three blocks:

<hypothesis>
State your initial assessment, assumptions, and expected outcome.
</hypothesis>

<verification>
Walk through evidence step by step. Check each assumption. Test edge cases.
Consider alternative explanations. Be thorough — this block should be the longest.
</verification>

<conclusion>
State what you determined, why, and what the implications are.
If uncertain, explain what would resolve the ambiguity.
</conclusion>

Each block must be present and substantive. Empty blocks will be rejected.
"""


# ── Token Counting ──────────────────────────────────────────────────────────


def _estimate_tokens(text: str) -> int:
    """Rough character-based token estimate."""
    return max(1, len(text) // TOKEN_CHAR_ESTIMATE)


def count_text_tokens(text: str, tokenizer: Optional[Any] = None) -> int:
    """Count tokens using tiktoken if available, else character estimate."""
    if tokenizer is not None:
        try:
            if hasattr(tokenizer, 'encode'):
                return len(tokenizer.encode(text))
            return tokenizer(text)
        except Exception:
            pass
    return _estimate_tokens(text)


def count_tool_tokens(tool: ToolDefinition, tokenizer: Optional[Any] = None) -> int:
    """Estimate tokens for a tool definition."""
    text = f"{tool.name}: {tool.description} {json.dumps(tool.parameters)}"
    return count_text_tokens(text, tokenizer)


# ── Priority Level Computation ──────────────────────────────────────────────


def _compute_priority(
    node: Union[Scope, Any],
    parent_priority: int,
) -> int:
    """Compute effective priority for a node."""
    if isinstance(node, Scope):
        if node.absolute_priority is not None:
            return node.absolute_priority
        rel = node.relative_priority if node.relative_priority is not None else 0
        return parent_priority + rel
    return parent_priority


def compute_priority_levels(
    nodes: Any,
    parent_priority: int,
    levels: set,
) -> None:
    """Collect all unique priority levels from the tree."""
    if isinstance(nodes, (list, tuple)):
        for child in nodes:
            compute_priority_levels(child, parent_priority, levels)
        return

    if nodes is None:
        return

    if isinstance(nodes, Text):
        return

    if isinstance(nodes, ChatMessage):
        compute_priority_levels(nodes.content, parent_priority, levels)
        return

    if isinstance(nodes, Empty):
        return

    if isinstance(nodes, Isolate):
        return

    if isinstance(nodes, ToolDefinition):
        return

    if isinstance(nodes, ChainOfThought):
        return

    if isinstance(nodes, AdaptiveThinking):
        return

    if isinstance(nodes, First):
        for child in nodes.children:
            if isinstance(child, Scope):
                p = _compute_priority(child, parent_priority)
                child.absolute_priority = p
                levels.add(p)
                compute_priority_levels(child.children, p, levels)
        return

    if isinstance(nodes, Scope):
        p = _compute_priority(nodes, parent_priority)
        nodes.absolute_priority = p
        levels.add(p)
        compute_priority_levels(nodes.children, p, levels)
        return


# ── Hydration (isolates and empty token counts) ────────────────────────────


def _hydrate_isolates(nodes: Any, tokenizer: Optional[Any]) -> None:
    """Pre-render isolated subtrees."""
    if isinstance(nodes, (list, tuple)):
        for child in nodes:
            _hydrate_isolates(child, tokenizer)
        return

    if nodes is None:
        return

    if isinstance(nodes, (Text, Empty, ChatMessage, ToolDefinition, ChainOfThought, AdaptiveThinking)):
        return

    if isinstance(nodes, First):
        for child in nodes.children:
            _hydrate_isolates(child, tokenizer)
        return

    if isinstance(nodes, Isolate):
        if nodes._cached_output is None:
            nodes._cached_output = render(
                nodes.children,
                token_limit=nodes.token_limit,
                tokenizer=tokenizer,
            )
        return

    if isinstance(nodes, Scope):
        _hydrate_isolates(nodes.children, tokenizer)
        return


# ── Rendering Engine ────────────────────────────────────────────────────────


def _render_with_level(
    nodes: Any,
    level: int,
    tokenizer: Optional[Any],
) -> Tuple[Optional[str], int, Optional[List[ChatMessage]], Optional[List[ToolDefinition]]]:
    """Render prompt content including all scopes with priority >= level.
    
    Returns (text, empty_tokens, chat_messages, tool_definitions).
    """
    text_parts: List[str] = []
    empty_token_count = 0
    chat_messages: Optional[List[ChatMessage]] = None
    tool_definitions: Optional[List[ToolDefinition]] = None

    def _render_inner(nodes_inner: Any) -> None:
        nonlocal text_parts, empty_token_count, chat_messages, tool_definitions

        if nodes_inner is None:
            return

        if isinstance(nodes_inner, str):
            text_parts.append(nodes_inner)
            return

        if isinstance(nodes_inner, (list, tuple)):
            for child in nodes_inner:
                _render_inner(child)
            return

        if isinstance(nodes_inner, Text):
            text_parts.append(nodes_inner.content)
            return

        if isinstance(nodes_inner, ChatMessage):
            sub_text, sub_empty, sub_chat, sub_tools = _render_with_level(
                nodes_inner.content, level, tokenizer
            )
            content = sub_text or ""
            msg = ChatMessage(
                role=nodes_inner.role,
                content=content,
                name=nodes_inner.name,
                tool_calls=nodes_inner.tool_calls,
            )
            if chat_messages is None:
                chat_messages = []
            chat_messages.append(msg)
            empty_token_count += sub_empty
            if sub_tools:
                if tool_definitions is None:
                    tool_definitions = []
                tool_definitions.extend(sub_tools)
            return

        if isinstance(nodes_inner, Empty):
            empty_token_count += nodes_inner.token_count
            return

        if isinstance(nodes_inner, Isolate):
            if nodes_inner._cached_output is not None:
                text, empty, chats, tools = nodes_inner._cached_output
                if text:
                    text_parts.append(text)
                empty_token_count += empty
                if chats:
                    if chat_messages is None:
                        chat_messages = []
                    chat_messages.extend(chats)
                if tools:
                    if tool_definitions is None:
                        tool_definitions = []
                    tool_definitions.extend(tools)
            return

        if isinstance(nodes_inner, ToolDefinition):
            if tool_definitions is None:
                tool_definitions = []
            tool_definitions.append(nodes_inner)
            return

        if isinstance(nodes_inner, ChainOfThought):
            parts = ["<hypothesis>", nodes_inner.content or "[Insert hypothesis here]"]
            if nodes_inner.force_verification:
                parts.append("</hypothesis>\n\n<verification>\n[Walk through evidence step by step]")
            else:
                parts.append("</hypothesis>\n\n<verification>")
                if nodes_inner.content:
                    parts.append(nodes_inner.content)
            if nodes_inner.force_conclusion:
                parts.append("</verification>\n\n<conclusion>\n[State conclusion and implications]")
            else:
                parts.append("</verification>\n\n<conclusion>")
            parts.append("</conclusion>")
            text_parts.append("\n\n".join(parts))
            return

        if isinstance(nodes_inner, AdaptiveThinking):
            profile_info = ADAPTIVE_THINKING_PROFILES.get(nodes_inner.profile, ADAPTIVE_THINKING_PROFILES[ThinkingProfile.DEFAULT])
            if nodes_inner.enable_thinking is False:
                think_tags = "<think>\n\n</think>\n\n"
            elif nodes_inner.enable_thinking is True:
                think_tags = "<think>"
            else:
                think_tags = "<think>\n\n</think>\n\n" if nodes_inner.profile == ThinkingProfile.FORCE_OFF else "<think>"
            thinking_rule = "Reasoning is optional — use it when the task requires it." if nodes_inner.enable_thinking is None else ""
            rendered = ADAPTIVE_THINKING_PROMPT_TEMPLATE.format(
                profile_instruction=profile_info["instruction"],
                profile_hint=profile_info["hint"],
                thinking_rule=thinking_rule,
            )
            if nodes_inner.content:
                rendered += f"\n\nContext: {nodes_inner.content}"
            text_parts.append(rendered)
            text_parts.append(think_tags)
            return

        if isinstance(nodes_inner, First):
            for child in nodes_inner.children:
                if isinstance(child, Scope):
                    p = child.absolute_priority if child.absolute_priority is not None else level
                    if p >= level:
                        _render_inner(child.children)
                        return
            return

        if isinstance(nodes_inner, Scope):
            p = nodes_inner.absolute_priority if nodes_inner.absolute_priority is not None else level
            if p >= level:
                _render_inner(nodes_inner.children)
            return

    _render_inner(nodes)

    text = "".join(text_parts) if text_parts else None
    return text, empty_token_count, chat_messages, tool_definitions


def _count_tokens_approx(text: Optional[str], tokenizer: Optional[Any]) -> int:
    """Count tokens in text, using tokenizer if available."""
    if not text:
        return 0
    return count_text_tokens(text, tokenizer)


def render(
    nodes: Any,
    token_limit: int = 4096,
    tokenizer: Optional[Any] = None,
) -> Tuple[Optional[str], int, Optional[List[ChatMessage]], Optional[List[ToolDefinition]]]:
    """Render prompt with priority-based token budget fitting.
    
    Uses binary search (like Priompt's renderBinarySearch) to find the
    priority cutoff that produces the most content within token_limit.
    
    Returns (text, tokens_reserved, chat_messages, tool_definitions).
    """
    # Collect all priority levels
    priority_levels: set = set()
    compute_priority_levels(nodes, BASE_PRIORITY, priority_levels)
    priority_levels.add(BASE_PRIORITY)
    sorted_levels = sorted(priority_levels)  # lowest to highest

    # Hydrate isolates
    _hydrate_isolates(nodes, tokenizer)

    if not sorted_levels:
        return "", 0, None, None

    # Binary search on priority levels
    exclusive_lower = -1
    inclusive_upper = len(sorted_levels) - 1

    best_text = None
    best_empty = 0
    best_chats = None
    best_tools = None

    while exclusive_lower < inclusive_upper - 1:
        mid_idx = (exclusive_lower + inclusive_upper) // 2
        mid_level = sorted_levels[mid_idx]

        text, empty, chats, tools = _render_with_level(nodes, mid_level, tokenizer)
        token_count = _count_tokens_approx(text, tokenizer)

        if token_count + empty > token_limit:
            exclusive_lower = mid_idx
        else:
            inclusive_upper = mid_idx
            best_text = text
            best_empty = empty
            best_chats = chats
            best_tools = tools

    # Final render with the chosen cutoff
    final_text, final_empty, final_chats, final_tools = _render_with_level(
        nodes, sorted_levels[inclusive_upper], tokenizer
    )

    # If even the highest priority (most restrictive) doesn't fit, 
    # render at the highest level anyway
    if final_text is None:
        final_text, final_empty, final_chats, final_tools = _render_with_level(
            nodes, sorted_levels[-1], tokenizer
        )

    return final_text or "", final_empty, final_chats, final_tools


# ── Render Result ───────────────────────────────────────────────────────────


@dataclass
class RenderResult:
    """Result of rendering a priority prompt."""
    text: str = ""
    tokens_reserved: int = 0
    token_count: int = 0
    token_limit: int = 4096
    chat_messages: Optional[List[ChatMessage]] = None
    tool_definitions: Optional[List[ToolDefinition]] = None
    priority_cutoff: int = BASE_PRIORITY

    @property
    def total_tokens(self) -> int:
        return self.token_count + self.tokens_reserved


# ── High-Level Builder / Renderer ───────────────────────────────────────────


class PromptBuilder:
    """High-level builder for priority-based prompts.
    
    Usage:
        result = PromptBuilder(token_limit=8000).render(
            [
                Scope(priority=0,
                    Text("Core instructions")
                ),
                Scope(priority=-1000, name="context",
                    Text("Optional context")
                ),
            ],
            tokenizer=tokenizer
        )
        system_prompt = result.text
    """

    def __init__(self, token_limit: int = 4096):
        self.token_limit = token_limit

    def render(
        self,
        tree: Any,
        tokenizer: Optional[Any] = None,
    ) -> RenderResult:
        """Render a prompt tree with priority-based token fitting."""
        text, empty, chats, tools = render(
            tree,
            token_limit=self.token_limit,
            tokenizer=tokenizer,
        )
        token_count = _count_tokens_approx(text, tokenizer)

        return RenderResult(
            text=text or "",
            tokens_reserved=empty,
            token_count=token_count,
            token_limit=self.token_limit,
            chat_messages=chats,
            tool_definitions=tools,
        )


# ── Convenience Constructors ────────────────────────────────────────────────


def system_message(content: str, name: Optional[str] = None) -> ChatMessage:
    return ChatMessage(role="system", content=content, name=name)


def user_message(content: str, name: Optional[str] = None) -> ChatMessage:
    return ChatMessage(role="user", content=content, name=name)


def assistant_message(content: str, tool_calls: Optional[List[Dict]] = None) -> ChatMessage:
    return ChatMessage(role="assistant", content=content, tool_calls=tool_calls)


def tool_result(content: str, name: str) -> ChatMessage:
    return ChatMessage(role="tool", content=content, name=name)


def adaptive_thinking_block(
    enable_thinking: Optional[bool] = None,
    profile: ThinkingProfile = ThinkingProfile.DEFAULT,
    content: str = "",
) -> AdaptiveThinking:
    """Create a Nex-N2-style Adaptive Thinking block.

    Controls reasoning depth dynamically per step.
    - enable_thinking=None: model autonomously decides whether to fill <think>
    - enable_thinking=True: always emit <think> tags with reasoning
    - enable_thinking=False: emit empty <think></think> (no reasoning)

    Profiles concentrate reasoning where it matters most for the task.
    """
    return AdaptiveThinking(
        enable_thinking=enable_thinking,
        profile=profile,
        content=content,
    )


def cot_block(
    content: str = "",
    force_verification: bool = True,
    force_conclusion: bool = True,
) -> ChainOfThought:
    """Create a Qwythos-style structured chain-of-thought block.
    
    Forces the model to produce reasoning in hypothesis→verification→conclusion format.
    """
    return ChainOfThought(
        content=content,
        force_verification=force_verification,
        force_conclusion=force_conclusion,
    )


import json
