"""
Multi-Provider Router - Sakana Fugu-style orchestration for Nova.

Classifies tasks and dynamically routes to the best provider.
Supports: OpenAI, Anthropic, Gemini, Ollama, OpenRouter, HuggingFace, Qwen, DeepSeek
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Type

from nova_arsenal.llm.base import LLMProvider

logger = logging.getLogger(__name__)


class TaskCategory(Enum):
    """Categories of tasks for provider routing."""
    CODE_GENERATION = "code_generation"
    CODE_REVIEW = "code_review"
    SECURITY_ANALYSIS = "security_analysis"
    REASONING = "reasoning"
    ANALYSIS = "analysis"
    CREATIVE = "creative"
    TRANSLATION = "translation"
    SUMMARIZATION = "summarization"
    DATA_PROCESSING = "data_processing"
    CONVERSATION = "conversation"
    RESEARCH = "research"
    PLANNING = "planning"
    UNKNOWN = "unknown"


@dataclass
class ProviderProfile:
    """Profile of a provider's strengths."""
    name: str
    models: List[str]
    strengths: List[TaskCategory]
    cost_per_1k_input: float
    cost_per_1k_output: float
    latency_ms: int
    max_context: int
    supports_streaming: bool = True
    supports_tools: bool = False


@dataclass
class RoutingDecision:
    """Decision made by the router."""
    provider: str
    model: str
    category: TaskCategory
    confidence: float
    reason: str
    fallback_chain: List[Dict[str, str]] = field(default_factory=list)


# ── Provider Registry ──────────────────────────────────────────────────────

PROVIDER_PROFILES: List[ProviderProfile] = [
    ProviderProfile(
        name="anthropic",
        models=["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-3-5-haiku-20241022"],
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.CODE_REVIEW,
            TaskCategory.REASONING,
            TaskCategory.ANALYSIS,
            TaskCategory.PLANNING,
        ],
        cost_per_1k_input=0.003,
        cost_per_1k_output=0.015,
        latency_ms=800,
        max_context=200000,
        supports_tools=True,
    ),
    ProviderProfile(
        name="openai",
        models=["gpt-4o", "gpt-4o-mini", "o3", "o4-mini"],
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.CREATIVE,
            TaskCategory.CONVERSATION,
            TaskCategory.SUMMARIZATION,
        ],
        cost_per_1k_input=0.0025,
        cost_per_1k_output=0.01,
        latency_ms=600,
        max_context=128000,
        supports_tools=True,
    ),
    ProviderProfile(
        name="gemini",
        models=["gemini-2.5-flash", "gemini-2.5-pro"],
        strengths=[
            TaskCategory.ANALYSIS,
            TaskCategory.RESEARCH,
            TaskCategory.DATA_PROCESSING,
            TaskCategory.TRANSLATION,
        ],
        cost_per_1k_input=0.00075,
        cost_per_1k_output=0.003,
        latency_ms=500,
        max_context=1000000,
        supports_tools=True,
    ),
    ProviderProfile(
        name="deepseek",
        models=["deepseek-chat", "deepseek-reasoner"],
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.REASONING,
            TaskCategory.SECURITY_ANALYSIS,
        ],
        cost_per_1k_input=0.00014,
        cost_per_1k_output=0.00028,
        latency_ms=700,
        max_context=64000,
        supports_tools=True,
    ),
    ProviderProfile(
        name="qwen",
        models=["qwen-max", "qwen-plus", "qwen-turbo", "qwen-long"],
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.ANALYSIS,
            TaskCategory.TRANSLATION,
            TaskCategory.DATA_PROCESSING,
        ],
        cost_per_1k_input=0.0004,
        cost_per_1k_output=0.0012,
        latency_ms=600,
        max_context=131072,
        supports_tools=True,
    ),
    ProviderProfile(
        name="openrouter",
        models=["anthropic/claude-sonnet-4", "openai/gpt-4o", "google/gemini-2.5-flash"],
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.REASONING,
            TaskCategory.CREATIVE,
        ],
        cost_per_1k_input=0.003,
        cost_per_1k_output=0.015,
        latency_ms=900,
        max_context=200000,
        supports_tools=True,
    ),
    ProviderProfile(
        name="huggingface",
        models=["meta-llama/Llama-3.3-70B-Instruct", "mistralai/Mistral-Large-Instruct-2411"],
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.ANALYSIS,
        ],
        cost_per_1k_input=0.0002,
        cost_per_1k_output=0.0002,
        latency_ms=1000,
        max_context=128000,
        supports_tools=False,
    ),
    ProviderProfile(
        name="ollama",
        models=["deepseek-r1", "llama3.3", "qwen2.5", "mistral"],
        strengths=[
            TaskCategory.CONVERSATION,
            TaskCategory.CODE_GENERATION,
        ],
        cost_per_1k_input=0.0,
        cost_per_1k_output=0.0,
        latency_ms=2000,
        max_context=32000,
        supports_tools=False,
    ),
    ProviderProfile(
        name="opencode",
        models=["opencode-qwen-72b"],
        strengths=[
            TaskCategory.CONVERSATION,
            TaskCategory.CODE_GENERATION,
            TaskCategory.REASONING,
            TaskCategory.ANALYSIS,
            TaskCategory.SECURITY_ANALYSIS,
            TaskCategory.CREATIVE,
        ],
        cost_per_1k_input=0.0,  # Free access
        cost_per_1k_output=0.0,  # Free access
        latency_ms=1500,
        max_context=128000,
        supports_tools=True,
    ),
]


# ── Task Classifier ────────────────────────────────────────────────────────

TASK_KEYWORDS: Dict[TaskCategory, List[str]] = {
    TaskCategory.CODE_GENERATION: [
        "write code", "implement", "function", "class", "script", "program",
        "create a", "build a", "generate code", "coding", "python", "javascript",
        "rust", "golang", "java", "c++", "html", "css", "bash",
        "algorithm", "data structure", "api endpoint", "webhook",
    ],
    TaskCategory.CODE_REVIEW: [
        "review code", "code review", "audit code", "check code", "lint",
        "refactor", "optimize code", "code quality", "best practice",
        "code smell", "technical debt", "code analysis",
    ],
    TaskCategory.SECURITY_ANALYSIS: [
        "vulnerability", "exploit", "penetration test", "security audit",
        "attack vector", "scan for vulnerability", "nmap", "sqlmap", "nuclei",
        "brute force", "xss", "sqli", "rce", "lfi", "ssrf", "csrf",
        "auth bypass", "privilege escalation", "reverse shell", "payload",
        "cve", "incident response", "forensics", "malware", "threat",
        "security scan", "pen test", "security assessment", "sql injection",
    ],
    TaskCategory.REASONING: [
        "reason", "think", "logic", "prove", "explain why",
        "deduce", "compare and contrast", "debate", "argument",
        "syllogism", "deduction", "induction", "inference", "logical",
    ],
    TaskCategory.ANALYSIS: [
        "analyze", "analysis", "examine", "investigate", "study",
        "assess", "evaluate", "review", "report", "summary",
        "data analysis", "trend", "pattern", "correlation",
        "network traffic", "anomalies",
    ],
    TaskCategory.CREATIVE: [
        "write", "story", "poem", "creative", "imagine", "fiction",
        "narrative", "essay", "article", "blog post", "content",
        "copywriting", "marketing", "slogan", "tagline",
    ],
    TaskCategory.TRANSLATION: [
        "translate", "translation", "localize", "internationalization",
        "i18n", "localization", "language", "multilingual",
    ],
    TaskCategory.SUMMARIZATION: [
        "summarize", "summary", "tldr", "brief", "overview",
        "condense", "abstract", "executive summary",
    ],
    TaskCategory.DATA_PROCESSING: [
        "parse", "extract", "transform", "ETL", "pipeline",
        "data processing", "csv", "json", "xml", "scrape",
        "web scraping", "data cleaning", "data wrangling",
    ],
    TaskCategory.CONVERSATION: [
        "chat", "talk", "discuss", "conversation", "ask",
        "question", "help me", "what is", "how to", "explain",
    ],
    TaskCategory.RESEARCH: [
        "research", "find", "search", "discover", "investigate",
        "literature review", "survey", "state of the art", "benchmark",
    ],
    TaskCategory.PLANNING: [
        "plan", "strategy", "roadmap", "architecture", "design",
        "blueprint", "workflow", "pipeline", "process", "methodology",
    ],
}


def classify_task(prompt: str) -> TaskCategory:
    """Classify a prompt into a task category."""
    prompt_lower = prompt.lower()
    scores: Dict[TaskCategory, int] = {cat: 0 for cat in TaskCategory}

    for category, keywords in TASK_KEYWORDS.items():
        for keyword in keywords:
            if keyword in prompt_lower:
                scores[category] += 1

    best_category = max(scores, key=lambda k: scores[k])
    if scores[best_category] == 0:
        return TaskCategory.UNKNOWN

    return best_category


# ── Multi-Provider Router ──────────────────────────────────────────────────

class MultiProviderRouter:
    """
    Sakana Fugu-style multi-provider orchestrator.
    
    Classifies tasks and routes to the best provider based on:
    - Task category (code, security, reasoning, etc.)
    - Provider strengths
    - Cost optimization
    - Latency requirements
    - Available providers
    """

    def __init__(
        self,
        providers: Optional[Dict[str, LLMProvider]] = None,
        preference: str = "balanced",
    ):
        self._providers = providers or {}
        self._preference = preference
        self._provider_profiles: Dict[str, ProviderProfile] = {
            p.name: p for p in PROVIDER_PROFILES
        }
        self._routing_history: List[RoutingDecision] = []
        self._provider_stats: Dict[str, Dict[str, int]] = {}

    def register_provider(self, name: str, provider: LLMProvider) -> None:
        """Register a provider instance."""
        self._providers[name] = provider
        logger.info(f"Registered provider: {name}")

    def get_provider(self, name: str) -> Optional[LLMProvider]:
        """Get a registered provider by name."""
        return self._providers.get(name)

    def list_providers(self) -> List[str]:
        """List all registered providers."""
        return list(self._providers.keys())

    def classify(self, prompt: str) -> TaskCategory:
        """Classify a task."""
        return classify_task(prompt)

    def route(
        self,
        prompt: str,
        preference: Optional[str] = None,
        exclude: Optional[List[str]] = None,
    ) -> RoutingDecision:
        """
        Route a task to the best provider.
        
        Preferences:
        - "balanced": best quality/cost ratio
        - "quality": highest quality regardless of cost
        - "speed": lowest latency
        - "cost": cheapest option
        """
        pref = preference or self._preference
        exclude = exclude or []
        category = classify_task(prompt)

        # Find available providers with matching strengths
        candidates: List[Dict[str, Any]] = []

        for name, profile in self._provider_profiles.items():
            if name in exclude:
                continue
            if name not in self._providers:
                continue

            score = self._score_provider(profile, category, pref)
            candidates.append({
                "name": name,
                "model": profile.models[0],
                "profile": profile,
                "score": score,
            })

        if not candidates:
            # Fallback to any available provider
            for name, provider in self._providers.items():
                if name not in exclude:
                    profile = self._provider_profiles.get(name)
                    candidates.append({
                        "name": name,
                        "model": profile.models[0] if profile else provider.model,
                        "profile": profile,
                        "score": 0.5,
                    })

        if not candidates:
            decision = RoutingDecision(
                provider="none",
                model="",
                category=category,
                confidence=0.0,
                reason="No providers available",
            )
            self._routing_history.append(decision)
            return decision

        # Sort by score
        candidates.sort(key=lambda c: c["score"], reverse=True)
        best = candidates[0]

        # Build fallback chain
        fallback_chain = []
        for c in candidates[1:4]:
            fallback_chain.append({
                "provider": c["name"],
                "model": c["model"],
            })

        decision = RoutingDecision(
            provider=best["name"],
            model=best["model"],
            category=category,
            confidence=best["score"],
            reason=f"Best match for {category.value} with {pref} preference",
            fallback_chain=fallback_chain,
        )

        self._routing_history.append(decision)
        return decision

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        preference: Optional[str] = None,
        **kwargs,
    ) -> str:
        """
        Complete a prompt using the best provider with automatic fallback.
        """
        decision = self.route(prompt, preference)
        providers_tried = []

        # Try primary provider
        providers_to_try = [decision.provider] + [f["provider"] for f in decision.fallback_chain]

        for provider_name in providers_to_try:
            provider = self._providers.get(provider_name)
            if not provider:
                continue

            providers_tried.append(provider_name)
            try:
                result = await provider.complete(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    **kwargs,
                )
                self._record_success(provider_name)
                logger.info(
                    f"Completed with {provider_name}/{provider.model} "
                    f"(category={decision.category.value}, confidence={decision.confidence:.2f})"
                )
                return result
            except Exception as e:
                self._record_failure(provider_name)
                logger.warning(f"Provider {provider_name} failed: {e}")
                continue

        raise RuntimeError(
            f"All providers failed. Tried: {providers_tried}"
        )

    async def stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        preference: Optional[str] = None,
        **kwargs,
    ):
        """Stream using the best provider with automatic fallback."""
        decision = self.route(prompt, preference)
        providers_to_try = [decision.provider] + [f["provider"] for f in decision.fallback_chain]

        for provider_name in providers_to_try:
            provider = self._providers.get(provider_name)
            if not provider:
                continue

            try:
                async for chunk in provider.stream(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    **kwargs,
                ):
                    yield chunk
                return
            except Exception as e:
                logger.warning(f"Provider {provider_name} stream failed: {e}")
                continue

        raise RuntimeError("All providers failed for streaming")

    def get_stats(self) -> Dict[str, Any]:
        """Get routing statistics."""
        return {
            "total_routes": len(self._routing_history),
            "category_distribution": self._get_category_distribution(),
            "provider_stats": self._provider_stats,
            "registered_providers": self.list_providers(),
        }

    def get_routing_history(self) -> List[Dict[str, Any]]:
        """Get the routing history."""
        return [
            {
                "provider": d.provider,
                "model": d.model,
                "category": d.category.value,
                "confidence": d.confidence,
                "reason": d.reason,
            }
            for d in self._routing_history
        ]

    # ── Private Methods ─────────────────────────────────────────────────────

    def _score_provider(
        self,
        profile: ProviderProfile,
        category: TaskCategory,
        preference: str,
    ) -> float:
        """Score a provider for a given task category and preference."""
        score = 0.0

        # Base score: strength match
        if category in profile.strengths:
            score += 0.5
        elif category != TaskCategory.UNKNOWN:
            score += 0.1

        # Preference modifiers
        if preference == "quality":
            # Prefer expensive, high-quality models
            if profile.cost_per_1k_output > 0.01:
                score += 0.3
            if profile.max_context >= 128000:
                score += 0.1
        elif preference == "speed":
            # Prefer low latency
            if profile.latency_ms < 600:
                score += 0.3
            elif profile.latency_ms < 1000:
                score += 0.1
        elif preference == "cost":
            # Prefer cheap providers
            if profile.cost_per_1k_input < 0.001:
                score += 0.3
            if profile.cost_per_1k_output < 0.001:
                score += 0.1
        else:  # balanced
            # Balanced scoring
            quality_score = min(profile.cost_per_1k_output * 10, 0.3)
            speed_score = max(0, 0.3 - (profile.latency_ms / 5000))
            score += quality_score + speed_score

        # Bonus for tool support
        if profile.supports_tools and category in (
            TaskCategory.CODE_GENERATION,
            TaskCategory.SECURITY_ANALYSIS,
            TaskCategory.PLANNING,
        ):
            score += 0.1

        return min(score, 1.0)

    def _record_success(self, provider_name: str) -> None:
        if provider_name not in self._provider_stats:
            self._provider_stats[provider_name] = {"success": 0, "failure": 0}
        self._provider_stats[provider_name]["success"] += 1

    def _record_failure(self, provider_name: str) -> None:
        if provider_name not in self._provider_stats:
            self._provider_stats[provider_name] = {"success": 0, "failure": 0}
        self._provider_stats[provider_name]["failure"] += 1

    def _get_category_distribution(self) -> Dict[str, int]:
        dist: Dict[str, int] = {}
        for d in self._routing_history:
            cat = d.category.value
            dist[cat] = dist.get(cat, 0) + 1
        return dist
