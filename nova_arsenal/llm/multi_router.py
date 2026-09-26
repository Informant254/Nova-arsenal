"""
Multi-Provider Router - Sakana Fugu-style orchestration for Nova.

Classifies tasks and dynamically routes to the best provider.
Supports: OpenAI, Anthropic, Gemini, Ollama, OpenRouter, HuggingFace, Qwen, DeepSeek
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

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
    """Stable provider capabilities used for cold-start routing.

    Model IDs, prices, context windows, and latency are intentionally not stored
    here because they change frequently and may differ per configured model.
    Runtime routing always uses the actual registered provider.model and learns
    reliability/latency from observed calls.
    """

    name: str
    strengths: list[TaskCategory]
    supports_tools: bool = False
    local: bool = False


@dataclass
class RoutingDecision:
    """Decision made by the router."""
    provider: str
    model: str
    category: TaskCategory
    confidence: float
    reason: str
    fallback_chain: list[dict[str, str]] = field(default_factory=list)


# ── Provider Registry ──────────────────────────────────────────────────────

PROVIDER_PROFILES: list[ProviderProfile] = [
    ProviderProfile(
        name="anthropic",
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.CODE_REVIEW,
            TaskCategory.REASONING,
            TaskCategory.ANALYSIS,
            TaskCategory.PLANNING,
            TaskCategory.SUMMARIZATION,
        ],
        supports_tools=True,
    ),
    ProviderProfile(
        name="openai",
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.CODE_REVIEW,
            TaskCategory.REASONING,
            TaskCategory.ANALYSIS,
            TaskCategory.CONVERSATION,
            TaskCategory.SUMMARIZATION,
            TaskCategory.PLANNING,
        ],
        supports_tools=True,
    ),
    ProviderProfile(
        name="gemini",
        strengths=[
            TaskCategory.ANALYSIS,
            TaskCategory.RESEARCH,
            TaskCategory.DATA_PROCESSING,
            TaskCategory.TRANSLATION,
            TaskCategory.SUMMARIZATION,
        ],
        supports_tools=True,
    ),
    ProviderProfile(
        name="deepseek",
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.CODE_REVIEW,
            TaskCategory.REASONING,
            TaskCategory.ANALYSIS,
        ],
        supports_tools=True,
    ),
    ProviderProfile(
        name="qwen",
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.CODE_REVIEW,
            TaskCategory.ANALYSIS,
            TaskCategory.TRANSLATION,
            TaskCategory.DATA_PROCESSING,
        ],
        supports_tools=True,
    ),
    ProviderProfile(
        name="openrouter",
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.REASONING,
            TaskCategory.ANALYSIS,
            TaskCategory.CREATIVE,
            TaskCategory.RESEARCH,
        ],
        supports_tools=True,
    ),
    ProviderProfile(
        name="huggingface",
        strengths=[
            TaskCategory.CODE_GENERATION,
            TaskCategory.ANALYSIS,
            TaskCategory.SUMMARIZATION,
        ],
    ),
    ProviderProfile(
        name="ollama",
        strengths=[
            TaskCategory.CONVERSATION,
            TaskCategory.CODE_GENERATION,
            TaskCategory.CODE_REVIEW,
            TaskCategory.SUMMARIZATION,
        ],
        local=True,
    ),
    ProviderProfile(
        name="local",
        strengths=[
            TaskCategory.CONVERSATION,
            TaskCategory.CODE_GENERATION,
            TaskCategory.CODE_REVIEW,
            TaskCategory.SUMMARIZATION,
        ],
        local=True,
    ),
    ProviderProfile(
        name="opencode",
        strengths=[
            TaskCategory.CONVERSATION,
            TaskCategory.CODE_GENERATION,
            TaskCategory.CODE_REVIEW,
            TaskCategory.REASONING,
            TaskCategory.ANALYSIS,
        ],
        supports_tools=True,
    ),
]


# ── Task Classifier ────────────────────────────────────────────────────────

TASK_KEYWORDS: dict[TaskCategory, list[str]] = {
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
    scores: dict[TaskCategory, int] = {cat: 0 for cat in TaskCategory}

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
        providers: dict[str, LLMProvider] | None = None,
        preference: str = "balanced",
    ):
        self._providers = providers or {}
        self._preference = preference
        self._provider_profiles: dict[str, ProviderProfile] = {
            p.name: p for p in PROVIDER_PROFILES
        }
        self._routing_history: list[RoutingDecision] = []
        self._provider_stats: dict[str, dict[str, float]] = {}

    def register_provider(self, name: str, provider: LLMProvider) -> None:
        """Register a provider instance."""
        self._providers[name] = provider
        logger.info(f"Registered provider: {name}")

    def get_provider(self, name: str) -> LLMProvider | None:
        """Get a registered provider by name."""
        return self._providers.get(name)

    def list_providers(self) -> list[str]:
        """List all registered providers."""
        return list(self._providers.keys())

    def classify(self, prompt: str) -> TaskCategory:
        """Classify a task."""
        return classify_task(prompt)

    def route(
        self,
        prompt: str,
        preference: str | None = None,
        exclude: list[str] | None = None,
    ) -> RoutingDecision:
        """Route to a registered provider using capabilities plus runtime telemetry.

        Static vendor price/latency/model tables age badly. Nova therefore uses
        stable task capabilities for cold start, the *actual configured model*
        from each provider instance, and observed success/latency once calls run.
        """
        pref = (preference or self._preference or "balanced").lower()
        if pref not in {"balanced", "quality", "speed", "cost"}:
            pref = "balanced"
        excluded = set(exclude or [])
        category = classify_task(prompt)

        candidates: list[dict[str, Any]] = []
        for name, provider in self._providers.items():
            if name in excluded:
                continue
            profile = self._provider_profiles.get(
                name,
                ProviderProfile(name=name, strengths=[]),
            )
            candidates.append(
                {
                    "name": name,
                    "model": provider.model,
                    "profile": profile,
                    "score": self._score_provider(name, profile, category, pref),
                }
            )

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

        candidates.sort(key=lambda item: item["score"], reverse=True)
        best = candidates[0]
        fallback_chain = [
            {"provider": item["name"], "model": item["model"]}
            for item in candidates[1:4]
        ]

        decision = RoutingDecision(
            provider=best["name"],
            model=best["model"],
            category=category,
            confidence=best["score"],
            reason=(
                f"Capability/runtime match for {category.value} "
                f"with {pref} preference"
            ),
            fallback_chain=fallback_chain,
        )
        self._routing_history.append(decision)
        return decision

    async def complete(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        preference: str | None = None,
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
                started = time.monotonic()
                result = await provider.complete(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    **kwargs,
                )
                self._record_success(
                    provider_name,
                    (time.monotonic() - started) * 1000,
                )
                logger.info(
                    f"Completed with {provider_name}/{provider.model} "
                    f"(category={decision.category.value}, confidence={decision.confidence:.2f})"
                )
                return result
            except Exception as e:
                elapsed_ms = (
                    (time.monotonic() - started) * 1000
                    if "started" in locals()
                    else 0.0
                )
                self._record_failure(provider_name, elapsed_ms)
                logger.warning(f"Provider {provider_name} failed: {e}")
                continue

        raise RuntimeError(
            f"All providers failed. Tried: {providers_tried}"
        )

    async def stream(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        preference: str | None = None,
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
                started = time.monotonic()
                async for chunk in provider.stream(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    **kwargs,
                ):
                    yield chunk
                self._record_success(
                    provider_name,
                    (time.monotonic() - started) * 1000,
                )
                return
            except Exception as e:
                elapsed_ms = (
                    (time.monotonic() - started) * 1000
                    if "started" in locals()
                    else 0.0
                )
                self._record_failure(provider_name, elapsed_ms)
                logger.warning(f"Provider {provider_name} stream failed: {e}")
                continue

        raise RuntimeError("All providers failed for streaming")

    def get_stats(self) -> dict[str, Any]:
        """Get routing statistics."""
        return {
            "total_routes": len(self._routing_history),
            "category_distribution": self._get_category_distribution(),
            "provider_stats": self._provider_stats,
            "registered_providers": self.list_providers(),
        }

    def get_routing_history(self) -> list[dict[str, Any]]:
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
        provider_name: str,
        profile: ProviderProfile,
        category: TaskCategory,
        preference: str,
    ) -> float:
        """Score with stable capabilities and observed runtime behavior."""
        score = 0.30

        if category in profile.strengths:
            score += 0.30
        elif category == TaskCategory.UNKNOWN:
            score += 0.05

        stats = self._provider_stats.get(provider_name, {})
        successes = stats.get("success", 0.0)
        failures = stats.get("failure", 0.0)
        attempts = successes + failures

        # Bayesian prior prevents a single request from dominating routing.
        reliability = (successes + 1.0) / (attempts + 2.0)
        score += 0.20 * reliability

        avg_latency = stats.get("avg_latency_ms", 0.0)
        if preference == "speed":
            if avg_latency > 0:
                score += max(0.0, 0.20 - min(avg_latency / 10000.0, 0.20))
            else:
                score += 0.10
        elif preference == "cost":
            # Cost is only treated as knowable when it is structurally local.
            # Cloud prices are model/account specific and must not be hardcoded.
            if profile.local:
                score += 0.20
        elif preference == "quality":
            # Reliability is measurable; vendor/model "quality" rankings are not.
            score += 0.10 * reliability
        else:  # balanced
            if profile.local:
                score += 0.05
            if avg_latency > 0:
                score += max(0.0, 0.10 - min(avg_latency / 20000.0, 0.10))

        if profile.supports_tools and category in (
            TaskCategory.CODE_GENERATION,
            TaskCategory.CODE_REVIEW,
            TaskCategory.PLANNING,
        ):
            score += 0.05

        return max(0.0, min(score, 1.0))

    def _record_success(self, provider_name: str, latency_ms: float = 0.0) -> None:
        stats = self._provider_stats.setdefault(
            provider_name,
            {"success": 0.0, "failure": 0.0, "latency_ms_total": 0.0, "avg_latency_ms": 0.0},
        )
        stats["success"] += 1.0
        self._record_latency(stats, latency_ms)

    def _record_failure(self, provider_name: str, latency_ms: float = 0.0) -> None:
        stats = self._provider_stats.setdefault(
            provider_name,
            {"success": 0.0, "failure": 0.0, "latency_ms_total": 0.0, "avg_latency_ms": 0.0},
        )
        stats["failure"] += 1.0
        self._record_latency(stats, latency_ms)

    @staticmethod
    def _record_latency(stats: dict[str, float], latency_ms: float) -> None:
        if latency_ms <= 0:
            return
        stats["latency_ms_total"] += latency_ms
        attempts = stats["success"] + stats["failure"]
        if attempts > 0:
            stats["avg_latency_ms"] = stats["latency_ms_total"] / attempts

    def _get_category_distribution(self) -> dict[str, int]:
        dist: dict[str, int] = {}
        for d in self._routing_history:
            cat = d.category.value
            dist[cat] = dist.get(cat, 0) + 1
        return dist
