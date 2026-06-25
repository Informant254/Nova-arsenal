"""
Unit tests for multi-provider routing system.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestTaskClassifier:
    """Test task classification."""

    def test_classify_code_generation(self):
        from nova_arsenal.llm.multi_router import classify_task, TaskCategory
        result = classify_task("write a python function to parse JSON")
        assert result == TaskCategory.CODE_GENERATION

    def test_classify_security(self):
        from nova_arsenal.llm.multi_router import classify_task, TaskCategory
        result = classify_task("scan for SQL injection vulnerabilities")
        assert result == TaskCategory.SECURITY_ANALYSIS

    def test_classify_reasoning(self):
        from nova_arsenal.llm.multi_router import classify_task, TaskCategory
        result = classify_task("analyze the logical argument and prove it wrong")
        assert result == TaskCategory.REASONING

    def test_classify_creative(self):
        from nova_arsenal.llm.multi_router import classify_task, TaskCategory
        result = classify_task("write a creative story about a hacker")
        assert result == TaskCategory.CREATIVE

    def test_classify_translation(self):
        from nova_arsenal.llm.multi_router import classify_task, TaskCategory
        result = classify_task("translate this document to Japanese")
        assert result == TaskCategory.TRANSLATION

    def test_classify_analysis(self):
        from nova_arsenal.llm.multi_router import classify_task, TaskCategory
        result = classify_task("analyze the network traffic data for anomalies")
        assert result == TaskCategory.ANALYSIS

    def test_classify_planning(self):
        from nova_arsenal.llm.multi_router import classify_task, TaskCategory
        result = classify_task("create an architecture plan for the microservices")
        assert result == TaskCategory.PLANNING

    def test_classify_conversation(self):
        from nova_arsenal.llm.multi_router import classify_task, TaskCategory
        result = classify_task("what is the meaning of life")
        assert result == TaskCategory.CONVERSATION

    def test_classify_unknown(self):
        from nova_arsenal.llm.multi_router import classify_task, TaskCategory
        result = classify_task("asdfghjkl")
        assert result == TaskCategory.UNKNOWN


class TestMultiProviderRouter:
    """Test MultiProviderRouter."""

    def test_initialization(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter
        router = MultiProviderRouter()
        assert router is not None

    def test_route_code_task(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter, TaskCategory

        router = MultiProviderRouter()
        decision = router.route("write a Python web scraper")
        assert decision.category == TaskCategory.CODE_GENERATION
        # No providers registered, so confidence is 0
        assert decision.confidence >= 0

    def test_route_security_task(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter, TaskCategory

        router = MultiProviderRouter()
        decision = router.route("find SQL injection vulnerabilities in this endpoint")
        assert decision.category == TaskCategory.SECURITY_ANALYSIS

    def test_route_with_preference(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter

        router = MultiProviderRouter()
        decision_quality = router.route("write code", preference="quality")
        decision_cost = router.route("write code", preference="cost")
        # Both should return a valid decision
        assert decision_quality.provider
        assert decision_cost.provider

    def test_route_excludes_providers(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter

        router = MultiProviderRouter()
        decision = router.route("write code", exclude=["nonexistent"])
        assert decision.provider

    def test_classify_method(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter, TaskCategory

        router = MultiProviderRouter()
        category = router.classify("analyze the vulnerability scan results")
        assert category == TaskCategory.SECURITY_ANALYSIS

    def test_stats(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter

        router = MultiProviderRouter()
        router.route("write code")
        stats = router.get_stats()
        assert "total_routes" in stats
        assert stats["total_routes"] == 1

    def test_provider_profiles_exist(self):
        from nova_arsenal.llm.multi_router import PROVIDER_PROFILES

        names = [p.name for p in PROVIDER_PROFILES]
        assert "anthropic" in names
        assert "openai" in names
        assert "gemini" in names
        assert "deepseek" in names
        assert "qwen" in names
        assert "openrouter" in names
        assert "huggingface" in names
        assert "ollama" in names


class TestProviderProfiles:
    """Test provider profile data."""

    def test_anthropic_profile(self):
        from nova_arsenal.llm.multi_router import PROVIDER_PROFILES
        anthropic = [p for p in PROVIDER_PROFILES if p.name == "anthropic"][0]
        assert "claude-sonnet-4-20250514" in anthropic.models
        assert anthropic.supports_tools is True

    def test_deepseek_profile(self):
        from nova_arsenal.llm.multi_router import PROVIDER_PROFILES
        deepseek = [p for p in PROVIDER_PROFILES if p.name == "deepseek"][0]
        assert deepseek.cost_per_1k_input < 0.001

    def test_ollama_profile(self):
        from nova_arsenal.llm.multi_router import PROVIDER_PROFILES
        ollama = [p for p in PROVIDER_PROFILES if p.name == "ollama"][0]
        assert ollama.cost_per_1k_input == 0.0
        assert ollama.cost_per_1k_output == 0.0
