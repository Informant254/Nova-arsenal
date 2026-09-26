"""Unit tests for multi-provider routing system."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class FakeProvider:
    """Minimal provider double for routing tests."""

    def __init__(self, name: str, model: str):
        self.name = name
        self.model = model

    async def complete(self, *args, **kwargs):
        return "ok"

    async def stream(self, *args, **kwargs):
        yield "ok"

    async def health_check(self):
        return True


class TestTaskClassifier:
    def test_classify_code_generation(self):
        from nova_arsenal.llm.multi_router import TaskCategory, classify_task

        assert (
            classify_task("write a python function to parse JSON") == TaskCategory.CODE_GENERATION
        )

    def test_classify_security(self):
        from nova_arsenal.llm.multi_router import TaskCategory, classify_task

        assert (
            classify_task("scan for SQL injection vulnerabilities")
            == TaskCategory.SECURITY_ANALYSIS
        )

    def test_classify_reasoning(self):
        from nova_arsenal.llm.multi_router import TaskCategory, classify_task

        assert (
            classify_task("analyze the logical argument and prove it wrong")
            == TaskCategory.REASONING
        )

    def test_classify_creative(self):
        from nova_arsenal.llm.multi_router import TaskCategory, classify_task

        assert classify_task("write a creative story about a hacker") == TaskCategory.CREATIVE

    def test_classify_translation(self):
        from nova_arsenal.llm.multi_router import TaskCategory, classify_task

        assert classify_task("translate this document to Japanese") == TaskCategory.TRANSLATION

    def test_classify_analysis(self):
        from nova_arsenal.llm.multi_router import TaskCategory, classify_task

        assert (
            classify_task("analyze the network traffic data for anomalies") == TaskCategory.ANALYSIS
        )

    def test_classify_planning(self):
        from nova_arsenal.llm.multi_router import TaskCategory, classify_task

        assert (
            classify_task("create an architecture plan for the microservices")
            == TaskCategory.PLANNING
        )

    def test_classify_conversation(self):
        from nova_arsenal.llm.multi_router import TaskCategory, classify_task

        assert classify_task("what is the meaning of life") == TaskCategory.CONVERSATION

    def test_classify_unknown(self):
        from nova_arsenal.llm.multi_router import TaskCategory, classify_task

        assert classify_task("asdfghjkl") == TaskCategory.UNKNOWN


class TestMultiProviderRouter:
    def test_initialization(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter

        assert MultiProviderRouter() is not None

    def test_route_without_providers(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter, TaskCategory

        decision = MultiProviderRouter().route("write a Python web scraper")
        assert decision.category == TaskCategory.CODE_GENERATION
        assert decision.provider == "none"
        assert decision.confidence == 0.0

    def test_route_uses_actual_configured_model(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter

        router = MultiProviderRouter(
            providers={"openai": FakeProvider("openai", "custom-model-id")}
        )
        decision = router.route("write code")
        assert decision.provider == "openai"
        assert decision.model == "custom-model-id"

    def test_cost_preference_favors_local_provider(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter

        router = MultiProviderRouter(
            providers={
                "openai": FakeProvider("openai", "cloud-model"),
                "ollama": FakeProvider("ollama", "local-model"),
            }
        )
        decision = router.route("write code", preference="cost")
        assert decision.provider == "ollama"
        assert decision.model == "local-model"

    def test_runtime_reliability_influences_quality_routing(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter

        router = MultiProviderRouter(
            providers={
                "openai": FakeProvider("openai", "model-a"),
                "deepseek": FakeProvider("deepseek", "model-b"),
            }
        )
        for _ in range(4):
            router._record_failure("openai", 100)
            router._record_success("deepseek", 100)

        decision = router.route("write code", preference="quality")
        assert decision.provider == "deepseek"

    def test_route_excludes_providers(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter

        router = MultiProviderRouter(
            providers={
                "openai": FakeProvider("openai", "cloud"),
                "ollama": FakeProvider("ollama", "local"),
            }
        )
        decision = router.route("write code", exclude=["openai"])
        assert decision.provider == "ollama"

    def test_classify_method(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter, TaskCategory

        category = MultiProviderRouter().classify("analyze the vulnerability scan results")
        assert category == TaskCategory.SECURITY_ANALYSIS

    def test_stats(self):
        from nova_arsenal.llm.multi_router import MultiProviderRouter

        router = MultiProviderRouter(providers={"openai": FakeProvider("openai", "model")})
        router.route("write code")
        stats = router.get_stats()
        assert stats["total_routes"] == 1
        assert stats["registered_providers"] == ["openai"]

    def test_provider_profiles_exist(self):
        from nova_arsenal.llm.multi_router import PROVIDER_PROFILES

        names = [profile.name for profile in PROVIDER_PROFILES]
        for expected in (
            "anthropic",
            "openai",
            "gemini",
            "deepseek",
            "qwen",
            "openrouter",
            "huggingface",
            "ollama",
            "local",
        ):
            assert expected in names


class TestProviderProfiles:
    def test_anthropic_tools_capability(self):
        from nova_arsenal.llm.multi_router import PROVIDER_PROFILES

        profile = next(p for p in PROVIDER_PROFILES if p.name == "anthropic")
        assert profile.supports_tools is True

    def test_local_profiles_are_marked_local(self):
        from nova_arsenal.llm.multi_router import PROVIDER_PROFILES

        ollama = next(p for p in PROVIDER_PROFILES if p.name == "ollama")
        local = next(p for p in PROVIDER_PROFILES if p.name == "local")
        assert ollama.local is True
        assert local.local is True

    def test_profiles_do_not_hardcode_model_catalogs(self):
        from nova_arsenal.llm.multi_router import PROVIDER_PROFILES

        assert all(not hasattr(profile, "models") for profile in PROVIDER_PROFILES)
