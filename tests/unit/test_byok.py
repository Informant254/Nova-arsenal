"""Tests for bring-your-own-key LLM configuration."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch):
    for k in list(os.environ.keys()):
        if any(
            k.startswith(p)
            for p in (
                "OPENAI",
                "ANTHROPIC",
                "GOOGLE",
                "GEMINI",
                "OPENROUTER",
                "DEEPSEEK",
                "DASHSCOPE",
                "QWEN",
                "HUGGINGFACE",
                "HF_",
                "OPCODE",
                "OPENCODE",
                "LLM_",
                "NOVA_LLM",
                "NOVA_CONFIG",
            )
        ):
            monkeypatch.delenv(k, raising=False)
    # Reset singletons
    import nova_arsenal.config as cfg
    import nova_arsenal.llm.router as router_mod

    cfg._config = None
    router_mod._router = None
    yield
    cfg._config = None
    router_mod._router = None


class TestKeysHelpers:
    def test_resolve_openai_key(self, monkeypatch):
        from nova_arsenal.llm.keys import resolve_api_key, resolve_model

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-12345678")
        assert resolve_api_key("openai") == "sk-test-12345678"
        assert resolve_api_key("openai", "explicit") == "explicit"
        assert resolve_model("openai") == "gpt-4o"

    def test_gemini_alias_env(self, monkeypatch):
        from nova_arsenal.llm.keys import normalize_provider, resolve_api_key

        monkeypatch.setenv("GEMINI_API_KEY", "gem-key")
        assert resolve_api_key("gemini") == "gem-key"
        # "google" is an accepted alias for gemini
        assert normalize_provider("google") == "gemini"
        assert resolve_api_key("google") == "gem-key"

    def test_preferred_provider(self, monkeypatch):
        from nova_arsenal.llm.keys import preferred_provider_from_env

        monkeypatch.setenv("OPENAI_API_KEY", "sk-aaa")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-bbb")
        # Without LLM_PROVIDER, prefers openai first
        assert preferred_provider_from_env() == "openai"
        monkeypatch.setenv("LLM_PROVIDER", "anthropic")
        assert preferred_provider_from_env() == "anthropic"
        monkeypatch.setenv("LLM_PROVIDER", "claude")
        assert preferred_provider_from_env() == "anthropic"

    def test_placeholder_ignored(self, monkeypatch):
        from nova_arsenal.llm.keys import resolve_api_key

        monkeypatch.setenv("OPENAI_API_KEY", "${OPENAI_API_KEY}")
        assert resolve_api_key("openai") == ""


class TestConfigByok:
    def test_auto_primary_from_openai_key(self, monkeypatch):
        from nova_arsenal.config import load_config

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-openai-key")
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        monkeypatch.setenv("LLM_MODEL", "gpt-4o-mini")
        cfg = load_config(config_path="/nonexistent/settings.yaml")
        assert cfg.llm.primary.provider == "openai"
        assert cfg.llm.primary.model == "gpt-4o-mini"
        assert cfg.llm.primary.api_key == "sk-test-openai-key"

    def test_multiple_keys_become_fallbacks(self, monkeypatch):
        from nova_arsenal.config import load_config

        monkeypatch.setenv("OPENAI_API_KEY", "sk-oai")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or")
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        cfg = load_config(config_path="/nonexistent/x.yaml")
        providers = {cfg.llm.primary.provider} | {f.provider for f in cfg.llm.fallbacks}
        assert "openai" in providers
        assert "anthropic" in providers
        assert "openrouter" in providers

    def test_router_registers_env_keys(self, monkeypatch):
        from nova_arsenal.config import reload_config
        from nova_arsenal.llm.router import get_llm_router, reset_llm_router

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-live")
        monkeypatch.setenv("LLM_PROVIDER", "anthropic")
        reload_config(config_path="/nonexistent/x.yaml")
        reset_llm_router()
        r = get_llm_router()
        names = [p.name for p in r.providers]
        assert "anthropic" in names
        status = r.byok_status()
        assert status["primary"]["provider"] == "anthropic"
        assert status["primary"]["has_key"] is True
        assert "anthropic" in status["env_keys_detected"]
        # Never leak full key
        catalog = {p["provider"]: p for p in status["provider_catalog"]}
        assert "sk-ant-live" not in str(status)
