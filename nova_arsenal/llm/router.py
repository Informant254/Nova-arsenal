"""
Nova-Arsenal LLM Router

Multi-provider routing with fallback support + Fugu-style orchestration.
Bring-your-own-key: providers are registered from settings.yaml and from
environment API keys (OpenAI, Anthropic, Gemini, OpenRouter, …).
"""

from __future__ import annotations

import logging
from typing import Optional

from nova_arsenal.config import get_config
from nova_arsenal.llm.base import LLMProvider
from nova_arsenal.llm.keys import (
    PROVIDER_SPECS,
    env_providers_with_keys,
    normalize_provider,
    provider_status_snapshot,
    resolve_api_key,
    resolve_model,
    resolve_url,
)
from nova_arsenal.llm.ollama import OllamaProvider
from nova_arsenal.llm.openai import OpenAIProvider
from nova_arsenal.llm.anthropic import AnthropicProvider
from nova_arsenal.llm.gemini import GeminiProvider
from nova_arsenal.llm.openrouter import OpenRouterProvider
from nova_arsenal.llm.huggingface import HuggingFaceProvider
from nova_arsenal.llm.qwen import QwenProvider
from nova_arsenal.llm.deepseek import DeepSeekProvider
from nova_arsenal.llm.opencode import OpencodeProvider
from nova_arsenal.llm.multi_router import MultiProviderRouter

logger = logging.getLogger(__name__)

PROVIDER_CLASSES = {
    "ollama": OllamaProvider,
    "local": OpenAIProvider,  # OpenAI-compatible local servers (LM Studio, vLLM, …)
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "gemini": GeminiProvider,
    "openrouter": OpenRouterProvider,
    "huggingface": HuggingFaceProvider,
    "qwen": QwenProvider,
    "deepseek": DeepSeekProvider,
    "opencode": OpencodeProvider,
}


class LLMRouter:
    """Multi-provider LLM router with fallback and Fugu-style orchestration."""

    def __init__(self):
        self.providers: list[LLMProvider] = []
        self._multi_router: Optional[MultiProviderRouter] = None
        self._setup_providers()

    def _setup_providers(self):
        """Setup providers from configuration + env keys."""
        config = get_config()

        primary = config.llm.primary
        provider = self._create_provider(
            provider=primary.provider,
            model=primary.model,
            api_key=primary.api_key,
            url=primary.url,
            timeout=primary.timeout,
        )
        if provider:
            self.providers.append(provider)

        for fb in config.llm.fallbacks:
            provider = self._create_provider(
                provider=fb.provider,
                model=fb.model,
                api_key=fb.api_key,
                url=fb.url,
                timeout=fb.timeout,
            )
            if provider:
                # Avoid duplicate provider/model pairs
                if any(p.name == provider.name and p.model == provider.model for p in self.providers):
                    continue
                self.providers.append(provider)

        self._setup_multi_router(config)
        logger.info(
            "Initialized %d LLM providers: %s",
            len(self.providers),
            [f"{p.name}/{p.model}" for p in self.providers],
        )

    def _setup_multi_router(self, config) -> None:
        """Setup the Fugu-style multi-provider router."""
        self._multi_router = MultiProviderRouter()

        def _register(name: str, model: str, api_key: str, url: str) -> None:
            assert self._multi_router is not None
            if name in self._multi_router.list_providers():
                return
            try:
                p = self._create_provider(name, model, api_key, url)
                if p:
                    self._multi_router.register_provider(name, p)
            except Exception as e:  # noqa: BLE001
                logger.warning("Failed to register %s in multi-router: %s", name, e)

        primary = config.llm.primary
        _register(primary.provider, primary.model, primary.api_key, primary.url)

        for fb in config.llm.fallbacks:
            _register(fb.provider, fb.model, fb.api_key, fb.url)

        # Any remaining env keys (covers keys not listed in YAML)
        self._register_env_providers()

    def _register_env_providers(self) -> None:
        """Register every provider that has an API key in the environment."""
        if not self._multi_router:
            return

        for name in list(PROVIDER_SPECS.keys()):
            if name == "ollama":
                # Always allow local ollama as multi-router option
                if name not in self._multi_router.list_providers():
                    try:
                        p = OllamaProvider(
                            model=resolve_model("ollama"),
                            base_url=resolve_url("ollama"),
                        )
                        self._multi_router.register_provider("ollama", p)
                    except Exception as e:  # noqa: BLE001
                        logger.debug("Ollama not registered: %s", e)
                continue

            api_key = resolve_api_key(name)
            if not api_key:
                continue
            if name in self._multi_router.list_providers():
                continue
            try:
                p = self._create_provider(
                    provider=name,
                    model=resolve_model(name),
                    api_key=api_key,
                    url=resolve_url(name),
                )
                if p:
                    self._multi_router.register_provider(name, p)
                    # Also add to sequential list if missing
                    if not any(x.name == name for x in self.providers):
                        self.providers.append(p)
                    logger.info("Registered %s from environment API key", name)
            except Exception as e:  # noqa: BLE001
                logger.warning("Failed to register %s from env: %s", name, e)

    def _create_provider(
        self,
        provider: str,
        model: str,
        api_key: str = "",
        url: str = "",
        timeout: int = 120,
    ) -> Optional[LLMProvider]:
        """Create a provider instance, resolving keys from env when empty."""
        name = normalize_provider(provider)
        key = resolve_api_key(name, api_key)
        model = resolve_model(name, model)
        base = resolve_url(name, url)

        try:
            if name == "ollama":
                # Apply account-store local URL/model if present
                try:
                    from nova_arsenal.llm.account_auth import get_account_store

                    acc = get_account_store().get("ollama")
                    if acc and acc.meta:
                        base = acc.meta.get("base_url") or base
                        model = acc.meta.get("model") or model
                except Exception:  # noqa: BLE001
                    pass
                return OllamaProvider(model=model, base_url=base or "http://localhost:11434")
            if name == "local":
                # Local OpenAI-compatible — no key required
                try:
                    from nova_arsenal.llm.account_auth import get_account_store

                    acc = get_account_store().get("local") or get_account_store().get("ollama")
                    if acc and acc.meta:
                        base = acc.meta.get("base_url") or base
                        model = acc.meta.get("model") or model
                except Exception:  # noqa: BLE001
                    pass
                return OpenAIProvider(
                    model=model or "local-model",
                    api_key=key or "local",
                    base_url=base or "http://127.0.0.1:1234/v1",
                )
            if name not in PROVIDER_CLASSES:
                logger.warning("Unknown provider: %s", provider)
                return None
            if not key:
                logger.warning("%s API key not provided, skipping", name)
                return None

            cls = PROVIDER_CLASSES[name]
            kwargs: dict = {"model": model, "api_key": key}
            # Pass base_url when the constructor supports it
            if base:
                kwargs["base_url"] = base
            # ChatGPT subscription OAuth tokens still use OpenAI HTTP APIs
            if name == "openai":
                try:
                    from nova_arsenal.llm.account_auth import get_account_store

                    acc = get_account_store().get("openai")
                    if acc and (acc.meta or {}).get("subscription_auth"):
                        kwargs["api_key"] = acc.access_token or key
                except Exception:  # noqa: BLE001
                    pass
            return cls(**kwargs)
        except Exception as e:  # noqa: BLE001
            logger.error("Failed to create provider %s: %s", provider, e)
            return None

    @property
    def multi_router(self) -> Optional[MultiProviderRouter]:
        """Access the Fugu-style multi-provider router."""
        return self._multi_router

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        use_multi_router: bool = True,
        preference: Optional[str] = None,
        **kwargs,
    ) -> str:
        """Generate a completion with automatic fallback."""
        if use_multi_router and self._multi_router and len(self._multi_router.list_providers()) > 0:
            try:
                return await self._multi_router.complete(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    preference=preference,
                    **kwargs,
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("Multi-router failed, falling back to sequential: %s", e)

        last_error = None
        config = get_config()
        max_retries = config.llm.max_retries

        if not self.providers:
            raise RuntimeError(
                "No LLM providers configured. Set OPENAI_API_KEY / ANTHROPIC_API_KEY / "
                "GOOGLE_API_KEY / OPENROUTER_API_KEY (or run Ollama) and restart Nova. "
                "See config/.env.example"
            )

        for provider in self.providers:
            for attempt in range(max_retries):
                try:
                    logger.debug(
                        "Trying provider %s/%s (attempt %s/%s)",
                        provider.name,
                        provider.model,
                        attempt + 1,
                        max_retries,
                    )
                    result = await provider.complete(
                        prompt=prompt,
                        system_prompt=system_prompt,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        **kwargs,
                    )
                    logger.debug("Success with provider %s", provider.name)
                    return result
                except Exception as e:  # noqa: BLE001
                    last_error = e
                    logger.warning(
                        "Provider %s failed (attempt %s): %s",
                        provider.name,
                        attempt + 1,
                        e,
                    )
                    continue

        raise RuntimeError(f"All LLM providers failed. Last error: {last_error}")

    async def stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        use_multi_router: bool = True,
        preference: Optional[str] = None,
        **kwargs,
    ):
        """Stream a completion with automatic fallback."""
        if use_multi_router and self._multi_router and len(self._multi_router.list_providers()) > 0:
            try:
                async for chunk in self._multi_router.stream(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    preference=preference,
                    **kwargs,
                ):
                    yield chunk
                return
            except Exception as e:  # noqa: BLE001
                logger.warning("Multi-router stream failed, falling back: %s", e)

        last_error = None
        config = get_config()
        max_retries = config.llm.max_retries

        if not self.providers:
            raise RuntimeError(
                "No LLM providers configured. Set an API key or start Ollama. "
                "See config/.env.example"
            )

        for provider in self.providers:
            for attempt in range(max_retries):
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
                except Exception as e:  # noqa: BLE001
                    last_error = e
                    logger.warning(
                        "Provider %s stream failed (attempt %s): %s",
                        provider.name,
                        attempt + 1,
                        e,
                    )
                    continue

        raise RuntimeError(f"All LLM providers failed for streaming. Last error: {last_error}")

    async def health_check(self) -> dict[str, bool]:
        """Check health of all providers."""
        results: dict[str, bool] = {}
        for provider in self.providers:
            try:
                results[f"{provider.name}/{provider.model}"] = await provider.health_check()
            except Exception:  # noqa: BLE001
                results[f"{provider.name}/{provider.model}"] = False

        if self._multi_router:
            for name in self._multi_router.list_providers():
                provider = self._multi_router.get_provider(name)
                if provider:
                    try:
                        results[f"multi/{name}/{provider.model}"] = await provider.health_check()
                    except Exception:  # noqa: BLE001
                        results[f"multi/{name}/{provider.model}"] = False

        return results

    def list_providers(self) -> list[str]:
        """List all configured providers."""
        providers = [f"{p.name}/{p.model}" for p in self.providers]
        if self._multi_router:
            for name in self._multi_router.list_providers():
                if f"multi/{name}" not in providers:
                    providers.append(f"multi/{name}")
        return providers

    def get_routing_stats(self) -> dict:
        """Get multi-router statistics."""
        if self._multi_router:
            return self._multi_router.get_stats()
        return {"total_routes": 0, "registered_providers": []}

    def byok_status(self) -> dict:
        """Public, non-secret status of BYOK + account logins."""
        config = get_config()
        accounts: dict = {}
        try:
            from nova_arsenal.llm.account_auth import account_status

            accounts = account_status()
        except Exception:  # noqa: BLE001
            accounts = {"accounts": [], "how_to": {}}

        return {
            "primary": {
                "provider": config.llm.primary.provider,
                "model": config.llm.primary.model,
                "has_key": bool(config.llm.primary.api_key)
                or config.llm.primary.provider == "ollama",
            },
            "fallbacks": [
                {
                    "provider": f.provider,
                    "model": f.model,
                    "has_key": bool(f.api_key) or f.provider == "ollama",
                }
                for f in config.llm.fallbacks
            ],
            "active_providers": self.list_providers(),
            "env_keys_detected": env_providers_with_keys(),
            "provider_catalog": provider_status_snapshot(),
            "accounts": accounts,
            "how_to": {
                "chatgpt_subscription": "nova-agent login --provider openai --oauth",
                "chatgpt_device_code": "nova-agent login --provider openai --oauth --device-code",
                "account_login": "nova-agent login --import-existing",
                "claude_token": "nova-agent login --provider anthropic --token $CLAUDE_CODE_OAUTH_TOKEN",
                "google_oauth": "nova-agent login --provider gemini --oauth",
                "local_ollama": "nova-agent login --provider ollama",
                "local_custom": "nova-agent login --provider ollama --url http://127.0.0.1:11434 --model llama3.2",
                "openai_key": "export OPENAI_API_KEY=sk-...",
                "anthropic_key": "export ANTHROPIC_API_KEY=sk-ant-...",
                "gemini_key": "export GOOGLE_API_KEY=...",
                "openrouter": "export OPENROUTER_API_KEY=...  # one key → many models",
                "prefer": "export LLM_PROVIDER=openai LLM_MODEL=gpt-4o",
                "prefer_local": "export LLM_PROVIDER=ollama LLM_MODEL=llama3.2",
                "env_file": "cp config/.env.example .env  # then fill keys",
            },
            "local_llm": self._local_status(),
        }

    def _local_status(self) -> dict:
        try:
            from nova_arsenal.llm.local_llm import local_llm_status

            return local_llm_status()
        except Exception as exc:  # noqa: BLE001
            return {"available": False, "error": str(exc)}


# Global router singleton
_router: Optional[LLMRouter] = None


def get_llm_router() -> LLMRouter:
    """Get the global LLM router instance."""
    global _router
    if _router is None:
        _router = LLMRouter()
    return _router


def reset_llm_router() -> None:
    """Clear singleton (used after reload_config)."""
    global _router
    _router = None
