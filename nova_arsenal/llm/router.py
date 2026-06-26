"""
Nova-Arsenal LLM Router

Multi-provider routing with fallback support + Fugu-style orchestration.
"""

import logging
import os
from typing import Optional

from nova_arsenal.config import get_config
from nova_arsenal.llm.base import LLMProvider
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


class LLMRouter:
    """Multi-provider LLM router with fallback and Fugu-style orchestration."""

    def __init__(self):
        self.providers: list[LLMProvider] = []
        self._multi_router: Optional[MultiProviderRouter] = None
        self._setup_providers()

    def _setup_providers(self):
        """Setup providers from configuration."""
        config = get_config()

        # Setup primary provider
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

        # Setup fallback providers
        for fb in config.llm.fallbacks:
            provider = self._create_provider(
                provider=fb.provider,
                model=fb.model,
                api_key=fb.api_key,
                url=fb.url,
                timeout=fb.timeout,
            )
            if provider:
                self.providers.append(provider)

        # Setup multi-provider router
        self._setup_multi_router(config)

        logger.info(f"Initialized {len(self.providers)} LLM providers")

    def _setup_multi_router(self, config) -> None:
        """Setup the Fugu-style multi-provider router."""
        self._multi_router = MultiProviderRouter()

        # Register all available providers
        provider_map = {
            "ollama": OllamaProvider,
            "openai": OpenAIProvider,
            "anthropic": AnthropicProvider,
            "gemini": GeminiProvider,
            "openrouter": OpenRouterProvider,
            "huggingface": HuggingFaceProvider,
            "qwen": QwenProvider,
            "deepseek": DeepSeekProvider,
            "opencode": OpencodeProvider,
        }

        # Register primary
        primary = config.llm.primary
        if primary.provider in provider_map:
            try:
                p = provider_map[primary.provider](
                    model=primary.model,
                    api_key=primary.api_key,
                    url=primary.url,
                )
                self._multi_router.register_provider(primary.provider, p)
            except Exception as e:
                logger.warning(f"Failed to register {primary.provider} in multi-router: {e}")

        # Register fallbacks
        for fb in config.llm.fallbacks:
            if fb.provider in provider_map:
                try:
                    p = provider_map[fb.provider](
                        model=fb.model,
                        api_key=fb.api_key,
                        url=fb.url,
                    )
                    self._multi_router.register_provider(fb.provider, p)
                except Exception as e:
                    logger.warning(f"Failed to register {fb.provider} in multi-router: {e}")

        # Also try to register providers from environment variables
        self._register_env_providers()

    def _register_env_providers(self) -> None:
        """Register providers from environment variables if keys are available."""
        if not self._multi_router:
            return

        env_providers = {
            "OPENROUTER_API_KEY": ("openrouter", OpenRouterProvider, "openrouter/google-gemini-2.5-flash"),
            "HUGGINGFACE_API_KEY": ("huggingface", HuggingFaceProvider, "meta-llama/Llama-3.3-70B-Instruct"),
            "DASHSCOPE_API_KEY": ("qwen", QwenProvider, "qwen-max"),
            "DEEPSEEK_API_KEY": ("deepseek", DeepSeekProvider, "deepseek-chat"),
            "OPCODE_API_KEY": ("opencode", OpencodeProvider, "opencode-qwen-72b"),
        }

        for env_key, (name, provider_cls, model) in env_providers.items():
            api_key = os.getenv(env_key, "")
            if api_key and name not in self._multi_router.list_providers():
                try:
                    p = provider_cls(model=model, api_key=api_key)
                    self._multi_router.register_provider(name, p)
                    logger.info(f"Registered {name} from environment")
                except Exception as e:
                    logger.warning(f"Failed to register {name}: {e}")

    def _create_provider(
        self,
        provider: str,
        model: str,
        api_key: str = "",
        url: str = "",
        timeout: int = 120,
    ) -> Optional[LLMProvider]:
        """Create a provider instance."""
        try:
            if provider == "ollama":
                return OllamaProvider(model=model, base_url=url or "http://localhost:11434")
            elif provider == "openai":
                if not api_key:
                    logger.warning("OpenAI API key not provided, skipping")
                    return None
                return OpenAIProvider(model=model, api_key=api_key)
            elif provider == "anthropic":
                if not api_key:
                    logger.warning("Anthropic API key not provided, skipping")
                    return None
                return AnthropicProvider(model=model, api_key=api_key)
            elif provider == "gemini":
                if not api_key:
                    logger.warning("Gemini API key not provided, skipping")
                    return None
                return GeminiProvider(model=model, api_key=api_key)
            elif provider == "openrouter":
                if not api_key:
                    logger.warning("OpenRouter API key not provided, skipping")
                    return None
                return OpenRouterProvider(model=model, api_key=api_key)
            elif provider == "huggingface":
                if not api_key:
                    logger.warning("HuggingFace API key not provided, skipping")
                    return None
                return HuggingFaceProvider(model=model, api_key=api_key)
            elif provider == "qwen":
                if not api_key:
                    logger.warning("Qwen/DashScope API key not provided, skipping")
                    return None
                return QwenProvider(model=model, api_key=api_key)
            elif provider == "deepseek":
                if not api_key:
                    logger.warning("DeepSeek API key not provided, skipping")
                    return None
                return DeepSeekProvider(model=model, api_key=api_key)
            elif provider == "opencode":
                if not api_key:
                    logger.warning("Opencode API key not provided, skipping")
                    return None
                return OpencodeProvider(model=model, api_key=api_key)
            else:
                logger.warning(f"Unknown provider: {provider}")
                return None
        except Exception as e:
            logger.error(f"Failed to create provider {provider}: {e}")
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
        """
        Generate a completion with automatic fallback.
        
        If use_multi_router=True, uses Fugu-style routing to pick the best provider.
        Otherwise, falls back through the ordered provider list.
        """
        # Use multi-router if available and requested
        if use_multi_router and self._multi_router and len(self._multi_router.list_providers()) > 1:
            try:
                return await self._multi_router.complete(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    preference=preference,
                    **kwargs,
                )
            except Exception as e:
                logger.warning(f"Multi-router failed, falling back to sequential: {e}")

        # Sequential fallback
        last_error = None
        config = get_config()
        max_retries = config.llm.max_retries

        for provider in self.providers:
            for attempt in range(max_retries):
                try:
                    logger.debug(
                        f"Trying provider {provider.name}/{provider.model} "
                        f"(attempt {attempt + 1}/{max_retries})"
                    )
                    result = await provider.complete(
                        prompt=prompt,
                        system_prompt=system_prompt,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        **kwargs,
                    )
                    logger.debug(f"Success with provider {provider.name}")
                    return result
                except Exception as e:
                    last_error = e
                    logger.warning(
                        f"Provider {provider.name} failed (attempt {attempt + 1}): {e}"
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
        """
        Stream a completion with automatic fallback.
        """
        # Use multi-router if available and requested
        if use_multi_router and self._multi_router and len(self._multi_router.list_providers()) > 1:
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
            except Exception as e:
                logger.warning(f"Multi-router stream failed, falling back: {e}")

        # Sequential fallback
        last_error = None
        config = get_config()
        max_retries = config.llm.max_retries

        for provider in self.providers:
            for attempt in range(max_retries):
                try:
                    logger.debug(
                        f"Trying provider {provider.name}/{provider.model} "
                        f"(attempt {attempt + 1}/{max_retries})"
                    )
                    async for chunk in provider.stream(
                        prompt=prompt,
                        system_prompt=system_prompt,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        **kwargs,
                    ):
                        yield chunk
                    logger.debug(f"Success with provider {provider.name}")
                    return
                except Exception as e:
                    last_error = e
                    logger.warning(
                        f"Provider {provider.name} stream failed (attempt {attempt + 1}): {e}"
                    )
                    continue

        raise RuntimeError(f"All LLM providers failed for streaming. Last error: {last_error}")

    async def health_check(self) -> dict[str, bool]:
        """Check health of all providers."""
        results = {}
        for provider in self.providers:
            try:
                results[f"{provider.name}/{provider.model}"] = await provider.health_check()
            except Exception:
                results[f"{provider.name}/{provider.model}"] = False

        # Also check multi-router providers
        if self._multi_router:
            for name in self._multi_router.list_providers():
                provider = self._multi_router.get_provider(name)
                if provider:
                    try:
                        results[f"multi/{name}/{provider.model}"] = await provider.health_check()
                    except Exception:
                        results[f"multi/{name}/{provider.model}"] = False

        return results

    def list_providers(self) -> list[str]:
        """List all configured providers."""
        providers = [f"{p.name}/{p.model}" for p in self.providers]
        if self._multi_router:
            for name in self._multi_router.list_providers():
                providers.append(f"multi/{name}")
        return providers

    def get_routing_stats(self) -> dict:
        """Get multi-router statistics."""
        if self._multi_router:
            return self._multi_router.get_stats()
        return {"total_routes": 0, "registered_providers": []}


# Global router singleton
_router: Optional[LLMRouter] = None


def get_llm_router() -> LLMRouter:
    """Get the global LLM router instance."""
    global _router
    if _router is None:
        _router = LLMRouter()
    return _router
