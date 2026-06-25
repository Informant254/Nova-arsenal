"""
Nova-Arsenal LLM Router

Multi-provider routing with fallback support.
"""

import logging
from typing import Optional

from nova_arsenal.config import get_config
from nova_arsenal.llm.base import LLMProvider
from nova_arsenal.llm.ollama import OllamaProvider
from nova_arsenal.llm.openai import OpenAIProvider
from nova_arsenal.llm.anthropic import AnthropicProvider
from nova_arsenal.llm.gemini import GeminiProvider

logger = logging.getLogger(__name__)


class LLMRouter:
    """Multi-provider LLM router with fallback."""

    def __init__(self):
        self.providers: list[LLMProvider] = []
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

        logger.info(f"Initialized {len(self.providers)} LLM providers")

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
            else:
                logger.warning(f"Unknown provider: {provider}")
                return None
        except Exception as e:
            logger.error(f"Failed to create provider {provider}: {e}")
            return None

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> str:
        """
        Generate a completion with automatic fallback.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Returns:
            Generated text
            
        Raises:
            RuntimeError: If all providers fail
        """
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
        **kwargs,
    ):
        """
        Stream a completion with automatic fallback.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Yields:
            Generated text chunks
            
        Raises:
            RuntimeError: If all providers fail
        """
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
                        f"Provider {provider.name} failed (attempt {attempt + 1}): {e}"
                    )
                    continue

        raise RuntimeError(f"All LLM providers failed. Last error: {last_error}")

    async def health_check(self) -> dict[str, bool]:
        """
        Check health of all providers.
        
        Returns:
            Dictionary mapping provider names to health status
        """
        results = {}
        for provider in self.providers:
            try:
                results[f"{provider.name}/{provider.model}"] = await provider.health_check()
            except Exception:
                results[f"{provider.name}/{provider.model}"] = False
        return results

    def list_providers(self) -> list[str]:
        """List all configured providers."""
        return [f"{p.name}/{p.model}" for p in self.providers]


# Global router singleton
_router: Optional[LLMRouter] = None


def get_llm_router() -> LLMRouter:
    """Get the global LLM router instance."""
    global _router
    if _router is None:
        _router = LLMRouter()
    return _router
