"""
Nova-Arsenal LLM Base Interface

Abstract base class for all LLM providers.
"""

from abc import ABC, abstractmethod
from typing import AsyncGenerator, Dict, Optional


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, name: str, model: str, api_key: str = "", **kwargs):
        """
        Initialize the provider.
        
        Args:
            name: Provider name (e.g., "ollama", "openai")
            model: Model name (e.g., "gpt-4o", "deepseek-r1")
            api_key: API key (not needed for Ollama)
            **kwargs: Additional provider-specific arguments
        """
        self.name = name
        self.model = model
        self.api_key = api_key
        self.config = kwargs

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> str:
        """
        Generate a completion.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Returns:
            Generated text
        """
        pass

    @abstractmethod
    async def stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> AsyncGenerator[str, None]:
        """
        Stream a completion.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Yields:
            Generated text chunks
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the provider is available.
        
        Returns:
            True if healthy, False otherwise
        """
        pass

    async def get_models(self) -> list[str]:
        """
        Get available models from this provider.
        
        Returns:
            List of model names
        """
        return [self.model]

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} model={self.model}>"
