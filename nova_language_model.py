"""
Nova Language Model v1.0
========================
Routes between different LLM providers for maximum flexibility.

Supports:
- Claude (Anthropic) - Best reasoning
- GPT-4 (OpenAI) - Fast, capable
- Ollama (Local) - Free, private
- Llama (Local) - Open source

Automatically falls back if primary fails.
Optimizes prompts per model.
"""

import logging
from typing import Dict, List, Optional, Tuple
from enum import Enum
from abc import ABC, abstractmethod
import os
import json

logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    """Supported LLM providers"""
    CLAUDE = "claude"
    GPT4 = "gpt4"
    OLLAMA = "ollama"
    LLAMA = "llama"
    LOCAL = "local"


class LLMResponse:
    """Standard response from any LLM"""
    def __init__(self, text: str, provider: str, tokens_used: int = 0):
        self.text = text
        self.provider = provider
        self.tokens_used = tokens_used
    
    def __str__(self):
        return self.text


class BaseLLM(ABC):
    """Base class for LLM implementations"""
    
    @abstractmethod
    def reason(self, prompt: str, max_tokens: int = 1000) -> LLMResponse:
        """Get reasoning from LLM"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if this LLM is available"""
        pass


class ClaudeLLM(BaseLLM):
    """Claude (Anthropic) integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = "claude-opus-4-6"
    
    def is_available(self) -> bool:
        """Check if Claude API is available"""
        return bool(self.api_key)
    
    def reason(self, prompt: str, max_tokens: int = 1000) -> LLMResponse:
        """Use Claude for reasoning"""
        
        if not self.is_available():
            raise ValueError("Claude API key not configured")
        
        try:
            import anthropic
            
            client = anthropic.Anthropic(api_key=self.api_key)
            
            message = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            text = message.content[0].text
            tokens = message.usage.input_tokens + message.usage.output_tokens
            
            logger.info(f"Claude response: {tokens} tokens")
            
            return LLMResponse(
                text=text,
                provider="claude",
                tokens_used=tokens
            )
        
        except Exception as e:
            logger.error(f"Claude API error: {e}")
            raise


class GPT4LLM(BaseLLM):
    """GPT-4 (OpenAI) integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = "gpt-4-turbo"
    
    def is_available(self) -> bool:
        """Check if OpenAI API is available"""
        return bool(self.api_key)
    
    def reason(self, prompt: str, max_tokens: int = 1000) -> LLMResponse:
        """Use GPT-4 for reasoning"""
        
        if not self.is_available():
            raise ValueError("OpenAI API key not configured")
        
        try:
            import openai
            
            openai.api_key = self.api_key
            
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens
            )
            
            text = response.choices[0].message.content
            tokens = response.usage.total_tokens
            
            logger.info(f"GPT-4 response: {tokens} tokens")
            
            return LLMResponse(
                text=text,
                provider="gpt4",
                tokens_used=tokens
            )
        
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise


class OllamaLLM(BaseLLM):
    """Local Ollama integration"""
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "mistral"):
        self.base_url = base_url
        self.model = model
    
    def is_available(self) -> bool:
        """Check if Ollama is running"""
        try:
            import requests
            response = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def reason(self, prompt: str, max_tokens: int = 1000) -> LLMResponse:
        """Use Ollama for reasoning"""
        
        try:
            import requests
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=60
            )
            
            if response.status_code != 200:
                raise ValueError(f"Ollama error: {response.text}")
            
            data = response.json()
            text = data.get("response", "")
            
            logger.info(f"Ollama response from {self.model}")
            
            return LLMResponse(
                text=text,
                provider="ollama",
                tokens_used=data.get("eval_count", 0)
            )
        
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            raise


class LanguageModelRouter:
    """
    Routes requests to appropriate LLM.
    Falls back if primary fails.
    Optimizes for best result.
    """
    
    def __init__(
        self,
        primary: str = "claude",
        fallbacks: List[str] = None,
        ollama_model: str = "mistral"
    ):
        """
        Initialize router.
        
        Args:
            primary: Primary provider (claude, gpt4, ollama)
            fallbacks: Fallback providers in order
            ollama_model: Which model to use in Ollama
        """
        self.primary_name = primary
        self.fallback_names = fallbacks or ["ollama", "local"]
        self.ollama_model = ollama_model
        
        # Initialize all providers
        self.providers = {
            "claude": ClaudeLLM(),
            "gpt4": GPT4LLM(),
            "ollama": OllamaLLM(model=ollama_model),
        }
        
        self.last_provider = None
    
    def get_available_providers(self) -> List[str]:
        """Get list of available providers"""
        available = []
        for name, provider in self.providers.items():
            if provider.is_available():
                available.append(name)
        return available
    
    def reason(
        self,
        prompt: str,
        max_tokens: int = 1000,
        preferred_provider: Optional[str] = None
    ) -> LLMResponse:
        """
        Get reasoning from LLM with automatic fallback.
        
        Args:
            prompt: Prompt to send
            max_tokens: Max response tokens
            preferred_provider: Force specific provider
            
        Returns:
            LLMResponse from whichever provider worked
        """
        
        # Try preferred provider first
        if preferred_provider and preferred_provider in self.providers:
            provider = self.providers[preferred_provider]
            if provider.is_available():
                try:
                    response = provider.reason(prompt, max_tokens)
                    self.last_provider = preferred_provider
                    return response
                except Exception as e:
                    logger.warning(f"{preferred_provider} failed: {e}")
        
        # Try primary provider
        if self.primary_name in self.providers:
            provider = self.providers[self.primary_name]
            if provider.is_available():
                try:
                    response = provider.reason(prompt, max_tokens)
                    self.last_provider = self.primary_name
                    return response
                except Exception as e:
                    logger.warning(f"Primary provider {self.primary_name} failed: {e}")
        
        # Try fallbacks in order
        for fallback_name in self.fallback_names:
            if fallback_name in self.providers:
                provider = self.providers[fallback_name]
                if provider.is_available():
                    try:
                        response = provider.reason(prompt, max_tokens)
                        self.last_provider = fallback_name
                        logger.info(f"Using fallback: {fallback_name}")
                        return response
                    except Exception as e:
                        logger.warning(f"Fallback {fallback_name} failed: {e}")
        
        # No providers available
        raise RuntimeError(
            "No LLM providers available. "
            "Please configure Claude API key, OpenAI API key, or run Ollama."
        )
    
    def optimize_prompt_for_provider(self, prompt: str, provider: str) -> str:
        """
        Optimize prompt for specific provider.
        Different models respond better to different formats.
        """
        
        if provider == "claude":
            # Claude likes structured thinking
            if "think step by step" not in prompt.lower():
                prompt += "\n\nThink through this step by step."
        
        elif provider == "gpt4":
            # GPT-4 likes examples
            if "example" not in prompt.lower():
                prompt += "\n\nProvide concrete examples."
        
        elif provider == "ollama":
            # Ollama (mistral) likes concise prompts
            prompt = prompt[:2000]  # Limit length
        
        return prompt
    
    def batch_reason(
        self,
        prompts: List[str],
        max_tokens: int = 1000
    ) -> List[LLMResponse]:
        """
        Process multiple prompts.
        Useful for batch analysis.
        """
        
        responses = []
        for prompt in prompts:
            try:
                response = self.reason(prompt, max_tokens)
                responses.append(response)
            except Exception as e:
                logger.error(f"Batch reasoning failed: {e}")
                responses.append(None)
        
        return responses
    
    def get_status(self) -> Dict[str, any]:
        """Get status of all providers"""
        
        status = {
            "primary": self.primary_name,
            "last_used": self.last_provider,
            "available": self.get_available_providers(),
            "providers": {}
        }
        
        for name, provider in self.providers.items():
            status["providers"][name] = {
                "available": provider.is_available(),
                "type": provider.__class__.__name__
            }
        
        return status


# Example usage
if __name__ == "__main__":
    router = LanguageModelRouter(
        primary="claude",
        fallbacks=["gpt4", "ollama"]
    )
    
    print("\n=== NOVA LANGUAGE MODEL ROUTER ===\n")
    
    # Check status
    status = router.get_status()
    print(f"Primary: {status['primary']}")
    print(f"Available: {status['available']}")
    print()
    
    # Try reasoning
    prompt = "What are the top 3 SQL injection prevention techniques?"
    
    try:
        response = router.reason(prompt)
        print(f"Response from {response.provider}:")
        print(response.text[:200] + "...")
    except RuntimeError as e:
        print(f"Error: {e}")
        print("\nTo use Nova's NLP features, configure one of:")
        print("1. ANTHROPIC_API_KEY (for Claude)")
        print("2. OPENAI_API_KEY (for GPT-4)")
        print("3. Run 'ollama serve' locally")
