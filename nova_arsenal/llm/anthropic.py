"""
Nova-Arsenal Anthropic Provider

Anthropic Claude API integration.
"""

import json
from typing import AsyncGenerator, Optional

import httpx

from nova_arsenal.llm.base import LLMProvider


class AnthropicProvider(LLMProvider):
    """Anthropic LLM provider for Claude models."""

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        api_key: str = "",
        base_url: str = "https://api.anthropic.com",
        **kwargs,
    ):
        super().__init__(name="anthropic", model=model, api_key=api_key, **kwargs)
        self.base_url = base_url.rstrip("/")

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> str:
        """Generate a completion using Anthropic API."""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        data = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }

        if system_prompt:
            data["system"] = system_prompt

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.base_url}/v1/messages",
                headers=headers,
                json=data,
            )
            response.raise_for_status()
            result = response.json()
            
            # Extract text from content blocks
            content = result.get("content", [])
            return "".join(
                block.get("text", "") for block in content if block.get("type") == "text"
            )

    async def stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> AsyncGenerator[str, None]:
        """Stream a completion using Anthropic API."""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        data = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
            "stream": True,
        }

        if system_prompt:
            data["system"] = system_prompt

        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/v1/messages",
                headers=headers,
                json=data,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        try:
                            data = json.loads(data_str)
                            event_type = data.get("type", "")
                            
                            if event_type == "content_block_delta":
                                delta = data.get("delta", {})
                                if delta.get("type") == "text_delta":
                                    yield delta.get("text", "")
                            elif event_type == "message_stop":
                                break
                        except json.JSONDecodeError:
                            continue

    async def health_check(self) -> bool:
        """Check if Anthropic API is accessible."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{self.base_url}/v1/models",
                    headers={"x-api-key": self.api_key},
                )
                # Anthropic doesn't have a models endpoint, so just check auth
                return response.status_code in [200, 404]
        except Exception:
            return False
