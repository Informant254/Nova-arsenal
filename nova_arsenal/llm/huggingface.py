"""
HuggingFace Provider - Access models via HuggingFace Inference API.
"""

import json
import logging
from typing import AsyncGenerator, Optional

import httpx

from nova_arsenal.llm.base import LLMProvider

logger = logging.getLogger(__name__)


class HuggingFaceProvider(LLMProvider):
    """HuggingFace Inference API provider."""

    def __init__(
        self,
        model: str = "meta-llama/Llama-3.3-70B-Instruct",
        api_key: str = "",
        base_url: str = "https://api-inference.huggingface.co",
        timeout: int = 120,
        **kwargs,
    ):
        super().__init__(name="huggingface", model=model, api_key=api_key, **kwargs)
        self.base_url = base_url
        self.timeout = timeout

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/models/{self.model}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "messages": messages,
                    "temperature": temperature,
                    "max_new_tokens": max_tokens,
                    "return_full_text": False,
                },
            )
            response.raise_for_status()
            data = response.json()

            if isinstance(data, list) and len(data) > 0:
                return data[0].get("generated_text", "")
            elif isinstance(data, dict):
                return data.get("generated_text", json.dumps(data))
            return str(data)

    async def stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> AsyncGenerator[str, None]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/models/{self.model}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "messages": messages,
                    "temperature": temperature,
                    "max_new_tokens": max_tokens,
                    "return_full_text": False,
                    "stream": True,
                },
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]
                        if data.strip() == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data)
                            token = chunk.get("token", {}).get("text", "")
                            if token:
                                yield token
                        except json.JSONDecodeError:
                            continue

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{self.base_url}/models/{self.model}",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                return response.status_code in (200, 503)
        except Exception:
            return False
