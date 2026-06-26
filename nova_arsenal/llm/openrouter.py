"""
OpenRouter Provider - Access 200+ models through OpenRouter API.
Includes Nex-N2-Pro and Nex-N2-mini support with Adaptive Thinking.
"""

import json
import logging
from typing import AsyncGenerator, Optional

import httpx

from nova_arsenal.llm.base import LLMProvider

logger = logging.getLogger(__name__)

# Nex-N2 specific sampling parameters from their deployment guide
NEXN2_SAMPLING_PARAMS = {
    "nexus/nex-n2-pro": {
        "temperature": 0.7,
        "top_p": 0.95,
        "top_k": 40,
        "max_tokens": 65536,
        "reasoning_parser": "qwen3",
        "tool_call_parser": "qwen3_coder",
    },
    "nexus/nex-n2-mini": {
        "temperature": 0.7,
        "top_p": 0.95,
        "top_k": 40,
        "max_tokens": 32768,
        "reasoning_parser": "qwen3",
        "tool_call_parser": "qwen3_coder",
    },
}

NOVA_AGENTIC_THINKING_SYSTEM_PROMPT = """You are Nexus, a powerful autonomous agent with adaptive reasoning capabilities.

You decide dynamically when to reason deeply vs. act directly.
- For simple tasks: respond directly without <think> blocks
- For complex tasks: use <think>...</think> to reason step-by-step
- For tool calls: reason first, then call tools using <tool_call> XML format

Output structure:
<think>
Optional reasoning content — only when needed
</think>

Final response content.

Tool calling format:
<tool_call>
<function=tool_name>
<parameter=param_name>
value
</parameter>
</function>
</tool_call>"""


class OpenRouterProvider(LLMProvider):
    """OpenRouter multi-model gateway provider."""

    def __init__(
        self,
        model: str = "anthropic/claude-sonnet-4",
        api_key: str = "",
        base_url: str = "https://openrouter.ai/api/v1",
        timeout: int = 120,
        **kwargs,
    ):
        super().__init__(name="openrouter", model=model, api_key=api_key, **kwargs)
        self.base_url = base_url
        self.timeout = timeout

    def _get_model_params(self, temperature: float, max_tokens: int) -> dict:
        """Get model-specific parameters, applying Nex-N2 defaults when appropriate."""
        params = {
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        model_key = self.model.lower()
        if model_key in NEXN2_SAMPLING_PARAMS:
            n2 = NEXN2_SAMPLING_PARAMS[model_key]
            params["top_p"] = n2["top_p"]
            params["top_k"] = n2.get("top_k", 40)
            params["temperature"] = temperature if temperature != 0.7 else n2["temperature"]
            params["max_tokens"] = min(max_tokens, n2["max_tokens"])
        return params

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> str:
        messages = []
        actual_system = system_prompt
        model_key = self.model.lower()

        # Use Nex-N2 system prompt for Nex models if no custom system prompt given
        if model_key in NEXN2_SAMPLING_PARAMS and not system_prompt:
            actual_system = NOVA_AGENTIC_THINKING_SYSTEM_PROMPT

        if actual_system:
            messages.append({"role": "system", "content": actual_system})
        messages.append({"role": "user", "content": prompt})

        body = {
            "model": self.model,
            "messages": messages,
            **self._get_model_params(temperature, max_tokens),
        }

        if kwargs.get("stream"):
            body["stream"] = True

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "HTTP-Referer": "https://nova-arsenal.ai",
                    "X-Title": "Nova-Arsenal",
                },
                json=body,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    async def stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> AsyncGenerator[str, None]:
        messages = []
        actual_system = system_prompt
        model_key = self.model.lower()

        if model_key in NEXN2_SAMPLING_PARAMS and not system_prompt:
            actual_system = NOVA_AGENTIC_THINKING_SYSTEM_PROMPT

        if actual_system:
            messages.append({"role": "system", "content": actual_system})
        messages.append({"role": "user", "content": prompt})

        body = {
            "model": self.model,
            "messages": messages,
            **self._get_model_params(temperature, max_tokens),
            "stream": True,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "HTTP-Referer": "https://nova-arsenal.ai",
                    "X-Title": "Nova-Arsenal",
                },
                json=body,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]
                        if data.strip() == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data)
                            delta = chunk.get("choices", [{}])[0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                yield content
                        except json.JSONDecodeError:
                            continue

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                return response.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                response.raise_for_status()
                data = response.json()
                return [m["id"] for m in data.get("data", [])]
        except Exception:
            return [self.model]
