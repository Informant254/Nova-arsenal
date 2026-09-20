"""OpenAI provider with Responses API support and compatible fallback."""

import json
from typing import AsyncGenerator, Optional

import httpx

from nova_arsenal.llm.base import LLMProvider


class OpenAIProvider(LLMProvider):
    """OpenAI provider.

    Official OpenAI endpoints use the Responses API. OpenAI-compatible servers
    (LM Studio, vLLM, llama.cpp gateways, and similar) keep using Chat
    Completions unless api_mode is explicitly overridden.
    """

    def __init__(
        self,
        model: str = "gpt-5.6-terra",
        api_key: str = "",
        base_url: str = "https://api.openai.com/v1",
        api_mode: str = "auto",
        timeout: float = 120.0,
        **kwargs,
    ):
        super().__init__(name="openai", model=model, api_key=api_key, **kwargs)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.api_mode = api_mode

    @property
    def uses_responses_api(self) -> bool:
        if self.api_mode == "responses":
            return True
        if self.api_mode == "chat_completions":
            return False
        return self.base_url in {
            "https://api.openai.com",
            "https://api.openai.com/v1",
        }

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _responses_payload(
        self,
        prompt: str,
        system_prompt: Optional[str],
        max_tokens: int,
        stream: bool = False,
        **kwargs,
    ) -> dict:
        payload: dict = {
            "model": self.model,
            "input": prompt,
            "max_output_tokens": max_tokens,
            "store": False,
        }
        if system_prompt:
            payload["instructions"] = system_prompt
        if stream:
            payload["stream"] = True

        reasoning_effort = kwargs.get("reasoning_effort")
        if reasoning_effort:
            payload["reasoning"] = {"effort": reasoning_effort}
        return payload

    @staticmethod
    def _extract_response_text(data: dict) -> str:
        # Some clients/proxies may expose a convenience output_text field.
        direct = data.get("output_text")
        if isinstance(direct, str):
            return direct

        chunks: list[str] = []
        for item in data.get("output", []) or []:
            if not isinstance(item, dict) or item.get("type") != "message":
                continue
            for part in item.get("content", []) or []:
                if isinstance(part, dict) and part.get("type") == "output_text":
                    text = part.get("text")
                    if isinstance(text, str):
                        chunks.append(text)
        return "".join(chunks)

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> str:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if self.uses_responses_api:
                response = await client.post(
                    f"{self.base_url}/responses",
                    headers=self._headers,
                    json=self._responses_payload(
                        prompt,
                        system_prompt,
                        max_tokens,
                        **kwargs,
                    ),
                )
                response.raise_for_status()
                return self._extract_response_text(response.json())

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers,
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
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
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if self.uses_responses_api:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/responses",
                    headers=self._headers,
                    json=self._responses_payload(
                        prompt,
                        system_prompt,
                        max_tokens,
                        stream=True,
                        **kwargs,
                    ),
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        raw = line[6:]
                        if not raw or raw == "[DONE]":
                            continue
                        try:
                            event = json.loads(raw)
                        except json.JSONDecodeError:
                            continue

                        event_type = event.get("type")
                        if event_type == "response.output_text.delta":
                            delta = event.get("delta", "")
                            if delta:
                                yield delta
                        elif event_type in {"error", "response.failed"}:
                            detail = event.get("message") or event.get("error") or event_type
                            raise RuntimeError(f"OpenAI response stream failed: {detail}")
                return

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            async with client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers=self._headers,
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "stream": True,
                },
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    raw = line[6:]
                    if raw == "[DONE]":
                        break
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    content = data.get("choices", [{}])[0].get("delta", {}).get("content", "")
                    if content:
                        yield content

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                return response.status_code == 200
        except Exception:
            return False
