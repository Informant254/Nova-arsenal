#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🔀 NOVA LLM ROUTER v1.0 — Multi-Provider LLM with Auto-Fallback           ║
║                                                                              ║
║  Provides a single, unified interface to:                                    ║
║    • Ollama (local — default, zero cost)                                     ║
║    • OpenAI (GPT-4o, o1, o3)                                                ║
║    • Anthropic (Claude Sonnet 4, Claude Opus 4)                             ║
║    • Google Gemini (gemini-2.0-flash, gemini-2.5-pro)                       ║
║    • Any OpenAI-compatible endpoint (Together, Groq, Mistral, etc.)         ║
║                                                                              ║
║  Features:                                                                   ║
║    • Auto-fallback chain:  primary → secondary → local Ollama               ║
║    • Streaming support across all providers                                  ║
║    • Structured output (JSON schema) across all providers                    ║
║    • Exponential backoff + circuit breaker                                   ║
║    • Per-provider token counting + cost estimation                           ║
║    • Async-first with sync wrappers                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    from nova_llm_router import LLMRouter, Message, ProviderConfig

    router = LLMRouter()                         # auto-detects available providers
    response = router.chat("Analyse this target: example.com")
    print(response.content)

    # Streaming
    for chunk in router.stream("Summarise these findings"):
        print(chunk, end="", flush=True)

    # Structured output
    result = router.chat_structured("Extract CVEs", schema={"type":"object", ...})
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple, Union

# ── Provider enum ──────────────────────────────────────────────────────────────

class Provider(str, Enum):
    OLLAMA    = "ollama"
    OPENAI    = "openai"
    ANTHROPIC = "anthropic"
    GEMINI    = "gemini"
    OPENAI_COMPAT = "openai_compat"   # any OpenAI-compatible endpoint


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class Message:
    role:    str          # "system" | "user" | "assistant" | "tool"
    content: str
    name:    Optional[str] = None

    def to_dict(self) -> Dict:
        d = {"role": self.role, "content": self.content}
        if self.name:
            d["name"] = self.name
        return d


@dataclass
class LLMResponse:
    content:        str
    provider:       Provider
    model:          str
    prompt_tokens:  int = 0
    output_tokens:  int = 0
    cost_usd:       float = 0.0
    latency_ms:     float = 0.0
    finish_reason:  str = "stop"
    raw:            Optional[Dict] = field(default=None, repr=False)


@dataclass
class ProviderConfig:
    provider:    Provider
    model:       str
    api_key:     Optional[str] = None
    base_url:    Optional[str] = None
    temperature: float = 0.1
    max_tokens:  int   = 4096
    timeout:     int   = 120
    enabled:     bool  = True

    # Cost per 1M tokens (USD) — approximate, updated 2026-05
    input_cost_per_1m:  float = 0.0
    output_cost_per_1m: float = 0.0


# ── Pricing table ──────────────────────────────────────────────────────────────

PRICING: Dict[str, Tuple[float, float]] = {
    # model_name: (input_per_1M, output_per_1M) in USD
    "gpt-4o":                 (2.50,  10.00),
    "gpt-4o-mini":            (0.15,   0.60),
    "o3":                     (10.00, 40.00),
    "o1":                     (15.00, 60.00),
    "claude-sonnet-4-5":      (3.00,  15.00),
    "claude-opus-4-5":        (15.00, 75.00),
    "claude-haiku-3-5":       (0.80,   4.00),
    "gemini-2.0-flash":       (0.075,  0.30),
    "gemini-2.5-pro":         (1.25,  10.00),
}

def _cost(model: str, in_tok: int, out_tok: int) -> float:
    p = PRICING.get(model, (0.0, 0.0))
    return (in_tok * p[0] + out_tok * p[1]) / 1_000_000


# ── Circuit breaker ────────────────────────────────────────────────────────────

class CircuitBreaker:
    """Simple circuit breaker per provider."""

    def __init__(self, threshold: int = 3, reset_after: int = 60):
        self._failures:   Dict[str, int]   = {}
        self._opened_at:  Dict[str, float] = {}
        self._threshold   = threshold
        self._reset_after = reset_after

    def is_open(self, name: str) -> bool:
        if name not in self._failures:
            return False
        if self._failures[name] < self._threshold:
            return False
        elapsed = time.time() - self._opened_at.get(name, 0)
        if elapsed > self._reset_after:
            self._failures[name] = 0
            return False
        return True

    def record_failure(self, name: str):
        self._failures[name] = self._failures.get(name, 0) + 1
        self._opened_at[name] = time.time()

    def record_success(self, name: str):
        self._failures[name] = 0


# ── Provider back-ends ─────────────────────────────────────────────────────────

def _http_post(url: str, payload: Dict, headers: Dict, timeout: int) -> Dict:
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _call_ollama(cfg: ProviderConfig, messages: List[Message],
                 schema: Optional[Dict] = None) -> LLMResponse:
    url = (cfg.base_url or "http://localhost:11434") + "/api/chat"
    payload: Dict[str, Any] = {
        "model":    cfg.model,
        "messages": [m.to_dict() for m in messages],
        "stream":   False,
        "options":  {"temperature": cfg.temperature, "num_predict": cfg.max_tokens},
    }
    if schema:
        payload["format"] = schema

    t0   = time.time()
    raw  = _http_post(url, payload, {"Content-Type": "application/json"}, cfg.timeout)
    ms   = (time.time() - t0) * 1000
    content = raw.get("message", {}).get("content", "").strip()
    pt   = raw.get("prompt_eval_count", 0)
    ot   = raw.get("eval_count", 0)
    return LLMResponse(content=content, provider=Provider.OLLAMA,
                       model=cfg.model, prompt_tokens=pt, output_tokens=ot,
                       cost_usd=0.0, latency_ms=ms, raw=raw)


def _call_openai_compat(cfg: ProviderConfig, messages: List[Message],
                        schema: Optional[Dict] = None) -> LLMResponse:
    api_key  = cfg.api_key or os.getenv("OPENAI_API_KEY", "")
    base_url = (cfg.base_url or "https://api.openai.com/v1") + "/chat/completions"
    payload: Dict[str, Any] = {
        "model":       cfg.model,
        "messages":    [m.to_dict() for m in messages],
        "temperature": cfg.temperature,
        "max_tokens":  cfg.max_tokens,
    }
    if schema:
        payload["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "nova_output", "strict": True, "schema": schema}
        }
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    t0  = time.time()
    raw = _http_post(base_url, payload, headers, cfg.timeout)
    ms  = (time.time() - t0) * 1000
    choice  = raw["choices"][0]
    content = choice["message"]["content"] or ""
    usage   = raw.get("usage", {})
    pt  = usage.get("prompt_tokens", 0)
    ot  = usage.get("completion_tokens", 0)
    return LLMResponse(content=content.strip(), provider=cfg.provider,
                       model=cfg.model, prompt_tokens=pt, output_tokens=ot,
                       cost_usd=_cost(cfg.model, pt, ot), latency_ms=ms,
                       finish_reason=choice.get("finish_reason", "stop"), raw=raw)


def _call_anthropic(cfg: ProviderConfig, messages: List[Message],
                    schema: Optional[Dict] = None) -> LLMResponse:
    api_key  = cfg.api_key or os.getenv("ANTHROPIC_API_KEY", "")
    url      = "https://api.anthropic.com/v1/messages"
    system_msgs = [m for m in messages if m.role == "system"]
    user_msgs   = [m for m in messages if m.role != "system"]
    payload: Dict[str, Any] = {
        "model":      cfg.model,
        "max_tokens": cfg.max_tokens,
        "messages":   [m.to_dict() for m in user_msgs],
    }
    if system_msgs:
        payload["system"] = "\n\n".join(m.content for m in system_msgs)
    if schema:
        payload["tools"] = [{
            "name":        "structured_output",
            "description": "Return structured output matching the schema",
            "input_schema": schema
        }]
        payload["tool_choice"] = {"type": "tool", "name": "structured_output"}
    headers = {
        "Content-Type":      "application/json",
        "x-api-key":         api_key,
        "anthropic-version": "2023-06-01",
    }
    t0  = time.time()
    raw = _http_post(url, payload, headers, cfg.timeout)
    ms  = (time.time() - t0) * 1000
    usage = raw.get("usage", {})
    pt  = usage.get("input_tokens", 0)
    ot  = usage.get("output_tokens", 0)
    # Extract content
    content = ""
    for block in raw.get("content", []):
        if block.get("type") == "text":
            content += block["text"]
        elif block.get("type") == "tool_use" and block.get("name") == "structured_output":
            content = json.dumps(block.get("input", {}))
    return LLMResponse(content=content.strip(), provider=Provider.ANTHROPIC,
                       model=cfg.model, prompt_tokens=pt, output_tokens=ot,
                       cost_usd=_cost(cfg.model, pt, ot), latency_ms=ms, raw=raw)


def _call_gemini(cfg: ProviderConfig, messages: List[Message],
                 schema: Optional[Dict] = None) -> LLMResponse:
    api_key = cfg.api_key or os.getenv("GEMINI_API_KEY", "")
    model   = cfg.model or "gemini-2.0-flash"
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={api_key}")
    contents = []
    system_text = ""
    for m in messages:
        if m.role == "system":
            system_text += m.content + "\n"
        else:
            role = "model" if m.role == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": m.content}]})
    payload: Dict[str, Any] = {
        "contents":          contents,
        "generationConfig":  {"temperature": cfg.temperature, "maxOutputTokens": cfg.max_tokens},
    }
    if system_text:
        payload["systemInstruction"] = {"parts": [{"text": system_text}]}
    if schema:
        payload["generationConfig"]["responseMimeType"] = "application/json"
        payload["generationConfig"]["responseSchema"]   = schema
    t0  = time.time()
    raw = _http_post(url, payload, {"Content-Type": "application/json"}, cfg.timeout)
    ms  = (time.time() - t0) * 1000
    content = ""
    try:
        content = raw["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError):
        pass
    usage = raw.get("usageMetadata", {})
    pt = usage.get("promptTokenCount", 0)
    ot = usage.get("candidatesTokenCount", 0)
    return LLMResponse(content=content.strip(), provider=Provider.GEMINI,
                       model=model, prompt_tokens=pt, output_tokens=ot,
                       cost_usd=_cost(model, pt, ot), latency_ms=ms, raw=raw)


# ── Streaming helpers ──────────────────────────────────────────────────────────

def _stream_ollama(cfg: ProviderConfig, messages: List[Message]) -> Iterator[str]:
    url     = (cfg.base_url or "http://localhost:11434") + "/api/chat"
    payload = json.dumps({
        "model": cfg.model, "messages": [m.to_dict() for m in messages],
        "stream": True, "options": {"temperature": cfg.temperature}
    }).encode()
    req = urllib.request.Request(url, data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=cfg.timeout) as r:
        for line in r:
            line = line.decode().strip()
            if not line:
                continue
            try:
                chunk = json.loads(line)
                token = chunk.get("message", {}).get("content", "")
                if token:
                    yield token
                if chunk.get("done"):
                    break
            except json.JSONDecodeError:
                continue


def _stream_openai_compat(cfg: ProviderConfig, messages: List[Message]) -> Iterator[str]:
    api_key  = cfg.api_key or os.getenv("OPENAI_API_KEY", "")
    base_url = (cfg.base_url or "https://api.openai.com/v1") + "/chat/completions"
    payload  = json.dumps({
        "model": cfg.model, "messages": [m.to_dict() for m in messages],
        "temperature": cfg.temperature, "max_tokens": cfg.max_tokens, "stream": True
    }).encode()
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    req = urllib.request.Request(base_url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=cfg.timeout) as r:
        for line in r:
            line = line.decode().strip()
            if not line.startswith("data: "):
                continue
            data = line[6:]
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
                delta = chunk["choices"][0].get("delta", {}).get("content", "")
                if delta:
                    yield delta
            except (json.JSONDecodeError, KeyError):
                continue


# ── LLM Router ─────────────────────────────────────────────────────────────────

class LLMRouter:
    """
    Single interface to all LLM providers.
    Auto-detects available providers based on environment variables.
    Tries providers in priority order with circuit-breaker fallback.
    """

    def __init__(self, configs: Optional[List[ProviderConfig]] = None):
        self._cb     = CircuitBreaker()
        self._configs = configs or self._auto_detect()
        self._total_cost = 0.0
        self._total_calls = 0

    # ── Auto-detection ─────────────────────────────────────────────

    def _auto_detect(self) -> List[ProviderConfig]:
        configs: List[ProviderConfig] = []

        # OpenAI
        if os.getenv("OPENAI_API_KEY"):
            configs.append(ProviderConfig(
                provider=Provider.OPENAI, model=os.getenv("NOVA_OPENAI_MODEL", "gpt-4o"),
                api_key=os.getenv("OPENAI_API_KEY")))

        # Anthropic
        if os.getenv("ANTHROPIC_API_KEY"):
            configs.append(ProviderConfig(
                provider=Provider.ANTHROPIC,
                model=os.getenv("NOVA_ANTHROPIC_MODEL", "claude-sonnet-4-5"),
                api_key=os.getenv("ANTHROPIC_API_KEY")))

        # Gemini
        if os.getenv("GEMINI_API_KEY"):
            configs.append(ProviderConfig(
                provider=Provider.GEMINI,
                model=os.getenv("NOVA_GEMINI_MODEL", "gemini-2.0-flash"),
                api_key=os.getenv("GEMINI_API_KEY")))

        # Always add Ollama as final fallback
        configs.append(ProviderConfig(
            provider=Provider.OLLAMA,
            model=os.getenv("NOVA_LLM_MODEL", "qwen3:8b"),
            base_url=os.getenv("NOVA_LLM_URL", "http://localhost:11434")))

        return configs

    # ── Core chat ──────────────────────────────────────────────────

    def chat(self, prompt: str, system: str = "", messages: Optional[List[Message]] = None,
             schema: Optional[Dict] = None, provider: Optional[Provider] = None,
             retries: int = 3) -> LLMResponse:
        """Send a chat message. Returns LLMResponse."""
        msgs = list(messages or [])
        if system:
            msgs.insert(0, Message(role="system", content=system))
        if prompt:
            msgs.append(Message(role="user", content=prompt))

        configs = ([c for c in self._configs if c.provider == provider]
                   if provider else self._configs)

        last_err: Optional[Exception] = None
        for cfg in configs:
            pname = cfg.provider.value
            if self._cb.is_open(pname):
                continue
            for attempt in range(retries):
                try:
                    resp = self._dispatch(cfg, msgs, schema)
                    self._cb.record_success(pname)
                    self._total_cost  += resp.cost_usd
                    self._total_calls += 1
                    return resp
                except Exception as e:
                    last_err = e
                    wait = 2 ** attempt
                    if attempt < retries - 1:
                        time.sleep(wait)
                    else:
                        self._cb.record_failure(pname)
                        print(f"  ⚠️  [{pname}] failed after {retries} retries: {e}")

        raise RuntimeError(f"All LLM providers failed. Last error: {last_err}")

    def chat_structured(self, prompt: str, schema: Dict, system: str = "") -> Dict:
        """Return a structured dict from the LLM."""
        resp = self.chat(prompt, system=system, schema=schema)
        try:
            return json.loads(resp.content)
        except json.JSONDecodeError:
            # Attempt extraction of JSON block
            import re
            m = re.search(r"\{.*\}", resp.content, re.DOTALL)
            if m:
                return json.loads(m.group())
            return {"raw": resp.content}

    def stream(self, prompt: str, system: str = "",
               provider: Optional[Provider] = None) -> Iterator[str]:
        """Stream tokens from the LLM."""
        msgs = []
        if system:
            msgs.append(Message(role="system", content=system))
        msgs.append(Message(role="user", content=prompt))

        configs = ([c for c in self._configs if c.provider == provider]
                   if provider else self._configs)

        for cfg in configs:
            if self._cb.is_open(cfg.provider.value):
                continue
            try:
                yield from self._dispatch_stream(cfg, msgs)
                return
            except Exception as e:
                self._cb.record_failure(cfg.provider.value)
                print(f"  ⚠️  Stream failed on {cfg.provider.value}: {e}")
                continue

        raise RuntimeError("All providers failed to stream.")

    # ── Dispatch ───────────────────────────────────────────────────

    def _dispatch(self, cfg: ProviderConfig, messages: List[Message],
                  schema: Optional[Dict]) -> LLMResponse:
        if cfg.provider == Provider.OLLAMA:
            return _call_ollama(cfg, messages, schema)
        elif cfg.provider in (Provider.OPENAI, Provider.OPENAI_COMPAT):
            return _call_openai_compat(cfg, messages, schema)
        elif cfg.provider == Provider.ANTHROPIC:
            return _call_anthropic(cfg, messages, schema)
        elif cfg.provider == Provider.GEMINI:
            return _call_gemini(cfg, messages, schema)
        else:
            raise ValueError(f"Unknown provider: {cfg.provider}")

    def _dispatch_stream(self, cfg: ProviderConfig,
                         messages: List[Message]) -> Iterator[str]:
        if cfg.provider == Provider.OLLAMA:
            return _stream_ollama(cfg, messages)
        elif cfg.provider in (Provider.OPENAI, Provider.OPENAI_COMPAT):
            return _stream_openai_compat(cfg, messages)
        else:
            # Fallback: non-streaming for providers without stream support here
            resp = self._dispatch(cfg, messages, None)
            return iter([resp.content])

    # ── Stats ──────────────────────────────────────────────────────

    def stats(self) -> Dict:
        return {
            "total_calls": self._total_calls,
            "total_cost_usd": round(self._total_cost, 6),
            "providers_configured": [c.provider.value for c in self._configs],
        }

    def available_providers(self) -> List[str]:
        return [c.provider.value for c in self._configs
                if not self._cb.is_open(c.provider.value)]


# ── Singleton ──────────────────────────────────────────────────────────────────
_router: Optional[LLMRouter] = None

def get_router() -> LLMRouter:
    global _router
    if _router is None:
        _router = LLMRouter()
    return _router


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Nova LLM Router")
    parser.add_argument("prompt", nargs="?", default="Say hello and list your capabilities.")
    parser.add_argument("--stream", action="store_true")
    parser.add_argument("--provider", choices=[p.value for p in Provider])
    args = parser.parse_args()

    router = get_router()
    print(f"Available providers: {router.available_providers()}\n")

    if args.stream:
        for token in router.stream(args.prompt,
                                   provider=Provider(args.provider) if args.provider else None):
            print(token, end="", flush=True)
        print()
    else:
        resp = router.chat(args.prompt,
                           provider=Provider(args.provider) if args.provider else None)
        print(f"[{resp.provider.value} / {resp.model}] {resp.latency_ms:.0f}ms "
              f"${resp.cost_usd:.6f}")
        print(resp.content)
    print(f"\nSession stats: {router.stats()}")
