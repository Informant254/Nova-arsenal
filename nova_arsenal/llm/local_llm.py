"""
Local LLM discovery and registration (Ollama and OpenAI-compatible servers).

No cloud account required. Users can run fully offline with Ollama, LM Studio,
llama.cpp server, vLLM, etc.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URLS = (
    os.getenv("NOVA_LLM_URL", "").strip(),
    os.getenv("OLLAMA_HOST", "").strip(),
    "http://127.0.0.1:11434",
    "http://localhost:11434",
)


@dataclass
class LocalLLMEndpoint:
    """A discovered or configured local model server."""

    kind: str  # ollama | openai_compatible
    base_url: str
    models: List[str] = field(default_factory=list)
    healthy: bool = False
    preferred_model: str = ""
    label: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "base_url": self.base_url,
            "models": self.models[:50],
            "healthy": self.healthy,
            "preferred_model": self.preferred_model or (self.models[0] if self.models else ""),
            "label": self.label or self.kind,
            "error": self.error,
        }


def _clean_url(url: str) -> str:
    u = (url or "").strip().rstrip("/")
    if u.startswith("http://") or u.startswith("https://"):
        return u
    if u:
        return f"http://{u}"
    return ""


def probe_ollama(base_url: str = "", timeout: float = 3.0) -> LocalLLMEndpoint:
    """Probe an Ollama server and list tags."""
    url = _clean_url(base_url) or "http://127.0.0.1:11434"
    ep = LocalLLMEndpoint(kind="ollama", base_url=url, label="Ollama (local)")
    try:
        with httpx.Client(timeout=timeout) as client:
            # tags endpoint
            r = client.get(f"{url}/api/tags")
            if r.status_code == 200:
                data = r.json()
                models = []
                for m in data.get("models") or []:
                    name = m.get("name") or m.get("model") or ""
                    if name:
                        models.append(name)
                ep.models = models
                ep.healthy = True
                env_model = os.getenv("LLM_MODEL", "") or os.getenv("OLLAMA_MODEL", "")
                if env_model and env_model in models:
                    ep.preferred_model = env_model
                elif models:
                    ep.preferred_model = models[0]
                return ep
            # fallback: version
            r2 = client.get(f"{url}/api/version")
            if r2.status_code == 200:
                ep.healthy = True
                ep.preferred_model = os.getenv("OLLAMA_MODEL", "llama3.2")
                return ep
            ep.error = f"HTTP {r.status_code}"
    except Exception as exc:  # noqa: BLE001
        ep.error = str(exc)
        logger.debug("Ollama probe failed at %s: %s", url, exc)
    return ep


def probe_openai_compatible(base_url: str, timeout: float = 3.0) -> LocalLLMEndpoint:
    """Probe LM Studio / vLLM / llama.cpp OpenAI-compatible /v1/models."""
    url = _clean_url(base_url)
    ep = LocalLLMEndpoint(kind="openai_compatible", base_url=url, label="Local OpenAI-compatible")
    if not url:
        ep.error = "empty url"
        return ep
    try:
        with httpx.Client(timeout=timeout) as client:
            # Try with and without /v1
            for path in (f"{url}/v1/models", f"{url}/models"):
                r = client.get(path)
                if r.status_code == 200:
                    data = r.json()
                    models = []
                    for m in data.get("data") or []:
                        mid = m.get("id") or m.get("name") or ""
                        if mid:
                            models.append(mid)
                    ep.models = models
                    ep.healthy = True
                    ep.preferred_model = models[0] if models else "local-model"
                    # Normalize base for chat completions
                    if path.endswith("/v1/models"):
                        ep.base_url = url if url.endswith("/v1") else f"{url.rstrip('/')}/v1"
                    return ep
            ep.error = "no /v1/models endpoint"
    except Exception as exc:  # noqa: BLE001
        ep.error = str(exc)
    return ep


def discover_local_llms(
    extra_urls: Optional[List[str]] = None,
    timeout: float = 3.0,
) -> List[LocalLLMEndpoint]:
    """Discover local LLM servers on common endpoints."""
    found: List[LocalLLMEndpoint] = []
    seen: set = set()

    urls = [u for u in DEFAULT_OLLAMA_URLS if u]
    for u in extra_urls or []:
        if u:
            urls.append(u)
    # LM Studio default
    urls.append("http://127.0.0.1:1234")
    urls.append("http://127.0.0.1:8080")

    for raw in urls:
        url = _clean_url(raw)
        if not url or url in seen:
            continue
        seen.add(url)
        # Prefer ollama probe on 11434
        if "11434" in url or "ollama" in url.lower():
            ep = probe_ollama(url, timeout=timeout)
            if ep.healthy:
                found.append(ep)
            continue
        # Try ollama first then openai-compatible
        ep = probe_ollama(url, timeout=timeout)
        if ep.healthy:
            found.append(ep)
            continue
        ep2 = probe_openai_compatible(url, timeout=timeout)
        if ep2.healthy:
            found.append(ep2)

    return found


def local_llm_status() -> Dict[str, Any]:
    endpoints = discover_local_llms()
    return {
        "available": any(e.healthy for e in endpoints),
        "endpoints": [e.to_dict() for e in endpoints],
        "how_to": {
            "ollama_install": "https://ollama.com — then: ollama pull llama3.2",
            "use_local": "nova-agent login --provider ollama",
            "custom_url": "nova-agent login --provider ollama --url http://127.0.0.1:11434 --model llama3.2",
            "openai_compatible": (
                "nova-agent login --provider local --url http://127.0.0.1:1234/v1 --model local-model"
            ),
            "env": "export LLM_PROVIDER=ollama LLM_MODEL=llama3.2 NOVA_LLM_URL=http://127.0.0.1:11434",
        },
    }
