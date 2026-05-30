#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   🧠 NOVA REASONING CORE — LLM BACKBONE                        ║
║                                                                  ║
║   Unified LLM interface used by all Nova modules.               ║
║   Connects to Ollama (local) or any OpenAI-compatible backend.  ║
║                                                                  ║
║   Config via environment variables:                             ║
║     NOVA_LLM_URL   — default: http://localhost:11434            ║
║     NOVA_LLM_MODEL — default: llama3                            ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

import requests

_OLLAMA_URL  = os.getenv("NOVA_LLM_URL",   "http://localhost:11434")
_OLLAMA_MDL  = os.getenv("NOVA_LLM_MODEL",  "llama3")
_OPENAI_URL  = os.getenv("NOVA_OPENAI_URL", "")   # optional OpenAI-compatible backend
_OPENAI_KEY  = os.getenv("NOVA_OPENAI_KEY", "")
_TIMEOUT     = int(os.getenv("NOVA_LLM_TIMEOUT", "60"))


class NovaReasoningCore:
    """
    Thin, reliable LLM wrapper.

    Priority order:
      1. OpenAI-compatible API if NOVA_OPENAI_URL + NOVA_OPENAI_KEY are set
      2. Ollama /api/chat  (Llama 3, Mistral, etc.)
      3. Graceful degradation — returns None when no LLM is reachable

    All Nova modules import this via:
        from nova_reasoning_core import NovaReasoningCore, get_reasoning_core
    """

    def __init__(self):
        self._backend: Optional[str] = None
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "Nova/3.0"
        self._probe()

    def _probe(self):
        """Auto-detect available backend on startup."""
        # 1. OpenAI-compatible
        if _OPENAI_URL and _OPENAI_KEY:
            try:
                r = self._session.get(_OPENAI_URL.rstrip("/") + "/models",
                                      headers={"Authorization": f"Bearer {_OPENAI_KEY}"},
                                      timeout=5)
                if r.status_code in (200, 401):
                    self._backend = "openai"
                    print(f"  🧠 ReasoningCore: OpenAI-compatible backend at {_OPENAI_URL}")
                    return
            except Exception:
                pass

        # 2. Ollama
        try:
            r = self._session.get(f"{_OLLAMA_URL}/api/tags", timeout=5)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                # Pick best available model
                preferred = [_OLLAMA_MDL, "llama3", "llama3:latest", "mistral",
                             "llama2", "codellama"]
                chosen = next((m for p in preferred for m in models if p in m), None)
                if chosen:
                    self._model   = chosen
                    self._backend = "ollama"
                    print(f"  🧠 ReasoningCore: Ollama ({chosen})")
                    return
                elif models:
                    self._model   = models[0]
                    self._backend = "ollama"
                    print(f"  🧠 ReasoningCore: Ollama ({self._model})")
                    return
        except Exception:
            pass

        print("  🧠 ReasoningCore: No LLM available — running in heuristic-only mode")
        self._backend = None

    @property
    def available(self) -> bool:
        return self._backend is not None

    def _chat(
        self,
        messages: List[Dict],
        temperature: float = 0.2,
        max_tokens: int    = 1000,
        retries: int       = 2,
    ) -> Optional[str]:
        """Send a chat request. Returns the assistant text or None."""
        if not self.available:
            return None

        for attempt in range(retries + 1):
            try:
                if self._backend == "openai":
                    return self._openai_chat(messages, temperature, max_tokens)
                else:
                    return self._ollama_chat(messages, temperature, max_tokens)
            except requests.exceptions.Timeout:
                if attempt < retries:
                    time.sleep(2 ** attempt)
                    continue
                return None
            except Exception:
                return None
        return None

    def _ollama_chat(self, messages: List[Dict], temperature: float,
                     max_tokens: int) -> Optional[str]:
        payload = {
            "model":    getattr(self, "_model", _OLLAMA_MDL),
            "messages": messages,
            "stream":   False,
            "options":  {"temperature": temperature, "num_predict": max_tokens},
        }
        r = self._session.post(f"{_OLLAMA_URL}/api/chat",
                               json=payload, timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "").strip()

    def _openai_chat(self, messages: List[Dict], temperature: float,
                     max_tokens: int) -> Optional[str]:
        payload = {
            "model":      _OLLAMA_MDL,
            "messages":   messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        r = self._session.post(
            _OPENAI_URL.rstrip("/") + "/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {_OPENAI_KEY}"},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()

    def _parse_json(self, text: Optional[str]) -> Any:
        """Extract and parse JSON from LLM response (handles markdown fences)."""
        if not text:
            return None
        # Strip ```json fences
        text = re.sub(r'^```(?:json)?\s*', '', text.strip(), flags=re.IGNORECASE)
        text = re.sub(r'\s*```$', '', text.strip())
        # Try direct parse
        try:
            return json.loads(text)
        except Exception:
            pass
        # Try finding first JSON block
        for pattern in [r'\{[\s\S]*\}', r'\[[\s\S]*\]']:
            m = re.search(pattern, text)
            if m:
                try:
                    return json.loads(m.group())
                except Exception:
                    pass
        return None

    def think(self, prompt: str, system: str = None, max_tokens: int = 800) -> Optional[str]:
        """Simple one-shot completion."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self._chat(messages, max_tokens=max_tokens)

    def reason_about_finding(self, finding: Dict) -> Dict:
        """Ask LLM to reason about a security finding and suggest next steps."""
        if not self.available:
            return {}
        prompt = f"""Security finding:
{json.dumps(finding, indent=2, default=str)[:800]}

1. Is this a real vulnerability? What's the confidence level?
2. What is the maximum exploitable impact?
3. What single action would escalate this further?

Return JSON: {{"real": true, "confidence": "high|medium|low", "impact": "...", "next_step": "..."}}"""
        result = self._chat([{"role": "user", "content": prompt}], max_tokens=400)
        return self._parse_json(result) or {}


# ── Singleton ─────────────────────────────────────────────────────

_core: Optional[NovaReasoningCore] = None

def get_reasoning_core() -> NovaReasoningCore:
    global _core
    if _core is None:
        _core = NovaReasoningCore()
    return _core
