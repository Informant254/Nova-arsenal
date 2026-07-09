"""
Bring-your-own-key (BYOK) helpers.

Maps LLM providers to env vars, default models, and base URLs so users can
plug in OpenAI / Anthropic / Gemini / OpenRouter / etc. subscriptions without
hand-editing YAML.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class ProviderKeySpec:
    name: str
    env_keys: Tuple[str, ...]  # first non-empty wins
    default_model: str
    default_url: str = ""
    # Optional alternate env for model override
    model_env: str = ""


# Canonical provider → key env mapping
PROVIDER_SPECS: Dict[str, ProviderKeySpec] = {
    "openai": ProviderKeySpec(
        name="openai",
        env_keys=("OPENAI_API_KEY", "CODEX_API_KEY"),
        default_model="gpt-4o",
        default_url="https://api.openai.com/v1",
        model_env="OPENAI_MODEL",
    ),
    "local": ProviderKeySpec(
        name="local",
        env_keys=(),  # OpenAI-compatible local server; no key
        default_model="local-model",
        default_url="http://127.0.0.1:1234/v1",
        model_env="LOCAL_LLM_MODEL",
    ),
    "anthropic": ProviderKeySpec(
        name="anthropic",
        env_keys=("ANTHROPIC_API_KEY",),
        default_model="claude-sonnet-4-20250514",
        default_url="https://api.anthropic.com",
        model_env="ANTHROPIC_MODEL",
    ),
    "gemini": ProviderKeySpec(
        name="gemini",
        env_keys=("GOOGLE_API_KEY", "GEMINI_API_KEY"),
        default_model="gemini-2.5-flash",
        default_url="https://generativelanguage.googleapis.com",
        model_env="GEMINI_MODEL",
    ),
    "openrouter": ProviderKeySpec(
        name="openrouter",
        env_keys=("OPENROUTER_API_KEY",),
        default_model="openrouter/auto",
        default_url="https://openrouter.ai/api/v1",
        model_env="OPENROUTER_MODEL",
    ),
    "deepseek": ProviderKeySpec(
        name="deepseek",
        env_keys=("DEEPSEEK_API_KEY",),
        default_model="deepseek-chat",
        default_url="https://api.deepseek.com/v1",
        model_env="DEEPSEEK_MODEL",
    ),
    "qwen": ProviderKeySpec(
        name="qwen",
        env_keys=("DASHSCOPE_API_KEY", "QWEN_API_KEY"),
        default_model="qwen-max",
        default_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        model_env="QWEN_MODEL",
    ),
    "huggingface": ProviderKeySpec(
        name="huggingface",
        env_keys=("HUGGINGFACE_API_KEY", "HF_TOKEN"),
        default_model="meta-llama/Llama-3.3-70B-Instruct",
        default_url="https://api-inference.huggingface.co",
        model_env="HUGGINGFACE_MODEL",
    ),
    "opencode": ProviderKeySpec(
        name="opencode",
        env_keys=("OPCODE_API_KEY", "OPENCODE_API_KEY"),
        default_model="opencode-qwen-72b",
        default_url="",
        model_env="OPENCODE_MODEL",
    ),
    "ollama": ProviderKeySpec(
        name="ollama",
        env_keys=(),  # no key required
        default_model="deepseek-r1",
        default_url="http://localhost:11434",
        model_env="OLLAMA_MODEL",
    ),
}

# Aliases users might set as LLM_PROVIDER
PROVIDER_ALIASES: Dict[str, str] = {
    "gpt": "openai",
    "chatgpt": "openai",
    "codex": "openai",
    "openai-codex": "openai",
    "claude": "anthropic",
    "google": "gemini",
    "google-gemini": "gemini",
    "hf": "huggingface",
    "dashscope": "qwen",
    "or": "openrouter",
    "lmstudio": "local",
    "vllm": "local",
    "llamacpp": "local",
}


def normalize_provider(name: str) -> str:
    n = (name or "").strip().lower()
    return PROVIDER_ALIASES.get(n, n)


def resolve_api_key(provider: str, explicit: str = "") -> str:
    """
    Return a usable credential for the provider.

    Priority:
      1. Explicit argument
      2. Account login token (Claude Code / Codex / OAuth / pasted session)
      3. Classic API key environment variables
    """
    if explicit and not _is_placeholder(explicit):
        return explicit
    prov = normalize_provider(provider)

    # Account-style sessions (Codex / Claude Code / Google OAuth)
    try:
        from nova_arsenal.llm.account_auth import account_token_for

        acct = account_token_for(prov)
        if acct and not _is_placeholder(acct):
            return acct
    except Exception:  # noqa: BLE001
        pass

    spec = PROVIDER_SPECS.get(prov)
    if not spec:
        return explicit or ""
    for env_name in spec.env_keys:
        val = os.getenv(env_name, "").strip()
        if val and not _is_placeholder(val):
            return val
    return ""


def resolve_model(provider: str, explicit: str = "") -> str:
    if explicit and not _is_placeholder(explicit):
        return explicit
    # Global LLM_MODEL wins when provider matches LLM_PROVIDER or primary unset
    global_model = os.getenv("LLM_MODEL", "").strip() or os.getenv("NOVA_LLM_MODEL", "").strip()
    preferred = normalize_provider(os.getenv("LLM_PROVIDER", "") or os.getenv("NOVA_LLM_PROVIDER", ""))
    prov = normalize_provider(provider)
    if global_model and (not preferred or preferred == prov):
        return global_model
    spec = PROVIDER_SPECS.get(prov)
    if spec and spec.model_env:
        m = os.getenv(spec.model_env, "").strip()
        if m:
            return m
    return (spec.default_model if spec else explicit) or explicit


def resolve_url(provider: str, explicit: str = "") -> str:
    if explicit and not _is_placeholder(explicit):
        # Allow NOVA_LLM_URL override for ollama primary
        return explicit
    prov = normalize_provider(provider)
    if prov == "ollama":
        return (
            os.getenv("NOVA_LLM_URL", "").strip()
            or os.getenv("OLLAMA_HOST", "").strip()
            or PROVIDER_SPECS["ollama"].default_url
        )
    spec = PROVIDER_SPECS.get(prov)
    return (spec.default_url if spec else "") or explicit


def env_providers_with_keys() -> List[str]:
    """List cloud providers that have API keys present in the environment."""
    found: List[str] = []
    for name, spec in PROVIDER_SPECS.items():
        if name == "ollama":
            continue
        if resolve_api_key(name):
            found.append(name)
    return found


def preferred_provider_from_env() -> Optional[str]:
    raw = os.getenv("LLM_PROVIDER", "").strip() or os.getenv("NOVA_LLM_PROVIDER", "").strip()
    if raw:
        return normalize_provider(raw)
    # Prefer first available key in a sensible order
    for name in (
        "openai",
        "anthropic",
        "gemini",
        "openrouter",
        "deepseek",
        "qwen",
        "huggingface",
        "opencode",
    ):
        if resolve_api_key(name):
            return name
    return None


def provider_status_snapshot() -> List[Dict[str, object]]:
    """Non-secret status for UI /health."""
    rows: List[Dict[str, object]] = []
    for name, spec in PROVIDER_SPECS.items():
        key = resolve_api_key(name) if name != "ollama" else ""
        rows.append(
            {
                "provider": name,
                "configured": bool(key) if name != "ollama" else True,
                "requires_key": name != "ollama",
                "key_env": list(spec.env_keys),
                "default_model": resolve_model(name, spec.default_model),
                "has_key": bool(key),
                # Never return the key; only prefix hint for UX
                "key_hint": (key[:7] + "…") if key and len(key) > 8 else ("" if not key else "set"),
            }
        )
    return rows


def _is_placeholder(value: str) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return True
    placeholders = {
        "changeme",
        "change-me",
        "your_key_here",
        "your-key-here",
        "sk-xxx",
        "xxx",
        "todo",
        "${openai_api_key}",
        "${anthropic_api_key}",
        "${google_api_key}",
        "${openrouter_api_key}",
    }
    if v in placeholders:
        return True
    if v.startswith("${") and v.endswith("}"):
        return True
    return False


def load_dotenv_files() -> List[str]:
    """
    Load .env files if present. Uses python-dotenv when installed; otherwise a
    minimal parser. Returns list of files loaded.
    """
    candidates = [
        ".env",
        "config/.env",
        os.path.expanduser("~/.nova/.env"),
    ]
    # Walk up from cwd a bit for monorepo layouts
    cwd = os.getcwd()
    candidates.extend(
        [
            os.path.join(cwd, ".env"),
            os.path.join(cwd, "config", ".env"),
            os.path.join(os.path.dirname(cwd), ".env"),
        ]
    )
    loaded: List[str] = []
    seen = set()
    for path in candidates:
        ap = os.path.abspath(path)
        if ap in seen or not os.path.isfile(ap):
            continue
        seen.add(ap)
        if _load_env_file(ap):
            loaded.append(ap)
    return loaded


def _load_env_file(path: str) -> bool:
    try:
        from dotenv import load_dotenv

        load_dotenv(path, override=False)
        return True
    except ImportError:
        pass
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip("'").strip('"')
                if key and key not in os.environ:
                    os.environ[key] = val
        return True
    except OSError:
        return False
