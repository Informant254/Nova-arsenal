"""
Nova-Arsenal Configuration Module

Handles loading and validating configuration from YAML files and environment
variables. Supports bring-your-own-key (BYOK): set OPENAI_API_KEY /
ANTHROPIC_API_KEY / etc. or LLM_PROVIDER + LLM_MODEL and the agent uses them.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from nova_arsenal.llm.keys import (
    env_providers_with_keys,
    load_dotenv_files,
    normalize_provider,
    preferred_provider_from_env,
    resolve_api_key,
    resolve_model,
    resolve_url,
)

logger = logging.getLogger(__name__)


@dataclass
class AgentConfig:
    name: str = "nova-agent"
    version: str = "1.3.0"
    workspace: str = "~/nova_workspace"
    max_steps: int = 40
    reflect_every: int = 5
    auto_plan: bool = True
    auto_visual: bool = True
    auto_cve: bool = True


@dataclass
class LLMProviderConfig:
    provider: str = "ollama"
    model: str = "deepseek-r1"
    url: str = "http://localhost:11434"
    api_key: str = ""
    timeout: int = 120

    def resolved(self) -> "LLMProviderConfig":
        """Return a copy with env-resolved key/model/url."""
        prov = normalize_provider(self.provider)
        return LLMProviderConfig(
            provider=prov,
            model=resolve_model(prov, self.model),
            url=resolve_url(prov, self.url),
            api_key=resolve_api_key(prov, self.api_key),
            timeout=self.timeout,
        )


@dataclass
class LLMConfig:
    primary: LLMProviderConfig = field(default_factory=LLMProviderConfig)
    fallbacks: List[LLMProviderConfig] = field(default_factory=list)
    routing_strategy: str = "balanced"
    fallback_threshold: int = 3
    max_retries: int = 3


@dataclass
class SecurityConfig:
    permission_profile: str = "scoped"
    blocked_patterns: List[str] = field(default_factory=list)
    allowed_tools: List[str] = field(default_factory=list)
    blocked_hosts: List[str] = field(default_factory=list)
    strict_mode: bool = False


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "json"
    file: str = ""
    max_size_mb: int = 100
    backup_count: int = 5


@dataclass
class DatabaseConfig:
    url: str = "sqlite+aiosqlite:///nova.db"
    echo: bool = False


@dataclass
class OAuthConfig:
    github_client_id: str = ""
    github_client_secret: str = ""
    github_redirect_uri: str = "http://localhost:8000/api/auth/oauth/github/callback"
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/api/auth/oauth/google/callback"
    state_secret: str = ""
    default_tier: str = "free"
    free_api_calls_per_day: int = 100
    pro_api_calls_per_day: int = 10000
    enterprise_api_calls_per_day: int = 100000


@dataclass
class AuthConfig:
    jwt_secret: str = ""
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    oauth: OAuthConfig = field(default_factory=OAuthConfig)


@dataclass
class NovaConfig:
    agent: AgentConfig = field(default_factory=AgentConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    scope: List[str] = field(default_factory=list)


def _resolve_env_vars(value: str) -> str:
    """Resolve ${ENV_VAR} patterns in strings."""
    if not isinstance(value, str):
        return value

    if value.startswith("${") and value.endswith("}"):
        env_var = value[2:-1]
        return os.getenv(env_var, "")

    return value


def _process_config(data: Any) -> Any:
    """Recursively process environment variables in config."""
    if isinstance(data, dict):
        return {k: _process_config(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_process_config(item) for item in data]
    if isinstance(data, str):
        return _resolve_env_vars(data)
    return data


def _provider_from_dict(raw: Dict[str, Any]) -> LLMProviderConfig:
    # Filter unknown keys so older/newer YAML stays compatible
    allowed = {"provider", "model", "url", "api_key", "timeout"}
    cleaned = {k: v for k, v in (raw or {}).items() if k in allowed}
    cfg = LLMProviderConfig(**cleaned)
    return cfg.resolved()


def _auto_llm_from_env(existing: Optional[LLMConfig] = None) -> LLMConfig:
    """
    Build / enrich LLM config from environment.

    Priority for primary:
      1. LLM_PROVIDER / NOVA_LLM_PROVIDER if set
      2. Existing YAML primary if it has a usable key (or is ollama)
      3. First available API key (openai → anthropic → …)
      4. Ollama local default
    """
    base = existing or LLMConfig()
    preferred = preferred_provider_from_env()

    # Resolve YAML primary with env keys
    primary = base.primary.resolved() if base.primary else LLMProviderConfig().resolved()

    if preferred:
        # User explicitly chose a provider via env
        primary = LLMProviderConfig(
            provider=preferred,
            model=resolve_model(preferred, primary.model if primary.provider == preferred else ""),
            url=resolve_url(preferred, ""),
            api_key=resolve_api_key(preferred, ""),
            timeout=primary.timeout,
        ).resolved()
    elif primary.provider != "ollama" and not primary.api_key:
        # Cloud primary in YAML but no key → switch to first available or ollama
        auto = preferred_provider_from_env()
        if auto:
            primary = LLMProviderConfig(
                provider=auto,
                model=resolve_model(auto),
                url=resolve_url(auto),
                api_key=resolve_api_key(auto),
                timeout=primary.timeout,
            ).resolved()
        else:
            primary = LLMProviderConfig(
                provider="ollama",
                model=resolve_model("ollama", os.getenv("LLM_MODEL", "deepseek-r1")),
                url=resolve_url("ollama"),
            ).resolved()

    # Build fallbacks: keep YAML fallbacks (resolved) + any env keys not already listed
    fallbacks: List[LLMProviderConfig] = []
    seen = {primary.provider}

    for fb in base.fallbacks or []:
        resolved = fb.resolved() if hasattr(fb, "resolved") else _provider_from_dict(fb.__dict__)
        if resolved.provider in seen:
            continue
        if resolved.provider != "ollama" and not resolved.api_key:
            continue  # skip unusable cloud fallbacks
        fallbacks.append(resolved)
        seen.add(resolved.provider)

    for name in env_providers_with_keys():
        if name in seen:
            continue
        fallbacks.append(
            LLMProviderConfig(
                provider=name,
                model=resolve_model(name),
                url=resolve_url(name),
                api_key=resolve_api_key(name),
            ).resolved()
        )
        seen.add(name)

    # Always offer ollama as last resort if not already primary
    if "ollama" not in seen:
        fallbacks.append(
            LLMProviderConfig(
                provider="ollama",
                model=resolve_model("ollama"),
                url=resolve_url("ollama"),
            ).resolved()
        )

    return LLMConfig(
        primary=primary,
        fallbacks=fallbacks,
        routing_strategy=base.routing_strategy if base else "balanced",
        fallback_threshold=base.fallback_threshold if base else 3,
        max_retries=base.max_retries if base else 3,
    )


def load_config(config_path: Optional[str] = None) -> NovaConfig:
    """
    Load configuration from a YAML file + environment.

    BYOK: export your provider API keys (or set LLM_PROVIDER/LLM_MODEL) and
    Nova will route to them even without a full settings.yaml.
    """
    # Load .env early so ${VAR} and key resolution see them
    loaded_env = load_dotenv_files()
    if loaded_env:
        logger.info("Loaded env files: %s", ", ".join(loaded_env))

    data: Dict[str, Any] = {}
    path = config_path
    if path is None:
        # Search common locations
        for candidate in (
            os.getenv("NOVA_CONFIG", ""),
            "settings.yaml",
            "config/settings.yaml",
            "config/settings.example.yaml",
        ):
            if candidate and Path(candidate).exists():
                path = candidate
                break

    if path and Path(path).exists():
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        data = _process_config(data)
        logger.info("Loaded config from %s", path)

    # Agent
    agent_raw = dict(data.get("agent") or {})
    # Filter unknown fields
    agent_fields = {f.name for f in AgentConfig.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    agent = AgentConfig(**{k: v for k, v in agent_raw.items() if k in agent_fields})

    # LLM from YAML then enrich with env BYOK
    llm_raw = data.get("llm") or {}
    primary_raw = llm_raw.get("primary") or {}
    fallbacks_raw = llm_raw.get("fallbacks") or []
    routing = llm_raw.get("routing") or {}

    yaml_llm = LLMConfig(
        primary=_provider_from_dict(primary_raw) if primary_raw else LLMProviderConfig(),
        fallbacks=[_provider_from_dict(fb) for fb in fallbacks_raw if isinstance(fb, dict)],
        routing_strategy=str(routing.get("strategy") or llm_raw.get("routing_strategy") or "balanced"),
        fallback_threshold=int(routing.get("fallback_threshold") or 3),
        max_retries=int(routing.get("max_retries") or 3),
    )
    llm = _auto_llm_from_env(yaml_llm)

    # Security / logging / database / auth
    sec_raw = data.get("security") or {}
    sec_fields = {f.name for f in SecurityConfig.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    security = SecurityConfig(**{k: v for k, v in sec_raw.items() if k in sec_fields})

    log_raw = data.get("logging") or {}
    log_fields = {f.name for f in LoggingConfig.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    logging_cfg = LoggingConfig(**{k: v for k, v in log_raw.items() if k in log_fields})
    if os.getenv("LOG_LEVEL"):
        logging_cfg.level = os.getenv("LOG_LEVEL", logging_cfg.level)

    db_raw = data.get("database") or {}
    db_fields = {f.name for f in DatabaseConfig.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    database = DatabaseConfig(**{k: v for k, v in db_raw.items() if k in db_fields})
    if os.getenv("DATABASE_URL"):
        database.url = os.getenv("DATABASE_URL", database.url)

    auth_raw = data.get("auth") or {}
    oauth_raw = auth_raw.get("oauth") or {}
    oauth_fields = {f.name for f in OAuthConfig.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    oauth = OAuthConfig(**{k: v for k, v in oauth_raw.items() if k in oauth_fields})
    auth = AuthConfig(
        jwt_secret=auth_raw.get("jwt_secret") or os.getenv("JWT_SECRET", ""),
        access_token_expire_minutes=int(auth_raw.get("access_token_expire_minutes") or 15),
        refresh_token_expire_days=int(auth_raw.get("refresh_token_expire_days") or 7),
        oauth=oauth,
    )

    scope = []
    if isinstance(data.get("scope"), dict):
        scope = list(data["scope"].get("targets") or [])
    elif isinstance(data.get("scope"), list):
        scope = list(data["scope"])

    logger.info(
        "LLM primary=%s/%s key=%s fallbacks=%s",
        llm.primary.provider,
        llm.primary.model,
        "yes" if llm.primary.api_key or llm.primary.provider == "ollama" else "no",
        [f.provider for f in llm.fallbacks],
    )

    return NovaConfig(
        agent=agent,
        llm=llm,
        security=security,
        logging=logging_cfg,
        database=database,
        auth=auth,
        scope=scope,
    )


# Global config singleton
_config: Optional[NovaConfig] = None


def get_config() -> NovaConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config(config_path: Optional[str] = None) -> NovaConfig:
    """Reload configuration from file + env (also resets LLM router if imported)."""
    global _config
    _config = load_config(config_path)
    try:
        from nova_arsenal.llm.router import reset_llm_router

        reset_llm_router()
    except Exception:  # noqa: BLE001
        pass
    return _config
