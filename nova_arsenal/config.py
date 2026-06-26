"""
Nova-Arsenal Configuration Module

Handles loading and validating configuration from YAML files and environment variables.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class AgentConfig:
    name: str = "nova-agent"
    version: str = "1.0.0"
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


@dataclass
class LLMConfig:
    primary: LLMProviderConfig = field(default_factory=LLMProviderConfig)
    fallbacks: List[LLMProviderConfig] = field(default_factory=list)
    routing_strategy: str = "cost-optimized"
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


def _process_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively process environment variables in config."""
    if isinstance(data, dict):
        return {k: _process_config(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_process_config(item) for item in data]
    elif isinstance(data, str):
        return _resolve_env_vars(data)
    return data


def load_config(config_path: Optional[str] = None) -> NovaConfig:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path: Path to configuration file. If None, uses defaults.
        
    Returns:
        NovaConfig instance with loaded configuration.
    """
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        
        data = _process_config(data)
        
        return NovaConfig(
            agent=AgentConfig(**data.get("agent", {})),
            llm=LLMConfig(
                primary=LLMProviderConfig(**data.get("llm", {}).get("primary", {})),
                fallbacks=[
                    LLMProviderConfig(**fb)
                    for fb in data.get("llm", {}).get("fallbacks", [])
                ],
                routing_strategy=data.get("llm", {}).get("routing", {}).get("strategy", "cost-optimized"),
                fallback_threshold=data.get("llm", {}).get("routing", {}).get("fallback_threshold", 3),
                max_retries=data.get("llm", {}).get("routing", {}).get("max_retries", 3),
            ),
            security=SecurityConfig(**data.get("security", {})),
            logging=LoggingConfig(**data.get("logging", {})),
            database=DatabaseConfig(**data.get("database", {})),
            auth=AuthConfig(
                **{k: v for k, v in data.get("auth", {}).items() if k != "oauth"},
                oauth=OAuthConfig(**data.get("auth", {}).get("oauth", {})),
            ),
            scope=data.get("scope", {}).get("targets", []),
        )
    
    # Return defaults
    return NovaConfig()


# Global config singleton
_config: Optional[NovaConfig] = None


def get_config() -> NovaConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        config_path = os.getenv("NOVA_CONFIG", "settings.yaml")
        _config = load_config(config_path)
    return _config


def reload_config(config_path: Optional[str] = None) -> NovaConfig:
    """Reload configuration from file."""
    global _config
    _config = load_config(config_path)
    return _config
