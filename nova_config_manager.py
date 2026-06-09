"""
Nova Config Manager v1.0
=========================
Central configuration for all Nova modules.

Instead of hardcoded values scattered everywhere,
one config file controls everything.

Config file location: ~/.nova/config.yaml
Environment variables override file values.
Defaults used if nothing configured.

Usage:
    config = NovaConfig()
    api_key = config.get("llm.claude_api_key")
    timeout = config.get("scanning.timeout", default=300)
"""

import os
import json
import logging
from typing import Any, Dict, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.nova/config.json")


# ─────────────────────────────────────────
# DEFAULT CONFIGURATION
# ─────────────────────────────────────────

DEFAULT_CONFIG = {
    "nova": {
        "version": "1.0.0",
        "name": "Nova",
        "debug": False,
        "log_level": "INFO",
        "log_file": "~/.nova/logs/nova.log"
    },

    "llm": {
        "primary": "ollama",
        "fallback": "claude",
        "claude_api_key": "",
        "openai_api_key": "",
        "ollama_url": "http://localhost:11434",
        "ollama_model": "qwen2:7b",
        "max_tokens": 2048,
        "temperature": 0.7,
        "timeout": 30
    },

    "scanning": {
        "default_risk_level": "medium",
        "timeout": 300,
        "threads": 10,
        "rate_limit": 100,
        "max_retries": 3,
        "retry_delay": 5,
        "output_dir": "~/.nova/outputs"
    },

    "memory": {
        "enabled": True,
        "db_path": "~/.nova/memory.db",
        "max_findings": 10000,
        "max_sessions": 1000,
        "auto_save": True,
        "auto_save_interval": 60
    },

    "sessions": {
        "dir": "~/.nova/sessions",
        "auto_resume": True,
        "max_sessions": 100
    },

    "notifications": {
        "enabled": False,
        "telegram_token": "",
        "telegram_chat_id": "",
        "email_smtp": "",
        "email_user": "",
        "email_password": "",
        "email_recipient": "",
        "notify_on_critical": True,
        "notify_on_high": False,
        "notify_on_completion": True
    },

    "reporting": {
        "output_dir": "~/.nova/reports",
        "default_format": "html",
        "include_evidence": True,
        "include_remediation": True,
        "company_name": "",
        "logo_path": ""
    },

    "tools": {
        "auto_install": False,
        "kali_path": "/usr/bin",
        "custom_tools_dir": "~/.nova/tools",
        "preferred": {
            "scanner": "nmap",
            "web_scanner": "nikto",
            "fuzzer": "ffuf",
            "sql_scanner": "sqlmap"
        }
    },

    "conversation": {
        "history_limit": 50,
        "auto_save": True,
        "language": "en"
    },

    "security": {
        "require_auth": False,
        "api_key": "",
        "encrypt_findings": False,
        "audit_log": True,
        "audit_log_path": "~/.nova/logs/audit.log"
    }
}


# ─────────────────────────────────────────
# CONFIG MANAGER
# ─────────────────────────────────────────

class NovaConfig:
    """
    Central configuration manager.

    Priority (highest to lowest):
    1. Environment variables (NOVA_LLM_PRIMARY, etc.)
    2. Config file (~/.nova/config.json)
    3. Default values
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self._config = {}
        self._load()

    def _load(self):
        """Load configuration from file and environment"""

        # Start with defaults
        self._config = self._deep_copy(DEFAULT_CONFIG)

        # Override with file config
        if os.path.exists(self.config_path):
            file_config = self._load_file()
            self._deep_merge(self._config, file_config)
            logger.info(f"Config loaded from: {self.config_path}")
        else:
            logger.info("No config file found, using defaults")
            self._save()  # Create default config file

        # Override with environment variables
        self._load_env_vars()

        logger.info("Configuration loaded")

    def _load_file(self) -> Dict:
        """Load config from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config file: {e}")
            return {}

    def _load_env_vars(self):
        """Load config from environment variables"""

        env_mappings = {
            "NOVA_LLM_PRIMARY": "llm.primary",
            "NOVA_LLM_FALLBACK": "llm.fallback",
            "ANTHROPIC_API_KEY": "llm.claude_api_key",
            "OPENAI_API_KEY": "llm.openai_api_key",
            "NOVA_OLLAMA_URL": "llm.ollama_url",
            "NOVA_OLLAMA_MODEL": "llm.ollama_model",
            "NOVA_TIMEOUT": "scanning.timeout",
            "NOVA_THREADS": "scanning.threads",
            "NOVA_RISK_LEVEL": "scanning.default_risk_level",
            "NOVA_DEBUG": "nova.debug",
            "NOVA_LOG_LEVEL": "nova.log_level",
            "NOVA_TELEGRAM_TOKEN": "notifications.telegram_token",
            "NOVA_TELEGRAM_CHAT": "notifications.telegram_chat_id",
            "NOVA_API_KEY": "security.api_key",
        }

        for env_var, config_key in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                self.set(config_key, value)
                logger.debug(f"Config override from env: {config_key}")

    def _save(self):
        """Save current config to file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(self._config, f, indent=2)
            logger.info(f"Config saved: {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    # ─────────────────────────────────────────
    # GET / SET
    # ─────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get config value using dot notation.

        Args:
            key: Dot-separated key (e.g. 'llm.primary')
            default: Default if not found

        Returns:
            Config value or default
        """

        parts = key.split(".")
        value = self._config

        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default

        # Expand ~ in paths
        if isinstance(value, str) and value.startswith("~"):
            value = os.path.expanduser(value)

        return value

    def set(self, key: str, value: Any, save: bool = False):
        """
        Set config value using dot notation.

        Args:
            key: Dot-separated key
            value: Value to set
            save: Save to file after setting
        """

        parts = key.split(".")
        config = self._config

        for part in parts[:-1]:
            if part not in config:
                config[part] = {}
            config = config[part]

        config[parts[-1]] = value

        if save:
            self._save()

        logger.debug(f"Config set: {key} = {value}")

    def save(self):
        """Save config to file"""
        self._save()

    # ─────────────────────────────────────────
    # SECTION GETTERS
    # ─────────────────────────────────────────

    @property
    def llm(self) -> Dict:
        """LLM configuration"""
        return self._config.get("llm", {})

    @property
    def scanning(self) -> Dict:
        """Scanning configuration"""
        return self._config.get("scanning", {})

    @property
    def memory(self) -> Dict:
        """Memory configuration"""
        return self._config.get("memory", {})

    @property
    def notifications(self) -> Dict:
        """Notifications configuration"""
        return self._config.get("notifications", {})

    @property
    def reporting(self) -> Dict:
        """Reporting configuration"""
        return self._config.get("reporting", {})

    @property
    def tools(self) -> Dict:
        """Tools configuration"""
        return self._config.get("tools", {})

    @property
    def security(self) -> Dict:
        """Security configuration"""
        return self._config.get("security", {})

    # ─────────────────────────────────────────
    # SETUP WIZARD
    # ─────────────────────────────────────────

    def setup_wizard(self):
        """
        Interactive setup wizard.
        Guides user through initial configuration.
        """

        print("\n" + "="*50)
        print(" NOVA SETUP WIZARD")
        print("="*50)
        print("\nLet's configure Nova for your environment.\n")

        # LLM Setup
        print("─── AI Model Setup ───\n")
        print("Which AI model do you want Nova to use?")
        print("1. Ollama (local, free, works offline)")
        print("2. Claude (Anthropic API, best quality)")
        print("3. GPT-4 (OpenAI API)")

        choice = input("\nChoice (1/2/3) [1]: ").strip() or "1"

        if choice == "1":
            self.set("llm.primary", "ollama")
            ollama_model = input("Ollama model [qwen2:7b]: ").strip() or "qwen2:7b"
            self.set("llm.ollama_model", ollama_model)
            print(f"✓ Using Ollama with {ollama_model}")

        elif choice == "2":
            self.set("llm.primary", "claude")
            api_key = input("Anthropic API key: ").strip()
            if api_key:
                self.set("llm.claude_api_key", api_key)
                print("✓ Claude configured")

        elif choice == "3":
            self.set("llm.primary", "gpt4")
            api_key = input("OpenAI API key: ").strip()
            if api_key:
                self.set("llm.openai_api_key", api_key)
                print("✓ GPT-4 configured")

        # Notifications
        print("\n─── Notifications ───\n")
        enable_notifs = input("Enable Telegram notifications? (y/n) [n]: ").strip().lower()

        if enable_notifs == "y":
            token = input("Telegram bot token: ").strip()
            chat_id = input("Telegram chat ID: ").strip()

            if token and chat_id:
                self.set("notifications.enabled", True)
                self.set("notifications.telegram_token", token)
                self.set("notifications.telegram_chat_id", chat_id)
                print("✓ Telegram notifications configured")

        # Risk Level
        print("\n─── Default Settings ───\n")
        print("Default risk level?")
        print("1. Low (safe, recon only)")
        print("2. Medium (active testing)")
        print("3. High (aggressive)")

        risk = input("\nChoice (1/2/3) [2]: ").strip() or "2"
        risk_map = {"1": "low", "2": "medium", "3": "high"}
        self.set("scanning.default_risk_level", risk_map.get(risk, "medium"))

        # Save
        self._save()

        print("\n✓ Configuration saved to: " + self.config_path)
        print("✓ Nova is ready!\n")
        print("Run: python3 nova.py")
        print("Or:  nova chat\n")

    # ─────────────────────────────────────────
    # DISPLAY
    # ─────────────────────────────────────────

    def show(self, section: Optional[str] = None):
        """Show current configuration"""

        print("\n=== NOVA CONFIGURATION ===\n")

        if section:
            data = self._config.get(section, {})
            print(f"[{section}]")
            for k, v in data.items():
                # Mask sensitive values
                if any(s in k for s in ["key", "token", "password", "secret"]):
                    v = "***" if v else "(not set)"
                print(f"  {k}: {v}")
        else:
            for section_name, section_data in self._config.items():
                print(f"[{section_name}]")
                if isinstance(section_data, dict):
                    for k, v in section_data.items():
                        if any(s in k for s in ["key", "token", "password", "secret"]):
                            v = "***" if v else "(not set)"
                        print(f"  {k}: {v}")
                print()

    def validate(self) -> Dict[str, Any]:
        """Validate configuration and report issues"""

        issues = []
        warnings = []

        # Check LLM config
        primary = self.get("llm.primary")
        if primary == "claude" and not self.get("llm.claude_api_key"):
            issues.append("Claude selected as primary but no API key set")
        elif primary == "gpt4" and not self.get("llm.openai_api_key"):
            issues.append("GPT-4 selected as primary but no API key set")
        elif primary == "ollama":
            warnings.append("Using local Ollama - ensure it's running")

        # Check directories
        for dir_key in ["scanning.output_dir", "memory.db_path", "sessions.dir"]:
            path = self.get(dir_key, "")
            if path:
                expanded = os.path.expanduser(path)
                dir_path = os.path.dirname(expanded) if "." in os.path.basename(expanded) else expanded
                if not os.path.exists(dir_path):
                    warnings.append(f"Directory doesn't exist yet: {dir_path}")

        result = {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings
        }

        if issues:
            print("\n❌ Configuration issues:")
            for issue in issues:
                print(f"  - {issue}")

        if warnings:
            print("\n⚠️  Warnings:")
            for warning in warnings:
                print(f"  - {warning}")

        if not issues and not warnings:
            print("\n✓ Configuration is valid")

        return result

    # ─────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────

    def _deep_copy(self, d: Dict) -> Dict:
        """Deep copy a dictionary"""
        return json.loads(json.dumps(d))

    def _deep_merge(self, base: Dict, override: Dict):
        """Deep merge override into base"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def export_env(self) -> str:
        """Export config as environment variables"""

        lines = [
            "# Nova Configuration",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            f"export NOVA_LLM_PRIMARY={self.get('llm.primary')}",
            f"export NOVA_OLLAMA_MODEL={self.get('llm.ollama_model')}",
            f"export NOVA_TIMEOUT={self.get('scanning.timeout')}",
            f"export NOVA_THREADS={self.get('scanning.threads')}",
            f"export NOVA_RISK_LEVEL={self.get('scanning.default_risk_level')}",
            "",
            "# Add API keys manually:",
            "# export ANTHROPIC_API_KEY=your_key",
            "# export OPENAI_API_KEY=your_key",
            "# export NOVA_TELEGRAM_TOKEN=your_token",
        ]

        return "\n".join(lines)


# ─────────────────────────────────────────
# EXAMPLE USAGE
# ─────────────────────────────────────────

if __name__ == "__main__":
    config = NovaConfig()

    print("=== NOVA CONFIG MANAGER ===\n")

    # Show config
    config.show("llm")

    # Get values
    print(f"\nPrimary LLM: {config.get('llm.primary')}")
    print(f"Timeout: {config.get('scanning.timeout')}s")
    print(f"Risk level: {config.get('scanning.default_risk_level')}")

    # Validate
    print("\nValidating config...")
    result = config.validate()

    # Export as env vars
    print("\nEnvironment variables:")
    print(config.export_env())
