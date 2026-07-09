"""
Account-based LLM auth (Codex / Claude Code style).

Users can sign in with their AI *accounts* (session / OAuth tokens) instead of
only pasting raw API keys. Supports:

1. Manual token login (paste Claude/Codex OAuth or session token)
2. Import from local Claude Code / Codex / Cursor credential files
3. Environment session tokens (CLAUDE_CODE_OAUTH_TOKEN, CODEX_API_KEY, …)
4. Google OAuth (browser localhost) when GOOGLE_CLIENT_ID is configured
5. Secure on-disk store at ~/.nova/accounts.json (mode 0600)

Resolved tokens are consumed by ``resolve_api_key()`` so every provider
automatically uses account credentials when present.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
import webbrowser
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

logger = logging.getLogger(__name__)

STORE_DIR = Path(os.getenv("NOVA_HOME", Path.home() / ".nova"))
STORE_PATH = STORE_DIR / "accounts.json"

# Paths we try when importing existing tool logins
IMPORT_CANDIDATES: Dict[str, List[Path]] = {
    "anthropic": [
        Path.home() / ".claude" / ".credentials.json",
        Path.home() / ".claude.json",
        Path.home() / ".config" / "claude" / "credentials.json",
        Path.home() / ".config" / "claude-code" / "auth.json",
    ],
    "openai": [
        Path.home() / ".codex" / "auth.json",
        Path.home() / ".codex" / "config.json",
        Path.home() / ".config" / "codex" / "auth.json",
        Path.home() / ".openai" / "auth.json",
    ],
    "cursor": [
        Path.home() / ".cursor" / "auth.json",
        Path.home() / ".config" / "cursor" / "auth.json",
    ],
}

# Env vars that hold *session* tokens (not classic sk- API keys)
SESSION_ENV: Dict[str, Tuple[str, ...]] = {
    "anthropic": ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_SESSION_TOKEN"),
    "openai": ("CODEX_API_KEY", "OPENAI_SESSION_TOKEN", "CHATGPT_SESSION_TOKEN"),
    "gemini": ("GOOGLE_OAUTH_TOKEN", "GEMINI_OAUTH_TOKEN"),
    "openrouter": ("OPENROUTER_SESSION_TOKEN",),
}


@dataclass
class AccountCredential:
    provider: str
    access_token: str
    auth_type: str = "session"  # session | oauth | api_key | imported
    refresh_token: str = ""
    expires_at: str = ""  # ISO
    email: str = ""
    label: str = ""
    source: str = "manual"
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) >= exp
        except ValueError:
            return False

    def to_public_dict(self) -> Dict[str, Any]:
        """Safe for UI — never includes full token."""
        tok = self.access_token or ""
        hint = (tok[:6] + "…" + tok[-4:]) if len(tok) > 12 else ("set" if tok else "")
        return {
            "provider": self.provider,
            "auth_type": self.auth_type,
            "email": self.email,
            "label": self.label or self.provider,
            "source": self.source,
            "expires_at": self.expires_at,
            "expired": self.is_expired(),
            "token_hint": hint,
            "updated_at": self.updated_at,
            "has_token": bool(tok),
        }


class AccountAuthStore:
    """Persistent multi-provider account credential store."""

    def __init__(self, path: Path = STORE_PATH) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._accounts: Dict[str, AccountCredential] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            for name, raw in (data.get("accounts") or {}).items():
                self._accounts[name] = AccountCredential(
                    provider=name,
                    access_token=raw.get("access_token", ""),
                    auth_type=raw.get("auth_type", "session"),
                    refresh_token=raw.get("refresh_token", ""),
                    expires_at=raw.get("expires_at", ""),
                    email=raw.get("email", ""),
                    label=raw.get("label", ""),
                    source=raw.get("source", "manual"),
                    updated_at=raw.get("updated_at", ""),
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load account store: %s", exc)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "accounts": {
                name: asdict(acc) for name, acc in self._accounts.items()
            },
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def set_account(self, cred: AccountCredential) -> None:
        with self._lock:
            cred.updated_at = datetime.now(timezone.utc).isoformat()
            self._accounts[cred.provider] = cred
            self._save()
        logger.info(
            "Saved account credentials for %s (source=%s, type=%s)",
            cred.provider,
            cred.source,
            cred.auth_type,
        )

    def get(self, provider: str) -> Optional[AccountCredential]:
        return self._accounts.get(provider)

    def remove(self, provider: str) -> bool:
        with self._lock:
            if provider not in self._accounts:
                return False
            del self._accounts[provider]
            self._save()
            return True

    def list_accounts(self) -> List[AccountCredential]:
        return list(self._accounts.values())

    def get_token(self, provider: str) -> str:
        """Return a usable access token for provider, or empty string."""
        # 1) Stored account
        acc = self._accounts.get(provider)
        if acc and acc.access_token and not acc.is_expired():
            return acc.access_token

        # 2) Session env vars
        for env_name in SESSION_ENV.get(provider, ()):
            val = os.getenv(env_name, "").strip()
            if val:
                return val

        return ""

    def login_with_token(
        self,
        provider: str,
        token: str,
        *,
        auth_type: str = "session",
        label: str = "",
        email: str = "",
        source: str = "manual",
    ) -> AccountCredential:
        token = (token or "").strip()
        if not token:
            raise ValueError("Token is empty")
        # Heuristic: classic API keys still work as auth_type api_key
        if token.startswith("sk-ant-") or token.startswith("sk-") and auth_type == "session":
            if "oauth" not in token.lower() and len(token) < 200:
                auth_type = "api_key"
        cred = AccountCredential(
            provider=provider,
            access_token=token,
            auth_type=auth_type,
            label=label or f"{provider} account",
            email=email,
            source=source,
        )
        self.set_account(cred)
        return cred

    def import_from_environment(self) -> List[AccountCredential]:
        imported: List[AccountCredential] = []
        for provider, envs in SESSION_ENV.items():
            for env_name in envs:
                val = os.getenv(env_name, "").strip()
                if val:
                    cred = self.login_with_token(
                        provider,
                        val,
                        auth_type="session",
                        label=f"{provider} via {env_name}",
                        source=f"env:{env_name}",
                    )
                    imported.append(cred)
                    break
        return imported

    def import_from_tools(self) -> List[Dict[str, Any]]:
        """
        Import credentials from Claude Code / Codex / Cursor local files.

        Returns list of {provider, status, detail} results.
        """
        results: List[Dict[str, Any]] = []

        # Env first
        for cred in self.import_from_environment():
            results.append(
                {
                    "provider": cred.provider,
                    "status": "imported",
                    "detail": f"from {cred.source}",
                }
            )

        # Claude Code
        token, source = _extract_token_from_paths(IMPORT_CANDIDATES["anthropic"])
        if token:
            self.login_with_token(
                "anthropic",
                token,
                auth_type="session",
                label="Claude Code account",
                source=source,
            )
            results.append({"provider": "anthropic", "status": "imported", "detail": source})
        else:
            results.append(
                {
                    "provider": "anthropic",
                    "status": "not_found",
                    "detail": "No Claude Code credentials found — run: claude /login or paste token",
                }
            )

        # Codex / OpenAI
        token, source = _extract_token_from_paths(IMPORT_CANDIDATES["openai"])
        if token:
            self.login_with_token(
                "openai",
                token,
                auth_type="session",
                label="Codex / ChatGPT account",
                source=source,
            )
            results.append({"provider": "openai", "status": "imported", "detail": source})
        else:
            results.append(
                {
                    "provider": "openai",
                    "status": "not_found",
                    "detail": "No Codex credentials found — run: codex login or paste token",
                }
            )

        # Cursor (optional)
        token, source = _extract_token_from_paths(IMPORT_CANDIDATES["cursor"])
        if token:
            # Cursor often uses Anthropic/OpenAI under the hood; store as openrouter-like generic
            self.login_with_token(
                "openai",
                token,
                auth_type="session",
                label="Cursor imported token",
                source=source,
            )
            results.append({"provider": "cursor→openai", "status": "imported", "detail": source})

        return results

    def login_google_oauth(
        self,
        client_id: str = "",
        client_secret: str = "",
        open_browser: bool = True,
        timeout: int = 180,
    ) -> AccountCredential:
        """
        Browser OAuth for Google (Gemini) using user's OAuth client.

        Requires a Google Cloud OAuth client (Desktop or Web) with redirect
        http://127.0.0.1:<port>/callback
        """
        client_id = client_id or os.getenv("GOOGLE_OAUTH_CLIENT_ID", "") or os.getenv(
            "GOOGLE_CLIENT_ID", ""
        )
        client_secret = client_secret or os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "") or os.getenv(
            "GOOGLE_CLIENT_SECRET", ""
        )
        if not client_id:
            raise ValueError(
                "Google OAuth requires GOOGLE_OAUTH_CLIENT_ID "
                "(create an OAuth client in Google Cloud Console)"
            )

        # Local callback server
        result: Dict[str, str] = {}
        state = secrets.token_urlsafe(16)
        port = _free_port()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                qs = parse_qs(urlparse(self.path).query)
                if qs.get("state", [""])[0] != state:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Invalid state")
                    return
                if "code" in qs:
                    result["code"] = qs["code"][0]
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body><h2>Nova: Google login complete. You can close this tab.</h2></body></html>"
                    )
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Missing code")

            def log_message(self, format, *args):  # noqa: A003
                return

        server = HTTPServer(("127.0.0.1", port), Handler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        redirect_uri = f"http://127.0.0.1:{port}/callback"
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email https://www.googleapis.com/auth/cloud-platform",
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
        url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
        logger.info("Open this URL to sign in with Google:\n%s", url)
        if open_browser:
            try:
                webbrowser.open(url)
            except Exception:  # noqa: BLE001
                pass

        thread.join(timeout=timeout)
        server.server_close()
        if "code" not in result:
            raise TimeoutError("Google OAuth timed out or was cancelled")

        # Exchange code
        import httpx

        data = {
            "code": result["code"],
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        if client_secret:
            data["client_secret"] = client_secret
        resp = httpx.post("https://oauth2.googleapis.com/token", data=data, timeout=30)
        resp.raise_for_status()
        tok = resp.json()
        access = tok.get("access_token", "")
        refresh = tok.get("refresh_token", "")
        expires_in = int(tok.get("expires_in") or 3600)
        exp = datetime.now(timezone.utc).timestamp() + expires_in
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()

        email = ""
        try:
            ui = httpx.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access}"},
                timeout=15,
            )
            if ui.status_code == 200:
                email = ui.json().get("email", "")
        except Exception:  # noqa: BLE001
            pass

        cred = AccountCredential(
            provider="gemini",
            access_token=access,
            refresh_token=refresh,
            expires_at=expires_at,
            auth_type="oauth",
            email=email,
            label="Google account (Gemini)",
            source="google_oauth",
        )
        self.set_account(cred)
        return cred


def _extract_token_from_paths(paths: List[Path]) -> Tuple[str, str]:
    """Best-effort extract access/session tokens from known JSON shapes."""
    keys_priority = (
        "claudeAiOauth",
        "accessToken",
        "access_token",
        "oauthToken",
        "oauth_token",
        "sessionKey",
        "session_key",
        "token",
        "apiKey",
        "api_key",
        "key",
        "OPENAI_API_KEY",
        "authToken",
    )
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            # JSON
            if text.strip().startswith("{") or text.strip().startswith("["):
                data = json.loads(text)
                found = _deep_find_token(data, keys_priority)
                if found:
                    return found, str(path)
            # KEY=VALUE lines
            for line in text.splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, _, v = line.partition("=")
                    if k.strip() in keys_priority and v.strip():
                        return v.strip().strip('"').strip("'"), str(path)
        except Exception:  # noqa: BLE001
            continue
    return "", ""


def _deep_find_token(obj: Any, keys: Tuple[str, ...], depth: int = 0) -> str:
    if depth > 6:
        return ""
    if isinstance(obj, dict):
        # Nested claudeAiOauth.accessToken pattern
        for k in keys:
            if k in obj and isinstance(obj[k], str) and len(obj[k]) > 20:
                return obj[k]
            if k in obj and isinstance(obj[k], dict):
                nested = _deep_find_token(obj[k], keys, depth + 1)
                if nested:
                    return nested
        for v in obj.values():
            found = _deep_find_token(v, keys, depth + 1)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _deep_find_token(item, keys, depth + 1)
            if found:
                return found
    return ""


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# Module-level singleton
_store: Optional[AccountAuthStore] = None


def get_account_store() -> AccountAuthStore:
    global _store
    if _store is None:
        _store = AccountAuthStore()
    return _store


def reset_account_store() -> None:
    global _store
    _store = None


def account_token_for(provider: str) -> str:
    """Convenience: token for provider from account store / session env."""
    try:
        return get_account_store().get_token(provider)
    except Exception:  # noqa: BLE001
        return ""


def account_status() -> Dict[str, Any]:
    store = get_account_store()
    return {
        "store_path": str(store.path),
        "accounts": [a.to_public_dict() for a in store.list_accounts()],
        "how_to": {
            "claude_code": (
                "Sign in with Claude Code (`claude`), then: "
                "nova-agent login --import-existing   OR   "
                "export CLAUDE_CODE_OAUTH_TOKEN=... from `claude setup-token`"
            ),
            "codex": (
                "Sign in with Codex (`codex login`), then: "
                "nova-agent login --import-existing   OR paste token via "
                "nova-agent login --provider openai --token <token>"
            ),
            "google": (
                "Set GOOGLE_OAUTH_CLIENT_ID (and secret), then: "
                "nova-agent login --provider gemini --oauth"
            ),
            "api_key_still_works": (
                "API keys via OPENAI_API_KEY / ANTHROPIC_API_KEY etc. still work "
                "alongside account logins."
            ),
        },
    }
