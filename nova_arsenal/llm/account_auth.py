"""
Account-based LLM auth (Codex / Claude Code style) + local LLM.

Users can sign in with their AI *accounts* (session / OAuth tokens) instead of
only pasting raw API keys. Supports:

1. OpenAI Codex / ChatGPT subscription OAuth (browser PKCE + device-code)
2. Manual token login (paste Claude/Codex OAuth or session token)
3. Import from local Claude Code / Codex / Cursor credential files
4. Environment session tokens (CLAUDE_CODE_OAUTH_TOKEN, CODEX_API_KEY, …)
5. Google OAuth (browser localhost) when GOOGLE_CLIENT_ID is configured
6. Local LLM (Ollama / OpenAI-compatible) — no cloud account
7. Secure on-disk store at ~/.nova/accounts.json (mode 0600)

Resolved tokens are consumed by ``resolve_api_key()`` so every provider
automatically uses account credentials when present.
"""

from __future__ import annotations

import base64
import hashlib
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

# Codex CLI public OAuth client (used by openai/codex and compatible tools).
# Override with OPENAI_CODEX_CLIENT_ID if OpenAI rotates the id.
DEFAULT_CODEX_CLIENT_ID = os.getenv(
    "OPENAI_CODEX_CLIENT_ID",
    "app_EMoamEEZ73f0CkXaXp7hrann",
)
CODEX_AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
CODEX_TOKEN_URL = "https://auth.openai.com/oauth/token"
CODEX_DEVICE_CODE_URL = "https://auth.openai.com/api/accounts/deviceauth/usercode"
CODEX_DEVICE_TOKEN_URL = "https://auth.openai.com/api/accounts/deviceauth/token"
CODEX_SCOPES = "openid profile email offline_access"
# Codex CLI default callback port
CODEX_CALLBACK_PORT = int(os.getenv("NOVA_CODEX_CALLBACK_PORT", "1455"))

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
    auth_type: str = "session"  # session | oauth | api_key | imported | local
    refresh_token: str = ""
    expires_at: str = ""  # ISO
    email: str = ""
    label: str = ""
    source: str = "manual"
    # Optional routing metadata (local URL, preferred model, account id, …)
    meta: Dict[str, Any] = field(default_factory=dict)
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
        safe_meta = {
            k: v
            for k, v in (self.meta or {}).items()
            if k not in {"access_token", "refresh_token", "id_token"}
        }
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
            "has_token": bool(tok) or self.auth_type == "local",
            "meta": safe_meta,
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
                    meta=dict(raw.get("meta") or {}),
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
        # 1) Stored account (refresh if expired and possible)
        acc = self._accounts.get(provider)
        if acc:
            if acc.auth_type == "local":
                # Local LLMs don't need a secret; return sentinel so config treats as configured
                return acc.access_token or "local"
            if acc.access_token and not acc.is_expired():
                return acc.access_token
            if acc.is_expired() and acc.refresh_token and provider == "openai":
                try:
                    refreshed = self.refresh_openai_codex(acc)
                    return refreshed.access_token
                except Exception as exc:  # noqa: BLE001
                    logger.warning("OpenAI token refresh failed: %s", exc)

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

    # ── OpenAI Codex / ChatGPT subscription OAuth ───────────────────────────

    def login_openai_codex_oauth(
        self,
        open_browser: bool = True,
        timeout: int = 300,
        device_code: bool = False,
        client_id: str = "",
    ) -> AccountCredential:
        """
        Sign in with ChatGPT / Codex subscription via OAuth (PKCE).

        Browser callback defaults to http://localhost:1455/auth/callback
        (Codex CLI compatible). Use device_code=True for headless/SSH.

        After login, tokens are stored as provider ``openai`` and used by the
        LLM router. Usage is billed against the ChatGPT/Codex subscription
        limits, not (necessarily) Platform API credits.
        """
        if device_code or os.getenv("NOVA_CODEX_DEVICE_CODE", "").lower() in {
            "1",
            "true",
            "yes",
        }:
            return self._login_openai_device_code(client_id=client_id, timeout=timeout)
        return self._login_openai_browser_pkce(
            open_browser=open_browser,
            timeout=timeout,
            client_id=client_id,
        )

    def _login_openai_browser_pkce(
        self,
        open_browser: bool = True,
        timeout: int = 300,
        client_id: str = "",
    ) -> AccountCredential:
        import httpx

        cid = client_id or DEFAULT_CODEX_CLIENT_ID
        verifier = secrets.token_urlsafe(64)
        challenge = _pkce_challenge(verifier)
        state = secrets.token_urlsafe(24)
        port = CODEX_CALLBACK_PORT
        # If 1455 busy, fall back to free port (user may need to allow redirect)
        try:
            _assert_port_free(port)
        except OSError:
            port = _free_port()
            logger.warning("Codex callback port 1455 busy; using %s", port)

        result: Dict[str, str] = {}
        done = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parsed = urlparse(self.path)
                qs = parse_qs(parsed.query)
                if "code" in qs:
                    if qs.get("state", [""])[0] and qs.get("state", [""])[0] != state:
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(b"Invalid state")
                        return
                    result["code"] = qs["code"][0]
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body style='font-family:sans-serif;padding:2rem'>"
                        b"<h2>Nova: ChatGPT / Codex login complete</h2>"
                        b"<p>You can close this tab and return to the terminal.</p>"
                        b"</body></html>"
                    )
                    done.set()
                else:
                    # Allow pasting full redirect URL path without code yet
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Nova OAuth callback ready.")

            def log_message(self, format, *args):  # noqa: A003
                return

        server = HTTPServer(("127.0.0.1", port), Handler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        redirect_uri = f"http://localhost:{port}/auth/callback"
        params = {
            "client_id": cid,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": CODEX_SCOPES,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "login",
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
        }
        auth_url = f"{CODEX_AUTHORIZE_URL}?{urlencode(params)}"
        print("\n=== Sign in with ChatGPT / Codex (subscription) ===")
        print(f"Open this URL if the browser did not open:\n\n{auth_url}\n")
        print(f"Waiting for callback on {redirect_uri} (timeout {timeout}s)…")
        print("Headless? Re-run with: nova-agent login --provider openai --oauth --device-code\n")

        if open_browser:
            try:
                webbrowser.open(auth_url)
            except Exception:  # noqa: BLE001
                pass

        done.wait(timeout=timeout)
        try:
            server.server_close()
        except Exception:  # noqa: BLE001
            pass

        if "code" not in result:
            # Manual paste fallback
            print(
                "No browser callback received. Paste the full redirect URL "
                "(from the address bar after login), or the `code=` value:"
            )
            try:
                pasted = input("> ").strip()
            except EOFError:
                pasted = ""
            if "code=" in pasted:
                qs = parse_qs(urlparse(pasted).query)
                if "code" in qs:
                    result["code"] = qs["code"][0]
            elif pasted:
                result["code"] = pasted

        if "code" not in result:
            raise TimeoutError(
                "OpenAI Codex OAuth timed out. Try --device-code or "
                "nova-agent login --import-existing after `codex login`."
            )

        data = {
            "grant_type": "authorization_code",
            "client_id": cid,
            "code": result["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
        resp = httpx.post(
            CODEX_TOKEN_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=45,
        )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Token exchange failed ({resp.status_code}): {resp.text[:400]}"
            )
        tok = resp.json()
        return self._store_openai_tokens(tok, source="openai_codex_oauth", client_id=cid)

    def _login_openai_device_code(
        self,
        client_id: str = "",
        timeout: int = 300,
    ) -> AccountCredential:
        """Headless device-code flow for ChatGPT / Codex."""
        import httpx

        cid = client_id or DEFAULT_CODEX_CLIENT_ID
        # Try device auth usercode endpoint
        with httpx.Client(timeout=30) as client:
            r = client.post(
                CODEX_DEVICE_CODE_URL,
                json={"client_id": cid},
                headers={"Content-Type": "application/json"},
            )
            if r.status_code >= 400:
                # Fallback: some deployments use standard OAuth device endpoint
                r = client.post(
                    "https://auth.openai.com/oauth/device/code",
                    data={
                        "client_id": cid,
                        "scope": CODEX_SCOPES,
                    },
                )
            if r.status_code >= 400:
                raise RuntimeError(
                    f"Device code request failed ({r.status_code}): {r.text[:300]}. "
                    "Use browser OAuth instead: nova-agent login --provider openai --oauth"
                )
            payload = r.json()

        user_code = payload.get("user_code") or payload.get("userCode") or ""
        device_code = payload.get("device_code") or payload.get("deviceCode") or ""
        verify_url = (
            payload.get("verification_uri_complete")
            or payload.get("verification_uri")
            or payload.get("verificationUrl")
            or "https://auth.openai.com/codex/device"
        )
        interval = int(payload.get("interval") or 5)
        expires_in = int(payload.get("expires_in") or timeout)

        print("\n=== ChatGPT / Codex device login ===")
        print(f"1. Open: {verify_url}")
        if user_code:
            print(f"2. Enter code: {user_code}")
        print("3. Approve access, then return here…\n")
        try:
            webbrowser.open(verify_url if verify_url.startswith("http") else f"https://{verify_url}")
        except Exception:  # noqa: BLE001
            pass

        deadline = time.time() + min(timeout, expires_in)
        import httpx

        while time.time() < deadline:
            time.sleep(max(3, interval))
            try:
                tr = httpx.post(
                    CODEX_DEVICE_TOKEN_URL,
                    json={
                        "client_id": cid,
                        "device_code": device_code,
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    },
                    timeout=30,
                )
                if tr.status_code == 200:
                    return self._store_openai_tokens(
                        tr.json(),
                        source="openai_codex_device",
                        client_id=cid,
                    )
                # also try standard token URL
                tr2 = httpx.post(
                    CODEX_TOKEN_URL,
                    data={
                        "client_id": cid,
                        "device_code": device_code,
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    },
                    timeout=30,
                )
                if tr2.status_code == 200:
                    return self._store_openai_tokens(
                        tr2.json(),
                        source="openai_codex_device",
                        client_id=cid,
                    )
                body = (tr.text or tr2.text or "")[:200]
                if "pending" in body.lower() or tr.status_code in {400, 403, 428}:
                    continue
            except Exception as exc:  # noqa: BLE001
                logger.debug("device poll: %s", exc)
                continue

        raise TimeoutError("Device code login timed out")

    def refresh_openai_codex(self, acc: AccountCredential) -> AccountCredential:
        import httpx

        cid = (acc.meta or {}).get("client_id") or DEFAULT_CODEX_CLIENT_ID
        resp = httpx.post(
            CODEX_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": acc.refresh_token,
                "client_id": cid,
            },
            timeout=30,
        )
        resp.raise_for_status()
        return self._store_openai_tokens(
            resp.json(),
            source=acc.source or "openai_codex_refresh",
            client_id=cid,
            email=acc.email,
        )

    def _store_openai_tokens(
        self,
        tok: Dict[str, Any],
        source: str,
        client_id: str = "",
        email: str = "",
    ) -> AccountCredential:
        access = tok.get("access_token") or tok.get("access") or ""
        refresh = tok.get("refresh_token") or tok.get("refresh") or ""
        if not access:
            raise RuntimeError(f"No access_token in OAuth response: {list(tok.keys())}")
        expires_in = int(tok.get("expires_in") or tok.get("expires") or 3600)
        # expires may be absolute ms in some responses
        if expires_in > 10_000_000:
            expires_at = datetime.fromtimestamp(
                expires_in / 1000.0, tz=timezone.utc
            ).isoformat()
        else:
            expires_at = datetime.fromtimestamp(
                time.time() + expires_in, tz=timezone.utc
            ).isoformat()

        account_id = tok.get("account_id") or tok.get("accountId") or ""
        if not account_id and access.count(".") == 2:
            try:
                payload = access.split(".")[1]
                pad = "=" * (-len(payload) % 4)
                data = json.loads(base64.urlsafe_b64decode(payload + pad))
                account_id = (
                    data.get("https://api.openai.com/auth", {}).get("chatgpt_account_id")
                    or data.get("account_id")
                    or ""
                )
                email = email or data.get("email") or ""
            except Exception:  # noqa: BLE001
                pass

        cred = AccountCredential(
            provider="openai",
            access_token=access,
            refresh_token=refresh,
            expires_at=expires_at,
            auth_type="oauth",
            email=email,
            label="ChatGPT / Codex subscription",
            source=source,
            meta={
                "client_id": client_id or DEFAULT_CODEX_CLIENT_ID,
                "account_id": account_id,
                "subscription_auth": True,
                "id_token": (tok.get("id_token") or "")[:20] + "…"
                if tok.get("id_token")
                else "",
            },
        )
        self.set_account(cred)
        return cred

    # ── Local LLM (Ollama / OpenAI-compatible) ──────────────────────────────

    def login_local_llm(
        self,
        url: str = "",
        model: str = "",
        kind: str = "ollama",
        label: str = "",
    ) -> AccountCredential:
        """
        Register a local LLM endpoint as the preferred backend.

        kind: ollama | local | openai_compatible
        """
        from nova_arsenal.llm.local_llm import (
            discover_local_llms,
            probe_ollama,
            probe_openai_compatible,
        )

        kind = (kind or "ollama").lower()
        if kind in {"local", "lmstudio", "vllm", "openai_compatible"}:
            kind = "openai_compatible" if kind != "ollama" else kind

        if not url:
            found = discover_local_llms()
            healthy = [e for e in found if e.healthy]
            if not healthy:
                raise RuntimeError(
                    "No local LLM found. Install Ollama (https://ollama.com), run "
                    "`ollama pull llama3.2`, then retry: "
                    "nova-agent login --provider ollama"
                )
            ep = healthy[0]
            url = ep.base_url
            model = model or ep.preferred_model
            kind = ep.kind
        else:
            if kind == "ollama" or "11434" in url:
                ep = probe_ollama(url)
                if not ep.healthy:
                    # try openai-compatible
                    ep2 = probe_openai_compatible(url)
                    if ep2.healthy:
                        ep = ep2
                        kind = "openai_compatible"
                    else:
                        raise RuntimeError(
                            f"Local LLM not reachable at {url}: {ep.error}"
                        )
                else:
                    kind = "ollama"
                model = model or ep.preferred_model
            else:
                ep = probe_openai_compatible(url)
                if not ep.healthy:
                    # last try ollama API on that host
                    ep = probe_ollama(url)
                    if not ep.healthy:
                        raise RuntimeError(
                            f"Local LLM not reachable at {url}: {ep.error}"
                        )
                    kind = "ollama"
                else:
                    kind = "openai_compatible"
                model = model or ep.preferred_model

        if not model:
            model = "llama3.2"

        provider = "ollama" if kind == "ollama" else "local"
        cred = AccountCredential(
            provider=provider,
            access_token="local",  # sentinel
            auth_type="local",
            label=label or f"Local {kind} ({model})",
            source="local_llm",
            meta={
                "base_url": url,
                "model": model,
                "kind": kind,
                "prefer_as_primary": True,
            },
        )
        self.set_account(cred)
        # Also set env hints for this process
        os.environ.setdefault("LLM_PROVIDER", provider if provider == "ollama" else "ollama")
        if provider == "ollama":
            os.environ["NOVA_LLM_URL"] = url
            os.environ["LLM_MODEL"] = model
            os.environ["OLLAMA_MODEL"] = model
        return cred


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _assert_port_free(port: int) -> None:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))


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
    local_status: Dict[str, Any] = {}
    try:
        from nova_arsenal.llm.local_llm import local_llm_status

        local_status = local_llm_status()
    except Exception as exc:  # noqa: BLE001
        local_status = {"available": False, "error": str(exc)}

    return {
        "store_path": str(store.path),
        "accounts": [a.to_public_dict() for a in store.list_accounts()],
        "local_llm": local_status,
        "how_to": {
            "openai_chatgpt_subscription": (
                "nova-agent login --provider openai --oauth   "
                "# browser ChatGPT/Codex sign-in (Plus/Pro subscription)"
            ),
            "openai_device_code": (
                "nova-agent login --provider openai --oauth --device-code  # headless/SSH"
            ),
            "claude_code": (
                "Sign in with Claude Code (`claude`), then: "
                "nova-agent login --import-existing   OR   "
                "export CLAUDE_CODE_OAUTH_TOKEN=... from `claude setup-token`"
            ),
            "codex_import": (
                "Sign in with Codex (`codex login`), then: "
                "nova-agent login --import-existing"
            ),
            "google": (
                "Set GOOGLE_OAUTH_CLIENT_ID (and secret), then: "
                "nova-agent login --provider gemini --oauth"
            ),
            "local_ollama": (
                "Install Ollama, pull a model, then: "
                "nova-agent login --provider ollama"
            ),
            "local_custom": (
                "nova-agent login --provider ollama --url http://127.0.0.1:11434 "
                "--model llama3.2"
            ),
            "api_key_still_works": (
                "API keys via OPENAI_API_KEY / ANTHROPIC_API_KEY etc. still work "
                "alongside account logins."
            ),
        },
    }
