"""
Nova-Arsenal OAuth Provider Handlers

Handles OAuth2 authorization code flow with PKCE for GitHub and Google.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlencode

import httpx

from nova_arsenal.config import get_config


@dataclass
class OAuthUserInfo:
    provider: str
    provider_user_id: str
    email: str
    username: str
    access_token: str
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None


@dataclass
class PKCEChallenge:
    code_verifier: str
    code_challenge: str

    @classmethod
    def generate(cls) -> "PKCEChallenge":
        """Generate a new PKCE code verifier and challenge (S256)."""
        code_verifier = secrets.token_urlsafe(64)[:128]
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return cls(code_verifier=code_verifier, code_challenge=code_challenge)


OAUTH_STATE_TTL_SECONDS = 600
OAUTH_STATE_FUTURE_SKEW_SECONDS = 60


def _state_secret() -> str:
    config = get_config()
    return config.auth.oauth.state_secret or config.auth.jwt_secret


def _encode_state_payload(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    signature = hmac.new(
        _state_secret().encode(),
        encoded.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{encoded}.{signature}"


def _decode_state_payload(state: str) -> Optional[dict[str, Any]]:
    try:
        encoded, signature = state.rsplit(".", 1)
    except ValueError:
        return None

    expected = hmac.new(
        _state_secret().encode(),
        encoded.encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None

    try:
        padding = "=" * (-len(encoded) % 4)
        raw = base64.urlsafe_b64decode(encoded + padding)
        payload = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None

    return payload if isinstance(payload, dict) else None


def generate_oauth_state(
    provider: str,
    redirect: str = "",
    pkce: Optional[PKCEChallenge] = None,
) -> str:
    """Generate a signed, short-lived OAuth state token."""
    return _encode_state_payload(
        {
            "provider": provider,
            "nonce": secrets.token_urlsafe(24),
            "redirect": redirect,
            "verifier": pkce.code_verifier if pkce else "",
            "iat": int(time.time()),
        }
    )


def verify_oauth_state(state: str, provider: str) -> bool:
    """Verify signature, provider binding, and state freshness."""
    payload = _decode_state_payload(state)
    if not payload or payload.get("provider") != provider:
        return False

    try:
        issued_at = int(payload.get("iat"))
    except (TypeError, ValueError):
        return False

    age = int(time.time()) - issued_at
    return -OAUTH_STATE_FUTURE_SKEW_SECONDS <= age <= OAUTH_STATE_TTL_SECONDS


def extract_redirect(state: str) -> str:
    """Extract a redirect value from a validly signed state payload."""
    payload = _decode_state_payload(state)
    value = payload.get("redirect", "") if payload else ""
    return value if isinstance(value, str) else ""


def extract_pkce_verifier(state: str) -> Optional[str]:
    """Extract the PKCE verifier from a validly signed state payload."""
    payload = _decode_state_payload(state)
    value = payload.get("verifier", "") if payload else ""
    return value if isinstance(value, str) and value else None


class BaseOAuthProvider(ABC):
    @abstractmethod
    def get_authorize_url(self, state: str, code_challenge: Optional[str] = None) -> str:
        ...

    @abstractmethod
    async def exchange_code(self, code: str, code_verifier: Optional[str] = None) -> OAuthUserInfo:
        ...

    @abstractmethod
    def provider_name(self) -> str:
        ...


class GitHubOAuthProvider(BaseOAuthProvider):
    AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    API_URL = "https://api.github.com/user"
    API_EMAIL_URL = "https://api.github.com/user/emails"
    SCOPES = "read:user user:email"

    def __init__(self):
        config = get_config()
        self.client_id = config.auth.oauth.github_client_id
        self.client_secret = config.auth.oauth.github_client_secret
        self.redirect_uri = config.auth.oauth.github_redirect_uri

    def provider_name(self) -> str:
        return "github"

    def get_authorize_url(self, state: str, code_challenge: Optional[str] = None) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.SCOPES,
            "state": state,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.AUTHORIZE_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str, code_verifier: Optional[str] = None) -> OAuthUserInfo:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier

        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                self.TOKEN_URL,
                json=data,
                headers={"Accept": "application/json"},
            )
            token_data = token_resp.json()

            if "error" in token_data:
                raise ValueError(f"GitHub OAuth error: {token_data.get('error_description', token_data['error'])}")

            access_token = token_data["access_token"]

            user_resp = await client.get(
                self.API_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_data = user_resp.json()

            email = user_data.get("email")
            if not email:
                emails_resp = await client.get(
                    self.API_EMAIL_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                emails = emails_resp.json()
                for e in emails:
                    if e.get("primary") and e.get("verified"):
                        email = e["email"]
                        break
                if not email and emails:
                    email = emails[0]["email"]

            return OAuthUserInfo(
                provider="github",
                provider_user_id=str(user_data["id"]),
                email=email or f"gh-{user_data['id']}+noreply@github.com",
                username=user_data.get("login", f"gh-{user_data['id']}"),
                access_token=access_token,
            )


class GoogleOAuthProvider(BaseOAuthProvider):
    AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    SCOPES = "openid email profile"

    def __init__(self):
        config = get_config()
        self.client_id = config.auth.oauth.google_client_id
        self.client_secret = config.auth.oauth.google_client_secret
        self.redirect_uri = config.auth.oauth.google_redirect_uri

    def provider_name(self) -> str:
        return "google"

    def get_authorize_url(self, state: str, code_challenge: Optional[str] = None) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.SCOPES,
            "response_type": "code",
            "state": state,
            "access_type": "offline",
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.AUTHORIZE_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str, code_verifier: Optional[str] = None) -> OAuthUserInfo:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        if code_verifier:
            data["code_verifier"] = code_verifier

        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                self.TOKEN_URL,
                data=data,
                headers={"Accept": "application/json"},
            )
            token_data = token_resp.json()

            if "error" in token_data:
                raise ValueError(f"Google OAuth error: {token_data.get('error_description', token_data['error'])}")

            access_token = token_data["access_token"]
            refresh_token = token_data.get("refresh_token")

            user_resp = await client.get(
                self.USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_data = user_resp.json()

            return OAuthUserInfo(
                provider="google",
                provider_user_id=user_data["id"],
                email=user_data.get("email", f"google-{user_data['id']}@google.com"),
                username=user_data.get("name", user_data.get("email", f"user-{user_data['id']}")),
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=datetime.now(timezone.utc).replace(second=0, microsecond=0),
            )


def get_oauth_provider(provider: str) -> BaseOAuthProvider:
    """Get the OAuth provider handler by name."""
    providers = {
        "github": GitHubOAuthProvider,
        "google": GoogleOAuthProvider,
    }
    cls = providers.get(provider)
    if cls is None:
        raise ValueError(f"Unsupported OAuth provider: {provider}")
    return cls()
