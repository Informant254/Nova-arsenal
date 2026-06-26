"""
Nova-Arsenal OAuth Provider Handlers

Handles OAuth2 authorization code flow for GitHub, Google, and GitLab.
"""

import hashlib
import hmac
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

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


def generate_oauth_state(provider: str, redirect: str = "") -> str:
    """Generate a signed state token for OAuth flow."""
    config = get_config()
    secret = config.auth.oauth.state_secret or config.auth.jwt_secret
    raw = f"{provider}:{secrets.token_hex(16)}:{redirect}"
    sig = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{raw}:{sig}"


def verify_oauth_state(state: str, provider: str) -> bool:
    """Verify a signed OAuth state token."""
    config = get_config()
    secret = config.auth.oauth.state_secret or config.auth.jwt_secret
    parts = state.split(":")
    if len(parts) < 4:
        return False
    expected_sig = hmac.new(
        secret.encode(), ":".join(parts[:-1]).encode(), hashlib.sha256
    ).hexdigest()[:16]
    return hmac.compare_digest(parts[-1], expected_sig) and parts[0] == provider


def extract_redirect(state: str) -> str:
    """Extract redirect URL from state token."""
    parts = state.split(":")
    return parts[2] if len(parts) >= 4 else ""


class BaseOAuthProvider(ABC):
    @abstractmethod
    def get_authorize_url(self, state: str) -> str:
        ...

    @abstractmethod
    async def exchange_code(self, code: str) -> OAuthUserInfo:
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

    def get_authorize_url(self, state: str) -> str:
        return (
            f"{self.AUTHORIZE_URL}?client_id={self.client_id}"
            f"&redirect_uri={self.redirect_uri}"
            f"&scope={self.SCOPES}&state={state}"
        )

    async def exchange_code(self, code: str) -> OAuthUserInfo:
        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                self.TOKEN_URL,
                json={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                },
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

    def get_authorize_url(self, state: str) -> str:
        return (
            f"{self.AUTHORIZE_URL}?client_id={self.client_id}"
            f"&redirect_uri={self.redirect_uri}"
            f"&scope={self.SCOPES}&response_type=code"
            f"&state={state}&access_type=offline"
        )

    async def exchange_code(self, code: str) -> OAuthUserInfo:
        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                self.TOKEN_URL,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "grant_type": "authorization_code",
                },
                headers={"Accept": "application/json"},
            )
            token_data = token_resp.json()

            if "error" in token_data:
                raise ValueError(f"Google OAuth error: {token_data.get('error_description', token_data['error'])}")

            access_token = token_data["access_token"]
            refresh_token = token_data.get("refresh_token")
            expires_in = token_data.get("expires_in", 3600)

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
