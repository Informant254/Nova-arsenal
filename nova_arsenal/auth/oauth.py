"""
Nova-Arsenal OAuth Provider Handlers

Handles OAuth2 authorization code flow with PKCE for GitHub and Google.
"""

import hashlib
import hmac
import secrets
import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
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


def generate_oauth_state(provider: str, redirect: str = "", pkce: Optional[PKCEChallenge] = None) -> str:
    """Generate a signed state token for OAuth flow.

    State format: provider:random:redirect:pkce_verifier:signature
    """
    config = get_config()
    secret = config.auth.oauth.state_secret or config.auth.jwt_secret
    verifier = pkce.code_verifier if pkce else ""
    raw = f"{provider}:{secrets.token_hex(16)}:{redirect}:{verifier}"
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


def extract_pkce_verifier(state: str) -> Optional[str]:
    """Extract PKCE code_verifier from state token."""
    parts = state.split(":")
    if len(parts) >= 5 and parts[3]:
        return parts[3]
    return None


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
        url = (
            f"{self.AUTHORIZE_URL}?client_id={self.client_id}"
            f"&redirect_uri={self.redirect_uri}"
            f"&scope={self.SCOPES}&state={state}"
        )
        if code_challenge:
            url += f"&code_challenge={code_challenge}&code_challenge_method=S256"
        return url

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
        url = (
            f"{self.AUTHORIZE_URL}?client_id={self.client_id}"
            f"&redirect_uri={self.redirect_uri}"
            f"&scope={self.SCOPES}&response_type=code"
            f"&state={state}&access_type=offline"
        )
        if code_challenge:
            url += f"&code_challenge={code_challenge}&code_challenge_method=S256"
        return url

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
