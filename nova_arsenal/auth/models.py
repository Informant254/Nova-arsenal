"""
Nova-Arsenal Authentication Models

Pydantic models for authentication requests and responses.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserBase(BaseModel):
    """Base user model."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)


class UserCreate(UserBase):
    """User creation model."""
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    """User login model."""
    email: EmailStr
    password: str


class UserResponse(UserBase):
    """User response model."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    role: str
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    """JWT token response model."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """JWT token payload model."""
    sub: int
    email: str
    role: str
    exp: datetime
    type: str = "access"  # "access" or "refresh"


class PasswordChange(BaseModel):
    """Password change model."""
    current_password: str
    new_password: str = Field(..., min_length=8)


# ── OAuth Models ─────────────────────────────────────────────────────────────

class OAuthAccountResponse(BaseModel):
    """OAuth account response model."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    provider: str
    provider_email: Optional[str] = None
    created_at: datetime


class OAuthLoginResponse(BaseModel):
    """Response after OAuth login."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    is_new_user: bool = False


# ── Subscription Models ──────────────────────────────────────────────────────

class SubscriptionResponse(BaseModel):
    """Subscription details response."""
    model_config = ConfigDict(from_attributes=True)

    tier: str
    api_calls_limit: int
    api_calls_used: int
    api_calls_remaining: int
    is_active: bool
    started_at: datetime
    expires_at: Optional[datetime] = None


class SubscriptionUpgradeRequest(BaseModel):
    """Subscription upgrade request."""
    tier: str = Field(..., pattern=r"^(pro|enterprise)$")


# ── API Key Models ───────────────────────────────────────────────────────────

class ApiKeyCreateRequest(BaseModel):
    """API key creation request."""
    name: str = Field(default="default", max_length=100)


class ApiKeyResponse(BaseModel):
    """API key response (shows full key only once)."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    key_prefix: str
    name: str
    is_active: bool
    full_key: Optional[str] = None
    created_at: datetime
    last_used_at: Optional[datetime] = None


class ApiKeyListResponse(BaseModel):
    """API key list response (never shows full key)."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    key_prefix: str
    name: str
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime] = None
