"""
Nova-Arsenal Authentication Routes

FastAPI routes for user authentication, OAuth, subscription, and API keys.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import secrets

from nova_arsenal.auth.middleware import get_current_user
from nova_arsenal.auth.models import (
    ApiKeyCreateRequest,
    ApiKeyListResponse,
    ApiKeyResponse,
    OAuthAccountResponse,
    OAuthLoginResponse,
    PasswordChange,
    SubscriptionResponse,
    SubscriptionUpgradeRequest,
    Token,
    UserCreate,
    UserLogin,
    UserResponse,
)
from nova_arsenal.auth.oauth import (
    extract_redirect,
    generate_oauth_state,
    get_oauth_provider,
    verify_oauth_state,
)
from nova_arsenal.config import get_config
from nova_arsenal.db import get_db
from nova_arsenal.db.models import (
    ApiKey,
    OAuthAccount,
    OAuthProvider,
    Subscription,
    SubscriptionTier,
    User,
    UserRole,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create an access token."""
    config = get_config()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=config.auth.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, config.auth.jwt_secret, algorithm="HS256")


def create_refresh_token(data: dict) -> str:
    """Create a refresh token."""
    config = get_config()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=config.auth.refresh_token_expire_days)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, config.auth.jwt_secret, algorithm="HS256")


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user."""
    # Check if email exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Check if username exists
    result = await db.execute(select(User).where(User.username == user_data.username))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken",
        )

    # Create user
    user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=get_password_hash(user_data.password),
        role=UserRole.ANALYST,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        role=user.role.value,
        is_active=user.is_active,
        created_at=user.created_at,
    )


@router.post("/login", response_model=Token)
async def login(credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    """Login and get JWT tokens."""
    result = await db.execute(select(User).where(User.email == credentials.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # Create tokens
    token_data = {"sub": user.id, "email": user.email, "role": user.role.value}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str, db: AsyncSession = Depends(get_db)):
    """Refresh access token using refresh token."""
    config = get_config()
    try:
        payload = jwt.decode(
            refresh_token, config.auth.jwt_secret, algorithms=["HS256"]
        )
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Create new tokens
    token_data = {"sub": user.id, "email": user.email, "role": user.role.value}
    new_access_token = create_access_token(token_data)
    new_refresh_token = create_refresh_token(token_data)

    return Token(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    current_user: User = Depends(get_current_user),
):
    """Get current user profile."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        role=current_user.role.value,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
    )


# ── OAuth Routes ─────────────────────────────────────────────────────────────

@router.get("/oauth/{provider}/login")
async def oauth_login(provider: str, redirect: str = ""):
    """Redirect to OAuth provider for authentication."""
    if provider not in ("github", "google"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {provider}",
        )
    oauth = get_oauth_provider(provider)
    state = generate_oauth_state(provider, redirect)
    authorize_url = oauth.get_authorize_url(state)
    return {"authorize_url": authorize_url, "state": state}


@router.get("/oauth/{provider}/callback", response_model=OAuthLoginResponse)
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    db: AsyncSession = Depends(get_db),
):
    """Handle OAuth provider callback."""
    if not verify_oauth_state(state, provider):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state token",
        )

    oauth = get_oauth_provider(provider)
    try:
        user_info = await oauth.exchange_code(code)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Check if OAuth account already linked
    result = await db.execute(
        select(OAuthAccount).where(
            OAuthAccount.provider == OAuthProvider(provider),
            OAuthAccount.provider_user_id == user_info.provider_user_id,
        )
    )
    existing_account = result.scalar_one_or_none()
    is_new_user = False

    if existing_account:
        user = existing_account.user
        # Update tokens
        existing_account.access_token = user_info.access_token
        if user_info.refresh_token:
            existing_account.refresh_token = user_info.refresh_token
        if user_info.expires_at:
            existing_account.expires_at = user_info.expires_at
    else:
        # Check if user exists with this email
        result = await db.execute(
            select(User).where(User.email == user_info.email)
        )
        user = result.scalar_one_or_none()

        if not user:
            # Create new user
            user = User(
                email=user_info.email,
                username=user_info.username,
                hashed_password="",
                role=UserRole.ANALYST,
            )
            db.add(user)
            await db.flush()
            await db.refresh(user)
            is_new_user = True

            # Auto-create free subscription for new OAuth users
            tier = SubscriptionTier(get_config().auth.oauth.default_tier)
            sub = Subscription(
                user_id=user.id,
                tier=tier,
                api_calls_limit=getattr(
                    get_config().auth.oauth, f"{tier.value}_api_calls_per_day", 100
                ),
            )
            db.add(sub)

        # Link OAuth account
        oauth_account = OAuthAccount(
            user_id=user.id,
            provider=OAuthProvider(provider),
            provider_user_id=user_info.provider_user_id,
            provider_email=user_info.email,
            access_token=user_info.access_token,
            refresh_token=user_info.refresh_token,
            expires_at=user_info.expires_at,
        )
        db.add(oauth_account)

    await db.commit()

    # Create JWT tokens
    token_data = {"sub": user.id, "email": user.email, "role": user.role.value}
    access_token = create_access_token(token_data)
    refresh_token_str = create_refresh_token(token_data)

    return OAuthLoginResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,
        is_new_user=is_new_user,
    )


@router.get("/oauth/accounts", response_model=list[OAuthAccountResponse])
async def list_oauth_accounts(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List OAuth accounts linked to current user."""
    result = await db.execute(
        select(OAuthAccount).where(OAuthAccount.user_id == current_user.id)
    )
    accounts = result.scalars().all()
    return [
        OAuthAccountResponse(
            id=acc.id,
            provider=acc.provider.value,
            provider_email=acc.provider_email,
            created_at=acc.created_at,
        )
        for acc in accounts
    ]


@router.delete("/oauth/{provider}")
async def unlink_oauth_account(
    provider: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Unlink an OAuth account."""
    result = await db.execute(
        select(OAuthAccount).where(
            OAuthAccount.user_id == current_user.id,
            OAuthAccount.provider == OAuthProvider(provider),
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No linked {provider} account",
        )

    # Prevent unlinking if user has no password set and no other OAuth accounts
    remaining = await db.execute(
        select(OAuthAccount).where(
            OAuthAccount.user_id == current_user.id,
            OAuthAccount.id != account.id,
        )
    )
    if not current_user.hashed_password and not remaining.scalars().all():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot unlink last authentication method. Set a password first.",
        )

    await db.delete(account)
    await db.commit()
    return {"message": f"Unlinked {provider} account"}


# ── Subscription Routes ──────────────────────────────────────────────────────

@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current user's subscription details."""
    result = await db.execute(
        select(Subscription).where(Subscription.user_id == current_user.id)
    )
    sub = result.scalar_one_or_none()

    if not sub:
        sub = Subscription(
            user_id=current_user.id,
            tier=SubscriptionTier.FREE,
        )
        db.add(sub)
        await db.commit()
        await db.refresh(sub)

    return SubscriptionResponse(
        tier=sub.tier.value,
        api_calls_limit=sub.api_calls_limit,
        api_calls_used=sub.api_calls_used,
        api_calls_remaining=max(0, sub.api_calls_limit - sub.api_calls_used),
        is_active=sub.is_active,
        started_at=sub.started_at,
        expires_at=sub.expires_at,
    )


@router.post("/subscription/upgrade")
async def upgrade_subscription(
    request: SubscriptionUpgradeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upgrade subscription tier."""
    result = await db.execute(
        select(Subscription).where(Subscription.user_id == current_user.id)
    )
    sub = result.scalar_one_or_none()

    new_tier = SubscriptionTier(request.tier)
    limit_map = {
        SubscriptionTier.FREE: get_config().auth.oauth.free_api_calls_per_day,
        SubscriptionTier.PRO: get_config().auth.oauth.pro_api_calls_per_day,
        SubscriptionTier.ENTERPRISE: get_config().auth.oauth.enterprise_api_calls_per_day,
    }

    if sub:
        sub.tier = new_tier
        sub.api_calls_limit = limit_map[new_tier]
        sub.is_active = True
    else:
        sub = Subscription(
            user_id=current_user.id,
            tier=new_tier,
            api_calls_limit=limit_map[new_tier],
        )
        db.add(sub)

    await db.commit()
    return {"message": f"Subscription upgraded to {new_tier.value}"}


# ── API Key Routes ───────────────────────────────────────────────────────────

def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key. Returns (full_key, key_prefix, key_hash)."""
    full_key = f"na_{secrets.token_hex(32)}"
    key_prefix = full_key[:10]
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    return full_key, key_prefix, key_hash


@router.post("/api-keys", response_model=ApiKeyResponse)
async def create_api_key(
    request: ApiKeyCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a new API key for subscription-based access."""
    # Check subscription exists
    result = await db.execute(
        select(Subscription).where(Subscription.user_id == current_user.id)
    )
    sub = result.scalar_one_or_none()
    if not sub or not sub.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active subscription. Please subscribe first.",
        )

    full_key, key_prefix, key_hash = generate_api_key()
    api_key = ApiKey(
        user_id=current_user.id,
        key_prefix=key_prefix,
        key_hash=key_hash,
        name=request.name,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return ApiKeyResponse(
        id=api_key.id,
        key_prefix=api_key.key_prefix,
        name=api_key.name,
        is_active=api_key.is_active,
        full_key=full_key,
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at,
    )


@router.get("/api-keys", response_model=list[ApiKeyListResponse])
async def list_api_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List API keys for the current user."""
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.user_id == current_user.id,
            ApiKey.is_active == True,
        )
    )
    keys = result.scalars().all()
    return [
        ApiKeyListResponse(
            id=key.id,
            key_prefix=key.key_prefix,
            name=key.name,
            is_active=key.is_active,
            created_at=key.created_at,
            last_used_at=key.last_used_at,
        )
        for key in keys
    ]


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an API key."""
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == key_id,
            ApiKey.user_id == current_user.id,
        )
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    key.is_active = False
    await db.commit()
    return {"message": "API key revoked"}


@router.get("/api-keys/usage")
async def get_api_key_usage(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get API key usage statistics."""
    result = await db.execute(
        select(ApiKey).where(ApiKey.user_id == current_user.id)
    )
    keys = result.scalars().all()
    total = len(keys)
    active = sum(1 for k in keys if k.is_active)
    return {
        "total_keys": total,
        "active_keys": active,
    }
