"""
Nova-Arsenal Authentication Middleware

FastAPI dependencies for authentication and authorization.
Supports JWT tokens, OAuth tokens, subscription API keys, and PAT tokens.
"""

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nova_arsenal.auth.audit import audit_api_key_used, audit_quota_exceeded, audit_unauthorized
from nova_arsenal.config import get_config
from nova_arsenal.db import get_db
from nova_arsenal.db.models import ApiKey, Subscription, SubscriptionTier, User, UserRole

security = HTTPBearer()
logger = logging.getLogger(__name__)

SUBSCRIPTION_CALL_LIMITS = {
    SubscriptionTier.FREE: 100,
    SubscriptionTier.PRO: 10000,
    SubscriptionTier.ENTERPRISE: 100000,
}


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = None,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Get the current authenticated user.

    Supports:
    - JWT tokens (from Authorization header)
    - Subscription API keys (X-API-Key header)
    - PAT tokens (PAT_TOKEN env var or X-PAT header)
    - Direct access when no auth is configured

    Args:
        request: FastAPI request
        credentials: JWT credentials from Authorization header
        db: Database session

    Returns:
        User: Current authenticated user
    """
    config = get_config()

    # 1) Check X-API-Key header (subscription-based API key)
    api_key_header = request.headers.get("X-API-Key")
    if api_key_header:
        key_hash = hashlib.sha256(api_key_header.encode()).hexdigest()
        result = await db.execute(
            select(ApiKey).where(
                ApiKey.key_hash == key_hash,
                ApiKey.is_active == True,
            )
        )
        api_key = result.scalar_one_or_none()
        if not api_key:
            client_ip = request.client.host if request.client else "unknown"
            audit_unauthorized(client_ip, "invalid_api_key")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )
        if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
            client_ip = request.client.host if request.client else "unknown"
            audit_unauthorized(client_ip, f"expired_key:{api_key.key_prefix}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired",
            )
        # Update last used
        api_key.last_used_at = datetime.now(timezone.utc)

        # Check subscription quota
        sub_result = await db.execute(
            select(Subscription).where(Subscription.user_id == api_key.user_id)
        )
        sub = sub_result.scalar_one_or_none()
        if sub:
            limit = SUBSCRIPTION_CALL_LIMITS.get(sub.tier, 100)
            if sub.api_calls_used >= limit:
                audit_quota_exceeded(api_key.user_id, sub.tier.value)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"API call limit reached for {sub.tier.value} tier ({limit}/day). Upgrade subscription.",
                )
            sub.api_calls_used += 1

        audit_api_key_used(api_key.user_id, api_key.key_prefix)
        await db.commit()

        user_result = await db.execute(select(User).where(User.id == api_key.user_id))
        user = user_result.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )
        return user

    # 2) Check for PAT token in environment or headers
    pat_token = os.environ.get("PAT_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if pat_token:
        x_pat = request.headers.get("X-PAT")
        if x_pat and x_pat == pat_token:
            result = await db.execute(select(User).where(User.role == UserRole.ANALYST))
            user = result.scalar_one_or_none()
            if user:
                return user
            return User(
                id=0,
                username="pat-user",
                email="pat@nova.local",
                hashed_password="",
                role=UserRole.ANALYST,
                is_active=True,
            )

    # 3) Fall back to JWT authentication
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(
            token, config.auth.jwt_secret, algorithms=["HS256"]
        )
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive",
        )

    return user


def require_role(*roles: UserRole):
    """
    Require specific roles for access.
    
    Args:
        roles: Allowed roles
        
    Returns:
        Dependency function
    """
    async def check_role(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {current_user.role.value} not in required roles: {[r.value for r in roles]}",
            )
        return current_user
    return check_role


# Convenience dependencies
require_admin = require_role(UserRole.ADMIN)
require_analyst = require_role(UserRole.ADMIN, UserRole.ANALYST)
