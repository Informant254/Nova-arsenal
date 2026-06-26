"""
Nova-Arsenal Authentication Middleware

FastAPI dependencies for authentication and authorization.
Supports JWT tokens, GitHub PAT, and direct API access.
"""

import os
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nova_arsenal.config import get_config
from nova_arsenal.db import get_db
from nova_arsenal.db.models import User, UserRole

security = HTTPBearer()


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = None,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Get the current authenticated user.
    
    Supports:
    - JWT tokens (from Authorization header)
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
    
    # Check for PAT token in environment or headers
    pat_token = os.environ.get("PAT_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if pat_token:
        # Check X-PAT header
        x_pat = request.headers.get("X-PAT")
        if x_pat and x_pat == pat_token:
            # Return a default user for PAT-authenticated requests
            result = await db.execute(select(User).where(User.role == UserRole.ANALYST))
            user = result.scalar_one_or_none()
            if user:
                return user
            # Create default PAT user if none exists
            return User(
                username="pat-user",
                email="pat@nova.local",
                password_hash="",
                role=UserRole.ANALYST,
                is_active=True,
            )
    
    # Fall back to JWT authentication if credentials provided
    if credentials:
        token = credentials.credentials
    
    # Fall back to JWT authentication if credentials provided
    if credentials:
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
