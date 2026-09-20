"""Secure, idempotent bootstrap for the first Nova administrator."""

from __future__ import annotations

import logging
import os

from passlib.context import CryptContext
from sqlalchemy import or_, select

from nova_arsenal.db.models import User, UserRole
from nova_arsenal.db.session import get_session_factory

logger = logging.getLogger(__name__)
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def ensure_bootstrap_admin() -> bool:
    """Create the configured bootstrap admin once.

    No account is created unless NOVA_ADMIN_EMAIL and NOVA_ADMIN_PASSWORD are
    explicitly supplied. Existing accounts are never silently promoted or have
    their password overwritten.
    """
    email = os.getenv("NOVA_ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("NOVA_ADMIN_PASSWORD", "")
    username = os.getenv("NOVA_ADMIN_USERNAME", "admin").strip() or "admin"

    configured = any(
        os.getenv(name)
        for name in ("NOVA_ADMIN_EMAIL", "NOVA_ADMIN_PASSWORD", "NOVA_ADMIN_USERNAME")
    )
    if not configured:
        return False
    if not email or not password:
        raise RuntimeError(
            "NOVA_ADMIN_EMAIL and NOVA_ADMIN_PASSWORD must both be set "
            "when bootstrap admin configuration is present"
        )
    if len(password) < 12:
        raise RuntimeError("NOVA_ADMIN_PASSWORD must be at least 12 characters")

    factory = get_session_factory()
    async with factory() as db:
        result = await db.execute(
            select(User).where(
                or_(User.email == email, User.username == username)
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            if existing.role != UserRole.ADMIN:
                logger.warning(
                    "Bootstrap admin identity already belongs to a non-admin user; "
                    "refusing silent privilege escalation"
                )
            return False

        user = User(
            email=email,
            username=username,
            hashed_password=_pwd_context.hash(password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(user)
        await db.commit()
        logger.info("Bootstrap administrator created for %s", email)
        return True
