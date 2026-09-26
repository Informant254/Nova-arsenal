"""
Nova-Arsenal API Key Cleanup

Background task that periodically removes expired API keys.
"""

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from nova_arsenal.db.models import ApiKey

logger = logging.getLogger(__name__)


async def cleanup_expired_api_keys():
    """Deactivate API keys that have passed their expiry date."""
    try:
        from nova_arsenal.db.session import get_session_factory

        factory = get_session_factory()
        async with factory() as db:
            result = await db.execute(
                select(ApiKey).where(
                    ApiKey.is_active.is_(True),
                    ApiKey.expires_at.isnot(None),
                    ApiKey.expires_at < datetime.now(timezone.utc),
                )
            )
            expired_keys = result.scalars().all()
            if expired_keys:
                for key in expired_keys:
                    key.is_active = False
                    logger.info(f"Deactivated expired API key: {key.key_prefix}...")
                await db.commit()
                logger.info(f"Cleaned up {len(expired_keys)} expired API keys")
    except Exception as e:
        logger.error(f"API key cleanup failed: {e}")


async def start_cleanup_task(interval_seconds: int = 3600):
    """Start the background cleanup task."""
    while True:
        await asyncio.sleep(interval_seconds)
        await cleanup_expired_api_keys()
