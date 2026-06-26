"""
Nova-Arsenal Database Session Management

Async database sessions using SQLAlchemy 2.0
"""

import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from nova_arsenal.db.models import Base

# Default database URL
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///nova.db")

# Lazy engine and session factory
_engine = None
_session_factory: async_sessionmaker | None = None


def get_engine():
    """Get or create the async engine (lazy initialization)."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            DATABASE_URL,
            echo=os.getenv("DATABASE_ECHO", "false").lower() == "true",
            future=True,
        )
    return _engine


def get_session_factory():
    """Get or create the async session factory (lazy initialization)."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


# Module-level convenience accessor — will be set on first use
async_session_factory = None


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get a database session.

    Yields:
        AsyncSession: Database session
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables() -> None:
    """Create all database tables."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_tables() -> None:
    """Drop all database tables."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
