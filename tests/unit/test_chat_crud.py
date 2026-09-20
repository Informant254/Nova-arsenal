"""Tests for chat-session persistence behavior."""

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from nova_arsenal.db.crud import (
    add_chat_message,
    get_or_create_chat_session,
    list_chat_sessions,
)
from nova_arsenal.db.models import Base


@pytest.mark.asyncio
async def test_first_user_message_titles_and_touches_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as db:
        session = await get_or_create_chat_session(
            db,
            session_id="00000000-0000-0000-0000-000000000001",
            user_id=7,
        )
        original_updated = session.updated_at

        await add_chat_message(
            db,
            session.session_id,
            "user",
            "   Explain   secure   session handling in a web app   ",
        )
        await db.commit()

        rows = await list_chat_sessions(db, user_id=7)
        assert len(rows) == 1
        assert rows[0]["title"] == "Explain secure session handling in a web app"
        assert rows[0]["message_count"] == 1
        assert session.updated_at >= original_updated

    await engine.dispose()


@pytest.mark.asyncio
async def test_existing_chat_title_is_not_replaced():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as db:
        session = await get_or_create_chat_session(
            db,
            session_id="00000000-0000-0000-0000-000000000002",
            user_id=7,
            title="Architecture review",
        )

        await add_chat_message(db, session.session_id, "user", "A later message")
        await db.commit()

        rows = await list_chat_sessions(db, user_id=7)
        assert rows[0]["title"] == "Architecture review"

    await engine.dispose()
