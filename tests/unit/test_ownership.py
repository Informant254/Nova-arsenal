"""Regression tests for user-owned chat and work-session boundaries."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_chat_session_rejects_foreign_owner():
    from nova_arsenal.db.crud import get_or_create_chat_session

    existing = SimpleNamespace(user_id=99)
    db = AsyncMock()

    with patch(
        "nova_arsenal.db.crud.get_chat_session",
        new=AsyncMock(return_value=existing),
    ):
        with pytest.raises(PermissionError):
            await get_or_create_chat_session(
                db,
                session_id="11111111-1111-1111-1111-111111111111",
                user_id=7,
            )


@pytest.mark.asyncio
async def test_chat_session_allows_matching_owner():
    from nova_arsenal.db.crud import get_or_create_chat_session

    existing = SimpleNamespace(user_id=7)
    db = AsyncMock()

    with patch(
        "nova_arsenal.db.crud.get_chat_session",
        new=AsyncMock(return_value=existing),
    ):
        result = await get_or_create_chat_session(
            db,
            session_id="11111111-1111-1111-1111-111111111111",
            user_id=7,
        )

    assert result is existing


def test_work_session_owner_access():
    from nova_arsenal.sessions.api_routes import _can_access

    analyst = SimpleNamespace(id=7, role=SimpleNamespace(value="analyst"))
    admin = SimpleNamespace(id=1, role=SimpleNamespace(value="admin"))
    owned = SimpleNamespace(metadata={"owner_id": 7})
    foreign = SimpleNamespace(metadata={"owner_id": 8})
    legacy = SimpleNamespace(metadata={})

    assert _can_access(owned, analyst) is True
    assert _can_access(foreign, analyst) is False
    assert _can_access(legacy, analyst) is False
    assert _can_access(foreign, admin) is True
