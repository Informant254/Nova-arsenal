"""Tests for concurrent work sessions + sub-agents."""
import asyncio
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


class TestConcurrentSessions:
    def test_create_and_run_parallel(self, tmp_path, monkeypatch):
        from nova_arsenal.sessions import runtime as rt
        from nova_arsenal.sessions.runtime import SessionManager

        monkeypatch.setattr(rt, "STORE_DIR", tmp_path)
        mgr = SessionManager(store_dir=tmp_path)
        sess = mgr.create(
            goal="Map attack surface and prioritize risks",
            target="lab.example.local",
            roles=["recon", "web", "osint", "researcher", "validator", "reporter"],
            max_concurrent=4,
            authorized=True,
            authorization_ref="TEST-1",
        )
        assert sess.session_id.startswith("sess_")
        assert len(sess.agents) == 6

        async def go():
            return await mgr.start(sess.session_id, wait=True)

        final = _run(go())
        assert final is not None
        assert final.status.value == "completed"
        assert final.summary
        completed = [a for a in final.agents.values() if a.status.value == "completed"]
        assert len(completed) >= 4
        assert len(final.aggregated_findings) >= 1
        # events should show parallel lifecycle
        types = {e.event_type for e in final.events}
        assert "session_started" in types
        assert "agent_started" in types
        assert "session_completed" in types

    def test_list_and_get(self, tmp_path, monkeypatch):
        from nova_arsenal.sessions import runtime as rt
        from nova_arsenal.sessions.runtime import SessionManager

        monkeypatch.setattr(rt, "STORE_DIR", tmp_path)
        mgr = SessionManager(store_dir=tmp_path)
        s1 = mgr.create(goal="g1", target="t1", roles=["recon"])
        s2 = mgr.create(goal="g2", target="t2", roles=["web"])
        assert len(mgr.list_sessions()) >= 2
        assert mgr.get(s1.session_id).goal == "g1"
        assert mgr.get(s2.session_id).target == "t2"

    def test_exports(self):
        from nova_arsenal import SessionManager, SubAgentRole, get_session_manager

        assert SubAgentRole.RECON.value == "recon"
        assert get_session_manager() is not None
        assert SessionManager is not None
