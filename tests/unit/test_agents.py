"""Tests for multi-agent coordinator."""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestAgentRole:
    def test_import(self):
        from nova_arsenal.agents.coordinator import AgentRole
        assert AgentRole.SCOUT.value == "scout"
        assert AgentRole.EXPLOITER.value == "exploiter"
        assert AgentRole.VALIDATOR.value == "validator"
        assert AgentRole.CHAINER.value == "chainer"
        assert AgentRole.REPORTER.value == "reporter"


class TestAgentTask:
    def test_import(self):
        from nova_arsenal.agents.coordinator import AgentTask, AgentRole
        t = AgentTask(
            task_id="t1", role=AgentRole.SCOUT, description="Recon",
            target="10.0.0.1", priority=5,
        )
        assert t.task_id == "t1"
        assert t.status == "pending"


class TestAgentResult:
    def test_import(self):
        from nova_arsenal.agents.coordinator import AgentResult, AgentRole
        r = AgentResult(
            task_id="t1", agent_id="a1", role=AgentRole.SCOUT,
            findings=[], evidence="test", confidence=0.9, duration_ms=100.0,
            reasoning_trace=["step1"],
        )
        assert r.confidence == 0.9


class TestAgentConfig:
    def test_import(self):
        from nova_arsenal.agents.coordinator import AgentConfig
        c = AgentConfig()
        assert c.max_concurrent_agents == 100
        assert c.agent_timeout == 300


class TestMultiAgentCoordinator:
    def test_import(self):
        from nova_arsenal.agents.coordinator import MultiAgentCoordinator
        c = MultiAgentCoordinator()
        assert c is not None

    def test_assign_task(self):
        from nova_arsenal.agents.coordinator import (
            MultiAgentCoordinator, AgentTask, AgentRole,
        )
        c = MultiAgentCoordinator()
        t = AgentTask(
            task_id="t1", role=AgentRole.SCOUT, description="Recon",
            target="10.0.0.1", priority=5,
        )
        _run(c.assign_task(t))
        assert c._tasks["t1"].status == "pending"

    def test_get_global_view(self):
        from nova_arsenal.agents.coordinator import MultiAgentCoordinator
        c = MultiAgentCoordinator()
        view = c.get_global_view()
        assert "tasks" in view
        assert "total_agents" in view

    def test_get_findings(self):
        from nova_arsenal.agents.coordinator import MultiAgentCoordinator
        c = MultiAgentCoordinator()
        findings = c.get_findings()
        assert isinstance(findings, list)

    def test_stop_all(self):
        from nova_arsenal.agents.coordinator import MultiAgentCoordinator
        c = MultiAgentCoordinator()
        c.stop_all()
        assert len(c._tasks) == 0
