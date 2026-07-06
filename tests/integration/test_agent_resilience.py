"""
Integration tests for resilient agent under stress and error conditions.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nova_arsenal.resilient_agent_core import ResilientNovaAgent, ResilientAgentConfig
from nova_swarm import NovaSwarm


@pytest.mark.integration
class TestAgentUnderStress:
    """Test agent behavior under stress conditions."""

    def test_agent_handles_multiple_errors(self):
        """Test agent gracefully handles multiple errors."""
        agent = ResilientNovaAgent(target="stress-test.com")
        
        # Simulate multiple errors
        for i in range(10):
            agent.step(
                action=f"action_{i}",
                result="failed",
                error=f"Error {i}",
            )
        
        assert agent.state.step == 10
        assert len(agent.state.errors) == 10
        summary = agent.summary()
        assert summary["total_errors"] == 10

    def test_agent_resource_limits_enforcement(self):
        """Test agent enforces resource limits."""
        config = ResilientAgentConfig(
            max_tool_calls_per_step=5,
        )
        agent = ResilientNovaAgent(
            target="resource-test.com",
            config=config,
        )
        
        agent.resource_tracker.start_execution()
        
        # Record tool calls
        for _ in range(5):
            agent.resource_tracker.record_tool_call()
        
        is_ok, msg = agent.resource_tracker.check_limits()
        assert is_ok is True
        
        # Exceed limit
        agent.resource_tracker.record_tool_call()
        is_ok, msg = agent.resource_tracker.check_limits()
        assert is_ok is False

    def test_agent_concurrent_task_tracking(self):
        """Test agent tracks concurrent task limits."""
        config = ResilientAgentConfig(
            max_concurrent_tasks=3,
        )
        agent = ResilientNovaAgent(
            target="concurrent-test.com",
            config=config,
        )
        
        agent.resource_tracker.start_execution()
        
        # Start tasks
        for _ in range(3):
            agent.resource_tracker.record_task_started()
        
        is_ok, msg = agent.resource_tracker.check_limits()
        assert is_ok is True
        
        # Exceed limit
        agent.resource_tracker.record_task_started()
        is_ok, msg = agent.resource_tracker.check_limits()
        assert is_ok is False
        
        # Complete a task and verify recovery
        agent.resource_tracker.record_task_completed()
        is_ok, msg = agent.resource_tracker.check_limits()
        assert is_ok is True


@pytest.mark.integration
class TestSwarmResilience:
    """Test multi-agent swarm resilience."""

    def test_swarm_handles_agent_failures(self):
        """Test swarm can handle individual agent failures."""
        swarm = NovaSwarm(target="swarm-test.com")
        
        # Verify swarm initializes
        agents = swarm.list_agents()
        assert len(agents) > 0
        
        # Each agent should have a role
        roles = [agent.role for agent in agents]
        assert "recon" in roles or "scanner" in roles

    def test_swarm_finding_sharing(self):
        """Test swarm agents can share findings."""
        swarm = NovaSwarm(target="swarm-share.com")
        agents = swarm.list_agents()
        
        # Agent shares a finding
        if agents:
            agent = agents[0]
            finding = {
                "type": "test_finding",
                "severity": "high",
            }
            swarm.share_finding(agent.id, finding)
        
        findings = swarm.get_all_findings()
        assert len(findings) >= 1
        assert findings[0]["type"] == "test_finding"

    def test_swarm_status_tracking(self):
        """Test swarm can track agent status."""
        swarm = NovaSwarm(target="swarm-status.com")
        
        status = swarm.status()
        assert isinstance(status, dict)
        
        summary = swarm.summary()
        assert summary["agents"] > 0
        assert summary["target"] == "swarm-status.com"
