"""
Unit tests for resilient agent core with error handling and timeouts.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nova_arsenal.resilient_agent_core import (
    ResilientNovaAgent,
    ResilientAgentConfig,
)


class TestResilientNovaAgent:
    """Test resilient agent behavior."""

    def test_resilient_agent_initialization(self):
        """Test resilient agent initializes correctly."""
        agent = ResilientNovaAgent(
            target="example.com",
            objective="Test objective",
        )
        assert agent.target == "example.com"
        assert agent.state.step == 0
        assert len(agent.get_execution_errors()) == 0

    def test_resilient_agent_config(self):
        """Test resilient agent accepts custom config."""
        config = ResilientAgentConfig(
            step_timeout=60.0,
            total_timeout=300.0,
            max_retries=5,
        )
        agent = ResilientNovaAgent(
            target="example.com",
            config=config,
        )
        assert agent.config.total_timeout == 300.0
        assert agent.config.max_retries == 5

    def test_resilient_agent_error_tracking(self):
        """Test agent tracks execution errors."""
        agent = ResilientNovaAgent(target="example.com")

        agent.add_execution_error({
            "type": "test_error",
            "message": "Test error message",
        })
        
        errors = agent.get_execution_errors()
        assert len(errors) == 1
        assert errors[0]["type"] == "test_error"

    def test_resilient_agent_step_with_error(self):
        """Test agent records errors in steps."""
        agent = ResilientNovaAgent(target="example.com")
        
        agent.step(
            action="scan_port",
            result="Failed",
            error="Connection refused",
        )
        
        assert agent.state.step == 1
        assert len(agent.state.errors) == 1
        assert agent.state.errors[0] == "Connection refused"
        assert len(agent.get_execution_errors()) == 1

    def test_resilient_agent_summary(self):
        """Test resilient agent summary includes error info."""
        agent = ResilientNovaAgent(target="example.com")
        
        agent.step("action1", "result1", error="error1")
        agent.add_execution_error({"type": "custom_error"})
        
        summary = agent.summary()
        assert "total_errors" in summary
        assert "execution_errors" in summary
        assert "circuit_breaker_state" in summary
        assert "resource_status" in summary
        assert summary["total_errors"] >= 1

    def test_resilient_agent_error_limit(self):
        """Test agent limits stored errors to prevent memory leak."""
        agent = ResilientNovaAgent(target="example.com")
        
        # Add many errors
        for i in range(150):
            agent.add_execution_error({
                "id": i,
                "message": f"Error {i}",
            })
        
        errors = agent.get_execution_errors()
        # Should keep only last 100
        assert len(errors) <= 100

    def test_resilient_agent_circuit_breaker_state(self):
        """Test resilient agent has circuit breaker."""
        agent = ResilientNovaAgent(target="example.com")
        summary = agent.summary()
        assert "circuit_breaker_state" in summary
        assert summary["circuit_breaker_state"] == "closed"

    def test_resilient_agent_resource_tracking(self):
        """Test resilient agent tracks resource usage."""
        agent = ResilientNovaAgent(target="example.com")
        
        agent.resource_tracker.start_execution()
        agent.resource_tracker.record_task_started()
        agent.resource_tracker.record_tool_call()
        
        summary = agent.summary()
        resource_status = summary["resource_status"]
        assert resource_status["active_tasks"] == 1
        assert resource_status["total_tool_calls"] == 1
