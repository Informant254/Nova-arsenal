"""
Enhanced tests for nova_agent_core.py covering edge cases and state management.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nova_agent_core import NovaAgent, AgentState


class TestNovaAgentState:
    """Test AgentState dataclass."""

    def test_agent_state_initialization(self):
        """Test agent state initializes correctly."""
        state = AgentState()
        assert state.step == 0
        assert len(state.findings) == 0
        assert len(state.actions_taken) == 0
        assert len(state.errors) == 0

    def test_agent_state_mutation(self):
        """Test agent state can be mutated."""
        state = AgentState()
        state.step = 5
        state.findings.append({"id": "test"})
        state.errors.append("test error")
        
        assert state.step == 5
        assert len(state.findings) == 1
        assert len(state.errors) == 1


class TestNovaAgentCore:
    """Test NovaAgent core functionality."""

    def test_nova_agent_initialization(self):
        """Test NovaAgent initializes correctly."""
        agent = NovaAgent(
            target="test.example.com",
            objective="Find vulnerabilities",
            max_steps=50,
            model="test-model",
        )
        assert agent.target == "test.example.com"
        assert agent.objective == "Find vulnerabilities"
        assert agent.max_steps == 50
        assert agent.model == "test-model"

    def test_nova_agent_plan(self):
        """Test agent generates a plan."""
        agent = NovaAgent(target="example.com")
        plan = agent.plan()
        
        assert isinstance(plan, list)
        assert len(plan) > 0
        assert all(isinstance(p, str) for p in plan)

    def test_nova_agent_step(self):
        """Test agent records steps."""
        agent = NovaAgent(target="example.com")
        
        agent.step("reconnaissance", "Found open port 80")
        
        assert agent.state.step == 1
        assert len(agent.state.actions_taken) == 1
        assert agent.state.actions_taken[0] == "reconnaissance"
        assert len(agent._history) == 1

    def test_nova_agent_multiple_steps(self):
        """Test agent tracks multiple steps."""
        agent = NovaAgent(target="example.com")
        
        for i in range(5):
            agent.step(f"action_{i}", f"result_{i}")
        
        assert agent.state.step == 5
        assert len(agent.state.actions_taken) == 5
        assert len(agent._history) == 5

    def test_nova_agent_finding(self):
        """Test agent can record findings."""
        agent = NovaAgent(target="example.com")
        
        finding = {
            "type": "sql_injection",
            "endpoint": "/api/search",
            "severity": "critical",
        }
        agent.add_finding(finding)
        
        assert len(agent.state.findings) == 1
        assert agent.state.findings[0]["type"] == "sql_injection"

    def test_nova_agent_multiple_findings(self):
        """Test agent can track multiple findings."""
        agent = NovaAgent(target="example.com")
        
        for i in range(10):
            agent.add_finding({
                "id": i,
                "severity": "high",
            })
        
        assert len(agent.state.findings) == 10

    def test_nova_agent_reflect(self):
        """Test agent can reflect on progress."""
        agent = NovaAgent(
            target="example.com",
            max_steps=20,
        )
        
        for i in range(5):
            agent.step(f"action_{i}", f"result_{i}")
            agent.add_finding({"id": i})
        
        reflection = agent.reflect()
        
        assert isinstance(reflection, str)
        assert "5/20" in reflection
        assert "5 findings" in reflection

    def test_nova_agent_history(self):
        """Test agent maintains action history."""
        agent = NovaAgent(target="example.com")
        
        agent.step("action_1", "result_1")
        agent.step("action_2", "result_2")
        
        history = agent.get_history()
        assert len(history) == 2
        assert history[0]["action"] == "action_1"
        assert history[1]["action"] == "action_2"

    def test_nova_agent_summary(self):
        """Test agent generates summary."""
        agent = NovaAgent(
            target="example.com",
            objective="Test objective",
            max_steps=30,
            model="test-model",
        )
        
        for i in range(3):
            agent.step(f"action_{i}", f"result_{i}")
            agent.add_finding({"id": i})
        
        summary = agent.summary()
        
        assert summary["target"] == "example.com"
        assert summary["objective"] == "Test objective"
        assert summary["steps_taken"] == 3
        assert summary["max_steps"] == 30
        assert summary["findings"] == 3
        assert summary["model"] == "test-model"

    def test_nova_agent_error_accumulation(self):
        """Test agent can accumulate errors."""
        agent = NovaAgent(target="example.com")
        
        # Simulate adding errors to state
        agent.state.errors.append("Error 1")
        agent.state.errors.append("Error 2")
        
        assert len(agent.state.errors) == 2
        summary = agent.summary()
        assert summary["errors"] == 2
