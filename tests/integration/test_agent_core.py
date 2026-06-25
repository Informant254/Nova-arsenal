"""
Integration tests for Nova Agent Core.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.mark.integration
class TestNovaAgent:
    """Test NovaAgent integration."""

    def test_agent_initialization(self):
        """Test agent can be initialized."""
        from nova_agent_core import NovaAgent

        agent = NovaAgent(
            target="example.com",
            objective="Find SQL injection vulnerabilities",
        )
        assert agent.target == "example.com"
        assert agent.max_steps > 0

    def test_agent_has_model(self):
        """Test that agent has a model configured."""
        from nova_agent_core import NovaAgent

        agent = NovaAgent(target="example.com")
        assert hasattr(agent, "model")
        assert isinstance(agent.model, str)

    def test_agent_workspace_created(self):
        """Test that agent creates workspace."""
        from nova_agent_core import NovaAgent

        agent = NovaAgent(target="example.com")
        assert hasattr(agent, "workspace")
