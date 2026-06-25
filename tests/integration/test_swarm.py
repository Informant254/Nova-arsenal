"""
Integration tests for Nova Swarm module.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.mark.integration
class TestNovaSwarm:
    """Test NovaSwarm integration."""

    def test_knowledge_graph_initialization(self):
        """Test knowledge graph can be initialized."""
        from nova_swarm import KnowledgeGraph

        kg = KnowledgeGraph()
        assert kg is not None
        assert hasattr(kg, "graph")
        assert "nodes" in kg.graph
        assert "edges" in kg.graph
        assert "findings" in kg.graph

    def test_knowledge_graph_add_node(self):
        """Test adding nodes to knowledge graph."""
        from nova_swarm import KnowledgeGraph

        kg = KnowledgeGraph()
        kg.add_node(
            node_id="test-1",
            node_type="target",
            data={"host": "example.com"},
            agent="test-agent",
        )
        assert "test-1" in kg.graph["nodes"]

    def test_knowledge_graph_add_finding(self):
        """Test adding findings to knowledge graph."""
        from nova_swarm import KnowledgeGraph

        kg = KnowledgeGraph()
        finding = {
            "type": "sql_injection",
            "endpoint": "/api/search",
            "severity": "critical",
        }
        kg.add_finding(finding, agent="test-agent")
        assert len(kg.graph["findings"]) == 1
