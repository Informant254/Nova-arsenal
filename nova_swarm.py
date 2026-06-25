"""
Nova Swarm Module - Multi-agent coordination for security research.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


class KnowledgeGraph:
    """Shared knowledge graph for swarm agents."""

    def __init__(self) -> None:
        self.graph: Dict[str, Any] = {
            "nodes": {},
            "edges": [],
            "findings": [],
        }

    def add_node(
        self,
        node_id: str,
        node_type: str,
        data: Optional[Dict[str, Any]] = None,
        agent: str = "",
    ) -> None:
        """Add a node to the knowledge graph."""
        self.graph["nodes"][node_id] = {
            "type": node_type,
            "data": data or {},
            "agent": agent,
        }

    def add_edge(
        self,
        source: str,
        target: str,
        relation: str = "",
        agent: str = "",
    ) -> None:
        """Add an edge between two nodes."""
        self.graph["edges"].append({
            "source": source,
            "target": target,
            "relation": relation,
            "agent": agent,
        })

    def add_finding(
        self,
        finding: Dict[str, Any],
        agent: str = "",
    ) -> None:
        """Add a finding to the knowledge graph."""
        finding["agent"] = agent
        self.graph["findings"].append(finding)

    def get_nodes_by_type(self, node_type: str) -> Dict[str, Any]:
        """Get all nodes of a given type."""
        return {
            nid: node
            for nid, node in self.graph["nodes"].items()
            if node["type"] == node_type
        }


@dataclass
class SwarmAgent:
    """An individual agent in the swarm."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    role: str = "scanner"
    target: str = ""
    status: str = "idle"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)


class NovaSwarm:
    """Multi-agent swarm for coordinated security research."""

    def __init__(
        self,
        target: str,
        roles: Optional[List[str]] = None,
    ) -> None:
        self.target = target
        self._roles = roles or ["recon", "scanner", "exploiter", "reporter"]
        self._agents: Dict[str, SwarmAgent] = {}
        self._shared_findings: List[Dict[str, Any]] = []
        self._initialize_agents()

    def _initialize_agents(self) -> None:
        """Create agents for each role."""
        for role in self._roles:
            agent = SwarmAgent(
                role=role,
                target=self.target,
                capabilities=self._get_capabilities(role),
            )
            self._agents[agent.id] = agent

    def _get_capabilities(self, role: str) -> List[str]:
        """Return capabilities for a given role."""
        caps = {
            "recon": ["subdomain_enum", "port_scan", "service_detection"],
            "scanner": ["vuln_scan", "web_scan", "credential_check"],
            "exploiter": ["exploitation", "privilege_escalation", "lateral_movement"],
            "reporter": ["report_generation", "finding_correlation", "risk_assessment"],
        }
        return caps.get(role, [])

    def get_agent(self, agent_id: str) -> Optional[SwarmAgent]:
        """Get an agent by ID."""
        return self._agents.get(agent_id)

    def list_agents(self) -> List[SwarmAgent]:
        """List all agents in the swarm."""
        return list(self._agents.values())

    def assign_task(self, agent_id: str, task: str) -> bool:
        """Assign a task to a specific agent."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.status = f"working: {task}"
        return True

    def share_finding(self, agent_id: str, finding: Dict[str, Any]) -> None:
        """Share a finding from an agent to the global pool."""
        finding["source_agent"] = agent_id
        self._shared_findings.append(finding)
        agent = self._agents.get(agent_id)
        if agent:
            agent.findings.append(finding)

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all shared findings from the swarm."""
        return list(self._shared_findings)

    def status(self) -> Dict[str, str]:
        """Get status of all agents."""
        return {aid: agent.status for aid, agent in self._agents.items()}

    def summary(self) -> Dict[str, Any]:
        """Get a summary of the swarm state."""
        return {
            "target": self.target,
            "agents": len(self._agents),
            "roles": self._roles,
            "total_findings": len(self._shared_findings),
            "statuses": self.status(),
        }
