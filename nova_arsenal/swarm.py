"""
Multi-Agent Swarm Architecture.

Parallel sub-agents (Recon, Web, Exploit, OSINT) that work
collaboratively with weighted voting for consensus decisions.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from nova_arsenal.agent_runner import AgentRunner, Finding
from nova_arsenal.sandbox_executor import SandboxExecutor

logger = logging.getLogger(__name__)


class SwarmAgentRole(Enum):
    RECON = "recon"
    WEB = "web"
    EXPLOIT = "exploit"
    OSINT = "osint"


@dataclass
class SwarmFinding:
    agent_role: SwarmAgentRole
    title: str
    severity: str
    description: str
    evidence: str = ""
    confidence: float = 1.0
    votes: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_role": self.agent_role.value,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence[:300],
            "confidence": self.confidence,
            "votes": self.votes,
        }


@dataclass
class SwarmResult:
    target: str
    findings: List[SwarmFinding] = field(default_factory=list)
    consensus_findings: List[SwarmFinding] = field(default_factory=list)
    agent_stats: Dict[str, Dict[str, int]] = field(default_factory=dict)
    total_steps: int = 0
    elapsed_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "findings_count": len(self.findings),
            "consensus_findings": [f.to_dict() for f in self.consensus_findings],
            "agent_stats": self.agent_stats,
            "total_steps": self.total_steps,
            "elapsed_seconds": self.elapsed_seconds,
        }


@dataclass
class SwarmAgentConfig:
    role: SwarmAgentRole
    max_steps: int = 10
    objective: str = ""
    weight: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role.value,
            "max_steps": self.max_steps,
            "objective": self.objective,
            "weight": self.weight,
        }


AGENT_ROLE_CONFIGS: Dict[SwarmAgentRole, Dict[str, str]] = {
    SwarmAgentRole.RECON: {
        "objective": "Discover all open ports, services, and attack surface",
        "persona": "Reconnaissance Specialist - thorough discovery of every entry point",
    },
    SwarmAgentRole.WEB: {
        "objective": "Find all web vulnerabilities including SQLi, XSS, LFI, and misconfigurations",
        "persona": "Web Application Security Expert - deep analysis of web services",
    },
    SwarmAgentRole.EXPLOIT: {
        "objective": "Exploit discovered vulnerabilities with Metasploit, hydra, and custom payloads",
        "persona": "Offensive Security Operator - aggressive exploitation specialist",
    },
    SwarmAgentRole.OSINT: {
        "objective": "Gather intelligence from public sources: subdomains, emails, breached credentials",
        "persona": "OSINT Investigator - passive intelligence gathering expert",
    },
}


class SwarmOrchestrator:
    """
    Orchestrates multiple agent roles in parallel.

    Each agent works independently on its specialty, then results
    are merged with weighted voting for consensus findings.
    """

    def __init__(
        self,
        target: str,
        executor: Optional[SandboxExecutor] = None,
        llm_complete: Optional[Callable[..., Any]] = None,
        on_event: Optional[Callable[..., Any]] = None,
        configs: Optional[List[SwarmAgentConfig]] = None,
    ) -> None:
        self.target = target
        self.executor = executor or SandboxExecutor(mode="local")
        self._llm_complete = llm_complete
        self._on_event = on_event

        if configs:
            self.agent_configs = configs
        else:
            self.agent_configs = [
                SwarmAgentConfig(role=role, max_steps=8, weight=w)
                for role, w in [(SwarmAgentRole.RECON, 1.0),
                                (SwarmAgentRole.WEB, 1.0),
                                (SwarmAgentRole.EXPLOIT, 1.2),
                                (SwarmAgentRole.OSINT, 0.8)]
            ]

    async def run(self) -> SwarmResult:
        start_time = datetime.now(timezone.utc)
        result = SwarmResult(target=self.target)

        tasks = []
        for config in self.agent_configs:
            tasks.append(self._run_agent(config))

        agent_results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, agent_result in enumerate(agent_results):
            config = self.agent_configs[i]
            role_name = config.role.value

            if isinstance(agent_result, Exception):
                logger.error(f"Swarm agent {role_name} failed: {agent_result}")
                continue

            findings, stats = agent_result
            result.findings.extend(findings)
            result.agent_stats[role_name] = stats

        result.consensus_findings = self._compute_consensus(result.findings)
        result.elapsed_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()

        logger.info(
            f"Swarm complete: {len(result.findings)} findings, "
            f"{len(result.consensus_findings)} consensus, "
            f"{result.elapsed_seconds:.1f}s"
        )

        return result

    async def _run_agent(self, config: SwarmAgentConfig) -> tuple:
        role_config = AGENT_ROLE_CONFIGS.get(config.role, {})
        objective = config.objective or role_config.get("objective", "Explore target")

        runner = AgentRunner(
            target=self.target,
            objective=objective,
            max_steps=config.max_steps,
            executor=self.executor,
            llm_complete=self._llm_complete,
            on_event=self._on_event,
        )

        run_result = await runner.run()

        swarm_findings = [
            SwarmFinding(
                agent_role=config.role,
                title=f["title"],
                severity=f["severity"],
                description=f["description"],
                evidence=f.get("evidence", ""),
                confidence=config.weight,
                votes=1,
            )
            for f in run_result.get("findings", [])
        ]

        stats = {
            "steps": run_result.get("steps_taken", 0),
            "findings": len(swarm_findings),
            "status": run_result.get("status", "unknown"),
        }

        return swarm_findings, stats

    def _compute_consensus(self, findings: List[SwarmFinding]) -> List[SwarmFinding]:
        merged: Dict[str, SwarmFinding] = {}

        for f in findings:
            key = f.title.lower().strip()
            if key in merged:
                existing = merged[key]
                existing.votes += f.votes
                existing.confidence = min(1.0, existing.confidence + f.confidence * 0.3)

                severity_order = ["low", "medium", "high", "critical"]
                if severity_order.index(f.severity) > severity_order.index(existing.severity):
                    existing.severity = f.severity
            else:
                merged[key] = f

        consensus = [f for f in merged.values() if f.votes >= 2 or f.severity in ("critical", "high")]
        consensus.sort(key=lambda x: (["low", "medium", "high", "critical"].index(x.severity), x.votes), reverse=True)

        return consensus

    def get_role_configs(self) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in self.agent_configs]


def create_swarm(
    target: str,
    roles: Optional[List[str]] = None,
    executor: Optional[SandboxExecutor] = None,
    **kwargs: Any,
) -> SwarmOrchestrator:
    configs = None
    if roles:
        role_map = {r.value: r for r in SwarmAgentRole}
        configs = [
            SwarmAgentConfig(role=role_map[r], max_steps=8, weight=1.0)
            for r in roles if r in role_map
        ]

    return SwarmOrchestrator(target=target, executor=executor, configs=configs)
