"""Tests for swarm recon → zeroday researcher wiring."""
import asyncio
import os
import sys
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from nova_arsenal.swarm import (
    SwarmAgentConfig,
    SwarmAgentRole,
    SwarmFinding,
    SwarmOrchestrator,
    create_swarm,
)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestSwarmZerodayWiring:
    def test_create_swarm_and_classmethod(self):
        s1 = create_swarm(target="lab.local", roles=["recon", "researcher"])
        assert s1.target == "lab.local"
        assert any(c.role == SwarmAgentRole.RESEARCHER for c in s1.agent_configs)

        s2 = SwarmOrchestrator.create_swarm(target="lab.local", roles=["recon", "researcher"])
        assert s2.target == "lab.local"

    def test_researcher_after_recon_mock_agents(self):
        """Recon mock findings feed ZeroDayHunter; researcher phase produces candidates."""
        orch = SwarmOrchestrator(
            target="lab.local",
            configs=[
                SwarmAgentConfig(role=SwarmAgentRole.RECON, max_steps=1, weight=1.0),
                SwarmAgentConfig(role=SwarmAgentRole.RESEARCHER, max_steps=1, weight=1.2),
            ],
            enable_zeroday=True,
            zeroday_authorized=False,  # plan-only
            execute_live_fuzz=False,
        )

        async def fake_run_agent(config):
            if config.role == SwarmAgentRole.RECON:
                findings = [
                    SwarmFinding(
                        agent_role=SwarmAgentRole.RECON,
                        title="https 443/tcp open nginx/1.25",
                        severity="info",
                        description="Service https version nginx/1.25 on port 443 path /api",
                        evidence="443/tcp open",
                    )
                ]
                return findings, {"steps": 1, "findings": 1, "status": "completed"}
            return [], {"steps": 0, "findings": 0, "status": "skipped"}

        with patch.object(orch, "_run_agent", side_effect=fake_run_agent):
            result = _run(orch.run_swarm())

        assert "recon" in result.phases
        assert "researcher_zeroday" in result.phases
        assert result.zeroday_hunt is not None
        assert result.zeroday_hunt.get("status") == "completed"
        assert result.agent_stats.get("researcher", {}).get("status") == "completed"
        # At least the summary finding from researcher
        researcher_findings = [
            f for f in result.findings if f.agent_role == SwarmAgentRole.RESEARCHER
        ]
        assert len(researcher_findings) >= 1
        assert result.summary

    def test_run_swarm_alias(self):
        orch = SwarmOrchestrator(
            target="lab.local",
            configs=[SwarmAgentConfig(role=SwarmAgentRole.RESEARCHER, max_steps=1)],
            enable_zeroday=True,
        )
        # No recon findings — still runs researcher with seeded services
        result = _run(orch.run())
        assert result.target == "lab.local"
        assert result.zeroday_hunt is not None
