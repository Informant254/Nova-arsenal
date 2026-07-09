"""
Multi-Agent Swarm Architecture.

Phased orchestration:
1. RECON (+ optional OSINT) discovers surface
2. RESEARCHER runs ZeroDayHunter on recon output (variant/fuzz/novelty)
3. WEB / EXPLOIT / VALIDATOR run with recon context
4. Weighted consensus merge
"""

from __future__ import annotations

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
    VALIDATOR = "validator"
    RESEARCHER = "researcher"


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
    zeroday_hunt: Optional[Dict[str, Any]] = None
    phases: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "findings_count": len(self.findings),
            "consensus_findings": [f.to_dict() for f in self.consensus_findings],
            "agent_stats": self.agent_stats,
            "total_steps": self.total_steps,
            "elapsed_seconds": self.elapsed_seconds,
            "zeroday_hunt": self.zeroday_hunt,
            "phases": self.phases,
            "summary": self.summary,
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
    SwarmAgentRole.VALIDATOR: {
        "objective": "Independently verify all findings to eliminate false positives",
        "persona": "Validator - skeptical auditor focused on proof and reliability",
    },
    SwarmAgentRole.RESEARCHER: {
        "objective": (
            "After recon, run zero-day candidate research: variant/patch-gap analysis, "
            "surface ranking, fuzz campaign planning, and novelty scoring"
        ),
        "persona": "Security Researcher - zero-day candidate pipeline operator",
    },
}


class SwarmOrchestrator:
    """
    Orchestrates multiple agent roles in phases.

    Default flow:
      recon (+osint) → researcher/zeroday → web+exploit+validator → consensus
    """

    def __init__(
        self,
        target: str = "",
        executor: Optional[SandboxExecutor] = None,
        llm_complete: Optional[Callable[..., Any]] = None,
        on_event: Optional[Callable[..., Any]] = None,
        configs: Optional[List[SwarmAgentConfig]] = None,
        # Zero-day research integration
        enable_zeroday: bool = True,
        zeroday_authorized: bool = False,
        zeroday_auth_ref: str = "",
        execute_live_fuzz: bool = False,
        dry_run_fuzz: bool = True,
    ) -> None:
        self.target = target
        self.executor = executor or SandboxExecutor(mode="local")
        self._llm_complete = llm_complete
        self._on_event = on_event
        self.enable_zeroday = enable_zeroday
        self.zeroday_authorized = zeroday_authorized
        self.zeroday_auth_ref = zeroday_auth_ref
        self.execute_live_fuzz = execute_live_fuzz
        self.dry_run_fuzz = dry_run_fuzz

        if configs:
            self.agent_configs = configs
        else:
            self.agent_configs = [
                SwarmAgentConfig(role=role, max_steps=10, weight=w)
                for role, w in [
                    (SwarmAgentRole.RECON, 1.0),
                    (SwarmAgentRole.WEB, 1.1),
                    (SwarmAgentRole.EXPLOIT, 1.3),
                    (SwarmAgentRole.OSINT, 0.8),
                    (SwarmAgentRole.VALIDATOR, 1.5),
                    (SwarmAgentRole.RESEARCHER, 1.2),
                ]
            ]

    async def run(self) -> SwarmResult:
        """Phased swarm: recon → zeroday researcher → remaining agents."""
        return await self.run_swarm(self.target)

    async def run_swarm(self, target: Optional[str] = None) -> SwarmResult:
        if target:
            self.target = target
        if not self.target:
            raise ValueError("SwarmOrchestrator requires a target")

        start_time = datetime.now(timezone.utc)
        result = SwarmResult(target=self.target)
        result.phases = []

        by_role = {c.role: c for c in self.agent_configs}
        recon_roles = [r for r in (SwarmAgentRole.RECON, SwarmAgentRole.OSINT) if r in by_role]
        researcher_cfg = by_role.get(SwarmAgentRole.RESEARCHER)
        later_roles = [
            r
            for r in (
                SwarmAgentRole.WEB,
                SwarmAgentRole.EXPLOIT,
                SwarmAgentRole.VALIDATOR,
            )
            if r in by_role
        ]

        # ── Phase 1: recon (+ osint) ──────────────────────────────────────
        recon_findings: List[SwarmFinding] = []
        if recon_roles:
            result.phases.append("recon")
            await self._emit("swarm_phase", {"phase": "recon", "roles": [r.value for r in recon_roles]})
            phase1 = await asyncio.gather(
                *[self._run_agent(by_role[r]) for r in recon_roles],
                return_exceptions=True,
            )
            for role, agent_result in zip(recon_roles, phase1):
                if isinstance(agent_result, Exception):
                    logger.error("Swarm agent %s failed: %s", role.value, agent_result)
                    result.agent_stats[role.value] = {"status": "error", "error": str(agent_result)}
                    continue
                findings, stats = agent_result
                recon_findings.extend(findings)
                result.findings.extend(findings)
                result.agent_stats[role.value] = stats
                result.total_steps += stats.get("steps", 0)

        # ── Phase 2: researcher + ZeroDayHunter (after recon) ─────────────
        if researcher_cfg and self.enable_zeroday:
            result.phases.append("researcher_zeroday")
            await self._emit(
                "swarm_phase",
                {"phase": "researcher_zeroday", "recon_findings": len(recon_findings)},
            )
            zd_findings, zd_stats, zd_payload = await self._run_researcher_zeroday(
                researcher_cfg,
                recon_findings,
            )
            result.findings.extend(zd_findings)
            result.agent_stats[SwarmAgentRole.RESEARCHER.value] = zd_stats
            result.zeroday_hunt = zd_payload
            result.total_steps += zd_stats.get("steps", 0)
        elif researcher_cfg:
            # Fallback: classic agent runner for researcher
            result.phases.append("researcher")
            try:
                findings, stats = await self._run_agent(researcher_cfg)
                result.findings.extend(findings)
                result.agent_stats[researcher_cfg.role.value] = stats
                result.total_steps += stats.get("steps", 0)
            except Exception as exc:  # noqa: BLE001
                logger.error("Researcher agent failed: %s", exc)

        # ── Phase 3: web / exploit / validator ────────────────────────────
        if later_roles:
            result.phases.append("deep_scan")
            await self._emit(
                "swarm_phase",
                {"phase": "deep_scan", "roles": [r.value for r in later_roles]},
            )
            phase3 = await asyncio.gather(
                *[self._run_agent(by_role[r]) for r in later_roles],
                return_exceptions=True,
            )
            for role, agent_result in zip(later_roles, phase3):
                if isinstance(agent_result, Exception):
                    logger.error("Swarm agent %s failed: %s", role.value, agent_result)
                    result.agent_stats[role.value] = {"status": "error", "error": str(agent_result)}
                    continue
                findings, stats = agent_result
                result.findings.extend(findings)
                result.agent_stats[role.value] = stats
                result.total_steps += stats.get("steps", 0)

        # Any other custom roles not in the phased sets
        handled = set(recon_roles) | set(later_roles)
        if researcher_cfg:
            handled.add(SwarmAgentRole.RESEARCHER)
        extras = [c for c in self.agent_configs if c.role not in handled]
        if extras:
            result.phases.append("extra")
            extra_results = await asyncio.gather(
                *[self._run_agent(c) for c in extras],
                return_exceptions=True,
            )
            for config, agent_result in zip(extras, extra_results):
                if isinstance(agent_result, Exception):
                    continue
                findings, stats = agent_result
                result.findings.extend(findings)
                result.agent_stats[config.role.value] = stats

        result.consensus_findings = self._compute_consensus(result.findings)
        result.elapsed_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()
        zd_n = 0
        if result.zeroday_hunt:
            zd_n = result.zeroday_hunt.get("candidate_count") or len(
                result.zeroday_hunt.get("candidates") or []
            )
        result.summary = (
            f"phases={result.phases}; findings={len(result.findings)}; "
            f"consensus={len(result.consensus_findings)}; "
            f"zeroday_candidates={zd_n}; elapsed={result.elapsed_seconds:.1f}s"
        )

        logger.info("Swarm complete: %s", result.summary)
        await self._emit("swarm_completed", result.to_dict())
        return result

    async def _run_researcher_zeroday(
        self,
        config: SwarmAgentConfig,
        recon_findings: List[SwarmFinding],
    ) -> tuple:
        """Run ZeroDayHunter using recon output; emit SwarmFindings from candidates."""
        from nova_arsenal.zeroday import ZeroDayHuntConfig, ZeroDayHunter, findings_to_services

        services = findings_to_services(recon_findings, target=self.target)
        findings_payload = [f.to_dict() for f in recon_findings]

        # Research planning always runs after recon; live fuzz only when authorized.
        authorized = self.zeroday_authorized
        auth_ref = self.zeroday_auth_ref or f"swarm:{self.target}"
        live = bool(self.execute_live_fuzz and authorized)

        hunter = ZeroDayHunter()
        hunt = await hunter.hunt(
            target=self.target,
            services=services,
            findings=findings_payload,
            config=ZeroDayHuntConfig(
                authorized=authorized,
                authorization_ref=auth_ref,
                require_authorization=False,  # candidate pipeline after recon (plan-safe)
                execute_fuzz=live,
                dry_run_fuzz=(not live) or self.dry_run_fuzz,
                live_fuzz=True,
                max_candidates=40,
            ),
        )

        swarm_findings: List[SwarmFinding] = []
        for c in hunt.candidates:
            swarm_findings.append(
                SwarmFinding(
                    agent_role=SwarmAgentRole.RESEARCHER,
                    title=c.title,
                    severity=c.severity if c.severity in {"low", "medium", "high", "critical"} else "medium",
                    description=c.evidence or c.bug_class,
                    evidence=(
                        f"novelty={c.novelty:.2f}; stage={c.source_stage}; "
                        f"next={'; '.join(c.next_steps[:2])}"
                    ),
                    confidence=min(1.0, config.weight * (0.4 + 0.6 * c.confidence * c.novelty)),
                    votes=1,
                )
            )

        # Always attach a summary finding so swarm consumers see the pipeline ran
        swarm_findings.insert(
            0,
            SwarmFinding(
                agent_role=SwarmAgentRole.RESEARCHER,
                title=f"Zero-day pipeline: {len(hunt.candidates)} candidates ({hunt.status})",
                severity="info" if hunt.status == "completed" else "medium",
                description=(
                    f"Services={list(services.keys())}; "
                    f"fuzz_jobs={(hunt.fuzz_campaign or {}).get('job_count', 0)}; "
                    f"elapsed_ms={hunt.elapsed_ms:.0f}"
                ),
                evidence="; ".join(hunt.warnings[:3]),
                confidence=config.weight,
                votes=1,
            ),
        )

        stats = {
            "steps": 1,
            "findings": len(swarm_findings),
            "status": hunt.status,
            "zeroday_candidates": len(hunt.candidates),
            "services": list(services.keys()),
        }
        return swarm_findings, stats, hunt.to_dict()

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
        severity_order = ["info", "low", "medium", "high", "critical"]

        for f in findings:
            key = f.title.lower().strip()
            if key in merged:
                existing = merged[key]
                existing.votes += f.votes
                boost = 0.5 if f.agent_role == SwarmAgentRole.VALIDATOR else 0.3
                if f.agent_role == SwarmAgentRole.RESEARCHER:
                    boost = 0.35
                existing.confidence = min(1.0, existing.confidence + f.confidence * boost)
                try:
                    if severity_order.index(f.severity) > severity_order.index(existing.severity):
                        existing.severity = f.severity
                except ValueError:
                    pass
            else:
                merged[key] = SwarmFinding(
                    agent_role=f.agent_role,
                    title=f.title,
                    severity=f.severity,
                    description=f.description,
                    evidence=f.evidence,
                    confidence=f.confidence,
                    votes=f.votes,
                )

        consensus = []
        for f in merged.values():
            is_validated = any(
                orig.agent_role == SwarmAgentRole.VALIDATOR
                and orig.title.lower().strip() == f.title.lower().strip()
                for orig in findings
            )
            is_research = f.agent_role == SwarmAgentRole.RESEARCHER and f.severity in (
                "critical",
                "high",
                "medium",
            )
            if (
                is_validated
                or is_research
                or f.votes >= 2
                or f.severity in ("critical", "high")
                or f.confidence > 0.8
            ):
                consensus.append(f)

        def sort_key(x: SwarmFinding) -> tuple:
            try:
                si = severity_order.index(x.severity)
            except ValueError:
                si = 0
            return (si, x.confidence, x.votes)

        consensus.sort(key=sort_key, reverse=True)
        return consensus

    def get_role_configs(self) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in self.agent_configs]

    async def _emit(self, event: str, data: Any) -> None:
        if not self._on_event:
            return
        try:
            maybe = self._on_event(event, data)
            if asyncio.iscoroutine(maybe):
                await maybe
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_event error: %s", exc)

    @classmethod
    def create_swarm(
        cls,
        target: str = "",
        roles: Optional[List[str]] = None,
        executor: Optional[SandboxExecutor] = None,
        **kwargs: Any,
    ) -> "SwarmOrchestrator":
        return create_swarm(target=target, roles=roles, executor=executor, **kwargs)


def create_swarm(
    target: str = "",
    roles: Optional[List[str]] = None,
    executor: Optional[SandboxExecutor] = None,
    **kwargs: Any,
) -> SwarmOrchestrator:
    configs = None
    if roles:
        role_map = {r.value: r for r in SwarmAgentRole}
        configs = [
            SwarmAgentConfig(role=role_map[r], max_steps=8, weight=1.0)
            for r in roles
            if r in role_map
        ]

    return SwarmOrchestrator(target=target, executor=executor, configs=configs, **kwargs)
