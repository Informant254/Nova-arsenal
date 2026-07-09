"""
Session manager: create work sessions and run sub-agents concurrently.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from .models import (
    DEFAULT_PARALLEL_ROLES,
    SessionStatus,
    SubAgentResult,
    SubAgentRole,
    SubAgentStatus,
    TaskSession,
    _id,
    _now,
)

logger = logging.getLogger(__name__)

STORE_DIR = Path(os.getenv("NOVA_HOME", Path.home() / ".nova")) / "work_sessions"

ROLE_OBJECTIVES: Dict[SubAgentRole, str] = {
    SubAgentRole.RECON: "Map ports, services, and attack surface for the target",
    SubAgentRole.WEB: "Analyze web surface for common vulns and misconfigurations",
    SubAgentRole.EXPLOIT: "Prioritize high-impact exploitation paths from recon (authorized only)",
    SubAgentRole.OSINT: "Gather passive intelligence: tech stack, public exposure, context",
    SubAgentRole.RESEARCHER: "Run zero-day candidate research on recon surface",
    SubAgentRole.VALIDATOR: "Validate and dedupe findings; flag low-confidence noise",
    SubAgentRole.REPORTER: "Summarize concurrent agent work into a clear status report",
}


class SessionManager:
    """In-memory + disk-backed registry of concurrent multi-agent sessions."""

    def __init__(self, store_dir: Path = STORE_DIR) -> None:
        self.store_dir = store_dir
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: Dict[str, TaskSession] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()
        self._load_index()

    def _load_index(self) -> None:
        for path in self.store_dir.glob("sess_*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                sess = self._from_dict(data)
                self._sessions[sess.session_id] = sess
            except Exception as exc:  # noqa: BLE001
                logger.debug("skip session file %s: %s", path, exc)

    def _persist(self, sess: TaskSession) -> None:
        path = self.store_dir / f"{sess.session_id}.json"
        path.write_text(json.dumps(sess.to_dict(), indent=2), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _from_dict(self, data: Dict[str, Any]) -> TaskSession:
        roles = [SubAgentRole(r) for r in data.get("roles") or [r.value for r in DEFAULT_PARALLEL_ROLES]]
        sess = TaskSession(
            session_id=data.get("session_id") or _id("sess_"),
            goal=data.get("goal") or "",
            target=data.get("target") or "",
            status=SessionStatus(data.get("status") or "pending"),
            roles=roles,
            max_concurrent=int(data.get("max_concurrent") or 6),
            authorized=bool(data.get("authorized")),
            authorization_ref=data.get("authorization_ref") or "",
            created_at=data.get("created_at") or _now(),
            started_at=data.get("started_at") or "",
            completed_at=data.get("completed_at") or "",
            summary=data.get("summary") or "",
            metadata=dict(data.get("metadata") or {}),
            aggregated_findings=list(data.get("aggregated_findings") or []),
            consensus=list(data.get("consensus") or []),
        )
        for aid, raw in (data.get("agents") or {}).items():
            sess.agents[aid] = SubAgentResult(
                agent_id=aid,
                role=SubAgentRole(raw.get("role", "recon")),
                status=SubAgentStatus(raw.get("status") or "pending"),
                findings=list(raw.get("findings") or []),
                summary=raw.get("summary") or "",
                evidence=raw.get("evidence") or "",
                confidence=float(raw.get("confidence") or 0),
                steps=int(raw.get("steps") or 0),
                duration_ms=float(raw.get("duration_ms") or 0),
                error=raw.get("error") or "",
                reasoning=list(raw.get("reasoning") or []),
            )
        return sess

    def create(
        self,
        goal: str,
        target: str = "",
        roles: Optional[Sequence[str]] = None,
        max_concurrent: int = 6,
        authorized: bool = False,
        authorization_ref: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TaskSession:
        role_list: List[SubAgentRole] = []
        if roles:
            for r in roles:
                try:
                    role_list.append(SubAgentRole(r.lower().strip()))
                except ValueError:
                    continue
        if not role_list:
            role_list = list(DEFAULT_PARALLEL_ROLES)

        sess = TaskSession(
            goal=goal,
            target=target or "unspecified",
            roles=role_list,
            max_concurrent=max(1, max_concurrent),
            authorized=authorized,
            authorization_ref=authorization_ref,
            metadata=dict(metadata or {}),
        )
        # Pre-create agent slots
        for role in role_list:
            aid = _id(f"{role.value}_")
            sess.agents[aid] = SubAgentResult(
                agent_id=aid,
                role=role,
                status=SubAgentStatus.PENDING,
                summary=ROLE_OBJECTIVES.get(role, role.value),
            )
        sess.emit("session_created", f"Session created for goal: {goal[:120]}")
        self._sessions[sess.session_id] = sess
        self._persist(sess)
        return sess

    def get(self, session_id: str) -> Optional[TaskSession]:
        return self._sessions.get(session_id)

    def list_sessions(self) -> List[TaskSession]:
        return sorted(
            self._sessions.values(),
            key=lambda s: s.created_at,
            reverse=True,
        )

    async def start(self, session_id: str, wait: bool = False) -> TaskSession:
        """
        Start concurrent sub-agents for a session.

        wait=False (default): fire-and-forget (poll via get/list).
        wait=True: await full completion before returning.
        """
        sess = self._sessions.get(session_id)
        if not sess:
            raise KeyError(f"Unknown session {session_id}")
        if sess.status == SessionStatus.RUNNING and session_id in self._tasks:
            if wait and not self._tasks[session_id].done():
                await self._tasks[session_id]
                return self._sessions[session_id]
            return sess
        if session_id in self._tasks and not self._tasks[session_id].done():
            if wait:
                await self._tasks[session_id]
                return self._sessions[session_id]
            return sess

        sess.status = SessionStatus.RUNNING
        sess.started_at = _now()
        sess.emit("session_started", "Spawning concurrent sub-agents")
        self._persist(sess)

        if wait:
            await self._run_session(sess)
            return self._sessions[session_id]

        task = asyncio.create_task(self._run_session(sess))
        self._tasks[session_id] = task
        return sess

    async def cancel(self, session_id: str) -> TaskSession:
        sess = self._sessions.get(session_id)
        if not sess:
            raise KeyError(session_id)
        t = self._tasks.get(session_id)
        if t and not t.done():
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
        sess.status = SessionStatus.CANCELLED
        sess.completed_at = _now()
        for a in sess.agents.values():
            if a.status in (SubAgentStatus.PENDING, SubAgentStatus.RUNNING):
                a.status = SubAgentStatus.CANCELLED
        sess.emit("session_cancelled", "Session cancelled by user")
        self._persist(sess)
        return sess

    async def _run_session(self, sess: TaskSession) -> None:
        sem = asyncio.Semaphore(sess.max_concurrent)
        agent_items = list(sess.agents.items())

        async def run_one(agent_id: str, result: SubAgentResult) -> SubAgentResult:
            async with sem:
                return await self._execute_subagent(sess, agent_id, result)

        try:
            outcomes = await asyncio.gather(
                *[run_one(aid, res) for aid, res in agent_items],
                return_exceptions=True,
            )
            for item, outcome in zip(agent_items, outcomes):
                aid, _ = item
                if isinstance(outcome, Exception):
                    r = sess.agents[aid]
                    r.status = SubAgentStatus.FAILED
                    r.error = str(outcome)
                    sess.emit("agent_failed", str(outcome), agent_id=aid)
                else:
                    sess.agents[aid] = outcome

            self._aggregate(sess)
            sess.status = SessionStatus.COMPLETED
            sess.completed_at = _now()
            sess.summary = self._build_summary(sess)
            sess.emit(
                "session_completed",
                sess.summary,
                findings=len(sess.aggregated_findings),
                agents=len(sess.agents),
            )
        except asyncio.CancelledError:
            sess.status = SessionStatus.CANCELLED
            sess.completed_at = _now()
            sess.emit("session_cancelled", "Cancelled during run")
            raise
        except Exception as exc:  # noqa: BLE001
            sess.status = SessionStatus.FAILED
            sess.completed_at = _now()
            sess.summary = f"Session failed: {exc}"
            sess.emit("session_failed", str(exc))
            logger.exception("Session %s failed", sess.session_id)
        finally:
            self._persist(sess)

    async def _execute_subagent(
        self,
        sess: TaskSession,
        agent_id: str,
        result: SubAgentResult,
    ) -> SubAgentResult:
        t0 = time.perf_counter()
        result.status = SubAgentStatus.RUNNING
        result.reasoning.append(f"start role={result.role.value} target={sess.target}")
        sess.emit("agent_started", f"{result.role.value} started", agent_id=agent_id)
        self._persist(sess)

        try:
            if result.role == SubAgentRole.RECON:
                await self._role_recon(sess, result)
            elif result.role == SubAgentRole.WEB:
                await self._role_web(sess, result)
            elif result.role == SubAgentRole.OSINT:
                await self._role_osint(sess, result)
            elif result.role == SubAgentRole.RESEARCHER:
                await self._role_researcher(sess, result)
            elif result.role == SubAgentRole.EXPLOIT:
                await self._role_exploit(sess, result)
            elif result.role == SubAgentRole.VALIDATOR:
                await self._role_validator(sess, result)
            elif result.role == SubAgentRole.REPORTER:
                await self._role_reporter(sess, result)
            else:
                result.summary = f"Unknown role {result.role}"
                result.status = SubAgentStatus.SKIPPED

            if result.status == SubAgentStatus.RUNNING:
                result.status = SubAgentStatus.COMPLETED
            result.duration_ms = (time.perf_counter() - t0) * 1000
            result.steps = max(result.steps, 1)
            sess.emit(
                "agent_completed",
                f"{result.role.value} finished ({len(result.findings)} findings)",
                agent_id=agent_id,
                findings=len(result.findings),
            )
        except Exception as exc:  # noqa: BLE001
            result.status = SubAgentStatus.FAILED
            result.error = str(exc)
            result.duration_ms = (time.perf_counter() - t0) * 1000
            result.reasoning.append(f"error: {exc}")
            sess.emit("agent_failed", str(exc), agent_id=agent_id)
            logger.warning("Sub-agent %s failed: %s", agent_id, exc)

        self._persist(sess)
        return result

    # ── Role implementations (fast concurrent workers) ────────────────────

    async def _role_recon(self, sess: TaskSession, result: SubAgentResult) -> None:
        from nova_arsenal.zeroday.surface import AttackSurfaceMapper
        from nova_arsenal.intelligence.tool_selector import ToolSelector

        result.reasoning.append("Mapping attack surface")
        services = sess.metadata.get("services") or {
            "https": {"ports": [443], "paths": ["/", "/api"]},
            "http": {"ports": [80], "paths": ["/"]},
            "ssh": [22],
        }
        surface = AttackSurfaceMapper().map(sess.target, services=services)
        result.steps = 3
        result.confidence = 0.8
        result.summary = f"Surface: {len(surface.endpoints)} endpoints ranked"
        for ep in surface.top[:10]:
            result.findings.append(
                {
                    "type": "surface",
                    "role": "recon",
                    "title": f"{ep.service}:{ep.port}{ep.path}",
                    "severity": "info",
                    "priority": ep.priority,
                    "surface_id": ep.surface_id,
                }
            )
        # Normalize services → Dict[str, List[int]] for ToolSelector
        svc_ports: Dict[str, List[int]] = {}
        for k, v in list(services.items())[:8]:
            if isinstance(v, list):
                ports = [int(x) for x in v if str(x).isdigit() or isinstance(x, int)]
            elif isinstance(v, dict):
                raw = v.get("ports") or v.get("port") or []
                if not isinstance(raw, list):
                    raw = [raw]
                ports = [int(x) for x in raw if str(x).isdigit() or isinstance(x, int)]
            else:
                ports = []
            svc_ports[str(k)] = ports or [0]
        suggestions = ToolSelector().suggest(
            services=svc_ports,
            findings=[],
            target=sess.target,
        )
        for s in suggestions[:5]:
            result.findings.append(
                {
                    "type": "tool_suggestion",
                    "role": "recon",
                    "title": s.tool_name,
                    "severity": "info",
                    "reasoning": s.reasoning,
                    "priority": s.priority,
                }
            )
        sess.metadata["services"] = services
        sess.metadata["surface_count"] = len(surface.endpoints)
        result.evidence = f"{len(surface.endpoints)} endpoints; top={surface.top[0].service if surface.top else 'n/a'}"

    async def _role_web(self, sess: TaskSession, result: SubAgentResult) -> None:
        result.reasoning.append("Analyzing web attack surface")
        result.steps = 2
        paths = ["/", "/login", "/api", "/admin", "/upload", "/graphql"]
        for p in paths:
            result.findings.append(
                {
                    "type": "web_check",
                    "role": "web",
                    "title": f"Review web path {p} on {sess.target}",
                    "severity": "medium" if p in {"/admin", "/upload"} else "low",
                    "endpoint": p,
                }
            )
        result.confidence = 0.65
        result.summary = f"Web review queued for {len(paths)} common paths"
        result.evidence = "Heuristic web surface checklist (authorized testing only)"

    async def _role_osint(self, sess: TaskSession, result: SubAgentResult) -> None:
        result.reasoning.append("Passive OSINT framing")
        result.steps = 2
        result.findings.append(
            {
                "type": "osint",
                "role": "osint",
                "title": f"OSINT context for {sess.target}",
                "severity": "info",
                "detail": "Subdomains, tech fingerprints, public exposure (passive)",
            }
        )
        # Try real OSINT chain if available and looks like a domain
        if "." in sess.target and not sess.target.replace(".", "").isdigit():
            try:
                from nova_arsenal.intelligence.osint_chain import OsintChain

                chain = OsintChain()
                osint = await asyncio.wait_for(chain.investigate(sess.target), timeout=15)
                result.findings.append(
                    {
                        "type": "osint",
                        "role": "osint",
                        "title": "OSINT chain result",
                        "severity": "info",
                        "subdomains": list(getattr(osint, "subdomains", []) or [])[:15],
                        "technologies": list(getattr(osint, "technologies", []) or [])[:15],
                        "summary": getattr(osint, "summary", "")[:300],
                    }
                )
                result.confidence = 0.75
                result.summary = f"OSINT: {len(getattr(osint, 'subdomains', []) or [])} subdomains"
            except Exception as exc:  # noqa: BLE001
                result.reasoning.append(f"osint soft-fail: {exc}")
                result.confidence = 0.5
                result.summary = "OSINT checklist prepared (live chain unavailable)"
        else:
            result.confidence = 0.5
            result.summary = "OSINT skipped deep chain (target not domain-like)"

    async def _role_researcher(self, sess: TaskSession, result: SubAgentResult) -> None:
        result.reasoning.append("Zero-day candidate pipeline")
        from nova_arsenal.zeroday import ZeroDayHuntConfig, ZeroDayHunter

        services = sess.metadata.get("services") or {
            "https": {"ports": [443], "paths": ["/", "/api", "/upload"]},
        }
        hunter = ZeroDayHunter()
        hunt = await hunter.hunt(
            target=sess.target,
            services=services,
            config=ZeroDayHuntConfig(
                authorized=sess.authorized,
                authorization_ref=sess.authorization_ref or f"session:{sess.session_id}",
                require_authorization=False,  # research planning always
                execute_fuzz=False,
                dry_run_fuzz=True,
                live_fuzz=True,
                max_candidates=20,
            ),
        )
        result.steps = 4
        result.confidence = 0.7
        result.summary = f"Zero-day pipeline: {len(hunt.candidates)} candidates ({hunt.status})"
        for c in hunt.candidates[:15]:
            result.findings.append(
                {
                    "type": "zeroday_candidate",
                    "role": "researcher",
                    "title": c.title,
                    "severity": c.severity,
                    "novelty": c.novelty,
                    "source_stage": c.source_stage,
                    "confidence": c.confidence,
                }
            )
        sess.metadata["zeroday_hunt"] = {
            "status": hunt.status,
            "candidate_count": len(hunt.candidates),
            "elapsed_ms": hunt.elapsed_ms,
        }

    async def _role_exploit(self, sess: TaskSession, result: SubAgentResult) -> None:
        result.reasoning.append("Prioritizing exploitation paths (safe/planned)")
        result.steps = 2
        if not sess.authorized:
            result.findings.append(
                {
                    "type": "exploit_plan",
                    "role": "exploit",
                    "title": "Exploitation gated — set authorized=true + auth_ref",
                    "severity": "info",
                }
            )
            result.summary = "Exploit agent idle (authorization required for live attempts)"
            result.confidence = 0.4
            return
        result.findings.append(
            {
                "type": "exploit_plan",
                "role": "exploit",
                "title": f"Authorized exploit plan for {sess.target}",
                "severity": "high",
                "detail": "Chain high-confidence findings after validator review",
            }
        )
        result.summary = "Authorized exploit planning complete"
        result.confidence = 0.6

    async def _role_validator(self, sess: TaskSession, result: SubAgentResult) -> None:
        # Wait briefly so peer findings exist (other agents run in parallel — snapshot peers)
        await asyncio.sleep(0.05)
        peer_findings: List[Dict[str, Any]] = []
        for a in sess.agents.values():
            if a.agent_id == result.agent_id:
                continue
            peer_findings.extend(a.findings)

        result.reasoning.append(f"Validating {len(peer_findings)} peer findings")
        kept = 0
        for f in peer_findings:
            sev = (f.get("severity") or "info").lower()
            if sev in {"critical", "high", "medium"} or f.get("type") == "zeroday_candidate":
                kept += 1
                result.findings.append(
                    {
                        **f,
                        "validated": True,
                        "validator": result.agent_id,
                        "type": f.get("type", "finding") + "_validated",
                    }
                )
        result.steps = 2
        result.confidence = 0.85
        result.summary = f"Validator promoted {kept}/{len(peer_findings)} findings"
        result.evidence = "Severity + novelty heuristics"

    async def _role_reporter(self, sess: TaskSession, result: SubAgentResult) -> None:
        await asyncio.sleep(0.1)  # let others progress
        counts: Dict[str, int] = {}
        total = 0
        for a in sess.agents.values():
            if a.agent_id == result.agent_id:
                continue
            counts[a.role.value] = len(a.findings)
            total += len(a.findings)
        result.steps = 1
        result.confidence = 0.9
        result.summary = (
            f"Session report for '{sess.goal[:80]}' on {sess.target}: "
            f"{total} raw findings across {len(counts)} agents"
        )
        result.findings.append(
            {
                "type": "report",
                "role": "reporter",
                "title": "Concurrent session summary",
                "severity": "info",
                "by_role": counts,
                "goal": sess.goal,
                "target": sess.target,
            }
        )
        result.evidence = json.dumps(counts)

    def _aggregate(self, sess: TaskSession) -> None:
        all_f: List[Dict[str, Any]] = []
        for a in sess.agents.values():
            for f in a.findings:
                item = dict(f)
                item.setdefault("agent_role", a.role.value)
                item.setdefault("agent_id", a.agent_id)
                all_f.append(item)
        sess.aggregated_findings = all_f

        # Consensus: validated or multi-role or high severity
        by_title: Dict[str, Dict[str, Any]] = {}
        for f in all_f:
            key = (f.get("title") or f.get("type") or "finding").lower().strip()
            if key not in by_title:
                by_title[key] = {**f, "votes": 1, "roles": {f.get("agent_role")}}
            else:
                by_title[key]["votes"] = by_title[key].get("votes", 1) + 1
                roles = by_title[key].setdefault("roles", set())
                if isinstance(roles, set):
                    roles.add(f.get("agent_role"))
        consensus = []
        for item in by_title.values():
            roles = item.get("roles") or set()
            if isinstance(roles, set):
                item["roles"] = list(roles)
            sev = (item.get("severity") or "info").lower()
            if (
                item.get("validated")
                or item.get("votes", 0) >= 2
                or sev in {"critical", "high"}
                or item.get("type") == "zeroday_candidate"
            ):
                consensus.append(item)
        consensus.sort(
            key=lambda x: (
                {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                    (x.get("severity") or "info").lower(), 0
                ),
                x.get("votes", 0),
            ),
            reverse=True,
        )
        sess.consensus = consensus

    def _build_summary(self, sess: TaskSession) -> str:
        done = sum(1 for a in sess.agents.values() if a.status == SubAgentStatus.COMPLETED)
        failed = sum(1 for a in sess.agents.values() if a.status == SubAgentStatus.FAILED)
        return (
            f"Session {sess.session_id}: {done} agents completed, {failed} failed; "
            f"{len(sess.aggregated_findings)} findings, {len(sess.consensus)} consensus; "
            f"goal={sess.goal[:60]!r} target={sess.target}"
        )


_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    global _manager
    if _manager is None:
        _manager = SessionManager()
    return _manager
