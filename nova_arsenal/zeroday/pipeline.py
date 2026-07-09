"""
Zero-Day Hunt Pipeline — parallel, multi-stage candidate discovery.

Stages (seconds-scale orchestration; validation still human-gated):
1. Authorization gate
2. Attack surface ranking
3. Known-CVE baseline + novelty filter
4. Variant / patch-gap expansion
5. Static bug-class scan (optional source)
6. Fuzz campaign planning
7. Crash triage (if crashes provided)
8. Ranked candidate report
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from .crash_triage import CrashReport, CrashTriageEngine, TriagedCrash
from .fuzz_orchestrator import FuzzCampaign, FuzzOrchestrator
from .novelty import NoveltyAssessment, NoveltyScorer
from .static_scanner import StaticBugScanner, StaticFinding
from .surface import AttackSurfaceMapper, SurfaceEndpoint, SurfaceMap
from .variant import VariantAnalyzer, VariantHypothesis

logger = logging.getLogger(__name__)


@dataclass
class ZeroDayHuntConfig:
    """Configuration for a zero-day research hunt."""

    # HARD REQUIREMENT: explicit authorization for the scope
    authorized: bool = False
    authorization_ref: str = ""  # ticket / RoE / engagement ID
    max_candidates: int = 50
    max_fuzz_jobs: int = 24
    fuzz_workers: int = 8
    include_seeded_surface: bool = True
    binary_path: str = ""
    corpus_dir: str = "./corpus"
    output_dir: str = "./fuzz_out"
    execute_fuzz: bool = False  # live engines when True + authorized
    dry_run_fuzz: bool = True
    live_fuzz: bool = True  # use LiveFuzzWorker (detect ffuf/afl++/etc.)
    fuzz_job_timeout: int = 60
    min_novelty_score: float = 0.45
    require_authorization: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authorized": self.authorized,
            "authorization_ref": self.authorization_ref,
            "max_candidates": self.max_candidates,
            "max_fuzz_jobs": self.max_fuzz_jobs,
            "fuzz_workers": self.fuzz_workers,
            "binary_path": self.binary_path,
            "execute_fuzz": self.execute_fuzz,
            "dry_run_fuzz": self.dry_run_fuzz,
            "live_fuzz": self.live_fuzz,
            "fuzz_job_timeout": self.fuzz_job_timeout,
            "min_novelty_score": self.min_novelty_score,
            "require_authorization": self.require_authorization,
        }


@dataclass
class ZeroDayCandidate:
    """A ranked candidate that *might* be novel — not a confirmed 0-day."""

    candidate_id: str
    title: str
    bug_class: str
    severity: str
    confidence: float
    novelty: float
    source_stage: str
    target: str
    evidence: str
    next_steps: List[str] = field(default_factory=list)
    related_cves: List[str] = field(default_factory=list)
    surface_id: str = ""
    tags: List[str] = field(default_factory=list)
    novelty_label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "title": self.title,
            "bug_class": self.bug_class,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "novelty": round(self.novelty, 3),
            "novelty_label": self.novelty_label,
            "source_stage": self.source_stage,
            "target": self.target,
            "evidence": self.evidence[:800],
            "next_steps": self.next_steps,
            "related_cves": self.related_cves,
            "surface_id": self.surface_id,
            "tags": self.tags,
        }


@dataclass
class ZeroDayHuntResult:
    """Full pipeline output."""

    hunt_id: str
    target: str
    status: str
    candidates: List[ZeroDayCandidate] = field(default_factory=list)
    surface: Optional[Dict[str, Any]] = None
    variants: List[Dict[str, Any]] = field(default_factory=list)
    static_findings: List[Dict[str, Any]] = field(default_factory=list)
    fuzz_campaign: Optional[Dict[str, Any]] = None
    triaged_crashes: List[Dict[str, Any]] = field(default_factory=list)
    elapsed_ms: float = 0.0
    stage_timings_ms: Dict[str, float] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    disclaimer: str = (
        "Candidates are research leads, not confirmed zero-days. "
        "Validate, minimize impact, and follow responsible disclosure. "
        "Only test systems you are authorized to assess."
    )
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hunt_id": self.hunt_id,
            "target": self.target,
            "status": self.status,
            "candidate_count": len(self.candidates),
            "candidates": [c.to_dict() for c in self.candidates],
            "surface": self.surface,
            "variants": self.variants,
            "static_findings": self.static_findings,
            "fuzz_campaign": self.fuzz_campaign,
            "triaged_crashes": self.triaged_crashes,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "stage_timings_ms": {k: round(v, 2) for k, v in self.stage_timings_ms.items()},
            "warnings": self.warnings,
            "disclaimer": self.disclaimer,
            "created_at": self.created_at,
        }


class ZeroDayHunter:
    """
    Orchestrates multi-stage zero-day *candidate* discovery at high speed.

    Example:
        hunter = ZeroDayHunter()
        result = await hunter.hunt(
            target="lab.example.local",
            services={"https": {"ports": [443], "version": "nginx 1.25"}},
            config=ZeroDayHuntConfig(authorized=True, authorization_ref="ENG-42"),
        )
        for c in result.candidates:
            print(c.severity, c.title, c.novelty)
    """

    def __init__(
        self,
        surface_mapper: Optional[AttackSurfaceMapper] = None,
        variant_analyzer: Optional[VariantAnalyzer] = None,
        static_scanner: Optional[StaticBugScanner] = None,
        fuzz_orchestrator: Optional[FuzzOrchestrator] = None,
        crash_triage: Optional[CrashTriageEngine] = None,
        novelty_scorer: Optional[NoveltyScorer] = None,
        cve_research: Any = None,
    ) -> None:
        self.surface_mapper = surface_mapper or AttackSurfaceMapper()
        self.variant_analyzer = variant_analyzer or VariantAnalyzer()
        self.static_scanner = static_scanner or StaticBugScanner()
        self.fuzz_orchestrator = fuzz_orchestrator or FuzzOrchestrator()
        self.crash_triage = crash_triage or CrashTriageEngine()
        self.novelty_scorer = novelty_scorer or NoveltyScorer()
        self._cve_research = cve_research

    async def hunt(
        self,
        target: str,
        services: Optional[Dict[str, Any]] = None,
        endpoints: Optional[Sequence[Dict[str, Any]]] = None,
        technologies: Optional[Sequence[str]] = None,
        findings: Optional[Sequence[Dict[str, Any]]] = None,
        known_cves: Optional[Sequence[Dict[str, Any]]] = None,
        source_files: Optional[Dict[str, str]] = None,
        crashes: Optional[Sequence[CrashReport]] = None,
        config: Optional[ZeroDayHuntConfig] = None,
    ) -> ZeroDayHuntResult:
        cfg = config or ZeroDayHuntConfig()
        hunt_id = uuid.uuid4().hex[:12]
        t0 = time.perf_counter()
        timings: Dict[str, float] = {}
        warnings: List[str] = []

        if cfg.require_authorization and not cfg.authorized:
            return ZeroDayHuntResult(
                hunt_id=hunt_id,
                target=target,
                status="blocked_unauthorized",
                warnings=[
                    "Zero-day hunt blocked: set authorized=True and authorization_ref "
                    "to a valid engagement / RoE reference before running."
                ],
                elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            )
        if cfg.require_authorization and not cfg.authorization_ref:
            warnings.append(
                "authorized=True but authorization_ref is empty — "
                "record RoE/ticket IDs for auditability"
            )

        # ── Stage 1: surface ──────────────────────────────────────────────
        s0 = time.perf_counter()
        surface = await self.surface_mapper.map_async(
            target=target,
            services=services,
            endpoints=endpoints,
            technologies=technologies,
            findings=findings,
        )
        timings["surface_ms"] = (time.perf_counter() - s0) * 1000.0

        # ── Stage 2: CVE baseline (parallel per service) ──────────────────
        s0 = time.perf_counter()
        cves: List[Dict[str, Any]] = list(known_cves or [])
        if not cves:
            cves = await self._research_cves(services or {})
        timings["cve_ms"] = (time.perf_counter() - s0) * 1000.0

        # ── Stages 3–6 parallel where possible ────────────────────────────
        s0 = time.perf_counter()

        async def run_variants() -> List[VariantHypothesis]:
            return await self.variant_analyzer.analyze_async(cves, services=services)

        async def run_static() -> List[StaticFinding]:
            if not source_files:
                return []
            return await self.static_scanner.scan_files_async(source_files)

        async def run_fuzz() -> FuzzCampaign:
            orch = FuzzOrchestrator(
                max_jobs=cfg.max_fuzz_jobs,
                workers=cfg.fuzz_workers,
            )
            return await orch.plan_async(
                target=target,
                endpoints=surface.endpoints,
                binary_path=cfg.binary_path,
                corpus_dir=cfg.corpus_dir,
                output_dir=cfg.output_dir,
            )

        variants, static_findings, fuzz_campaign = await asyncio.gather(
            run_variants(),
            run_static(),
            run_fuzz(),
        )
        timings["parallel_analysis_ms"] = (time.perf_counter() - s0) * 1000.0

        fuzz_exec_results: List[Dict[str, Any]] = []
        live_crashes: List[CrashReport] = []
        if cfg.execute_fuzz or cfg.live_fuzz:
            s0 = time.perf_counter()
            # dry_run when not execute_fuzz; still uses LiveFuzzWorker for capability report
            dry = cfg.dry_run_fuzz if cfg.execute_fuzz else True
            if cfg.execute_fuzz and not dry:
                dry = False
            elif not cfg.execute_fuzz:
                dry = True
            fuzz_exec_results = await self.fuzz_orchestrator.execute_campaign(
                fuzz_campaign,
                dry_run=dry,
                authorized=cfg.authorized,
                authorization_ref=cfg.authorization_ref,
                use_live_worker=cfg.live_fuzz,
                job_timeout=cfg.fuzz_job_timeout,
            )
            timings["fuzz_exec_ms"] = (time.perf_counter() - s0) * 1000.0
            if dry:
                warnings.append(
                    "Live fuzz worker ran in plan/detect mode "
                    "(set execute_fuzz=True and dry_run_fuzz=False for real runs)"
                )
            # Pull crash list from live worker meta if present
            for item in fuzz_exec_results:
                if isinstance(item, dict) and item.get("_meta") == "live_campaign":
                    for c in item.get("crashes") or []:
                        if isinstance(c, dict):
                            live_crashes.append(
                                CrashReport(
                                    crash_id=c.get("crash_id", "live"),
                                    engine=c.get("engine", "unknown"),
                                    signal=c.get("signal", ""),
                                    stack_trace=c.get("stack_trace", ""),
                                    reproducer=c.get("reproducer", ""),
                                    stderr=c.get("stderr", ""),
                                    target=target,
                                    metadata=c.get("metadata") or {},
                                )
                            )

        # ── Stage 7: crash triage ─────────────────────────────────────────
        triaged: List[TriagedCrash] = []
        all_crashes: List[CrashReport] = list(crashes or []) + live_crashes
        if all_crashes:
            s0 = time.perf_counter()
            triaged = await self.crash_triage.triage_async(all_crashes)
            timings["crash_triage_ms"] = (time.perf_counter() - s0) * 1000.0

        # ── Stage 8: synthesize candidates ────────────────────────────────
        s0 = time.perf_counter()
        candidates = self._synthesize(
            target=target,
            surface=surface,
            variants=variants,
            static_findings=static_findings,
            triaged=triaged,
            cves=cves,
            min_novelty=cfg.min_novelty_score,
            max_candidates=cfg.max_candidates,
        )
        timings["synthesize_ms"] = (time.perf_counter() - s0) * 1000.0

        elapsed = (time.perf_counter() - t0) * 1000.0
        if elapsed < 1000:
            # Honest speed claim for orchestration only
            warnings.append(
                f"Pipeline orchestration completed in {elapsed:.0f}ms. "
                "That is prioritization + planning speed, not a guarantee of "
                "confirmed zero-day discovery."
            )

        fuzz_dict = fuzz_campaign.to_dict()
        if fuzz_exec_results:
            fuzz_dict["execution"] = fuzz_exec_results

        return ZeroDayHuntResult(
            hunt_id=hunt_id,
            target=target,
            status="completed",
            candidates=candidates,
            surface=surface.to_dict(),
            variants=[v.to_dict() for v in variants],
            static_findings=[f.to_dict() for f in static_findings],
            fuzz_campaign=fuzz_dict,
            triaged_crashes=[t.to_dict() for t in triaged],
            elapsed_ms=elapsed,
            stage_timings_ms=timings,
            warnings=warnings,
        )

    def hunt_sync(self, *args: Any, **kwargs: Any) -> ZeroDayHuntResult:
        return asyncio.get_event_loop().run_until_complete(self.hunt(*args, **kwargs))

    async def _research_cves(self, services: Dict[str, Any]) -> List[Dict[str, Any]]:
        try:
            if self._cve_research is None:
                from nova_arsenal.intelligence.cve_research import CveResearch

                self._cve_research = CveResearch()
            researcher = self._cve_research
        except Exception as exc:  # noqa: BLE001
            logger.warning("CVE research unavailable: %s", exc)
            return []

        async def one(name: str, meta: Any) -> List[Dict[str, Any]]:
            version = ""
            port = 0
            if isinstance(meta, dict):
                version = str(meta.get("version") or "")
                p = meta.get("port") or meta.get("ports") or 0
                if isinstance(p, list) and p:
                    port = int(p[0]) if str(p[0]).isdigit() else 0
                elif str(p).isdigit():
                    port = int(p)
            elif isinstance(meta, list) and meta:
                port = int(meta[0]) if str(meta[0]).isdigit() else 0
            try:
                result = await researcher.research(str(name), version, port)
                return [c.to_dict() for c in result.cves]
            except Exception as exc:  # noqa: BLE001
                logger.debug("CVE lookup failed for %s: %s", name, exc)
                return []

        batches = await asyncio.gather(*[one(k, v) for k, v in services.items()])
        out: List[Dict[str, Any]] = []
        for batch in batches:
            out.extend(batch)
        return out

    def _synthesize(
        self,
        target: str,
        surface: SurfaceMap,
        variants: List[VariantHypothesis],
        static_findings: List[StaticFinding],
        triaged: List[TriagedCrash],
        cves: List[Dict[str, Any]],
        min_novelty: float,
        max_candidates: int,
    ) -> List[ZeroDayCandidate]:
        candidates: List[ZeroDayCandidate] = []
        known_ids = {
            str(c.get("cve_id") or c.get("id") or "").upper()
            for c in cves
            if c.get("cve_id") or c.get("id")
        }
        scorer = NoveltyScorer(known_cve_ids=known_ids)

        # High-yield surfaces without matching critical known exploits → research leads
        for ep in surface.top[:15]:
            if ep.priority < 8.0:
                continue
            title = f"High-yield surface: {ep.service}:{ep.port}{ep.path}"
            nov = scorer.assess(title=title, description=ep.rationale, evidence=ep.banner)
            if nov.score < min_novelty:
                continue
            candidates.append(
                ZeroDayCandidate(
                    candidate_id=uuid.uuid4().hex[:10],
                    title=title,
                    bug_class="surface_priority",
                    severity="medium" if ep.blast_radius < 4 else "high",
                    confidence=min(0.7, ep.priority / 20.0),
                    novelty=nov.score,
                    novelty_label=nov.label,
                    source_stage="surface",
                    target=target,
                    evidence=ep.rationale,
                    next_steps=[
                        "Run planned fuzz jobs for this surface",
                        "Diff against vendor advisories for this product/version",
                        "Exercise dangerous paths/params with protocol-aware mutators",
                    ],
                    surface_id=ep.surface_id,
                    tags=ep.tags + ["surface"],
                )
            )

        for v in variants:
            nov = scorer.assess(
                title=v.title,
                description=v.hypothesis,
                bug_class=v.bug_class,
                extra_cves=[v.source_cve] if v.source_cve not in {"", "UNKNOWN"} else None,
            )
            # Variants are interesting even with related CVE; novelty may be mid-range
            adj_novelty = max(nov.score, 0.4 if v.confidence >= 0.5 else nov.score)
            if adj_novelty < min_novelty and v.severity not in {"critical", "high"}:
                continue
            candidates.append(
                ZeroDayCandidate(
                    candidate_id=uuid.uuid4().hex[:10],
                    title=f"[Variant] {v.title} ({v.source_cve})",
                    bug_class=v.bug_class,
                    severity=v.severity,
                    confidence=v.confidence,
                    novelty=adj_novelty,
                    novelty_label=nov.label if nov.score >= 0.45 else "variant_of_known",
                    source_stage="variant",
                    target=target,
                    evidence=v.hypothesis,
                    next_steps=[
                        f"Test ideas: {', '.join(v.test_ideas[:5])}",
                        f"Focus service: {v.target_service}",
                        "Compare patched vs unpatched code paths (patch-gap analysis)",
                    ],
                    related_cves=[v.source_cve] if v.source_cve != "UNKNOWN" else [],
                    tags=["variant", v.bug_class],
                )
            )

        for f in static_findings:
            nov = scorer.assess(
                title=f.title,
                description=f.rationale,
                evidence=f.snippet,
                bug_class=f.bug_class,
            )
            if nov.score < min_novelty and f.severity not in {"critical", "high"}:
                continue
            candidates.append(
                ZeroDayCandidate(
                    candidate_id=uuid.uuid4().hex[:10],
                    title=f"[Static] {f.title} @ {f.location}",
                    bug_class=f.bug_class,
                    severity=f.severity,
                    confidence=f.confidence * nov.score,
                    novelty=nov.score,
                    novelty_label=nov.label,
                    source_stage="static",
                    target=target,
                    evidence=f"{f.rationale} | {f.snippet}",
                    next_steps=[
                        "Confirm sink is reachable from untrusted input",
                        "Write a minimal proof-of-concept for authorized lab only",
                        f"Map to {f.cwe}" if f.cwe else "Assign CWE after validation",
                    ],
                    tags=f.tags,
                )
            )

        for t in triaged:
            nov = scorer.assess(
                title=t.title,
                description=t.recommendation,
                evidence=" ".join(t.sanitizer_hints + t.top_frames),
                bug_class="memory_corruption",
            )
            candidates.append(
                ZeroDayCandidate(
                    candidate_id=uuid.uuid4().hex[:10],
                    title=f"[Crash] {t.title}",
                    bug_class="memory_corruption",
                    severity=t.severity,
                    confidence=t.exploitability,
                    novelty=max(nov.score, 0.7),  # unique crashes often novel
                    novelty_label=nov.label if nov.matched_known else "crash_candidate",
                    source_stage="crash_triage",
                    target=target,
                    evidence=t.recommendation,
                    next_steps=[
                        "Minimize reproducer",
                        "Root-cause with ASan/GDB",
                        "Evaluate remote reachability before severity finalization",
                    ],
                    tags=["crash", t.signal.lower()],
                )
            )

        # Rank: severity weight × novelty × confidence
        sev_w = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.5}

        def rank_key(c: ZeroDayCandidate) -> float:
            return sev_w.get(c.severity, 1.0) * c.novelty * (0.5 + c.confidence)

        candidates.sort(key=rank_key, reverse=True)
        return candidates[:max_candidates]
