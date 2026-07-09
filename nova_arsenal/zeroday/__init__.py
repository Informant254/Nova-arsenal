"""
Zero-Day Research Pipeline (authorized testing only).

Accelerates *candidate* novel-vulnerability discovery by stacking:
- Parallel attack-surface ranking (seconds-scale prioritization)
- CVE variant / patch-gap analysis
- Static bug-class heuristics
- Coverage-guided fuzz campaign orchestration
- Crash triage + novelty scoring against known CVE patterns

This module finds and ranks *candidates*. Confirmed zero-days still require
human validation, root-cause analysis, and responsible disclosure.
"""

from .pipeline import (
    ZeroDayHunter,
    ZeroDayHuntConfig,
    ZeroDayHuntResult,
    ZeroDayCandidate,
)
from .surface import AttackSurfaceMapper, SurfaceEndpoint, SurfaceMap
from .variant import VariantAnalyzer, VariantHypothesis
from .fuzz_orchestrator import FuzzOrchestrator, FuzzCampaign, FuzzJob
from .fuzz_worker import LiveFuzzWorker, LiveCampaignResult, EngineStatus
from .crash_triage import CrashTriageEngine, CrashReport, TriagedCrash
from .static_scanner import StaticBugScanner, StaticFinding
from .novelty import NoveltyScorer, NoveltyAssessment
from .recon_bridge import findings_to_services

__all__ = [
    "ZeroDayHunter",
    "ZeroDayHuntConfig",
    "ZeroDayHuntResult",
    "ZeroDayCandidate",
    "AttackSurfaceMapper",
    "SurfaceEndpoint",
    "SurfaceMap",
    "VariantAnalyzer",
    "VariantHypothesis",
    "FuzzOrchestrator",
    "FuzzCampaign",
    "FuzzJob",
    "LiveFuzzWorker",
    "LiveCampaignResult",
    "EngineStatus",
    "CrashTriageEngine",
    "CrashReport",
    "TriagedCrash",
    "StaticBugScanner",
    "StaticFinding",
    "NoveltyScorer",
    "NoveltyAssessment",
    "findings_to_services",
]
