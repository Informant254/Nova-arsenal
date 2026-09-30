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

from .crash_triage import CrashReport, CrashTriageEngine, TriagedCrash
from .fuzz_orchestrator import FuzzCampaign, FuzzJob, FuzzOrchestrator
from .fuzz_worker import EngineStatus, LiveCampaignResult, LiveFuzzWorker
from .novelty import NoveltyAssessment, NoveltyScorer
from .pipeline import (
    ZeroDayCandidate,
    ZeroDayHuntConfig,
    ZeroDayHunter,
    ZeroDayHuntResult,
)
from .recon_bridge import findings_to_services
from .static_scanner import StaticBugScanner, StaticFinding
from .surface import AttackSurfaceMapper, SurfaceEndpoint, SurfaceMap
from .variant import VariantAnalyzer, VariantHypothesis

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
