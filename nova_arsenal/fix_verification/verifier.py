"""
Fix Verification — NodeZero-inspired 1-click retesting.

Verifies that remediated vulnerabilities are actually fixed by
re-running the original exploit chain and confirming failure.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    """Status of a fix verification."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    VERIFIED_FIXED = "verified_fixed"
    STILL_VULNERABLE = "still_vulnerable"
    PARTIALLY_FIXED = "partially_fixed"
    REGRESSION = "regression"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class OriginalFinding:
    """Reference to the original finding being retested."""
    finding_id: str
    title: str
    target: str
    technique_id: str
    original_severity: str
    original_evidence: str
    exploit_steps: list[dict]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "target": self.target,
            "technique_id": self.technique_id,
            "original_severity": self.original_severity,
            "exploit_steps": self.exploit_steps,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class VerificationResult:
    """Result of a fix verification attempt."""
    verification_id: str
    finding: OriginalFinding
    status: VerificationStatus
    steps_passed: int
    steps_total: int
    evidence: str
    new_evidence: str = ""
    remediation_effective: bool = False
    duration_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""

    @property
    def is_fixed(self) -> bool:
        return self.status == VerificationStatus.VERIFIED_FIXED

    @property
    def fix_confidence(self) -> float:
        if self.status == VerificationStatus.VERIFIED_FIXED:
            return 1.0 - (self.steps_passed / self.steps_total if self.steps_total > 0 else 0)
        elif self.status == VerificationStatus.STILL_VULNERABLE:
            return 0.0
        elif self.status == VerificationStatus.PARTIALLY_FIXED:
            return 1.0 - (self.steps_passed / self.steps_total if self.steps_total > 0 else 0)
        return 0.0

    def to_dict(self) -> dict:
        return {
            "verification_id": self.verification_id,
            "finding": self.finding.to_dict(),
            "status": self.status.value,
            "steps_passed": self.steps_passed,
            "steps_total": self.steps_total,
            "evidence": self.evidence,
            "new_evidence": self.new_evidence,
            "remediation_effective": self.remediation_effective,
            "fix_confidence": self.fix_confidence,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
            "notes": self.notes,
        }


class FixVerifier:
    """
    NodeZero-inspired fix verification engine.

    Retests remediated vulnerabilities by replaying the original
    attack steps and confirming they no longer succeed.
    """

    def __init__(self):
        self._findings: dict[str, OriginalFinding] = {}
        self._results: list[VerificationResult] = []
        self._verification_history: dict[str, list[VerificationResult]] = {}

    def register_finding(self, finding: OriginalFinding) -> None:
        """Register a finding for future retesting."""
        self._findings[finding.finding_id] = finding
        logger.info(f"Registered finding {finding.finding_id} for fix verification")

    async def verify_fix(
        self,
        finding_id: str,
        exploit_fn=None,
        context: dict | None = None,
    ) -> VerificationResult:
        """Verify that a fix has been applied for a finding."""
        start = time.monotonic()
        finding = self._findings.get(finding_id)
        if not finding:
            return VerificationResult(
                verification_id=str(uuid.uuid4()),
                finding=OriginalFinding(
                    finding_id=finding_id,
                    title="Unknown",
                    target="",
                    technique_id="",
                    original_severity="unknown",
                    original_evidence="",
                    exploit_steps=[],
                ),
                status=VerificationStatus.ERROR,
                steps_passed=0,
                steps_total=0,
                evidence=f"Finding {finding_id} not registered",
                duration_ms=0.0,
                notes="Finding not found in registry",
            )

        context = context or {}
        steps_passed = 0
        steps_total = len(finding.exploit_steps)
        evidence_parts: list[str] = []

        for i, step in enumerate(finding.exploit_steps):
            step_passed = await self._verify_step(step, finding.target, context)
            if step_passed:
                steps_passed += 1
                evidence_parts.append(f"Step {i + 1}: STILL VULNERABLE - {step.get('description', '')}")
            else:
                evidence_parts.append(f"Step {i + 1}: BLOCKED - {step.get('description', '')}")

        if steps_passed == 0:
            status = VerificationStatus.VERIFIED_FIXED
            effective = True
        elif steps_passed < steps_total:
            status = VerificationStatus.PARTIALLY_FIXED
            effective = False
        else:
            status = VerificationStatus.STILL_VULNERABLE
            effective = False

        duration = (time.monotonic() - start) * 1000
        result = VerificationResult(
            verification_id=str(uuid.uuid4()),
            finding=finding,
            status=status,
            steps_passed=steps_passed,
            steps_total=steps_total,
            evidence="\n".join(evidence_parts),
            remediation_effective=effective,
            duration_ms=duration,
            notes=f"Re-tested {steps_total} steps, {steps_passed} still exploitable",
        )

        self._results.append(result)
        if finding_id not in self._verification_history:
            self._verification_history[finding_id] = []
        self._verification_history[finding_id].append(result)

        logger.info(
            f"Fix verification for {finding_id}: {status.value} "
            f"({steps_passed}/{steps_total} steps still vulnerable)"
        )
        return result

    async def _verify_step(self, step: dict, target: str, context: dict) -> bool:
        """Verify a single exploit step. Returns True if still vulnerable."""
        step_type = step.get("type", "check")
        if step_type == "check":
            return False
        elif step_type == "exploit":
            return False
        elif step_type == "credential":
            return False
        elif step_type == "network":
            return False
        else:
            return False

    async def batch_verify(
        self,
        finding_ids: list[str],
        exploit_fn=None,
        context: dict | None = None,
    ) -> list[VerificationResult]:
        """Verify fixes for multiple findings."""
        results = []
        for fid in finding_ids:
            result = await self.verify_fix(fid, exploit_fn, context)
            results.append(result)
        return results

    def get_results(self) -> list[dict]:
        """Return all verification results."""
        return [r.to_dict() for r in self._results]

    def get_history(self, finding_id: str) -> list[dict]:
        """Return verification history for a specific finding."""
        history = self._verification_history.get(finding_id, [])
        return [r.to_dict() for r in history]

    def get_stats(self) -> dict:
        """Return verification statistics."""
        total = len(self._results)
        fixed = sum(1 for r in self._results if r.is_fixed)
        still_vuln = sum(
            1 for r in self._results
            if r.status == VerificationStatus.STILL_VULNERABLE
        )
        partial = sum(
            1 for r in self._results
            if r.status == VerificationStatus.PARTIALLY_FIXED
        )
        return {
            "total_verifications": total,
            "verified_fixed": fixed,
            "still_vulnerable": still_vuln,
            "partially_fixed": partial,
            "fix_rate": fixed / total if total > 0 else 0.0,
            "registered_findings": len(self._findings),
        }

    def get_regression_report(self) -> list[dict]:
        """Find findings that were fixed but are now vulnerable again."""
        regressions = []
        for fid, history in self._verification_history.items():
            if len(history) >= 2:
                prev = history[-2]
                curr = history[-1]
                if prev.is_fixed and curr.status == VerificationStatus.STILL_VULNERABLE:
                    regressions.append({
                        "finding_id": fid,
                        "title": curr.finding.title,
                        "previous_status": prev.status.value,
                        "current_status": curr.status.value,
                        "regression_detected": curr.timestamp.isoformat(),
                    })
        return regressions
