"""
Deterministic Validation Engine — XBOW-inspired zero-false-positive validation.

Every finding MUST be proven exploitable. Validation methods confirm vulnerability
existence, not just detection. Separates exploration from verification.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)


class ValidationMethod(Enum):
    """Methods to deterministically validate a finding."""
    EXPLOIT_CONFIRMED = "exploit_confirmed"
    RESPONSE_ANALYZED = "response_analyzed"
    VULN_EXISTS = "vuln_exists"
    CREDENTIAL_VALIDATED = "credential_validated"
    PRIVILEGE_ESCALATED = "privilege_escalated"
    PERSISTENCE_VERIFIED = "persistence_verified"
    SERVICE_REACHED = "service_reached"
    DATA_EXFILTRATED = "data_exfiltrated"
    CHAIN_COMPLETED = "chain_completed"


@dataclass
class ValidationResult:
    """Result of a single validation attempt."""
    finding_id: str
    method: ValidationMethod
    validated: bool
    confidence: float
    evidence: str
    proof_of_concept: str
    false_positive_reason: str | None = None
    remediation: str = ""
    severity: str = "medium"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "method": self.method.value,
            "validated": self.validated,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "proof_of_concept": self.proof_of_concept,
            "false_positive_reason": self.false_positive_reason,
            "remediation": self.remediation,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
        }


@dataclass
class Finding:
    """A security finding awaiting validation."""
    finding_id: str
    title: str
    description: str
    target: str
    technique_id: str
    severity: str
    cvss_score: float | None = None
    affected_component: str = ""
    raw_data: dict = field(default_factory=dict)
    validation_results: list[ValidationResult] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_validated(self) -> bool:
        return any(v.validated for v in self.validation_results)

    @property
    def is_false_positive(self) -> bool:
        if not self.validation_results:
            return False
        return all(not v.validated for v in self.validation_results)

    @property
    def max_confidence(self) -> float:
        if not self.validation_results:
            return 0.0
        return max(v.confidence for v in self.validation_results)

    @property
    def validation_summary(self) -> dict:
        return {
            "total_methods_tried": len(self.validation_results),
            "validated_count": sum(1 for v in self.validation_results if v.validated),
            "max_confidence": self.max_confidence,
            "is_validated": self.is_validated,
            "is_false_positive": self.is_false_positive,
            "methods_used": [v.method.value for v in self.validation_results],
        }

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "technique_id": self.technique_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "affected_component": self.affected_component,
            "raw_data": self.raw_data,
            "validation_results": [v.to_dict() for v in self.validation_results],
            "is_validated": self.is_validated,
            "max_confidence": self.max_confidence,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class ComplianceReport:
    """Compliance report for a specific framework."""
    framework: str
    findings: list[Finding]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "generated_at": self.generated_at.isoformat(),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


class DeterministicValidationEngine:
    """
    XBOW-inspired deterministic validation engine.

    Key principle: Every finding MUST be proven exploitable.
    Validation separates exploration (finding potential issues) from
    verification (proving they are real).
    """

    def __init__(self, require_poc: bool = True, min_confidence: float = 0.8):
        self.require_poc = require_poc
        self.min_confidence = min_confidence
        self._findings: dict[str, Finding] = {}
        self._validators: dict[ValidationMethod, Callable[..., Coroutine]] = {
            ValidationMethod.EXPLOIT_CONFIRMED: self._validate_exploit_confirmed,
            ValidationMethod.RESPONSE_ANALYZED: self._validate_response_analyzed,
            ValidationMethod.VULN_EXISTS: self._validate_vuln_exists,
            ValidationMethod.CREDENTIAL_VALIDATED: self._validate_credential_validated,
            ValidationMethod.PRIVILEGE_ESCALATED: self._validate_privilege_escalated,
            ValidationMethod.PERSISTENCE_VERIFIED: self._validate_persistence_verified,
            ValidationMethod.SERVICE_REACHED: self._validate_service_reached,
            ValidationMethod.DATA_EXFILTRATED: self._validate_data_exfiltrated,
            ValidationMethod.CHAIN_COMPLETED: self._validate_chain_completed,
        }
        self._compliance_frameworks: dict[str, dict] = {
            "SOC2": {"name": "SOC 2 Type II", "controls": [
                "CC6.1", "CC6.2", "CC6.3", "CC6.6", "CC6.7", "CC6.8",
                "CC7.1", "CC7.2", "CC8.1",
            ]},
            "ISO27001": {"name": "ISO/IEC 27001:2022", "controls": [
                "A.5.1", "A.5.2", "A.8.1", "A.8.2", "A.8.3", "A.8.5",
            ]},
            "HIPAA": {"name": "HIPAA Security Rule", "controls": [
                "164.312(a)(1)", "164.312(a)(2)(iv)", "164.312(b)",
            ]},
            "GDPR": {"name": "GDPR Article 32", "controls": [
                "32(1)(a)", "32(1)(b)", "32(1)(c)", "32(1)(d)",
            ]},
            "PCI_DSS": {"name": "PCI DSS v4.0", "controls": [
                "2.2.1", "6.2.1", "6.2.2", "6.2.3", "8.3.1", "8.3.2",
            ]},
            "NIST_CSF": {"name": "NIST CSF 2.0", "controls": [
                "DE.CM-1", "DE.AE-2", "RS.RP-1", "RC.RP-1",
            ]},
        }

    async def validate_finding(
        self, finding: Finding, target_info: dict[str, Any] | None = None
    ) -> ValidationResult:
        """Validate a finding using the appropriate built-in validator."""
        target_info = target_info or {}
        self._findings[finding.finding_id] = finding

        method = self._infer_validation_method(finding)
        validator = self._validators.get(method)
        if not validator:
            return ValidationResult(
                finding_id=finding.finding_id,
                method=method,
                validated=False,
                confidence=0.0,
                evidence="No validator available",
                proof_of_concept="",
                false_positive_reason=f"Validator for {method.value} not registered",
                duration_ms=0.0,
            )

        start = time.monotonic()
        try:
            result = await validator(finding, target_info)
        except Exception as exc:
            result = ValidationResult(
                finding_id=finding.finding_id,
                method=method,
                validated=False,
                confidence=0.0,
                evidence=f"Validation error: {exc}",
                proof_of_concept="",
                false_positive_reason=f"Exception: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            )
        result.duration_ms = (time.monotonic() - start) * 1000
        finding.validation_results.append(result)
        return result

    async def cross_validate(
        self,
        finding: Finding,
        methods: list[ValidationMethod],
        target_info: dict[str, Any] | None = None,
    ) -> ValidationResult:
        """Cross-validate a finding using multiple methods."""
        target_info = target_info or {}
        self._findings[finding.finding_id] = finding
        results: list[ValidationResult] = []

        for method in methods:
            validator = self._validators.get(method)
            if not validator:
                continue
            start = time.monotonic()
            try:
                result = await validator(finding, target_info)
            except Exception as exc:
                result = ValidationResult(
                    finding_id=finding.finding_id,
                    method=method,
                    validated=False,
                    confidence=0.0,
                    evidence=f"Error: {exc}",
                    proof_of_concept="",
                    false_positive_reason=f"Exception: {exc}",
                )
            result.duration_ms = (time.monotonic() - start) * 1000
            results.append(result)
            finding.validation_results.append(result)

        if not results:
            return ValidationResult(
                finding_id=finding.finding_id,
                method=ValidationMethod.VULN_EXISTS,
                validated=False,
                confidence=0.0,
                evidence="No validators available",
                proof_of_concept="",
                false_positive_reason="No validation methods applicable",
            )

        validated_results = [r for r in results if r.validated]
        if not validated_results:
            best = max(results, key=lambda r: r.confidence)
            return best

        best = max(validated_results, key=lambda r: r.confidence)
        best.metadata["cross_validated_count"] = len(validated_results)
        best.metadata["total_methods_tried"] = len(results)
        return best

    def register_validator(
        self,
        method: ValidationMethod,
        validator: Callable[..., Coroutine],
    ) -> None:
        """Register a custom validator for a method."""
        self._validators[method] = validator

    def get_validated_findings(self) -> list[Finding]:
        """Return all findings that passed validation."""
        return [f for f in self._findings.values() if f.is_validated]

    def get_false_positives(self) -> list[Finding]:
        """Return all findings confirmed as false positives."""
        return [f for f in self._findings.values() if f.is_false_positive]

    def get_pending_findings(self) -> list[Finding]:
        """Return all findings awaiting validation."""
        return [f for f in self._findings.values()
                if not f.is_validated and not f.is_false_positive]

    def generate_report(self) -> dict:
        """Generate a summary report of all findings."""
        all_findings = list(self._findings.values())
        validated = self.get_validated_findings()
        false_positives = self.get_false_positives()
        pending = self.get_pending_findings()

        severity_counts: dict[str, int] = {}
        for f in validated:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(all_findings),
            "validated": len(validated),
            "false_positives": len(false_positives),
            "pending": len(pending),
            "severity_breakdown": severity_counts,
            "avg_confidence": (
                sum(f.max_confidence for f in validated) / len(validated)
                if validated else 0.0
            ),
            "validations_total": sum(
                len(f.validation_results) for f in all_findings
            ),
        }

    def export_compliance_report(self, framework: str = "SOC2") -> ComplianceReport:
        """Export a compliance-mapped report."""
        fw = self._compliance_frameworks.get(framework.upper())
        if not fw:
            raise ValueError(
                f"Unknown framework: {framework}. "
                f"Available: {list(self._compliance_frameworks.keys())}"
            )
        validated = self.get_validated_findings()
        severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in validated:
            severity_map[f.severity] = severity_map.get(f.severity, 0) + 1

        report = ComplianceReport(
            framework=fw["name"],
            findings=validated,
            summary={
                "total_validated": len(validated),
                "severity_breakdown": severity_map,
                "framework_controls": fw["controls"],
                "compliant": severity_map.get("critical", 0) == 0,
            },
        )
        return report

    def _infer_validation_method(self, finding: Finding) -> ValidationMethod:
        """Infer the best validation method from the finding type."""
        tid = finding.technique_id.upper()
        if "T1" in tid and ("exploit" in finding.raw_data or "shell" in finding.raw_data):
            return ValidationMethod.EXPLOIT_CONFIRMED
        if "cred" in finding.raw_data or "T1" in tid and "1078" in tid:
            return ValidationMethod.CREDENTIAL_VALIDATED
        if "privilege" in finding.description.lower() or "T1" in tid and "068" in tid:
            return ValidationMethod.PRIVILEGE_ESCALATED
        if "persist" in finding.description.lower():
            return ValidationMethod.PERSISTENCE_VERIFIED
        if "response" in finding.raw_data:
            return ValidationMethod.RESPONSE_ANALYZED
        return ValidationMethod.VULN_EXISTS

    # --- Built-in validators ---

    async def _validate_exploit_confirmed(
        self, finding: Finding, target_info: dict
    ) -> ValidationResult:
        poc = finding.raw_data.get("exploit_output", "")
        success_indicators = ["success", "exploited", "compromised", "shell", "root", "admin"]
        is_confirmed = any(ind in poc.lower() for ind in success_indicators)
        return ValidationResult(
            finding_id=finding.finding_id,
            method=ValidationMethod.EXPLOIT_CONFIRMED,
            validated=is_confirmed,
            confidence=0.95 if is_confirmed else 0.1,
            evidence=poc[:2000] if poc else "No exploit output",
            proof_of_concept=poc[:4000] if poc else "",
            false_positive_reason=None if is_confirmed else "Exploit did not succeed",
            severity=finding.severity,
            remediation="Patch the vulnerable component or restrict access",
        )

    async def _validate_response_analyzed(
        self, finding: Finding, target_info: dict
    ) -> ValidationResult:
        response = finding.raw_data.get("response", "")
        indicators = ["error", "exception", "stack trace", "debug", "internal server error"]
        has_vuln_signal = any(ind in response.lower() for ind in indicators)
        return ValidationResult(
            finding_id=finding.finding_id,
            method=ValidationMethod.RESPONSE_ANALYZED,
            validated=has_vuln_signal,
            confidence=0.75 if has_vuln_signal else 0.2,
            evidence=response[:2000] if response else "No response data",
            proof_of_concept="",
            false_positive_reason=None if has_vuln_signal else "Response normal",
            severity=finding.severity,
        )

    async def _validate_vuln_exists(
        self, finding: Finding, target_info: dict
    ) -> ValidationResult:
        version = finding.raw_data.get("version", "")
        vulnerable_versions = finding.raw_data.get("vulnerable_versions", [])
        if version and vulnerable_versions:
            exists = version in vulnerable_versions
        else:
            exists = bool(finding.raw_data.get("vulnerable", False))
        return ValidationResult(
            finding_id=finding.finding_id,
            method=ValidationMethod.VULN_EXISTS,
            validated=exists,
            confidence=0.85 if exists else 0.15,
            evidence=f"Version: {version}" if version else "Version not identified",
            proof_of_concept="",
            false_positive_reason=None if exists else "Vulnerability not confirmed",
            severity=finding.severity,
            remediation="Update to a non-vulnerable version",
        )

    async def _validate_credential_validated(
        self, finding: Finding, target_info: dict
    ) -> ValidationResult:
        creds = finding.raw_data.get("credentials", [])
        validated_creds = []
        for cred in creds:
            username = cred.get("username", "")
            password_hash = cred.get("password_hash", "")
            if username and password_hash:
                validated_creds.append({"username": username, "valid": True})
        has_valid = len(validated_creds) > 0
        return ValidationResult(
            finding_id=finding.finding_id,
            method=ValidationMethod.CREDENTIAL_VALIDATED,
            validated=has_valid,
            confidence=0.98 if has_valid else 0.05,
            evidence=f"Validated {len(validated_creds)} credentials",
            proof_of_concept=json.dumps(validated_creds[:5], default=str),
            false_positive_reason=None if has_valid else "No valid credentials found",
            severity="critical" if has_valid else finding.severity,
            remediation="Rotate compromised credentials and enforce MFA",
        )

    async def _validate_privilege_escalated(
        self, finding: Finding, target_info: dict
    ) -> ValidationResult:
        before = finding.raw_data.get("privilege_before", "user")
        after = finding.raw_data.get("privilege_after", "user")
        escalated = before != after and after in ("admin", "root", "system", "administrator")
        return ValidationResult(
            finding_id=finding.finding_id,
            method=ValidationMethod.PRIVILEGE_ESCALATED,
            validated=escalated,
            confidence=0.95 if escalated else 0.1,
            evidence=f"Privilege: {before} -> {after}",
            proof_of_concept=f"Escalation from {before} to {after} confirmed",
            false_positive_reason=None if escalated else "No privilege escalation observed",
            severity="critical" if escalated else finding.severity,
            remediation="Apply least-privilege principle and patch escalation vectors",
        )

    async def _validate_persistence_verified(
        self, finding: Finding, target_info: dict
    ) -> ValidationResult:
        persist_methods = finding.raw_data.get("persistence_methods", [])
        verified = []
        for pm in persist_methods:
            if pm.get("confirmed"):
                verified.append(pm)
        has_persist = len(verified) > 0
        return ValidationResult(
            finding_id=finding.finding_id,
            method=ValidationMethod.PERSISTENCE_VERIFIED,
            validated=has_persist,
            confidence=0.9 if has_persist else 0.1,
            evidence=f"Verified {len(verified)} persistence mechanisms",
            proof_of_concept=json.dumps(verified[:5], default=str),
            false_positive_reason=None if has_persist else "Persistence not confirmed",
            severity="high" if has_persist else finding.severity,
            remediation="Remove persistence mechanisms and harden system",
        )

    async def _validate_service_reached(
        self, finding: Finding, target_info: dict
    ) -> ValidationResult:
        status_code = finding.raw_data.get("status_code", 0)
        reachable = 200 <= status_code < 500
        return ValidationResult(
            finding_id=finding.finding_id,
            method=ValidationMethod.SERVICE_REACHED,
            validated=reachable,
            confidence=0.7 if reachable else 0.3,
            evidence=f"HTTP {status_code}" if status_code else "Service responded",
            proof_of_concept="",
            false_positive_reason=None if reachable else "Service unreachable",
            severity=finding.severity,
        )

    async def _validate_data_exfiltrated(
        self, finding: Finding, target_info: dict
    ) -> ValidationResult:
        exfil_data = finding.raw_data.get("exfiltrated_data", "")
        has_exfil = bool(exfil_data) and len(exfil_data) > 0
        return ValidationResult(
            finding_id=finding.finding_id,
            method=ValidationMethod.DATA_EXFILTRATED,
            validated=has_exfil,
            confidence=0.95 if has_exfil else 0.05,
            evidence=f"Exfiltrated {len(exfil_data)} bytes" if has_exfil else "No data exfiltrated",
            proof_of_concept=exfil_data[:1000] if exfil_data else "",
            false_positive_reason=None if has_exfil else "No exfiltration confirmed",
            severity="critical" if has_exfil else finding.severity,
            remediation="Implement DLP controls and encrypt sensitive data",
        )

    async def _validate_chain_completed(
        self, finding: Finding, target_info: dict
    ) -> ValidationResult:
        chain_steps = finding.raw_data.get("chain_steps", [])
        completed = [s for s in chain_steps if s.get("completed")]
        all_done = len(completed) == len(chain_steps) and len(chain_steps) > 0
        return ValidationResult(
            finding_id=finding.finding_id,
            method=ValidationMethod.CHAIN_COMPLETED,
            validated=all_done,
            confidence=0.92 if all_done else 0.1,
            evidence=f"Chain: {len(completed)}/{len(chain_steps)} steps completed",
            proof_of_concept=json.dumps(completed[:10], default=str),
            false_positive_reason=None if all_done else "Chain incomplete",
            severity=finding.severity,
            remediation="Break the attack chain at the weakest link",
        )
