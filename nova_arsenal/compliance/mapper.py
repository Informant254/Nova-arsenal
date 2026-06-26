"""
Compliance Framework Mapper.

Maps security findings to control IDs across major compliance frameworks.
Supports PCI DSS, SOC 2, ISO 27001, and NIST SP 800-53.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FrameworkControl:
    framework: str
    control_id: str
    control_name: str
    description: str
    status: str = "unmapped"
    evidence: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "framework": self.framework,
            "control_id": self.control_id,
            "control_name": self.control_name,
            "description": self.description,
            "status": self.status,
            "evidence": self.evidence,
        }


@dataclass
class ComplianceResult:
    finding_title: str
    finding_severity: str
    finding_type: str
    controls: List[FrameworkControl] = field(default_factory=list)
    frameworks_affected: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_title": self.finding_title,
            "finding_severity": self.finding_severity,
            "finding_type": self.finding_type,
            "control_count": len(self.controls),
            "frameworks_affected": self.frameworks_affected,
            "controls": [c.to_dict() for c in self.controls],
        }


FINDING_TYPE_MAP: Dict[str, List[FrameworkControl]] = {
    "sql_injection": [
        FrameworkControl("PCI DSS", "6.5.1", "Injection flaws",
                         "Ensure applications are not vulnerable to SQL injection"),
        FrameworkControl("ISO 27001", "A.14.2.5", "System security testing",
                         "Verify systems against injection vulnerabilities during development"),
        FrameworkControl("NIST SP 800-53", "SI-10", "Information input validation",
                         "Validate all input to prevent injection attacks"),
        FrameworkControl("SOC 2", "CC6.1", "Logical and physical access controls",
                         "Prevent unauthorized access through input validation"),
    ],
    "xss": [
        FrameworkControl("PCI DSS", "6.5.2", "Cross-site scripting",
                         "Ensure applications are not vulnerable to XSS"),
        FrameworkControl("ISO 27001", "A.14.2.5", "System security testing",
                         "Test for XSS vulnerabilities during development"),
        FrameworkControl("NIST SP 800-53", "SI-15", "Information output filtering",
                         "Filter output to prevent XSS attacks"),
        FrameworkControl("SOC 2", "CC6.1", "Logical and physical access controls",
                         "Implement input/output encoding for web applications"),
    ],
    "rce": [
        FrameworkControl("PCI DSS", "6.5.3", "Improper error handling/command injection",
                         "Prevent command injection and RCE vulnerabilities"),
        FrameworkControl("ISO 27001", "A.14.2.5", "System security testing",
                         "Test for command injection during development"),
        FrameworkControl("NIST SP 800-53", "SI-10", "Information input validation",
                         "Validate input to prevent command injection"),
        FrameworkControl("SOC 2", "CC7.1", "System monitoring and detection",
                         "Detect and prevent unauthorized code execution"),
    ],
    "lfi": [
        FrameworkControl("PCI DSS", "6.5.4", "Directory traversal",
                         "Ensure applications prevent path traversal attacks"),
        FrameworkControl("NIST SP 800-53", "AC-6", "Least privilege",
                         "Restrict file system access to minimum required"),
    ],
    "info_disclosure": [
        FrameworkControl("PCI DSS", "6.5.5", "Information leakage",
                         "Prevent sensitive information exposure in error messages"),
        FrameworkControl("ISO 27001", "A.8.2", "Information classification",
                         "Classify and protect sensitive information"),
        FrameworkControl("NIST SP 800-53", "RA-5", "Vulnerability scanning",
                         "Regularly scan for information disclosure vulnerabilities"),
    ],
    "default_creds": [
        FrameworkControl("PCI DSS", "8.3.1", "Authentication requirements",
                         "Change all default passwords before deployment"),
        FrameworkControl("ISO 27001", "A.9.4.2", "Secure log-on procedures",
                         "Enforce strong authentication and remove default credentials"),
        FrameworkControl("NIST SP 800-53", "IA-5", "Authenticator management",
                         "Manage authenticators including default credential changes"),
        FrameworkControl("SOC 2", "CC6.3", "Access authorization",
                         "Remove default credentials and enforce authentication"),
    ],
    "open_port": [
        FrameworkControl("PCI DSS", "1.2.1", "Port and service controls",
                         "Restrict inbound and outbound traffic to necessary ports"),
        FrameworkControl("ISO 27001", "A.13.1.1", "Network controls",
                         "Control and secure network services"),
        FrameworkControl("NIST SP 800-53", "SC-7", "Boundary protection",
                         "Monitor and control communications at system boundaries"),
    ],
    "outdated_software": [
        FrameworkControl("PCI DSS", "6.3.3", "Security patching",
                         "Deploy critical security patches within 30 days"),
        FrameworkControl("ISO 27001", "A.8.8", "Technical vulnerability management",
                         "Regularly update software to address vulnerabilities"),
        FrameworkControl("NIST SP 800-53", "SI-2", "Flaw remediation",
                         "Remediate flaws and install security patches promptly"),
        FrameworkControl("SOC 2", "CC7.3", "Vulnerability management",
                         "Manage vulnerabilities through patching and updates"),
    ],
    "weak_ssl": [
        FrameworkControl("PCI DSS", "4.2.1", "Strong cryptography",
                         "Use strong encryption protocols and ciphers"),
        FrameworkControl("ISO 27001", "A.10.1.1", "Cryptographic controls",
                         "Implement strong cryptographic controls for data in transit"),
        FrameworkControl("NIST SP 800-53", "SC-8", "Transmission confidentiality",
                         "Protect transmitted data with strong encryption"),
    ],
    "insecure_headers": [
        FrameworkControl("PCI DSS", "6.5.6", "Security configuration",
                         "Implement security headers to protect web applications"),
        FrameworkControl("NIST SP 800-53", "SC-8", "Transmission confidentiality",
                         "Use security headers to enforce secure communications"),
    ],
    "authentication_bypass": [
        FrameworkControl("PCI DSS", "8.3.2", "Authentication bypass",
                         "Implement strong authentication mechanisms"),
        FrameworkControl("ISO 27001", "A.9.4.2", "Secure log-on procedures",
                         "Prevent authentication bypass through secure implementation"),
        FrameworkControl("NIST SP 800-53", "IA-2", "Identification and authentication",
                         "Implement robust identity and authentication controls"),
    ],
}

SEVERITY_THRESHOLDS: Dict[str, str] = {
    "critical": "Requires immediate remediation. High risk of compromise.",
    "high": "Requires prompt remediation within 30 days.",
    "medium": "Should be remediated within 60-90 days.",
    "low": "Best practice recommendation.",
}


class ComplianceMapper:
    """
    Maps security findings to compliance control IDs.

    Each finding type (sql_injection, xss, rce, etc.) maps to
    relevant controls across PCI DSS, SOC 2, ISO 27001, NIST.
    """

    def map_finding(self, finding_type: str, title: str,
                    severity: str, evidence: str = "") -> ComplianceResult:
        finding_key = finding_type.lower().replace(" ", "_")
        controls = FINDING_TYPE_MAP.get(finding_key, [])

        if not controls:
            finding_key = self._fuzzy_match(finding_key)
            controls = FINDING_TYPE_MAP.get(finding_key, [])

        frameworks: set = set()
        for c in controls:
            frameworks.add(c.framework)
            c.status = "affected"
            c.evidence = evidence or SEVERITY_THRESHOLDS.get(severity, "Finding detected")

        return ComplianceResult(
            finding_title=title,
            finding_severity=severity,
            finding_type=finding_type,
            controls=controls,
            frameworks_affected=sorted(frameworks),
        )

    def map_findings(self, findings: List[Dict[str, str]]) -> List[ComplianceResult]:
        return [self.map_finding(
            finding_type=f.get("finding_type", f.get("title", "unknown")),
            title=f.get("title", "Unknown finding"),
            severity=f.get("severity", "medium"),
            evidence=f.get("evidence", ""),
        ) for f in findings]

    def _fuzzy_match(self, key: str) -> str:
        fuzzy_map = {
            "sqli": "sql_injection",
            "injection": "sql_injection",
            "cross_site_scripting": "xss",
            "command_execution": "rce",
            "remote_code_execution": "rce",
            "path_traversal": "lfi",
            "information_disclosure": "info_disclosure",
            "information_exposure": "info_disclosure",
            "weak_password": "default_creds",
            "default_password": "default_creds",
            "ssl_tls": "weak_ssl",
            "unpatched": "outdated_software",
            "missing_header": "insecure_headers",
        }
        return fuzzy_map.get(key, key)

    def list_frameworks(self) -> Dict[str, List[str]]:
        frameworks: Dict[str, set] = {}
        for finding_type, controls in FINDING_TYPE_MAP.items():
            for c in controls:
                if c.framework not in frameworks:
                    frameworks[c.framework] = set()
                frameworks[c.framework].add(c.control_id)

        return {
            fw: sorted(controls)
            for fw, controls in frameworks.items()
        }

    def get_summary_stats(self, results: List[ComplianceResult]) -> Dict[str, Any]:
        framework_hits: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}

        for r in results:
            for fw in r.frameworks_affected:
                framework_hits[fw] = framework_hits.get(fw, 0) + 1
            severity_counts[r.finding_severity] = severity_counts.get(r.finding_severity, 0) + 1

        total_controls = sum(len(r.controls) for r in results)
        unique_controls = set()
        for r in results:
            for c in r.controls:
                unique_controls.add((c.framework, c.control_id))

        return {
            "total_findings_mapped": len(results),
            "total_controls_affected": total_controls,
            "unique_controls_affected": len(unique_controls),
            "frameworks_affected": len(framework_hits),
            "framework_breakdown": framework_hits,
            "severity_breakdown": severity_counts,
        }
