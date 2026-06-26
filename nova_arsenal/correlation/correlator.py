"""
Cross-Tool Result Correlation Engine.

Nova reads output from ALL tools and correlates:

- Metasploit says exploitable + Burp confirms weak headers + Nmap shows outdated service
  → CRITICAL finding (multi-source confirmation)

- One source alone might miss it. Nova sees the full picture
  by combining results from Nmap, Nuclei, Burp, Metasploit, SQLmap.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedFinding:
    """
    A finding that has been correlated across multiple tools.

    The severity is boosted when multiple independent tools
    confirm the same vulnerability.
    """
    title: str
    severity: str
    description: str
    evidence: str = ""
    endpoint: str = ""
    remediation: str = ""

    # Correlation metadata
    source_tools: List[str] = field(default_factory=list)
    source_count: int = 0
    confidence: float = 0.0
    correlation_tags: List[str] = field(default_factory=list)
    raw_sources: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.source_count = len(self.source_tools)
        if self.confidence == 0.0 and self.source_count > 0:
            self.confidence = min(1.0, self.source_count * 0.3)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence[:500],
            "endpoint": self.endpoint,
            "remediation": self.remediation[:500],
            "source_tools": self.source_tools,
            "source_count": self.source_count,
            "confidence": round(self.confidence, 2),
            "correlation_tags": self.correlation_tags,
        }


@dataclass
class CorrelationResult:
    """Complete correlation output."""
    correlated_findings: List[CorrelatedFinding] = field(default_factory=list)
    uncorrelated_findings: List[Dict[str, Any]] = field(default_factory=list)
    tool_coverage: Dict[str, int] = field(default_factory=dict)
    cross_tool_insights: List[str] = field(default_factory=list)
    correlation_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def critical_findings(self) -> List[CorrelatedFinding]:
        return [f for f in self.correlated_findings if f.severity == "critical"]

    @property
    def high_findings(self) -> List[CorrelatedFinding]:
        return [f for f in self.correlated_findings if f.severity == "high"]

    @property
    def total_correlated(self) -> int:
        return len(self.correlated_findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlated_findings": [f.to_dict() for f in self.correlated_findings],
            "uncorrelated_count": len(self.uncorrelated_findings),
            "tool_coverage": self.tool_coverage,
            "cross_tool_insights": self.cross_tool_insights,
            "correlation_time": self.correlation_time,
            "critical_count": len(self.critical_findings),
            "high_count": len(self.high_findings),
            "total_correlated": self.total_correlated,
            "confidence_score": self._overall_confidence(),
        }

    def _overall_confidence(self) -> float:
        """Overall confidence score for the entire assessment."""
        if not self.correlated_findings:
            return 0.0
        return round(
            sum(f.confidence for f in self.correlated_findings) / len(self.correlated_findings),
            2,
        )


class Correlator:
    """
    Correlates findings across multiple security tools.

    Correlation rules define how findings from different tools
    combine to produce higher-confidence results.

    Usage:
        correlator = Correlator()
        result = await correlator.correlate(
            nmap_data={...},
            burp_issues=[...],
            msf_results=[...],
            sqlmap_tasks=[...],
            findings=[...],
        )
        for f in result.correlated_findings:
            print(f"CRITICAL: {f.title} ({f.source_count} tools)")
    """

    def __init__(self) -> None:
        self._correlation_rules = self._build_rules()

    def _build_rules(self) -> List[Dict[str, Any]]:
        """Build correlation rules for cross-tool finding matching."""
        return [
            # ── Web Vulnerability Chains ──
            {
                "name": "web_critical_chain",
                "description": "Web vulnerability confirmed by multiple web tools",
                "severity": "critical",
                "min_sources": 2,
                "tags": ["web", "multi-source"],
                "sources": ["burp", "nuclei", "nikto", "sqlmap", "nmap", "metasploit", "findings"],
                "indicators": [
                    "injection", "rce", "xss", "sql", "exploit",
                    "vulnerable", "critical", "remote code",
                ],
            },
            {
                "name": "web_high_chain",
                "description": "Web issue confirmed by at least one tool",
                "severity": "high",
                "min_sources": 1,
                "tags": ["web"],
                "sources": ["burp", "nuclei", "nikto", "whatweb", "nmap", "findings"],
                "indicators": [
                    "misconfig", "disclosure", "exposure", "leak",
                    "weak", "outdated", "directory listing", "http",
                    "open port", "web service",
                ],
            },
            # ── SMB / Network Chain ──
            {
                "name": "smb_critical_chain",
                "description": "SMB vulnerability confirmed by multiple tools",
                "severity": "critical",
                "min_sources": 2,
                "tags": ["smb", "network", "multi-source"],
                "sources": ["metasploit", "nmap", "enum4linux", "crackmapexec", "findings"],
                "indicators": [
                    "smb", "eternalblue", "ms17-010", "smb_vuln",
                    "vulnerable", "exploitable", "remote code execution",
                ],
            },
            {
                "name": "smb_high_chain",
                "description": "SMB issue from one solid source",
                "severity": "high",
                "min_sources": 1,
                "tags": ["smb", "network"],
                "sources": ["metasploit", "nmap", "enum4linux", "findings"],
                "indicators": [
                    "smb", "share", "null session", "anonymous",
                    "default", "password", "credentials",
                ],
            },
            # ── Service Version Chain ──
            {
                "name": "outdated_service_chain",
                "description": "Outdated service version detected + exploit available",
                "severity": "high",
                "min_sources": 2,
                "tags": ["version", "cve", "multi-source"],
                "sources": ["nmap", "metasploit", "whatweb", "nuclei", "findings"],
                "indicators": [
                    "outdated", "old", "deprecated", "cve-",
                    "version", "1.0.", "2.4.", "unsupported",
                ],
            },
            # ── Credential Chain ──
            {
                "name": "credential_chain",
                "description": "Credentials found via multiple methods",
                "severity": "critical",
                "min_sources": 2,
                "tags": ["credentials", "auth", "multi-source"],
                "sources": ["hydra", "metasploit", "crackmapexec", "burp", "nmap", "findings"],
                "indicators": [
                    "password", "credentials", "login", "auth",
                    "brute", "default", "hash", "session",
                ],
            },
        ]

    async def correlate(
        self,
        nmap_data: Optional[Dict[str, Any]] = None,
        burp_issues: Optional[List[Dict[str, Any]]] = None,
        msf_results: Optional[List[Dict[str, Any]]] = None,
        sqlmap_tasks: Optional[List[Dict[str, Any]]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> CorrelationResult:
        """
        Correlate findings from all tool sources.

        Each source provides structured data. The correlator:
        1. Normalizes all findings to a common format
        2. Matches them against correlation rules
        3. Boosts severity based on multi-source confirmation
        4. Generates cross-tool insights

        Returns:
            CorrelationResult with correlated + uncorrelated findings
        """
        # Normalize all sources
        all_sources: Dict[str, List[Dict[str, Any]]] = {}

        if nmap_data:
            all_sources["nmap"] = self._normalize_nmap(nmap_data)
        if burp_issues:
            all_sources["burp"] = burp_issues
        if msf_results:
            all_sources["metasploit"] = self._normalize_msf(msf_results)
        if sqlmap_tasks:
            all_sources["sqlmap"] = self._normalize_sqlmap(sqlmap_tasks)
        if findings:
            all_sources["findings"] = findings

        # Track tool coverage
        tool_coverage = {
            tool: len(items) for tool, items in all_sources.items()
        }

        # Flatten all findings from all tools
        all_flat = []
        for tool, items in all_sources.items():
            for item in items:
                item["_source_tool"] = tool
                all_flat.append(item)

        if not all_flat:
            return CorrelationResult(tool_coverage=tool_coverage)

        # Run correlation
        correlated: List[Dict[str, Any]] = []
        used_indices: set = set()

        for rule in self._correlation_rules:
            matching = self._find_matching(all_flat, rule, used_indices)
            if matching and len(matching) >= rule["min_sources"]:
                correlated.append({
                    "title": self._build_title(matching, rule),
                    "severity": rule["severity"],
                    "description": self._build_description(matching, rule),
                    "source_tools": list(set(m["_source_tool"] for m in matching)),
                    "source_count": len(matching),
                    "confidence": min(1.0, len(matching) * 0.3),
                    "correlation_tags": rule["tags"],
                    "endpoint": matching[0].get("url", matching[0].get("endpoint", "")),
                    "evidence": self._build_evidence(matching),
                    "remediation": self._build_remediation(matching),
                    "raw_sources": matching,
                })

                # Mark used
                for m in matching:
                    idx = all_flat.index(m)
                    used_indices.add(idx)

        # Uncorrelated findings
        uncorrelated = [
            f for i, f in enumerate(all_flat) if i not in used_indices
        ]

        # Build correlated findings
        correlated_findings = [
            CorrelatedFinding(**c) for c in correlated
        ]

        # Cross-tool insights
        insights = self._generate_insights(
            correlated_findings, all_sources, tool_coverage
        )

        result = CorrelationResult(
            correlated_findings=correlated_findings,
            uncorrelated_findings=uncorrelated,
            tool_coverage=tool_coverage,
            cross_tool_insights=insights,
        )

        logger.info(
            f"Correlation: {len(correlated_findings)} correlated, "
            f"{len(uncorrelated)} uncorrelated, "
            f"{len(insights)} insights"
        )
        return result

    def _find_matching(
        self,
        all_flat: List[Dict[str, Any]],
        rule: Dict[str, Any],
        used_indices: set,
    ) -> List[Dict[str, Any]]:
        """Find findings matching a correlation rule."""
        matching = []

        for i, item in enumerate(all_flat):
            if i in used_indices:
                continue

            source = item.get("_source_tool", "")
            if source not in rule["sources"]:
                continue

            # Check if any indicator matches
            text = json.dumps(item).lower()
            for indicator in rule["indicators"]:
                if indicator.lower() in text:
                    matching.append(item)
                    break

        return matching

    def _build_title(
        self, matching: List[Dict[str, Any]], rule: Dict[str, Any]
    ) -> str:
        """Build a descriptive title for a correlated finding."""
        sources = [m["_source_tool"] for m in matching]
        base = rule["description"].split(".")[0]

        if rule["severity"] == "critical":
            return f"CORRELATED CRITICAL: {base} ({', '.join(set(sources))})"
        return f"Correlated: {base} ({', '.join(set(sources))})"

    def _build_description(
        self, matching: List[Dict[str, Any]], rule: Dict[str, Any]
    ) -> str:
        """Build description from matching sources."""
        parts = [rule["description"]]
        for m in matching:
            title = m.get("title", m.get("name", ""))
            if title:
                source = m.get("_source_tool", "unknown")
                parts.append(f"  [{source}] {title}")
        return "\n".join(parts)

    def _build_evidence(self, matching: List[Dict[str, Any]]) -> str:
        """Collect evidence from all sources."""
        evidence = []
        for m in matching[:3]:
            ev = m.get("evidence", m.get("output", m.get("raw_output", "")))
            if ev and isinstance(ev, str) and len(ev) > 10:
                evidence.append(f"[{m.get('_source_tool', '?')}]\n{ev[:300]}")
        return "\n---\n".join(evidence[:3])

    def _build_remediation(self, matching: List[Dict[str, Any]]) -> str:
        """Build composite remediation from sources."""
        remediations = []
        for m in matching:
            rem = m.get("remediation", "")
            if rem and rem not in remediations:
                remediations.append(rem)
        return "\n".join(remediations[:3]) if remediations else "Review and patch each identified vulnerability."

    def _generate_insights(
        self,
        correlated: List[CorrelatedFinding],
        all_sources: Dict[str, List[Dict[str, Any]]],
        tool_coverage: Dict[str, int],
    ) -> List[str]:
        """Generate high-level cross-tool insights."""
        insights = []

        if correlated:
            multi_source = [f for f in correlated if f.source_count >= 2]
            if multi_source:
                insights.append(
                    f"{len(multi_source)} findings confirmed by multiple "
                    f"independent tools (high confidence)"
                )

        # Tool-specific insights
        svc_tools = [t for t in tool_coverage if tool_coverage[t] > 0]
        if "burp" in svc_tools and "nmap" in svc_tools:
            insights.append(
                "Burp Suite + Nmap both active: service enumeration paired "
                "with web-layer vulnerability scanning"
            )
        if "metasploit" in svc_tools:
            insights.append(
                "Metasploit integration active: exploit modules can be "
                "deployed for confirmed vulnerabilities"
            )
        if "sqlmap" in svc_tools:
            insights.append(
                "SQLmap integration active: automated SQL injection "
                "testing available"
            )

        # Severity insights
        critical = [f for f in correlated if f.severity == "critical"]
        if critical:
            insights.append(
                f"{len(critical)} CRITICAL severity findings require "
                f"immediate attention"
            )

        if not insights:
            insights.append("No correlations found across available tool data")

        return insights

    # ── Normalizers ──

    def _normalize_nmap(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize nmap parser output to common format."""
        items = []
        for host in data.get("hosts", []):
            for port in host.get("ports", []):
                items.append({
                    "title": f"Open Port: {port['protocol']}/{port['port']}",
                    "name": f"{port['service']} ({port.get('version', '')})",
                    "severity": "info",
                    "url": f"{port['protocol']}://{host['ip']}:{port['port']}",
                    "endpoint": host["ip"],
                    "description": f"Port {port['port']}/{port['protocol']}: "
                                   f"{port.get('product', port['service'])} "
                                   f"{port.get('version', '')}",
                    "evidence": json.dumps(port),
                    "service": port["service"],
                    "port": port["port"],
                    "version": port.get("version", ""),
                    "remediation": f"Review if {port['port']}/{port['protocol']} should be publicly accessible",
                })
        return items

    def _normalize_msf(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize Metasploit results to common format."""
        items = []
        for result in results:
            items.append({
                "title": f"MSF Module: {result.get('module', 'unknown')}",
                "name": result.get("module", "unknown"),
                "severity": "high" if result.get("status") == "completed" else "medium",
                "output": result.get("output", ""),
                "endpoint": "",
                "findings": result.get("findings", []),
                "evidence": result.get("output", "")[:500],
                "description": f"Module {result.get('module', '?')} "
                               f"({result.get('status', '?')})",
                "remediation": "Verify findings and apply vendor patches",
            })
        return items

    def _normalize_sqlmap(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize SQLmap results to common format."""
        items = []
        for task in tasks:
            for finding in task.get("findings", []):
                items.append({
                    "title": finding.get("title", "SQL Injection"),
                    "name": f"SQLi: {finding.get('parameter', '?')}",
                    "severity": finding.get("severity", "high"),
                    "url": finding.get("url", task.get("url", "")),
                    "endpoint": task.get("url", ""),
                    "description": f"SQL injection in '{finding.get('parameter', '?')}' "
                                   f"via {finding.get('technique', '?')}",
                    "evidence": f"Payload: {finding.get('payload', '')[:300]}",
                    "parameter": finding.get("parameter", ""),
                    "technique": finding.get("technique", ""),
                    "remediation": "Use parameterized queries and input validation",
                })
        return items
