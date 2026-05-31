#!/usr/bin/env python3
"""
NOVA AUDIT REPORTER v1.0
Daybreak-style enterprise audit-ready reporting.
Aggregates findings from all Nova modules into a single structured
compliance report with CVSS scores, remediation timelines, and executive summary.
"""

import json
import os
from typing import Dict, List, Optional
from datetime import datetime, timedelta


CVSS_BASE_SCORES = {
    "SQL Injection":             {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cwe": "CWE-89"},
    "Command Injection":         {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cwe": "CWE-78"},
    "XXE":                       {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "cwe": "CWE-611"},
    "Insecure Deserialization":  {"score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "cwe": "CWE-502"},
    "SSRF":                      {"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "cwe": "CWE-918"},
    "Auth Bypass":               {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "cwe": "CWE-287"},
    "Path Traversal":            {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "cwe": "CWE-22"},
    "XSS":                       {"score": 7.4, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N", "cwe": "CWE-79"},
    "Prototype Pollution":       {"score": 7.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", "cwe": "CWE-1321"},
    "Open Redirect":             {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "cwe": "CWE-601"},
    "secret_in_history":         {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "cwe": "CWE-798"},
    "secret_in_working_tree":    {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "cwe": "CWE-798"},
}

REMEDIATION_SLA = {
    "CRITICAL": 7,
    "HIGH":     30,
    "MEDIUM":   90,
    "LOW":      180,
    "INFO":     365,
}

SEVERITY_FROM_CVSS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "INFO"),
]


def _severity_from_score(score: float) -> str:
    for threshold, label in SEVERITY_FROM_CVSS:
        if score >= threshold:
            return label
    return "INFO"


def _enrich_finding(finding: Dict) -> Dict:
    vuln_type = (
        finding.get("type") or finding.get("vulnerability_type") or
        finding.get("attack_type") or finding.get("secret_type") or "Unknown"
    )
    cvss_info = CVSS_BASE_SCORES.get(vuln_type, {"score": 5.0, "vector": "N/A", "cwe": "N/A"})
    score = cvss_info["score"]
    severity = _severity_from_score(score)
    sla_days = REMEDIATION_SLA.get(severity, 90)
    due_date = (datetime.now() + timedelta(days=sla_days)).strftime("%Y-%m-%d")
    return {
        **finding,
        "cvss_score": score,
        "cvss_vector": cvss_info["vector"],
        "cwe": cvss_info["cwe"],
        "severity": severity,
        "remediation_due": due_date,
        "sla_days": sla_days,
        "vuln_type_normalized": vuln_type,
    }


class NovaAuditReporter:
    def __init__(self, org_name: str = "Target Organization", assessor: str = "Nova Arsenal v4.0"):
        self.org_name = org_name
        self.assessor = assessor
        self.all_findings: List[Dict] = []
        self.report: Dict = {}

    def load_findings(self, *finding_sources: List[Dict]):
        all_raw = []
        for source in finding_sources:
            if isinstance(source, list):
                all_raw.extend(source)
        self.all_findings = [_enrich_finding(f) for f in all_raw]
        return self

    def load_from_files(self, *paths: str):
        for path in paths:
            try:
                with open(path) as f:
                    data = json.load(f)
                items = (
                    data if isinstance(data, list)
                    else data.get("findings") or data.get("all") or
                         data.get("critical", []) + data.get("high", []) or []
                )
                self.all_findings.extend([_enrich_finding(i) for i in items])
            except Exception as e:
                print(f"  ⚠️  Could not load {path}: {e}")
        return self

    def build(self) -> Dict:
        findings = self.all_findings
        by_severity: Dict[str, List] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for f in findings:
            sev = f.get("severity", "INFO")
            by_severity.setdefault(sev, []).append(f)

        by_type: Dict[str, int] = {}
        for f in findings:
            vt = f.get("vuln_type_normalized", "Unknown")
            by_type[vt] = by_type.get(vt, 0) + 1

        risk_score = sum(
            f.get("cvss_score", 0) *
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(f.get("severity", "INFO"), 0)
            for f in findings
        )

        self.report = {
            "meta": {
                "title": f"Security Assessment Report — {self.org_name}",
                "assessor": self.assessor,
                "generated": datetime.now().isoformat(),
                "assessment_date": datetime.now().strftime("%B %d, %Y"),
                "report_version": "1.0",
                "classification": "CONFIDENTIAL",
            },
            "executive_summary": {
                "organization": self.org_name,
                "total_findings": len(findings),
                "overall_risk_score": round(risk_score, 1),
                "risk_rating": "CRITICAL" if risk_score > 100 else "HIGH" if risk_score > 50 else "MEDIUM" if risk_score > 20 else "LOW",
                "critical_count": len(by_severity["CRITICAL"]),
                "high_count": len(by_severity["HIGH"]),
                "medium_count": len(by_severity["MEDIUM"]),
                "low_count": len(by_severity["LOW"]),
                "immediate_action_required": len(by_severity["CRITICAL"]) > 0,
                "top_vuln_types": sorted(by_type.items(), key=lambda x: -x[1])[:5],
                "remediation_summary": {
                    sev: {
                        "count": len(items),
                        "sla_days": REMEDIATION_SLA.get(sev, 90),
                        "due_by": (datetime.now() + timedelta(days=REMEDIATION_SLA.get(sev, 90))).strftime("%Y-%m-%d"),
                    }
                    for sev, items in by_severity.items() if items
                },
            },
            "findings_by_severity": {
                sev: [
                    {
                        "id": f"NOVA-{i+1:04d}",
                        "type": f.get("vuln_type_normalized"),
                        "file": f.get("file") or f.get("endpoint") or "N/A",
                        "line": f.get("line") or f.get("line_num") or "N/A",
                        "cvss_score": f.get("cvss_score"),
                        "cvss_vector": f.get("cvss_vector"),
                        "cwe": f.get("cwe"),
                        "description": f.get("description") or f.get("issue") or f.get("message") or "",
                        "snippet": (f.get("snippet") or f.get("sink_code") or "")[:150],
                        "remediation_due": f.get("remediation_due"),
                        "sla_days": f.get("sla_days"),
                    }
                    for i, f in enumerate(items)
                ]
                for sev, items in by_severity.items() if items
            },
            "remediation_roadmap": [
                {
                    "priority": i + 1,
                    "severity": sev,
                    "count": len(by_severity[sev]),
                    "action": f"Remediate all {sev} findings",
                    "due_by": (datetime.now() + timedelta(days=REMEDIATION_SLA[sev])).strftime("%Y-%m-%d"),
                    "sla_days": REMEDIATION_SLA[sev],
                }
                for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
                if by_severity.get(sev)
            ],
            "compliance_notes": self._compliance_notes(by_type),
            "methodology": (
                "This assessment was conducted using Nova Arsenal v4.0 — an autonomous AI security research system. "
                "Analysis included: static source code analysis with file prioritization (Mythos-style 1-5 risk scoring), "
                "automated threat modeling, software composition analysis (SCA), git history secret scanning, "
                "sandbox-based exploit validation, and SIEM detection rule generation. "
                "All findings were triaged and enriched with CVSS 3.1 base scores."
            ),
        }
        return self.report

    def _compliance_notes(self, by_type: Dict[str, int]) -> List[str]:
        notes = []
        if "SQL Injection" in by_type:
            notes.append("PCI DSS Req 6.3.1: SQL injection vulnerabilities identified — remediate before card data scope review")
        if "XSS" in by_type:
            notes.append("OWASP ASVS L1 V5.3.3: XSS findings present — CSP headers and output encoding required")
        if "secret_in_history" in by_type or "secret_in_working_tree" in by_type:
            notes.append("SOC 2 CC6.1: Secrets found in source/history — rotate credentials immediately and implement pre-commit scanning")
        if "Auth Bypass" in by_type:
            notes.append("ISO 27001 A.9.4.2: Authentication control failures detected — review and harden access control")
        if "Path Traversal" in by_type:
            notes.append("OWASP ASVS L1 V12.3: Path traversal vulnerabilities — enforce server-side path validation")
        return notes

    def _print_summary(self):
        es = self.report.get("executive_summary", {})
        print("\n📋 NOVA AUDIT REPORT — Executive Summary")
        print("=" * 60)
        print(f"  Organization  : {self.org_name}")
        print(f"  Total Findings: {es.get('total_findings', 0)}")
        print(f"  Risk Rating   : {es.get('risk_rating', 'N/A')}")
        print(f"  Critical      : {es.get('critical_count', 0)}")
        print(f"  High          : {es.get('high_count', 0)}")
        print(f"  Medium        : {es.get('medium_count', 0)}")
        if es.get("immediate_action_required"):
            print("\n  ⚠️  IMMEDIATE ACTION REQUIRED — Critical findings present")

    def save_json(self, path: str):
        with open(path, "w") as f:
            json.dump(self.report, f, indent=2)
        print(f"  💾 JSON report → {path}")

    def save_markdown(self, path: str):
        es = self.report.get("executive_summary", {})
        meta = self.report.get("meta", {})
        lines = [
            f"# {meta.get('title', 'Security Assessment Report')}\n",
            f"**Assessor:** {meta.get('assessor')}  ",
            f"**Date:** {meta.get('assessment_date')}  ",
            f"**Classification:** {meta.get('classification')}\n",
            f"---\n",
            f"## Executive Summary\n",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Total Findings | {es.get('total_findings', 0)} |",
            f"| Overall Risk | **{es.get('risk_rating', 'N/A')}** |",
            f"| Critical | 🔴 {es.get('critical_count', 0)} |",
            f"| High | 🟠 {es.get('high_count', 0)} |",
            f"| Medium | 🟡 {es.get('medium_count', 0)} |",
            f"| Low | 🟢 {es.get('low_count', 0)} |\n",
            f"## Findings\n",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            items = self.report.get("findings_by_severity", {}).get(sev, [])
            if items:
                lines.append(f"### {sev} ({len(items)})\n")
                for item in items:
                    lines.append(f"**{item['id']}** — {item['type']} in `{item['file']}`")
                    lines.append(f"- CVSS: {item['cvss_score']} | {item['cwe']} | Due: {item['remediation_due']}")
                    if item.get("snippet"):
                        lines.append(f"```\n{item['snippet']}\n```")
                    lines.append("")
        lines.append("## Remediation Roadmap\n")
        for step in self.report.get("remediation_roadmap", []):
            lines.append(f"{step['priority']}. **{step['severity']}** — {step['count']} findings — due {step['due_by']} ({step['sla_days']} days)")
        if self.report.get("compliance_notes"):
            lines.append("\n## Compliance Notes\n")
            for note in self.report["compliance_notes"]:
                lines.append(f"- {note}")
        lines.append(f"\n---\n*{self.report.get('methodology', '')}*")
        with open(path, "w") as f:
            f.write("\n".join(lines))
        print(f"  📄 Markdown report → {path}")

    def generate(self, json_out: str = "nova_audit_report.json", md_out: str = "nova_audit_report.md"):
        self.build()
        self._print_summary()
        self.save_json(json_out)
        self.save_markdown(md_out)
        return self.report


if __name__ == "__main__":
    import sys, glob
    finding_files = sys.argv[1:] if len(sys.argv) > 1 else glob.glob("nova_*_report.json")
    reporter = NovaAuditReporter()
    reporter.load_from_files(*finding_files)
    reporter.generate()
