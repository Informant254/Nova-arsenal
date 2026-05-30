#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   📋 NOVA REPORT v1.0 — BUG BOUNTY REPORT GENERATOR            ║
║                                                                  ║
║   Generates professional reports after every hunt:             ║
║   • HTML  — standalone, shareable, colour-coded by severity    ║
║   • Markdown — for GitHub, Notion, HackerOne submission        ║
║   • JSON  — machine-readable, for pipelines                    ║
║                                                                  ║
║   Includes per-finding:                                         ║
║   • CVSS score (calculated automatically)                      ║
║   • Reproduction steps                                          ║
║   • Impact analysis                                             ║
║   • Remediation advice                                          ║
║   • HackerOne / Bugcrowd submission-ready format               ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import os
import sys
import hashlib
from datetime import datetime
from typing import Dict, List, Optional


WORKSPACE   = os.path.expanduser("~/nova_workspace")
REPORTS_DIR = os.path.join(WORKSPACE, "reports")

SEVERITY_COLOUR = {
    "critical": "#dc3545",
    "high":     "#fd7e14",
    "medium":   "#ffc107",
    "low":      "#0dcaf0",
    "info":     "#6c757d",
}

SEVERITY_CVSS_RANGE = {
    "critical": (9.0, 10.0),
    "high":     (7.0, 8.9),
    "medium":   (4.0, 6.9),
    "low":      (0.1, 3.9),
    "info":     (0.0, 0.0),
}

REMEDIATION = {
    "sql injection":          "Use parameterised queries / prepared statements. Never concatenate user input into SQL. Apply least-privilege DB accounts.",
    "xss":                    "Encode all user-controlled output (HTML entity encoding). Use a Content Security Policy (CSP) header. Use modern framework auto-escaping.",
    "cross-site scripting":   "Encode all user-controlled output. Implement strict CSP. Validate and sanitise all inputs server-side.",
    "ssrf":                   "Whitelist allowed outbound hosts. Disable internal network access from application servers. Use a separate egress proxy.",
    "ssti":                   "Never pass user input to template engines unsanitised. Use sandboxed template execution. Switch to logic-less templates where possible.",
    "xxe":                    "Disable external entity processing in XML parsers. Use JSON where possible. Apply XML schema validation.",
    "open redirect":          "Validate redirect targets against a whitelist. Never reflect user-supplied URLs directly.",
    "idor":                   "Implement object-level authorization checks on every request. Use indirect references (tokens) instead of sequential IDs.",
    "rce":                    "Never pass user input to shell commands. Use parameterised system calls. Apply strict input validation and sandboxing.",
    "path traversal":         "Canonicalise file paths and validate against a whitelist root. Never expose raw filesystem paths to users.",
    "broken authentication":  "Implement rate limiting, account lockout, MFA. Use secure session management (HttpOnly, Secure, SameSite cookies).",
    "cors":                   "Define explicit CORS origin whitelists. Never reflect the Origin header unconditionally. Avoid credentials with wildcard origins.",
    "csrf":                   "Use SameSite=Strict cookies. Implement synchroniser token pattern or double-submit cookies.",
    "http smuggling":         "Use HTTP/2 end-to-end or normalise Content-Length vs. Transfer-Encoding. Update reverse proxies and load balancers.",
    "subdomain takeover":     "Implement monitoring for dangling DNS records. Remove CNAME records pointing to deprovisioned cloud services immediately.",
    "information disclosure": "Remove verbose error messages in production. Audit HTTP response headers. Review backup/config files exposed publicly.",
    "jwt":                    "Use strong algorithms (RS256, ES256). Validate algorithm header server-side. Implement key rotation. Check expiry claims.",
    "default":                "Review the affected component's security documentation. Apply principle of least privilege. Consider a thorough code review.",
}


def _cvss_estimate(severity: str, has_auth: bool = False) -> float:
    lo, hi = SEVERITY_CVSS_RANGE.get(severity.lower(), (0.0, 0.0))
    if lo == hi:
        return lo
    base = (lo + hi) / 2
    return round(base - (0.5 if has_auth else 0), 1)


def _find_remediation(vuln_type: str) -> str:
    vl = vuln_type.lower()
    for key, advice in REMEDIATION.items():
        if key in vl:
            return advice
    return REMEDIATION["default"]


def _finding_id(finding: Dict) -> str:
    raw = f"{finding.get('name','')}{finding.get('url','')}{finding.get('payload','')}"
    return "NOVA-" + hashlib.md5(raw.encode()).hexdigest()[:6].upper()


# ── HTML REPORT ───────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nova Hunt Report — {target}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; line-height: 1.6; }}
    .header {{ background: linear-gradient(135deg, #161b22 0%, #21262d 100%); padding: 40px; border-bottom: 1px solid #30363d; }}
    .header h1 {{ font-size: 2rem; color: #58a6ff; margin-bottom: 8px; }}
    .header .meta {{ color: #8b949e; font-size: 0.9rem; }}
    .header .meta span {{ margin-right: 20px; }}
    .summary {{ display: flex; gap: 16px; padding: 32px 40px; flex-wrap: wrap; }}
    .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px 28px; min-width: 140px; text-align: center; }}
    .stat-card .num {{ font-size: 2.2rem; font-weight: 700; }}
    .stat-card .label {{ font-size: 0.8rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }}
    .stat-card.critical .num {{ color: #f85149; }}
    .stat-card.high     .num {{ color: #fb8f44; }}
    .stat-card.medium   .num {{ color: #e3b341; }}
    .stat-card.low      .num {{ color: #39d353; }}
    .stat-card.info     .num {{ color: #8b949e; }}
    .findings {{ padding: 0 40px 40px; }}
    .findings h2 {{ font-size: 1.3rem; margin-bottom: 20px; color: #e6edf3; padding-top: 20px; }}
    .finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
    .finding-header {{ display: flex; align-items: center; padding: 16px 20px; cursor: pointer; gap: 12px; }}
    .severity-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #fff; }}
    .badge-critical {{ background: #da3633; }}
    .badge-high     {{ background: #bd5b00; }}
    .badge-medium   {{ background: #9e6a03; color: #fff; }}
    .badge-low      {{ background: #1f6feb; }}
    .badge-info     {{ background: #30363d; }}
    .finding-header h3 {{ flex: 1; font-size: 1rem; }}
    .finding-header .cvss {{ font-size: 0.85rem; color: #8b949e; margin-left: auto; }}
    .finding-header .fid {{ font-size: 0.75rem; color: #6e7681; font-family: monospace; }}
    .finding-body {{ padding: 20px; border-top: 1px solid #21262d; }}
    .finding-body .section {{ margin-bottom: 16px; }}
    .finding-body .section h4 {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; color: #8b949e; margin-bottom: 6px; }}
    .finding-body .section p {{ color: #c9d1d9; font-size: 0.9rem; }}
    code {{ background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 2px 6px; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.85rem; color: #79c0ff; }}
    pre {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 14px; overflow-x: auto; font-size: 0.83rem; color: #79c0ff; white-space: pre-wrap; word-break: break-all; }}
    .tag {{ display: inline-block; background: #21262d; border: 1px solid #30363d; border-radius: 4px; padding: 2px 8px; font-size: 0.75rem; color: #8b949e; margin-right: 6px; }}
    .footer {{ text-align: center; padding: 24px; color: #6e7681; font-size: 0.8rem; border-top: 1px solid #21262d; }}
    .tools-used {{ padding: 0 40px 20px; }}
    .tools-used h2 {{ font-size: 1.1rem; margin-bottom: 12px; color: #8b949e; }}
    @media (max-width: 600px) {{ .summary {{ flex-direction: column; }} .header {{ padding: 24px; }} .findings {{ padding: 0 16px 24px; }} }}
  </style>
</head>
<body>
  <div class="header">
    <h1>🦅 Nova Hunt Report</h1>
    <div class="meta">
      <span>🎯 Target: <strong>{target}</strong></span>
      <span>📅 {date}</span>
      <span>⏱ Duration: {duration}</span>
      <span>🔧 Mission: {mission}</span>
    </div>
  </div>

  <div class="summary">
    <div class="stat-card" style="border-left: 3px solid #58a6ff;">
      <div class="num" style="color:#58a6ff;">{total}</div>
      <div class="label">Total</div>
    </div>
    <div class="stat-card critical"><div class="num">{n_critical}</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="num">{n_high}</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="num">{n_medium}</div><div class="label">Medium</div></div>
    <div class="stat-card low"><div class="num">{n_low}</div><div class="label">Low</div></div>
    <div class="stat-card info"><div class="num">{n_info}</div><div class="label">Info</div></div>
  </div>

  <div class="findings">
    <h2>Findings</h2>
    {findings_html}
  </div>

  <div class="tools-used">
    <h2>Tools used</h2>
    <p>{tools_str}</p>
  </div>

  <div class="footer">
    Generated by Nova Arsenal &nbsp;•&nbsp; {date} &nbsp;•&nbsp; <em>For authorised security testing only</em>
  </div>
</body>
</html>"""

FINDING_HTML = """
  <div class="finding">
    <div class="finding-header">
      <span class="severity-badge badge-{sev_lower}">{severity}</span>
      <h3>{name}</h3>
      <span class="cvss">CVSS {cvss}</span>
      <span class="fid">{fid}</span>
    </div>
    <div class="finding-body">
      <div class="section">
        <h4>Affected URL</h4>
        <code>{url}</code>
      </div>
      {param_section}
      {payload_section}
      <div class="section">
        <h4>Description</h4>
        <p>{description}</p>
      </div>
      <div class="section">
        <h4>Reproduction Steps</h4>
        <pre>{repro}</pre>
      </div>
      <div class="section">
        <h4>Impact</h4>
        <p>{impact}</p>
      </div>
      <div class="section">
        <h4>Remediation</h4>
        <p>{remediation}</p>
      </div>
      <div class="section">
        <span class="tag">{tool_tag}</span>
        <span class="tag">{vuln_type}</span>
      </div>
    </div>
  </div>"""


def _build_html(target: str, findings: List[Dict], meta: Dict) -> str:
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity","info").lower(), 5))

    counts = {s: 0 for s in ("critical","high","medium","low","info")}
    for f in sorted_findings:
        s = f.get("severity","info").lower()
        counts[s] = counts.get(s, 0) + 1

    findings_html = ""
    for f in sorted_findings:
        sev      = f.get("severity","info").lower()
        name     = f.get("name") or f.get("type") or "Unknown Finding"
        url      = f.get("url") or f.get("endpoint") or target
        param    = f.get("parameter") or f.get("param") or ""
        payload  = f.get("payload") or ""
        desc     = f.get("description") or f.get("detail") or f"A {sev} severity {name} was detected."
        tool     = f.get("tool") or f.get("technique") or "nova"
        vuln_t   = f.get("type") or name
        cvss     = f.get("cvss") or _cvss_estimate(sev)
        fid      = _finding_id(f)

        # Impact by severity
        impact_map = {
            "critical": "Full compromise possible. Attacker may gain complete control over affected system, extract all data, or pivot to internal networks.",
            "high":     "Significant security impact. Sensitive data exposure, authentication bypass, or unauthorized privilege escalation possible.",
            "medium":   "Moderate security impact. May allow limited data access, user-level compromise, or denial of service.",
            "low":      "Minor security impact. Limited attack surface but contributes to attack chain.",
            "info":     "Informational finding. No immediate exploitability but may assist attackers in reconnaissance.",
        }
        impact = f.get("impact") or impact_map.get(sev, "")
        remediation = f.get("remediation") or _find_remediation(name + " " + vuln_t)

        # Build repro steps
        repro_steps = f.get("reproduction_steps") or (
            f"1. Navigate to: {url}\n"
            f"2. Identify parameter: {param or '[parameter]'}\n"
            f"3. Inject payload: {payload or '[payload]'}\n"
            f"4. Observe the vulnerable response"
        )

        param_section = f'<div class="section"><h4>Parameter</h4><code>{param}</code></div>' if param else ""
        payload_section = f'<div class="section"><h4>Payload</h4><pre>{payload}</pre></div>' if payload else ""

        findings_html += FINDING_HTML.format(
            sev_lower=sev, severity=sev.upper(), name=name, url=url,
            param_section=param_section, payload_section=payload_section,
            description=desc, repro=repro_steps, impact=impact,
            remediation=remediation, tool_tag=f"tool:{tool}", vuln_type=vuln_t,
            cvss=cvss, fid=fid,
        )

    tools_used = meta.get("tools_used") or []
    return HTML_TEMPLATE.format(
        target=target,
        date=meta.get("date", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")),
        duration=meta.get("duration", "N/A"),
        mission=meta.get("mission", "Bug bounty hunt"),
        total=len(findings),
        n_critical=counts["critical"],
        n_high=counts["high"],
        n_medium=counts["medium"],
        n_low=counts["low"],
        n_info=counts["info"],
        findings_html=findings_html or "<p style='color:#8b949e;padding:20px'>No findings recorded.</p>",
        tools_str=" &nbsp;•&nbsp; ".join(f'<span class="tag">{t}</span>' for t in tools_used) or "N/A",
    )


# ── MARKDOWN REPORT ───────────────────────────────────────────────

def _build_markdown(target: str, findings: List[Dict], meta: Dict) -> str:
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity","info").lower(), 5))

    counts = {s: 0 for s in ("critical","high","medium","low","info")}
    for f in sorted_findings:
        s = f.get("severity","info").lower()
        counts[s] = counts.get(s, 0) + 1

    sev_icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}

    lines = [
        f"# 🦅 Nova Hunt Report",
        f"",
        f"**Target:** `{target}`  ",
        f"**Date:** {meta.get('date', datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))}  ",
        f"**Duration:** {meta.get('duration', 'N/A')}  ",
        f"**Mission:** {meta.get('mission', 'Bug bounty hunt')}  ",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {counts['critical']} |",
        f"| 🟠 High     | {counts['high']} |",
        f"| 🟡 Medium   | {counts['medium']} |",
        f"| 🔵 Low      | {counts['low']} |",
        f"| ⚪ Info     | {counts['info']} |",
        f"| **Total**   | **{len(findings)}** |",
        f"",
        f"---",
        f"",
        f"## Findings",
        f"",
    ]

    for i, f in enumerate(sorted_findings, 1):
        sev    = f.get("severity","info").lower()
        name   = f.get("name") or f.get("type") or "Unknown Finding"
        url    = f.get("url") or f.get("endpoint") or target
        param  = f.get("parameter") or ""
        payload = f.get("payload") or ""
        desc   = f.get("description") or f"A {sev}-severity {name} was detected."
        tool   = f.get("tool") or "nova"
        cvss   = f.get("cvss") or _cvss_estimate(sev)
        fid    = _finding_id(f)
        remediation = f.get("remediation") or _find_remediation(name)

        lines += [
            f"### {sev_icons.get(sev,'❓')} [{fid}] {name}",
            f"",
            f"**Severity:** {sev.upper()}  ",
            f"**CVSS:** {cvss}  ",
            f"**Tool:** {tool}  ",
            f"",
            f"**Affected URL:**",
            f"```",
            url,
            f"```",
        ]
        if param:
            lines += [f"**Parameter:** `{param}`  "]
        if payload:
            lines += [f"", f"**Payload:**", f"```", payload, f"```"]

        lines += [
            f"",
            f"**Description:**  ",
            desc,
            f"",
            f"**Reproduction Steps:**",
            f"```",
            f.get("reproduction_steps") or (
                f"1. Navigate to: {url}\n"
                f"2. Identify parameter: {param or '[parameter]'}\n"
                f"3. Inject payload: {payload or '[payload]'}\n"
                f"4. Observe the vulnerable response"
            ),
            f"```",
            f"",
            f"**Remediation:**  ",
            remediation,
            f"",
            f"---",
            f"",
        ]

    return "\n".join(lines)


# ── MAIN REPORT CLASS ─────────────────────────────────────────────

class NovaReport:

    def __init__(self, target: str, findings: List[Dict], meta: Dict = None):
        self.target   = target
        self.findings = findings
        self.meta     = meta or {}
        if "date" not in self.meta:
            self.meta["date"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        os.makedirs(REPORTS_DIR, exist_ok=True)
        slug = target.replace("https://","").replace("http://","").replace("/","_").replace(":","_")[:40]
        ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.base_path = os.path.join(REPORTS_DIR, f"nova_report_{slug}_{ts}")

    def save_all(self) -> Dict[str, str]:
        paths = {}

        # HTML
        html_path = self.base_path + ".html"
        with open(html_path, "w") as f:
            f.write(_build_html(self.target, self.findings, self.meta))
        paths["html"] = html_path

        # Markdown
        md_path = self.base_path + ".md"
        with open(md_path, "w") as f:
            f.write(_build_markdown(self.target, self.findings, self.meta))
        paths["md"] = md_path

        # JSON
        json_path = self.base_path + ".json"
        with open(json_path, "w") as f:
            json.dump({
                "target":    self.target,
                "meta":      self.meta,
                "findings":  self.findings,
                "generated": datetime.utcnow().isoformat(),
                "summary": {
                    s: sum(1 for fi in self.findings if fi.get("severity","info").lower() == s)
                    for s in ("critical","high","medium","low","info")
                },
            }, f, indent=2)
        paths["json"] = json_path

        return paths

    def print_summary(self):
        counts = {}
        for f in self.findings:
            s = f.get("severity","info").lower()
            counts[s] = counts.get(s, 0) + 1
        icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}
        print(f"\n  📋 Nova Report — {self.target}")
        print(f"     Findings: {len(self.findings)}")
        for sev in ("critical","high","medium","low","info"):
            c = counts.get(sev, 0)
            if c:
                print(f"     {icons[sev]} {sev.capitalize()}: {c}")


def generate_report(
    target:   str,
    findings: List[Dict],
    duration: str = "",
    mission:  str = "",
    tools_used: List[str] = None,
) -> Dict[str, str]:
    meta = {
        "date":       datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "duration":   duration,
        "mission":    mission,
        "tools_used": tools_used or [],
    }
    report = NovaReport(target=target, findings=findings, meta=meta)
    paths  = report.save_all()
    report.print_summary()
    for fmt, path in paths.items():
        print(f"  📄 {fmt.upper()}: {path}")
    return paths


# ── ENTRY POINT ───────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, glob

    parser = argparse.ArgumentParser(description="📋 Nova Report Generator")
    parser.add_argument("--from-json",  help="Generate report from nova_agent_report_*.json")
    parser.add_argument("--target",     help="Target URL (if not in JSON)")
    parser.add_argument("--demo",       action="store_true", help="Generate a demo report")
    args = parser.parse_args()

    if args.demo:
        demo_findings = [
            {"name": "SQL Injection", "severity": "critical", "url": "https://example.com/login",
             "parameter": "username", "payload": "' OR 1=1--", "tool": "sqlmap",
             "description": "The username parameter is vulnerable to SQL injection."},
            {"name": "Reflected XSS", "severity": "high", "url": "https://example.com/search",
             "parameter": "q", "payload": "<script>alert(1)</script>", "tool": "dalfox"},
            {"name": "CORS Misconfiguration", "severity": "medium", "url": "https://example.com/api",
             "tool": "corsy", "description": "The API reflects arbitrary Origin headers."},
            {"name": "Server Version Disclosure", "severity": "info", "url": "https://example.com/",
             "tool": "httpx", "description": "Server version exposed in response headers."},
        ]
        paths = generate_report("https://example.com", demo_findings,
                                duration="12m 34s", mission="Demo report",
                                tools_used=["sqlmap","dalfox","corsy","httpx"])
        print(f"\n  Open: {paths.get('html')}")

    elif args.from_json:
        report_file = args.from_json
        if not os.path.exists(report_file):
            matches = sorted(glob.glob("nova_agent_report_*.json"), reverse=True)
            report_file = matches[0] if matches else None

        if not report_file:
            print("  ❌ No report JSON found")
            sys.exit(1)

        with open(report_file) as f:
            data = json.load(f)

        target   = args.target or data.get("target", "unknown")
        findings = []
        for phase in data.get("phases", {}).values():
            if isinstance(phase, dict):
                findings.extend(phase.get("findings", []))
        findings.extend(data.get("findings", []))

        paths = generate_report(
            target=target,
            findings=findings,
            duration=f"{data.get('duration_sec',0):.0f}s",
            mission=data.get("mission",""),
        )

    else:
        parser.print_help()
