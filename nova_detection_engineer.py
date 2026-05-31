#!/usr/bin/env python3
"""
NOVA DETECTION ENGINEER v1.0
Daybreak-style SIEM detection rule generation.
Converts confirmed vulnerability findings into detection rules for
Sigma (universal), Splunk SPL, Elastic KQL, and Suricata IDS.
"""

import json
import re
from typing import Dict, List
from datetime import datetime

SIGMA_TEMPLATES = {
    "sqli": {
        "title": "SQL Injection Attempt Detected",
        "description": "Detects SQL injection patterns in HTTP query parameters or POST bodies",
        "logsource": {"category": "webserver", "product": "apache"},
        "detection_field": "cs-uri-query|cs-uri-stem|cs-bytes",
        "patterns": ["' OR ", "1=1", "UNION SELECT", "SLEEP(", "WAITFOR DELAY", "'; DROP", "' AND "],
        "tags": ["attack.initial_access", "attack.t1190", "cwe.89"],
        "level": "high",
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS) Attempt",
        "description": "Detects XSS payloads in HTTP parameters",
        "logsource": {"category": "webserver"},
        "detection_field": "cs-uri-query|cs-bytes",
        "patterns": ["<script>", "javascript:", "onerror=", "onload=", "eval(", "alert(", "document.cookie"],
        "tags": ["attack.t1059.007", "cwe.79"],
        "level": "medium",
    },
    "path_traversal": {
        "title": "Path Traversal Attempt",
        "description": "Detects directory traversal sequences in HTTP requests",
        "logsource": {"category": "webserver"},
        "detection_field": "cs-uri-stem|cs-uri-query",
        "patterns": ["../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f", "..%5c"],
        "tags": ["attack.t1083", "cwe.22"],
        "level": "high",
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF) Attempt",
        "description": "Detects outbound requests to internal metadata endpoints",
        "logsource": {"category": "proxy"},
        "detection_field": "DestinationIp|c-uri",
        "patterns": ["169.254.169.254", "metadata.google.internal", "127.0.0.1", "0.0.0.0", "::1"],
        "tags": ["attack.t1090", "cwe.918"],
        "level": "critical",
    },
    "command_injection": {
        "title": "Command Injection Attempt",
        "description": "Detects shell metacharacters in HTTP input fields",
        "logsource": {"category": "webserver"},
        "detection_field": "cs-uri-query|cs-bytes",
        "patterns": [";ls", "|cat", "&&id", "`id`", "$(id)", ";whoami", "|whoami", "& ping"],
        "tags": ["attack.t1059", "cwe.78"],
        "level": "critical",
    },
    "open_redirect": {
        "title": "Open Redirect Attempt",
        "description": "Detects redirect parameters pointing to external domains",
        "logsource": {"category": "webserver"},
        "detection_field": "cs-uri-query",
        "patterns": ["next=http://", "redirect=http://", "url=http://", "next=//", "redirect=//"],
        "tags": ["attack.t1566.002", "cwe.601"],
        "level": "medium",
    },
    "xxe": {
        "title": "XML External Entity (XXE) Injection Attempt",
        "description": "Detects XXE payloads in XML request bodies",
        "logsource": {"category": "webserver"},
        "detection_field": "cs-bytes",
        "patterns": ["<!DOCTYPE", "<!ENTITY", "SYSTEM \"file://", "SYSTEM \"http://"],
        "tags": ["attack.t1190", "cwe.611"],
        "level": "critical",
    },
    "auth_bypass": {
        "title": "Authentication Bypass Attempt",
        "description": "Detects authentication bypass patterns in login requests",
        "logsource": {"category": "webserver"},
        "detection_field": "cs-bytes|cs-uri-query",
        "patterns": ["' OR '1'='1", "admin'--", "' OR 1=1", "\" OR \"1\"=\"1"],
        "tags": ["attack.t1078", "cwe.287"],
        "level": "high",
    },
}


def _sigma_rule(vuln_type: str, endpoint: str, finding: Dict) -> str:
    tmpl = SIGMA_TEMPLATES.get(vuln_type, SIGMA_TEMPLATES.get("sqli"))
    patterns = " | ".join(f"'*{p}*'" for p in tmpl["patterns"])
    tags_yaml = "\n".join(f"        - {t}" for t in tmpl["tags"])
    return f"""title: {tmpl['title']}
id: nova-{vuln_type}-{datetime.now().strftime('%Y%m%d')}
status: experimental
description: "{tmpl['description']} — detected on {endpoint}"
author: Nova Arsenal v4.0
date: {datetime.now().strftime('%Y/%m/%d')}
tags:
{tags_yaml}
logsource:
    category: {tmpl['logsource'].get('category', 'webserver')}
    product: {tmpl['logsource'].get('product', 'any')}
detection:
    keywords:
        - {patterns}
    condition: keywords
fields:
    - {tmpl['detection_field']}
    - c-ip
    - cs-method
    - sc-status
falsepositives:
    - Security testing
    - Automated scanners
level: {tmpl['level']}
"""


def _splunk_spl(vuln_type: str, endpoint: str, finding: Dict) -> str:
    tmpl = SIGMA_TEMPLATES.get(vuln_type, {})
    pattern_search = " OR ".join(f'uri_query="*{p}*"' for p in tmpl.get("patterns", [])[:4])
    return f"""| tstats count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Web.Web
    where Web.url="{endpoint}*"
    AND ({pattern_search})
    by Web.src Web.dest Web.url Web.status Web.http_method
| rename Web.* as *
| eval severity="{tmpl.get('level', 'high').upper()}"
| eval vuln_type="{vuln_type}"
| table firstTime lastTime src dest url status http_method severity vuln_type count
| sort -count
"""


def _elastic_kql(vuln_type: str, endpoint: str, finding: Dict) -> str:
    tmpl = SIGMA_TEMPLATES.get(vuln_type, {})
    patterns = " or ".join(f'url.query: "*{p}*"' for p in tmpl.get("patterns", [])[:4])
    return f"""(url.path: "{endpoint}*" or http.request.body.content: "*") and ({patterns})"""


def _suricata_rule(vuln_type: str, endpoint: str, finding: Dict, rule_id: int = 9000001) -> str:
    tmpl = SIGMA_TEMPLATES.get(vuln_type, {})
    level_map = {"critical": "1", "high": "2", "medium": "3"}
    priority = level_map.get(tmpl.get("level", "high"), "2")
    content_parts = "; ".join(f'content:"{p}"; nocase' for p in tmpl.get("patterns", [])[:2])
    return (
        f'alert http any any -> $HTTP_SERVERS any '
        f'(msg:"NOVA {vuln_type.upper().replace("_"," ")} ATTEMPT on {endpoint}"; '
        f'flow:established,to_server; '
        f'{content_parts}; '
        f'http.uri; '
        f'classtype:web-application-attack; '
        f'sid:{rule_id}; rev:1; '
        f'priority:{priority}; '
        f'metadata:created_at {datetime.now().strftime("%Y_%m_%d")}, nova_arsenal v4;)'
    )


class NovaDetectionEngineer:
    def __init__(self):
        self.rules: List[Dict] = []

    def generate_rules(self, findings: List[Dict]) -> List[Dict]:
        print("\n🛡  NOVA DETECTION ENGINEER — Generating SIEM rules...")
        print("=" * 60)
        rules = []
        for i, finding in enumerate(findings):
            vuln_type = (
                finding.get("type") or finding.get("vulnerability_type") or
                finding.get("attack_type") or "sqli"
            ).lower().replace(" ", "_")
            endpoint = finding.get("endpoint") or finding.get("file") or "/"
            rule = {
                "vuln_type": vuln_type,
                "endpoint": endpoint,
                "finding_ref": finding,
                "generated_at": datetime.now().isoformat(),
                "sigma": _sigma_rule(vuln_type, endpoint, finding),
                "splunk_spl": _splunk_spl(vuln_type, endpoint, finding),
                "elastic_kql": _elastic_kql(vuln_type, endpoint, finding),
                "suricata": _suricata_rule(vuln_type, endpoint, finding, 9000001 + i),
            }
            rules.append(rule)
            print(f"  ✅ {vuln_type:25s} → Sigma + Splunk SPL + Elastic KQL + Suricata")
        self.rules = rules
        print(f"\n  📊 Generated {len(rules)} detection rule sets (4 formats each)")
        return rules

    def save(self, output_path: str):
        report = {
            "generated": datetime.now().isoformat(),
            "total_rule_sets": len(self.rules),
            "formats": ["sigma", "splunk_spl", "elastic_kql", "suricata"],
            "rules": self.rules,
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        sigma_out = output_path.replace(".json", "_sigma.yml")
        with open(sigma_out, "w") as f:
            for r in self.rules:
                f.write(r["sigma"])
                f.write("\n---\n\n")
        suricata_out = output_path.replace(".json", "_suricata.rules")
        with open(suricata_out, "w") as f:
            for r in self.rules:
                f.write(r["suricata"] + "\n")
        print(f"\n  💾 Rules saved → {output_path}")
        print(f"  📄 Sigma YAML → {sigma_out}")
        print(f"  📄 Suricata rules → {suricata_out}")
        return report


if __name__ == "__main__":
    import sys
    findings_file = sys.argv[1] if len(sys.argv) > 1 else None
    if not findings_file:
        findings = [
            {"type": "sqli", "endpoint": "/rest/products/search", "param": "q"},
            {"type": "xss", "endpoint": "/profile", "param": "username"},
            {"type": "ssrf", "endpoint": "/api/fetchUrl", "param": "url"},
        ]
    else:
        with open(findings_file) as f:
            data = json.load(f)
        findings = data if isinstance(data, list) else data.get("findings", [])
    eng = NovaDetectionEngineer()
    eng.generate_rules(findings)
    eng.save("nova_detection_rules.json")
