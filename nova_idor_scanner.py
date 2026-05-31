#!/usr/bin/env python3
"""
NOVA IDOR SCANNER v1.0
Broken Object Level Authorization (BOLA/IDOR) + Privilege Escalation.
Autonomously tests every API endpoint for horizontal + vertical access
control failures — the #1 API vulnerability class (OWASP API1:2023).
"""

import json
import re
import time
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple
from datetime import datetime


IDOR_PATTERNS = [
    r'/api/\w+/(\d+)',
    r'/\w+/(\d+)(?:/|$)',
    r'/\w+/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
    r'/\w+/([a-zA-Z0-9_\-]{8,})(?:/|$)',
    r'[?&](?:id|user_id|account_id|order_id|doc_id|file_id|post_id)=(\w+)',
]

PRIVILEGE_ESCALATION_PATHS = [
    "/api/admin", "/api/admin/users", "/api/admin/settings",
    "/admin", "/admin/users", "/admin/config", "/admin/panel",
    "/api/users", "/api/users/all", "/api/accounts",
    "/api/debug", "/api/health/debug", "/api/config",
    "/api/internal", "/api/private",
    "/.env", "/.git/config", "/config.json", "/package.json",
    "/api/swagger", "/api-docs", "/swagger.json", "/openapi.json",
    "/graphql", "/graphiql", "/__schema",
]

SENSITIVE_RESPONSE_PATTERNS = [
    (r'"password"\s*:', "password field exposed"),
    (r'"token"\s*:', "token field exposed"),
    (r'"secret"\s*:', "secret field exposed"),
    (r'"ssn"\s*:', "SSN exposed"),
    (r'"credit_card"\s*:', "credit card exposed"),
    (r'"api_key"\s*:', "API key exposed"),
    (r'"admin"\s*:\s*true', "admin flag accessible"),
    (r'"role"\s*:\s*"admin"', "admin role accessible"),
    (r'"email"\s*:', "email exposed"),
]


def _request(url: str, method: str = "GET", headers: Dict = None,
             data: bytes = None, timeout: int = 8) -> Tuple[int, str, Dict]:
    try:
        req = urllib.request.Request(url, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        if data:
            req.data = data
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, {}
    except Exception as e:
        return 0, str(e), {}


class NovaIDORScanner:
    def __init__(self, base_url: str, token: str = None, token2: str = None):
        self.base_url = base_url.rstrip("/")
        self.headers1 = {"Authorization": f"Bearer {token}"} if token else {}
        self.headers2 = {"Authorization": f"Bearer {token2}"} if token2 else {}
        self.findings: List[Dict] = []

    def _full_url(self, path: str) -> str:
        return path if path.startswith("http") else self.base_url + path

    def discover_endpoints(self) -> List[str]:
        discovered = []
        discovery_paths = [
            "/api-docs", "/swagger.json", "/openapi.json", "/api/swagger",
            "/.well-known/openapi.yaml", "/docs/api.json",
        ]
        for path in discovery_paths:
            status, body, _ = _request(self._full_url(path))
            if status == 200 and body:
                try:
                    spec = json.loads(body)
                    paths = spec.get("paths", {})
                    for p in paths.keys():
                        discovered.append(p)
                    if discovered:
                        print(f"  📋 Discovered {len(discovered)} endpoints from {path}")
                        return discovered
                except Exception:
                    pass
        return []

    def test_horizontal_idor(self, path_template: str, id_range: range = range(1, 20)) -> List[Dict]:
        findings = []
        m = re.search(r'\{(\w+)\}|\:(\w+)', path_template)
        if not m:
            return []
        param_name = m.group(1) or m.group(2)
        base_path = re.sub(r'\{(\w+)\}|\:(\w+)', '{}', path_template)

        status_own, body_own, _ = _request(self._full_url(base_path.format(1)), headers=self.headers1)
        if status_own not in (200, 201):
            return []

        for oid in id_range:
            if oid == 1:
                continue
            url = self._full_url(base_path.format(oid))
            status2, body2, _ = _request(url, headers=self.headers2)
            if status2 == 200 and body2 and len(body2) > 20:
                sensitive = [desc for pat, desc in SENSITIVE_RESPONSE_PATTERNS
                             if re.search(pat, body2, re.IGNORECASE)]
                findings.append({
                    "type": "IDOR",
                    "subtype": "Horizontal Privilege Escalation",
                    "severity": "HIGH",
                    "endpoint": url,
                    "object_id": oid,
                    "status_code": status2,
                    "response_length": len(body2),
                    "sensitive_fields": sensitive,
                    "description": f"User 2 can access object {oid} belonging to user 1",
                })
                print(f"  🔴 IDOR FOUND: {url} → {status2} ({len(body2)} bytes)")
        return findings

    def test_privilege_escalation(self) -> List[Dict]:
        findings = []
        print(f"\n  🔐 Testing {len(PRIVILEGE_ESCALATION_PATHS)} privileged paths...")
        for path in PRIVILEGE_ESCALATION_PATHS:
            url = self._full_url(path)
            status_anon, body_anon, _ = _request(url)
            if status_anon in (200, 201):
                sensitive = [desc for pat, desc in SENSITIVE_RESPONSE_PATTERNS
                             if re.search(pat, body_anon, re.IGNORECASE)]
                findings.append({
                    "type": "Broken Access Control",
                    "subtype": "Unauthenticated Admin Access",
                    "severity": "CRITICAL" if "admin" in path.lower() else "HIGH",
                    "endpoint": url,
                    "status_code": status_anon,
                    "response_length": len(body_anon),
                    "sensitive_fields": sensitive,
                    "description": f"Privileged path accessible without auth: {path}",
                })
                print(f"  🔴 UNAUTH ACCESS: {path} → {status_anon}")
            elif status_anon in (403, 401) and self.headers1:
                status_auth, body_auth, _ = _request(url, headers=self.headers1)
                if status_auth == 200:
                    print(f"  ✅ Properly protected (auth required): {path}")
        return findings

    def test_parameter_tampering(self, endpoint: str, params: Dict) -> List[Dict]:
        findings = []
        tamper_values = {
            "role": ["admin", "superuser", "root", "administrator"],
            "admin": [True, 1, "true"],
            "is_admin": [True, 1, "true"],
            "user_id": [1, 2, 999],
            "account_id": [1, 0, -1],
            "privilege": ["admin", "superuser"],
            "access_level": [9, 99, 999],
        }
        for param, evil_vals in tamper_values.items():
            for evil_val in evil_vals[:2]:
                tampered = {**params, param: evil_val}
                url = self._full_url(endpoint)
                qs = urllib.parse.urlencode(tampered)
                full_url = f"{url}?{qs}"
                status, body, _ = _request(full_url, headers=self.headers2)
                if status == 200:
                    findings.append({
                        "type": "Parameter Tampering",
                        "severity": "HIGH",
                        "endpoint": full_url,
                        "param": param,
                        "value": str(evil_val),
                        "status_code": status,
                        "description": f"Parameter {param}={evil_val} accepted — potential privilege escalation",
                    })
        return findings

    def test_mass_assignment(self, endpoint: str, method: str = "PUT") -> List[Dict]:
        findings = []
        mass_assign_payloads = [
            {"role": "admin", "is_admin": True},
            {"admin": True, "privilege_level": 9},
            {"account_type": "premium", "credits": 99999},
            {"verified": True, "email_verified": True},
        ]
        for payload in mass_assign_payloads:
            status, body, _ = _request(
                self._full_url(endpoint), method=method,
                data=json.dumps(payload).encode(),
                headers={**self.headers2, "Content-Type": "application/json"}
            )
            if status in (200, 201):
                for key in payload:
                    if re.search(rf'"{key}"\s*:', body):
                        findings.append({
                            "type": "Mass Assignment",
                            "severity": "HIGH",
                            "endpoint": endpoint,
                            "payload": payload,
                            "status_code": status,
                            "description": f"Mass assignment: {key} accepted in response",
                        })
                        break
        return findings

    def run(self) -> List[Dict]:
        print(f"\n🔑 NOVA IDOR SCANNER — {self.base_url}")
        print("=" * 60)
        all_findings = []
        endpoints = self.discover_endpoints()
        all_findings.extend(self.test_privilege_escalation())
        for path in endpoints[:20]:
            for pat in IDOR_PATTERNS:
                if re.search(pat, path):
                    all_findings.extend(self.test_horizontal_idor(path))
                    break
        self.findings = all_findings
        critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
        print(f"\n  📊 IDOR Scan: {len(all_findings)} findings | {len(critical)} CRITICAL")
        return all_findings

    def save(self, path: str):
        report = {"generated": datetime.now().isoformat(), "target": self.base_url,
                  "total": len(self.findings), "findings": self.findings}
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  💾 IDOR report → {path}")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    token = sys.argv[2] if len(sys.argv) > 2 else None
    scanner = NovaIDORScanner(target, token1=token)
    scanner.run()
    scanner.save("nova_idor_report.json")
