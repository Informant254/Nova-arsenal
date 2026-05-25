#!/usr/bin/env python3
import json, time, re, requests, base64, os
from datetime import datetime

class NovaAuthenticatedScanner:
    def __init__(self, token):
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "Nova/3.0",
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"Bearer {token}",
        })
        self.findings = []
        self.queries = {
            "command_injection": {"q": "subprocess extension:py", "cwe": "CWE-78", "cvss": "9.8"},
            "sql_injection": {"q": "execute extension:py", "cwe": "CWE-89", "cvss": "9.8"},
            "insecure_pickle": {"q": "pickle.loads extension:py", "cwe": "CWE-502", "cvss": "9.8"},
        }
        self.targets = ["python/cpython", "django/django", "openssl/openssl", "nodejs/node"]

    def scan(self, repo):
        print(f"\n🔍 {repo}")
        for vuln, data in self.queries.items():
            q = f"{data['q']} repo:{repo}"
            try:
                r = self.s.get("https://api.github.com/search/code", params={"q": q, "per_page": 3}, timeout=30)
                if r.status_code == 200:
                    items = r.json().get("items", [])
                    if items:
                        print(f"   📄 [{vuln}] {len(items)} matches")
                        for item in items[:2]:
                            try:
                                cr = self.s.get(item["url"], timeout=10)
                                if cr.status_code == 200:
                                    content = base64.b64decode(cr.json().get("content","")).decode("utf-8", errors="ignore")
                                    f = {"repo": repo, "file": item["path"], "type": vuln, "cwe": data["cwe"], "cvss": data["cvss"], "url": item["html_url"], "code": content[:200]}
                                    self.findings.append(f)
                                    print(f"      📁 {item['path']}")
                            except: pass
                elif r.status_code == 403:
                    print("   ⚠️ Rate limited")
                    time.sleep(30)
            except Exception as e:
                print(f"   ❌ {str(e)[:60]}")
            time.sleep(2)

    def run(self):
        print("🦅 NOVA AUTHENTICATED SCANNER")
        for repo in self.targets:
            self.scan(repo)
        
        total = len(self.findings)
        critical = [f for f in self.findings if float(f["cvss"]) >= 9.0]
        
        print(f"\n{'='*50}")
        print(f"Repos: {len(self.targets)} | Findings: {total} | Critical: {len(critical)}")
        
        if self.findings:
            for f in self.findings[:10]:
                print(f"🔥 [{f['type']}] {f['repo']}/{f['file']}")
                print(f"   {f['cwe']} | CVSS {f['cvss']} | {f['url']}")
        
        with open("nova_auth_scan_results.json", "w") as f:
            json.dump({"findings": self.findings, "total": total}, f, indent=2)
        print("\n📁 Report: nova_auth_scan_results.json")

if __name__ == "__main__":
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        token = input("GitHub token: ").strip()
    NovaAuthenticatedScanner(token).run()
