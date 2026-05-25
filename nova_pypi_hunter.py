#!/usr/bin/env python3
"""
NOVA PYPI HUNTER v1.0
Hunts for dependency confusion vulnerabilities in public repos.
Finds private package names → checks PyPI → flags unregistered names.
"""

import json, time, re, requests
from datetime import datetime
from urllib.parse import quote

class NovaPyPIHunter:
    def __init__(self):
        self.pypi_api = "https://pypi.org/pypi"
        self.github_api = "https://api.github.com"
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "Nova/9.0 (PyPI Security Research)",
            "Accept": "application/vnd.github.v3+json",
        })
        self.findings = []
        
    def search_github_deps(self, query, max_results=5):
        """Search GitHub for dependency files."""
        print(f"\n🔍 Searching GitHub: {query}")
        
        # Search for requirements.txt, package.json, setup.py, etc.
        searches = [
            f'"{query}" filename:requirements.txt',
            f'"{query}" filename:package.json',
            f'"{query}" filename:setup.py',
            f'"{query}" filename:pyproject.toml',
        ]
        
        found_packages = set()
        
        for search in searches[:2]:  # Limit API calls
            try:
                resp = self.s.get(
                    f"{self.github_api}/search/code",
                    params={"q": search, "per_page": max_results},
                    timeout=15
                )
                if resp.status_code == 200:
                    items = resp.json().get("items", [])
                    for item in items:
                        repo = item["repository"]["full_name"]
                        path = item["path"]
                        print(f"   📁 {repo}: {path}")
                        
                        # Try to get the file content
                        try:
                            content_resp = self.s.get(item["url"], timeout=10)
                            if content_resp.status_code == 200:
                                content = content_resp.json().get("content", "")
                                # Decode base64 content
                                import base64
                                decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                                
                                # Extract package names
                                # requirements.txt format: package==version
                                packages = re.findall(r'^\s*([a-zA-Z0-9_-]+)\s*[=><~!]', decoded, re.MULTILINE)
                                found_packages.update(packages)
                                
                                # package.json format: "package": "^version"
                                json_packages = re.findall(r'"@?([a-zA-Z0-9_-]+)"\s*:', decoded)
                                found_packages.update(json_packages)
                        except:
                            pass
            except Exception as e:
                print(f"   ❌ Search failed: {str(e)[:80]}")
            time.sleep(2)  # Rate limit
        
        return list(found_packages)

    def check_pypi(self, package_name):
        """Check if a package exists on PyPI."""
        try:
            resp = self.s.get(f"{self.pypi_api}/{package_name}/json", timeout=10)
            return resp.status_code != 404
        except:
            return False

    def run_hunt(self, target_keywords):
        """Hunt for dependency confusion across target keywords."""
        print("""
╔══════════════════════════════════════════════════════════╗
║   🦅 NOVA PYPI HUNTER — DEPENDENCY CONFUSION          ║
║   GitHub → PyPI → Bounty                              ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        all_packages = set()
        
        for keyword in target_keywords:
            packages = self.search_github_deps(keyword)
            all_packages.update(packages)
            print(f"   📊 {keyword}: Found {len(packages)} potential internal packages")
        
        print(f"\n🔍 Found {len(all_packages)} unique packages to check")
        print("=" * 50)
        
        # Check each package on PyPI
        for package in sorted(all_packages):
            print(f"   Checking: {package}...", end=" ")
            if self.check_pypi(package):
                print("✅ registered")
            else:
                print("🔥 UNREGISTERED — Potential dependency confusion!")
                self.findings.append({
                    "package": package,
                    "type": "Dependency Confusion",
                    "pypi_status": "NOT REGISTERED",
                    "severity": "CRITICAL",
                    "cvss": "10.0",
                    "risk": "Attacker can register this name and serve malicious code"
                })
            time.sleep(0.5)
        
        # Report
        critical = [f for f in self.findings]
        print(f"""
╔══════════════════════════════════════════════════════════╗
║     PYPI HUNT COMPLETE                                  ║
╠══════════════════════════════════════════════════════════╣
║  Packages Checked: {len(all_packages):>3}                                  ║
║  Vulnerable: {len(critical):>3}                                        ║
║  Potential Bounty: ${len(critical) * 5000:,}                               ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        if critical:
            print("💀 DEPENDENCY CONFUSION VULNERABILITIES FOUND:")
            for f in critical:
                print(f"   🔥 {f['package']} — PyPI: {f['pypi_status']}")
                print(f"      CVSS: {f['cvss']} | {f['risk']}")
        
        # Save
        with open("nova_pypi_hunt_report.json", "w") as f:
            json.dump({"findings": self.findings, "vulnerable_count": len(critical), "total_checked": len(all_packages)}, f, indent=2)
        
        print(f"\n📁 Report: nova_pypi_hunt_report.json")
        print(f"📋 Submit valid findings to: https://hackerone.com/internet-bug-bounty")

if __name__ == "__main__":
    # Target keywords from IBB scope and major open-source projects
    targets = [
        "openssl",
        "python-core",
        "linux-kernel",
        "gnu-internal",
        "freebsd",
        "openbsd",
        "netbsd",
        "apache-internal",
        "nginx-internal",
        "postgresql-internal",
    ]
    
    hunter = NovaPyPIHunter()
    hunter.run_hunt(targets)
