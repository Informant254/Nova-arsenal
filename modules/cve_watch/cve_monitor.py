"""
Nova Arsenal — CVE Monitor Module
Searches the locally cloned windows-kernel-exploits, trickest/cve, and
nomi-sec/PoC-in-GitHub repositories for relevant CVEs by keyword.
Integrates with the API server tracker via HTTP.
"""

import os
import re
import json
from pathlib import Path
from typing import List, Optional
import requests


EXPLOIT_REPOS = [
    "windows-kernel-exploits",
    "RoguePlanet",
    "GreatXML",
    "herpaderping",
    "ByePg",
    "KernelForge",
    "Certify",
    "WubbabooMark",
]

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class CVEMonitor:
    def __init__(self, base_dir: Optional[str] = None):
        # Try to find cloned_repos relative to this file or cwd
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            candidates = [
                Path(__file__).parents[3] / "cloned_repos",
                Path.cwd() / "cloned_repos",
                Path.cwd().parent / "cloned_repos",
            ]
            self.base_dir = next((p for p in candidates if p.exists()), Path("cloned_repos"))

    def search_local(self, keywords: List[str] = None) -> List[dict]:
        """
        Walk all cloned exploit repos and surface CVEs + files matching keywords.
        """
        keywords = keywords or ["Defender", "BitLocker", "SYSTEM", "LPE", "TOCTOU", "privilege"]
        kw_lower = [k.lower() for k in keywords]
        findings = []

        print(f"\n[*] CVE Monitor — scanning {self.base_dir}\n")
        print(f"    Keywords: {', '.join(keywords)}\n")

        for repo in EXPLOIT_REPOS:
            repo_path = self.base_dir / repo
            if not repo_path.exists():
                continue

            repo_hits = []
            for fpath in repo_path.rglob("*"):
                if not fpath.is_file():
                    continue
                if fpath.suffix not in (".md", ".txt", ".py", ".cpp", ".c", ".h", ".cs", ".json"):
                    continue
                try:
                    content = fpath.read_text(errors="ignore")
                except Exception:
                    continue

                cves = CVE_PATTERN.findall(content)
                matched_kw = [kw for kw in kw_lower if kw in content.lower()]
                if cves or matched_kw:
                    repo_hits.append({
                        "file": str(fpath.relative_to(self.base_dir)),
                        "cves": list(set(cves)),
                        "keywords": matched_kw,
                    })

            if repo_hits:
                print(f"  📦 {repo}")
                for h in repo_hits[:8]:
                    cve_str = ", ".join(h["cves"]) if h["cves"] else "—"
                    kw_str  = ", ".join(h["keywords"]) if h["keywords"] else "—"
                    print(f"     {h['file']}")
                    print(f"       CVEs: {cve_str} | Keywords: {kw_str}")
                findings.extend(repo_hits)
                print()

        print(f"[=] Done. {len(findings)} relevant files found across {len(EXPLOIT_REPOS)} repos.\n")
        return findings

    def query_tracker_api(self, api_base: str = "http://localhost:8080") -> dict:
        """
        Hit the Nova API tracker endpoint to get the latest MSNightmare repo state.
        """
        try:
            r = requests.get(f"{api_base}/api/tracker/repos", timeout=5)
            data = r.json()
            print(f"\n[*] Tracker API — @{data['user']} | {len(data['repos'])} repos tracked")
            for repo in data["repos"]:
                status = "✓ cloned" if repo["cloned"] else "○ pending"
                print(f"    [{status}] {repo['name']} ★{repo['stars']} — {repo['description'] or '(no desc)'}")
            return data
        except Exception as e:
            print(f"[!] Tracker API unreachable: {e}")
            return {}

    def export_sarif(self, findings: List[dict], path: str = "nova_cve_findings.sarif"):
        """
        Export findings in SARIF format for IDE integration.
        """
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Nova CVE Monitor", "version": "2.0"}},
                "results": [
                    {
                        "ruleId": cve,
                        "message": {"text": f"CVE reference found in {f['file']}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]}}}],
                    }
                    for f in findings
                    for cve in (f.get("cves") or ["NOVA-KEYWORD-HIT"])
                ]
            }]
        }
        with open(path, "w") as out:
            json.dump(sarif, out, indent=2)
        print(f"[+] SARIF report written to {path}")
