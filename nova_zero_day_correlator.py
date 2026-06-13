#!/usr/bin/env python3
"""
NOVA ZERO-DAY CORRELATOR v1.0
Correlates discovered findings against live CVE feeds:
NVD (NIST), GitHub Security Advisories, and OSV.dev.
Surfaces recently-disclosed vulnerabilities affecting the target's tech stack.
"""
import json, re, os, urllib.request, urllib.error
from typing import Dict, List
from datetime import datetime, timedelta

NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API   = "https://api.osv.dev/v1/query"
GHSA_API  = "https://api.github.com/advisories"

TECH_CVE_MAP = {
    "express":     ["CVE-2024-29041","CVE-2022-24999"],
    "lodash":      ["CVE-2021-23337","CVE-2020-8203","CVE-2019-10744"],
    "axios":       ["CVE-2023-45857","CVE-2021-3749"],
    "jsonwebtoken":["CVE-2022-23529","CVE-2022-23539"],
    "node":        ["CVE-2024-22019","CVE-2023-32002","CVE-2023-30588"],
    "react":       [],
    "django":      ["CVE-2023-43665","CVE-2023-41164","CVE-2023-36053"],
    "flask":       ["CVE-2023-30861","CVE-2018-1000656"],
    "spring":      ["CVE-2022-22965","CVE-2022-22963","CVE-2021-22053"],
    "log4j":       ["CVE-2021-44228","CVE-2021-45046","CVE-2021-44832"],
    "wordpress":   ["CVE-2024-4358","CVE-2023-2745"],
    "nginx":       ["CVE-2024-24989","CVE-2023-44487"],
    "apache":      ["CVE-2024-38476","CVE-2021-41773","CVE-2021-42013"],
    "jquery":      ["CVE-2020-11022","CVE-2019-11358"],
    "openssl":     ["CVE-2022-0778","CVE-2023-0286","CVE-2022-1292"],
    "postgres":    ["CVE-2023-5869","CVE-2023-2454"],
    "mysql":       ["CVE-2024-21013","CVE-2023-22114"],
    "redis":       ["CVE-2023-28856","CVE-2022-24736"],
    "mongodb":     ["CVE-2023-2650"],
    "kubernetes":  ["CVE-2023-5528","CVE-2023-3955","CVE-2022-3294"],
    "docker":      ["CVE-2024-21626","CVE-2023-28840","CVE-2021-21284"],
}

TECH_DETECT_PATTERNS = {
    "express":     [r'"express"\s*:', r"require\('express'\)"],
    "lodash":      [r'"lodash"\s*:', r"require\('lodash'\)"],
    "axios":       [r'"axios"\s*:', r"require\('axios'\)"],
    "jsonwebtoken":[r'"jsonwebtoken"\s*:', r"require\('jsonwebtoken'\)"],
    "node":        [r'"node"\s*:', r"process\.version"],
    "django":      [r"from django", r"import django"],
    "flask":       [r"from flask", r"import flask"],
    "spring":      [r"springframework", r"@SpringBootApplication"],
    "log4j":       [r"import org\.apache\.logging\.log4j"],
    "jquery":      [r'"jquery"\s*:', r"\$\(document\)\.ready"],
    "nginx":       [r"nginx", r"upstream {"],
    "apache":      [r"<VirtualHost", r"mod_rewrite"],
    "postgres":    [r"postgres|postgresql", r"pg\.connect"],
    "mysql":       [r"mysql\.createConnection", r"import mysql"],
    "redis":       [r"redis\.createClient", r"import redis"],
    "mongodb":     [r"mongoose\.connect", r"MongoClient"],
    "kubernetes":  [r"apiVersion:", r"kind: Deployment"],
    "docker":      [r"FROM ", r"EXPOSE ", r"docker-compose"],
    "react":       [r'"react"\s*:', r"import React"],
    "openssl":     [r"openssl", r"require\('tls'\)"],
}


def _fetch_nvd_recent(days: int = 30) -> List[Dict]:
    """Fetch recent CRITICAL CVEs from NVD v2 API with proper date format, headers, and retry."""
    import urllib.parse, time as _time
    now   = datetime.utcnow()
    since = (now - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000") + "+00:00"
    until = now.strftime("%Y-%m-%dT23:59:59.999") + "+00:00"
    params = {
        "pubStartDate":    since,
        "pubEndDate":      until,
        "resultsPerPage":  "100",
        "cvssV3Severity":  "CRITICAL",
    }
    api_key = os.environ.get("NVD_API_KEY", "")
    headers = {
        "Accept":     "application/json",
        "User-Agent": "Nova-Arsenal/2.0 (Bug Bounty Research; github.com/Informant254/Nova-arsenal)",
    }
    if api_key:
        headers["apiKey"] = api_key
    url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
            vulns = []
            for item in data.get("vulnerabilities", []):
                cve   = item.get("cve", {})
                cid   = cve.get("id", "")
                desc  = " ".join(d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en")[:200]
                score = 0.0
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    try:
                        score = cve["metrics"][metric_key][0]["cvssData"]["baseScore"]
                        break
                    except Exception:
                        pass
                vulns.append({"cve_id": cid, "description": desc, "cvss": score, "source": "NVD"})
            print(f"  ✅ NVD API: {len(vulns)} recent CRITICAL CVEs fetched (last {days}d)")
            return vulns
        except urllib.error.HTTPError as e:
            print(f"  ⚠️  NVD API HTTP {e.code} (attempt {attempt+1}/3): {e.reason}")
            if e.code in (403, 429):
                _time.sleep(6 * (attempt + 1))
            elif e.code == 404:
                print("  ⚠️  NVD 404 — falling back to OSV-only mode")
                return []
        except Exception as e:
            print(f"  ⚠️  NVD API error (attempt {attempt+1}/3): {e}")
            _time.sleep(3)
    return []


def _fetch_osv_for_package(pkg: str, ecosystem: str = "npm") -> List[Dict]:
    eco_map = {"npm":"npm","pypi":"PyPI","go":"Go","maven":"Maven"}
    try:
        payload = json.dumps({"package":{"name":pkg,"ecosystem":eco_map.get(ecosystem,ecosystem)}}).encode()
        req = urllib.request.Request(OSV_API, data=payload,
            headers={"Content-Type":"application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        results = []
        for v in data.get("vulns",[])[:5]:
            results.append({
                "cve_id": v.get("id",""), "description": v.get("summary","")[:150],
                "cvss": 0, "source": "OSV", "package": pkg, "ecosystem": ecosystem,
                "aliases": v.get("aliases",[]),
            })
        return results
    except: return []


def _detect_tech_stack(directory: str) -> List[str]:
    detected = []
    text_sample = ""
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in (".git","node_modules","dist","build")]
        for fname in files[:50]:
            try:
                text_sample += open(os.path.join(root,fname), encoding="utf-8", errors="ignore").read(2000)
            except: pass
    for tech, patterns in TECH_DETECT_PATTERNS.items():
        for p in patterns:
            if re.search(p, text_sample, re.IGNORECASE):
                detected.append(tech)
                break
    return list(set(detected))


class NovaZeroDayCorrelator:
    def __init__(self):
        self.findings: List[Dict] = []

    def correlate(self, directory: str = ".", findings: List[Dict] = None) -> List[Dict]:
        print(f"\n🌐 NOVA ZERO-DAY CORRELATOR — live CVE correlation")
        print("=" * 60)

        tech_stack = _detect_tech_stack(directory)
        print(f"  🔍 Detected tech stack: {', '.join(tech_stack) or 'unknown'}")

        all_cve_findings = []

        # Correlate against known CVE map for detected technologies
        for tech in tech_stack:
            cves = TECH_CVE_MAP.get(tech, [])
            for cve_id in cves:
                all_cve_findings.append({
                    "type": "Known CVE — Detected Technology",
                    "severity": "HIGH",
                    "tech": tech,
                    "cve_id": cve_id,
                    "description": f"Technology '{tech}' has known CVE: {cve_id}",
                    "source": "nova_known_map",
                    "action": f"Check if {tech} version in use is patched for {cve_id}",
                })
            # Live OSV query for this package
            eco = "npm" if tech in ("express","lodash","axios","jsonwebtoken","jquery","react") else "pypi"
            osv_results = _fetch_osv_for_package(tech, eco)
            for r in osv_results:
                all_cve_findings.append({
                    "type": "Live OSV Advisory",
                    "severity": "HIGH",
                    "tech": tech,
                    "cve_id": r.get("cve_id",""),
                    "description": r.get("description",""),
                    "source": "OSV.dev",
                    "aliases": r.get("aliases",[]),
                })

        # Fetch recent critical CVEs from NVD
        print(f"  📡 Fetching recent CRITICAL CVEs from NVD (last 30 days)...")
        recent_nvd = _fetch_nvd_recent(30)
        for vuln in recent_nvd[:10]:
            # Try to correlate with detected tech
            relevant_tech = []
            for tech in tech_stack:
                if tech.lower() in vuln.get("description","").lower():
                    relevant_tech.append(tech)
            if relevant_tech:
                all_cve_findings.append({
                    "type": "Recent NVD CVE — Matches Tech Stack",
                    "severity": "CRITICAL",
                    "cve_id": vuln["cve_id"],
                    "cvss": vuln["cvss"],
                    "description": vuln["description"],
                    "relevant_tech": relevant_tech,
                    "source": "NVD",
                })

        # Correlate with existing findings by vuln type
        if findings:
            for f in findings:
                vuln_type = str(f.get("type","")).lower()
                if "sql" in vuln_type:
                    all_cve_findings.append({"type": "CVE Correlation", "severity": "HIGH",
                        "description": "SQL injection finding correlates with CWE-89 — check ORM/DB version CVEs",
                        "cve_id": "CWE-89", "source": "correlation"})
                elif "deserialization" in vuln_type:
                    all_cve_findings.append({"type": "CVE Correlation", "severity": "CRITICAL",
                        "description": "Insecure deserialization — check Java/Python version for deserialization CVEs",
                        "cve_id": "CWE-502", "source": "correlation"})

        # Deduplicate
        seen = set()
        deduped = []
        for f in all_cve_findings:
            key = f.get("cve_id","") + f.get("description","")[:30]
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        self.findings = deduped
        print(f"\n  📊 CVE Correlation: {len(deduped)} advisories | {len(recent_nvd)} recent NVD hits")
        for f in deduped[:5]:
            icon = "🔴" if f["severity"]=="CRITICAL" else "🟠"
            print(f"  {icon} [{f['severity']}] {f.get('cve_id','')} — {f['description'][:70]}")
        return deduped

    def save(self, path):
        with open(path,"w") as f:
            json.dump({"generated":datetime.now().isoformat(),"findings":self.findings},f,indent=2)
        print(f"  💾 CVE correlation report → {path}")


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv)>1 else "."
    c = NovaZeroDayCorrelator()
    c.correlate(d); c.save("nova_zero_day_report.json")
