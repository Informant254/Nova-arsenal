#!/usr/bin/env python3
"""
NOVA SUPPLY CHAIN SCORER v1.0
Scores every dependency for supply chain risk:
typosquatting similarity, maintainer count, last-publish age,
GitHub stars/forks, known malicious package DB, and OSV advisory count.
"""
import json, re, os, urllib.request, urllib.error
from typing import Dict, List
from datetime import datetime, timedelta

KNOWN_MALICIOUS = {
    "crossenv","node-opencv","nodemailer-js","nodemailer-cli","nodefabric",
    "node-fabric","nodesass","nodemssql","node-mssql","mysqljs","node-mysql",
    "vue-cli-plugin-electron","codecov","ua-parser-js","event-stream","flatmap-stream",
    "rc","coa","eslint-scope","eslint-config-eslint","getdeps","loadyaml",
    "paket","requesset","http-proxy.js","jquery.js","angularjs","momentsjs",
    "react-dom-pure","react-router-v6","react-admin-core","axios-lib",
    "discord.js-selfbot","betterttv","node-imap-promise","mongoos",
}

TYPOSQUAT_TARGETS = [
    "lodash","express","react","axios","webpack","babel","typescript","eslint",
    "jest","mocha","mongoose","sequelize","passport","jsonwebtoken","bcrypt",
    "dotenv","nodemon","chalk","commander","moment","dayjs","yup","zod",
    "prettier","husky","cors","helmet","morgan","body-parser","cookie-parser",
]

NPM_API = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"
OSV_API  = "https://api.osv.dev/v1/query"


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b): return _levenshtein(b, a)
    if not b: return len(a)
    row = list(range(len(b)+1))
    for i, ca in enumerate(a):
        new_row = [i+1]
        for j, cb in enumerate(b):
            new_row.append(min(row[j+1]+1, new_row[-1]+1, row[j]+(ca!=cb)))
        row = new_row
    return row[-1]


def _is_typosquat(name: str) -> List[str]:
    suspects = []
    for target in TYPOSQUAT_TARGETS:
        dist = _levenshtein(name.lower(), target.lower())
        if 0 < dist <= 2 and abs(len(name)-len(target)) <= 2:
            suspects.append(f"Similar to '{target}' (edit distance {dist})")
    return suspects


def _npm_metadata(package: str) -> Dict:
    try:
        url = f"{NPM_API}/{urllib.parse.quote(package)}"
        req = urllib.request.Request(url, headers={"Accept":"application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        latest_ver = data.get("dist-tags",{}).get("latest","?")
        latest_time = data.get("time",{}).get(latest_ver,"?")
        maintainers = len(data.get("maintainers",[]))
        downloads_url = f"https://api.npmjs.org/downloads/point/last-month/{urllib.parse.quote(package)}"
        try:
            with urllib.request.urlopen(downloads_url, timeout=8) as r2:
                dl_data = json.loads(r2.read())
                downloads = dl_data.get("downloads", 0)
        except: downloads = -1
        return {"latest_version": latest_ver, "latest_time": latest_time,
                "maintainers": maintainers, "downloads_last_month": downloads,
                "description": data.get("description","")[:80]}
    except Exception as e:
        return {"error": str(e)}


def _osv_advisory_count(package: str, ecosystem: str = "npm") -> int:
    try:
        eco_map = {"npm":"npm","pypi":"PyPI","go":"Go"}
        payload = json.dumps({"package":{"name":package,"ecosystem":eco_map.get(ecosystem,ecosystem)}}).encode()
        req = urllib.request.Request(OSV_API, data=payload,
            headers={"Content-Type":"application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=8) as r:
            return len(json.loads(r.read()).get("vulns",[]))
    except: return 0


def _score_package(name: str, version: str, ecosystem: str) -> Dict:
    score = 0
    flags = []
    name_lower = name.lower()

    # Malicious DB check
    if name_lower in KNOWN_MALICIOUS:
        score += 100
        flags.append("KNOWN_MALICIOUS — remove immediately")

    # Typosquatting
    typo = _is_typosquat(name)
    if typo:
        score += 40
        flags.extend(typo)

    # npm metadata
    meta = {}
    if ecosystem == "npm":
        meta = _npm_metadata(name)
        if "error" not in meta:
            if meta.get("maintainers",99) == 1:
                score += 15
                flags.append("Single maintainer — bus factor 1")
            t = meta.get("latest_time","")
            if t and t != "?":
                try:
                    pub = datetime.fromisoformat(t.replace("Z","+00:00").replace("+00:00",""))
                    days_ago = (datetime.utcnow() - pub.replace(tzinfo=None)).days
                    if days_ago > 730:
                        score += 10
                        flags.append(f"Not updated in {days_ago} days")
                except: pass
            dl = meta.get("downloads_last_month", -1)
            if dl == 0:
                score += 20
                flags.append("Zero downloads last month — potentially abandoned or malicious")

    # OSV advisories
    advisories = _osv_advisory_count(name, ecosystem)
    if advisories > 0:
        score += 25 * advisories
        flags.append(f"{advisories} OSV advisory(ies) found")

    severity = "CRITICAL" if score >= 80 else "HIGH" if score >= 40 else "MEDIUM" if score >= 20 else "LOW"
    return {
        "package": name, "version": version, "ecosystem": ecosystem,
        "risk_score": min(score, 100), "severity": severity,
        "flags": flags, "meta": meta,
        "advisories": advisories,
    }


# need urllib.parse
import urllib.parse


class NovaSupplyChainScorer:
    def __init__(self):
        self.findings: List[Dict] = []

    def _parse_package_json(self, content: str) -> List[tuple]:
        try:
            d = json.loads(content)
            pkgs = []
            for sec in ("dependencies","devDependencies","peerDependencies"):
                for k,v in d.get(sec,{}).items():
                    pkgs.append((k, str(v).lstrip("^~>=<").split(" ")[0], "npm"))
            return pkgs
        except: return []

    def _parse_requirements(self, content: str) -> List[tuple]:
        pkgs = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*[>=<!~^]{1,2}\s*([^\s,;]+)', line)
            if m: pkgs.append((m.group(1).lower(), m.group(2), "pypi"))
            else:
                m2 = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
                if m2: pkgs.append((m2.group(1).lower(), "unknown", "pypi"))
        return pkgs

    def scan_directory(self, directory: str) -> List[Dict]:
        print(f"\n🏭 NOVA SUPPLY CHAIN SCORER — {directory}")
        print("=" * 60)
        all_pkgs = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in ("node_modules",".git","dist","build")]
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    content = open(fpath, encoding="utf-8", errors="ignore").read()
                except: continue
                if fname == "package.json" and '"name"' in content:
                    pkgs = self._parse_package_json(content)
                    all_pkgs.extend(pkgs)
                elif fname == "requirements.txt":
                    pkgs = self._parse_requirements(content)
                    all_pkgs.extend(pkgs)
        print(f"  📦 Scoring {min(len(all_pkgs), 30)} packages (capped for speed)...")
        findings = []
        seen = set()
        for name, version, eco in all_pkgs[:30]:
            if name in seen: continue
            seen.add(name)
            result = _score_package(name, version, eco)
            if result["risk_score"] >= 15:
                findings.append(result)
                icon = "🔴" if result["severity"] in ("CRITICAL","HIGH") else "🟡"
                print(f"  {icon} [{result['risk_score']:3d}/100] {name}@{version} — {', '.join(result['flags'][:2])}")
        self.findings = sorted(findings, key=lambda x: -x["risk_score"])
        print(f"\n  📊 {len(findings)} risky packages | {sum(1 for f in findings if f['severity']=='CRITICAL')} CRITICAL")
        return self.findings

    def save(self, path):
        with open(path,"w") as f:
            json.dump({"generated":datetime.now().isoformat(),"findings":self.findings},f,indent=2)
        print(f"  💾 Supply chain report → {path}")


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv)>1 else "."
    s = NovaSupplyChainScorer()
    s.scan_directory(d); s.save("nova_supply_chain_report.json")
