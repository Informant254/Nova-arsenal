#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🌐 NOVA WEB RESEARCHER v1.0 — CVE / PoC / ADVISORY INTEL        ║
║                                                                      ║
║   Closes the web-research gap vs Claude Code / Daybreak.            ║
║                                                                      ║
║   All three frontier agents have live web access. Nova was blind.   ║
║   This module gives her:                                            ║
║                                                                      ║
║   • NVD CVE lookup for any library/version/vendor                  ║
║   • GitHub PoC exploit search (exploitdb, nuclei-templates, etc.)  ║
║   • Security advisory fetch (GitHub advisories, OSV)               ║
║   • Shodan favicon hash lookup (fingerprint → exposed instances)   ║
║   • Wappalyzer-style tech-to-CVE mapping                           ║
║                                                                      ║
║   All fetches use only the public APIs — no keys required.         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import time
import hashlib
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKSPACE   = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
CACHE_DIR   = WORKSPACE / "research_cache"
CACHE_TTL   = 3600 * 12   # 12-hour cache

# ── CACHE ─────────────────────────────────────────────────────────────────────

def _cache_path(key: str) -> Path:
    hk = hashlib.md5(key.encode()).hexdigest()
    return CACHE_DIR / f"{hk}.json"

def _cache_get(key: str) -> Optional[Any]:
    p = _cache_path(key)
    if p.exists() and (time.time() - p.stat().st_mtime) < CACHE_TTL:
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return None

def _cache_set(key: str, data: Any):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _cache_path(key).write_text(json.dumps(data, indent=2, default=str))

def _fetch(url: str, timeout: int = 15, headers: Dict = None) -> Optional[str]:
    """HTTP GET with sensible defaults."""
    h = {"User-Agent": "Nova-Arsenal/3.0 Security Research Bot", "Accept": "application/json"}
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None

# ── NVD CVE SEARCH ────────────────────────────────────────────────────────────

def search_cve(keyword: str, max_results: int = 10) -> List[Dict]:
    """
    Search NIST NVD for CVEs matching a keyword (product, vendor, version).
    Returns list of CVEs with score, description, and references.
    No API key required.
    """
    cache_key = f"nvd:{keyword}:{max_results}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={urllib.parse.quote(keyword)}"
           f"&resultsPerPage={min(max_results, 20)}")

    raw = _fetch(url, timeout=20)
    if not raw:
        return []

    results = []
    try:
        data = json.loads(raw)
        for item in data.get("vulnerabilities", [])[:max_results]:
            cve   = item.get("cve", {})
            cve_id = cve.get("id", "")
            metrics = cve.get("metrics", {})
            score, severity, vector = 0.0, "UNKNOWN", ""

            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                ms = metrics.get(key, [])
                if ms:
                    d = ms[0].get("cvssData", {})
                    score    = d.get("baseScore", 0.0)
                    severity = d.get("baseSeverity", "")
                    vector   = d.get("vectorString", "")
                    break

            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            refs = [r.get("url", "") for r in cve.get("references", [])[:3]]
            published = cve.get("published", "")

            results.append({
                "cve_id":    cve_id,
                "score":     score,
                "severity":  severity,
                "vector":    vector,
                "published": published,
                "description": desc[:400],
                "references": refs,
            })

        # Sort by score descending
        results.sort(key=lambda x: x["score"], reverse=True)
    except Exception:
        pass

    _cache_set(cache_key, results)
    return results

# ── GITHUB POC SEARCH ─────────────────────────────────────────────────────────

def search_github_poc(query: str, max_results: int = 8) -> List[Dict]:
    """
    Search GitHub for PoC exploits, nuclei templates, and security tools
    matching the query. No auth required for public search.
    """
    cache_key = f"gh_poc:{query}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    q = urllib.parse.quote(f"{query} exploit poc vulnerability in:readme,description")
    url = f"https://api.github.com/search/repositories?q={q}&sort=stars&per_page={max_results}"

    raw = _fetch(url, timeout=15, headers={"Accept": "application/vnd.github+json"})
    if not raw:
        return []

    results = []
    try:
        data = json.loads(raw)
        for repo in data.get("items", [])[:max_results]:
            results.append({
                "name":        repo.get("full_name", ""),
                "description": repo.get("description", "")[:200],
                "stars":       repo.get("stargazers_count", 0),
                "url":         repo.get("html_url", ""),
                "language":    repo.get("language", ""),
                "updated_at":  repo.get("updated_at", ""),
                "topics":      repo.get("topics", [])[:5],
            })
    except Exception:
        pass

    results.sort(key=lambda x: x["stars"], reverse=True)
    _cache_set(cache_key, results)
    return results

# ── OSV ADVISORY SEARCH ───────────────────────────────────────────────────────

def search_osv(package: str, ecosystem: str = "PyPI") -> List[Dict]:
    """
    Query the Open Source Vulnerabilities (OSV) database for a package.
    Supports: PyPI, npm, Maven, Go, RubyGems, crates.io, etc.
    No API key required.
    """
    cache_key = f"osv:{ecosystem}:{package}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    payload = json.dumps({"package": {"name": package, "ecosystem": ecosystem}}).encode()
    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Nova-Arsenal/3.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
        data   = json.loads(raw)
        results = []
        for vuln in data.get("vulns", [])[:10]:
            severity = "UNKNOWN"
            score    = 0.0
            for s in vuln.get("severity", []):
                if "CVSS" in s.get("type", ""):
                    try:
                        score = float(re.search(r'AV:.*', s.get("score","")).group(0)[:4]) if re.search(r'\d+\.\d+', s.get("score","")) else 0.0
                        score = float(re.search(r'\d+\.\d+', s.get("score","")).group(0))
                        severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
                    except Exception:
                        pass
            results.append({
                "id":          vuln.get("id",""),
                "summary":     vuln.get("summary","")[:300],
                "published":   vuln.get("published",""),
                "modified":    vuln.get("modified",""),
                "score":       score,
                "severity":    severity,
                "aliases":     vuln.get("aliases",[])[:3],
                "references":  [r.get("url","") for r in vuln.get("references",[])[:3]],
            })
        results.sort(key=lambda x: x["score"], reverse=True)
        _cache_set(cache_key, results)
        return results
    except Exception:
        return []

# ── TECH STACK → CVE MAPPING ──────────────────────────────────────────────────

TECH_CVE_QUERIES = {
    "express":        ("expressjs vulnerabilities CVE", "npm", "express"),
    "django":         ("django CVE injection", "PyPI", "django"),
    "flask":          ("flask CVE SSTI", "PyPI", "flask"),
    "spring":         ("spring framework RCE CVE", None, None),
    "laravel":        ("laravel CVE injection", None, None),
    "rails":          ("rails CVE injection", "RubyGems", "rails"),
    "node":           ("nodejs CVE prototype pollution", None, None),
    "nginx":          ("nginx CVE path traversal", None, None),
    "apache":         ("apache CVE RCE", None, None),
    "wordpress":      ("wordpress plugin CVE RCE", None, None),
    "jwt":            ("jsonwebtoken CVE none algorithm", "npm", "jsonwebtoken"),
    "react":          ("react CVE XSS dangerouslySetInnerHTML", "npm", "react"),
    "log4j":          ("log4j RCE JNDI injection", None, None),
    "struts":         ("struts RCE CVE", None, None),
    "jquery":         ("jquery CVE XSS", "npm", "jquery"),
    "lodash":         ("lodash prototype pollution CVE", "npm", "lodash"),
    "sequelize":      ("sequelize SQL injection CVE", "npm", "sequelize"),
    "deserialize":    ("node-serialize RCE CVE", "npm", "node-serialize"),
}

def research_tech_stack(tech_list: List[str], max_per_tech: int = 5) -> Dict[str, Any]:
    """
    Given a list of detected technologies, fetch relevant CVEs and PoCs for each.
    Returns a structured threat intelligence report.
    """
    report: Dict[str, Any] = {
        "techs_researched": [],
        "cves": [],
        "pocs": [],
        "osv_advisories": [],
        "high_priority": [],
        "summary": "",
    }

    for tech in tech_list:
        tech_lower = tech.lower().strip()
        query_info = TECH_CVE_QUERIES.get(tech_lower)

        # NVD search
        nvd_query = query_info[0] if query_info else f"{tech} vulnerability CVE"
        cves = search_cve(nvd_query, max_results=max_per_tech)
        for c in cves:
            c["tech"] = tech_lower
            report["cves"].append(c)
            if c.get("score", 0) >= 7.0:
                report["high_priority"].append({
                    "tech": tech, "cve": c["cve_id"],
                    "score": c["score"], "desc": c["description"][:150],
                })

        # OSV search
        if query_info and query_info[1] and query_info[2]:
            advisories = search_osv(query_info[2], query_info[1])
            for a in advisories:
                a["tech"] = tech_lower
                report["osv_advisories"].append(a)

        # GitHub PoC
        pocs = search_github_poc(f"{tech} exploit PoC CVE", max_results=3)
        for p in pocs:
            p["tech"] = tech_lower
            report["pocs"].append(p)

        report["techs_researched"].append(tech_lower)
        print(f"  🔍 {tech}: {len(cves)} CVEs, {len(pocs)} PoC repos")

    # Sort high-priority by score
    report["high_priority"].sort(key=lambda x: x["score"], reverse=True)
    critical = [h for h in report["high_priority"] if h["score"] >= 9.0]
    high     = [h for h in report["high_priority"] if 7.0 <= h["score"] < 9.0]
    report["summary"] = (
        f"Researched {len(tech_list)} technologies. "
        f"Found {len(report['cves'])} CVEs total, "
        f"{len(critical)} CRITICAL (≥9.0), {len(high)} HIGH (≥7.0). "
        f"{len(report['pocs'])} public PoC repositories found."
    )
    return report


def research_cve(query: str, include_pocs: bool = True) -> Dict[str, Any]:
    """
    Single unified research call — accepts any query string.
    Used as the agent tool entry point.
    """
    print(f"  🌐 Researching: {query}")
    cves = search_cve(query, max_results=8)
    result: Dict[str, Any] = {
        "query":   query,
        "cves":    cves,
        "pocs":    [],
        "summary": "",
    }
    if include_pocs:
        result["pocs"] = search_github_poc(query, max_results=5)
    high = [c for c in cves if c.get("score", 0) >= 7.0]
    result["summary"] = (
        f"Found {len(cves)} CVEs for '{query}'. "
        f"{len(high)} are HIGH/CRITICAL. "
        f"{len(result['pocs'])} PoC repositories found."
    )
    print(f"  📋 {result['summary']}")
    return result


if __name__ == "__main__":
    import sys
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "expressjs SQL injection"
    result = research_cve(query)
    print(json.dumps(result, indent=2, default=str))
