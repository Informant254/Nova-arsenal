#!/usr/bin/env python3
"""
NOVA REPORT GENERATOR v1.0
===========================
Compiles all 5 learning iterations into a single HackerOne-ready report.

Actions:
  1. Merge all nova_ci_all_findings_*.json from all iterations
  2. Cross-reference confirmed PoCs from nova_poc_report.json
  3. Score + deduplicate via NovaTriage
  4. Compute CVSS 3.1 base scores
  5. Generate per-finding H1-formatted writeups with reproduction steps
  6. Build executive summary with attack chains
  7. Post as GitHub Issue (labelled nova-h1-ready)
  8. Save nova_h1_report.md + nova_h1_report.json to workspace
"""
import json, os, sys, glob, importlib, urllib.request, urllib.parse
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ── Workspace & env ─────────────────────────────────────────────────────────
WORKSPACE  = os.environ.get("NOVA_WORKSPACE", os.path.expanduser("~/nova_workspace"))
TARGET     = os.environ.get("NOVA_TARGET", "")
PROGRAM    = os.environ.get("NOVA_PROGRAM", "unknown")
GH_TOKEN   = os.environ.get("GITHUB_TOKEN", "")
GH_REPO    = os.environ.get("GITHUB_REPOSITORY", "")   # owner/repo
RUN_ID     = os.environ.get("GITHUB_RUN_ID", "")
RUN_URL    = f"https://github.com/{GH_REPO}/actions/runs/{RUN_ID}" if GH_REPO else ""
DATE       = datetime.utcnow().strftime("%Y-%m-%d")
TS         = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
os.makedirs(WORKSPACE, exist_ok=True)
os.makedirs(os.path.join(WORKSPACE, "reports"), exist_ok=True)

# ── CVSS 3.1 base-score lookup table (AV:N/AC:L/PR:N/UI:N by default) ───────
CVSS_VECTORS = {
    "csrf":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", 8.1),
    "xss":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "sqli":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "sql injection":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "ssrf":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", 9.3),
    "idor":              ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    "open redirect":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "rce":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "race condition":    ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N", 6.8),
    "prototype":         ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "jwt":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "xxe":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "lfi":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "path traversal":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "secret":            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "information":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "cve":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "default":           ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5),
}

REMEDIATION = {
    "csrf":           "Implement synchronised CSRF tokens (double-submit cookie or server-side). Validate `Origin`/`Referer` headers. Set `SameSite=Strict` on session cookies.",
    "xss":            "HTML-encode all user-supplied output using a context-aware escaping library. Implement a strict Content-Security-Policy (`script-src 'self'`).",
    "sqli":           "Use parameterised queries / prepared statements for all DB interactions. Never interpolate user input into SQL strings. Apply least-privilege DB roles.",
    "sql injection":  "Use parameterised queries / prepared statements for all DB interactions. Never interpolate user input into SQL strings. Apply least-privilege DB roles.",
    "ssrf":           "Validate and allowlist outbound URLs against a strict schema+host allowlist. Block RFC-1918 and link-local address ranges at the network layer. Use a DNS rebinding-safe resolver.",
    "idor":           "Enforce server-side authorisation checks on every object access using the authenticated user's identity — never trust client-supplied IDs alone.",
    "open redirect":  "Validate redirect targets against a strict allowlist of known-safe domains. Reject or encode any URL that is not on the list.",
    "rce":            "Sandbox all code-execution paths. Avoid `eval`, `exec`, `subprocess` with user input. Apply a WAF rule and restrict egress from the affected service.",
    "race condition": "Use atomic DB transactions with row-level locking (`SELECT FOR UPDATE`) or idempotency tokens to prevent TOCTOU races.",
    "prototype":      "Freeze the `Object.prototype` at startup (`Object.freeze`). Use `Object.create(null)` for untrusted key stores. Validate user input with a JSON Schema before merging.",
    "jwt":            "Enforce algorithm allowlisting server-side (`HS256` or `RS256` only). Validate `alg` header before processing. Use a well-maintained JWT library.",
    "secret":         "Rotate the exposed credential immediately. Move secrets to an environment-specific secrets manager (Vault, AWS Secrets Manager). Add secret-scanning to CI/CD pipeline.",
    "cve":            "Apply the vendor-released patch or update to a non-vulnerable version. Subscribe to the vendor's security advisory feed.",
    "default":        "Apply input validation, output encoding, and principle of least privilege. Review the affected component against OWASP Top-10 guidance.",
}

REFERENCES = {
    "csrf":        ["https://owasp.org/www-community/attacks/csrf", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
    "xss":         ["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    "sqli":        ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    "ssrf":        ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
    "idor":        ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"],
    "prototype":   ["https://portswigger.net/web-security/prototype-pollution", "https://github.com/nicolo-ribaudo/tc39-proposal-shadowrealm"],
    "jwt":         ["https://portswigger.net/web-security/jwt", "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
    "rce":         ["https://owasp.org/www-community/attacks/Code_Injection"],
    "secret":      ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cvss_for(finding: Dict) -> Tuple[str, float]:
    vtype = (finding.get("type","") + " " + finding.get("description","")).lower()
    for key, val in CVSS_VECTORS.items():
        if key in vtype:
            # Override with finding's own score if higher
            own = float(finding.get("cvss", 0) or 0)
            return val[0], max(val[1], own)
    own = float(finding.get("cvss", 0) or 0)
    default = CVSS_VECTORS["default"]
    return default[0], max(default[1], own)


def _severity_badge(score: float) -> str:
    if score >= 9.0: return "🔴 CRITICAL"
    if score >= 7.0: return "🟠 HIGH"
    if score >= 4.0: return "🟡 MEDIUM"
    return "🟢 LOW"


def _remediation_for(finding: Dict) -> str:
    vtype = (finding.get("type","") + " " + finding.get("description","")).lower()
    for key, val in REMEDIATION.items():
        if key in vtype:
            return val
    return REMEDIATION["default"]


def _references_for(finding: Dict) -> List[str]:
    vtype = (finding.get("type","") + " " + finding.get("description","")).lower()
    for key, refs in REFERENCES.items():
        if key in vtype:
            return refs
    return ["https://owasp.org/www-project-top-ten/"]


def _poc_for(finding: Dict, poc_map: Dict) -> Optional[Dict]:
    url   = finding.get("url", finding.get("endpoint",""))
    vtype = finding.get("type","")
    for poc in poc_map.get("pocs", []):
        if (poc.get("url","") == url or poc.get("endpoint","") == url) and poc.get("type","") == vtype:
            return poc
    return None


def _steps_to_reproduce(finding: Dict, poc: Optional[Dict]) -> str:
    url    = finding.get("url", finding.get("endpoint", TARGET)) or TARGET
    method = finding.get("method","GET").upper()
    vtype  = (finding.get("type","") + " " + finding.get("description","")).lower()
    steps  = []

    if "csrf" in vtype:
        steps = [
            f"Open a browser and log in to `{TARGET}` as a legitimate user.",
            f"From a **different origin** (e.g. attacker.com), send a `{method}` request to `{url}` with `Origin: https://evil-attacker.com` and no CSRF token.",
            "Observe the server returns HTTP 2xx and processes the request — no token required.",
            f"PoC: `{poc.get('poc_curl', f'curl -sk -X POST \"{url}\" -H \"Origin: https://evil-attacker.com\" -d \"{{}}\"') if poc else ''}`",
        ]
    elif "sqli" in vtype or "sql" in vtype:
        steps = [
            f"Navigate to `{url}` in a browser or use curl.",
            "Append `?id=1' OR '1'='1` to the URL (or inject into the relevant form parameter).",
            "Observe a database error in the response, or that the page returns all records — confirming unsanitised SQL execution.",
            f"PoC: `{poc.get('poc_curl', f'curl -sk \"{url}?id=1%27+OR+%271%27%3D%271\"') if poc else ''}`",
        ]
    elif "xss" in vtype:
        steps = [
            f"Navigate to `{url}?q=<script>alert(1)</script>` in a browser.",
            "Observe the injected payload reflects in the HTML response without encoding.",
            "The JavaScript executes in the victim's browser context — confirming stored/reflected XSS.",
            f"PoC: `{poc.get('poc_curl', f'curl -sk \"{url}?q=%3Cscript%3Ealert(1)%3C/script%3E\"') if poc else ''}`",
        ]
    elif "ssrf" in vtype:
        steps = [
            f"Send a request to `{url}` with a user-controlled URL parameter pointing to the cloud IMDS endpoint.",
            "Set the parameter to `http://169.254.169.254/latest/meta-data/` (AWS) or `http://metadata.google.internal/` (GCP).",
            "Observe the server proxies the request and returns cloud metadata in the response.",
            f"PoC: `{poc.get('poc_curl', f'curl -sk \"{url}?url=http://169.254.169.254/latest/meta-data/\"') if poc else ''}`",
        ]
    elif "idor" in vtype:
        steps = [
            "Log in as User A and note your resource ID (e.g. `/api/user/100`).",
            "Without switching accounts, change the ID to another user's (e.g. `/api/user/101`).",
            "Observe the server returns User B's data — no ownership check is enforced.",
            f"PoC: `{poc.get('poc_curl', f'curl -sk \"{url}\"') if poc else ''}`",
        ]
    elif "race" in vtype:
        steps = [
            f"Identify an endpoint that processes a one-time or limited action (e.g. `{url}`).",
            "Send **15 concurrent POST requests** to the endpoint simultaneously using ffuf or a script.",
            "Observe that multiple requests succeed beyond the expected limit — confirming a TOCTOU race.",
            f"PoC: `ffuf -u {url} -X POST -d '{{}}' -H 'Content-Type: application/json' -rate 15 -w /dev/null:FUZZ`",
        ]
    elif "secret" in vtype or "key" in vtype or "token" in vtype:
        endpoint = finding.get("file", url)
        steps = [
            f"Access the public resource at `{endpoint}`.",
            f"Search the response for the credential pattern: `{finding.get('evidence','')[:80]}`.",
            "The secret is exposed in plaintext and can be used to authenticate as the service account.",
            f"PoC: `{poc.get('poc_curl', f'curl -sk \"{url}\"') if poc else ''}`",
        ]
    elif "cve" in vtype:
        cve_id = finding.get("cve_id", finding.get("cve",""))
        steps = [
            f"The target is running `{finding.get('tech', finding.get('description','')[:60])}` which is affected by **{cve_id}**.",
            f"Refer to the public PoC at `https://www.exploit-db.com/search?cve={cve_id}` for full reproduction steps.",
            "Verify the vulnerable version is in use by inspecting response headers or the `/package.json` endpoint.",
        ]
    else:
        evidence = finding.get("evidence", finding.get("proof",""))
        steps = [
            f"Send a request to `{url}` using `{method}`.",
            f"Observe the response: {evidence[:200] if evidence else 'the vulnerability is present in the response.'}",
            "Confirm the finding matches the vulnerability description above.",
        ]

    return "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))


# ── Core: merge all iteration findings ────────────────────────────────────────

def load_all_findings() -> List[Dict]:
    pattern = os.path.join(WORKSPACE, "nova_ci_all_findings_*.json")
    files   = sorted(glob.glob(pattern))
    if not files:
        print(f"  ⚠️  No findings files found in {WORKSPACE}")
        return []
    merged = []
    seen   = set()
    for fp in files:
        try:
            with open(fp) as fh:
                data = json.load(fh)
            batch = data if isinstance(data, list) else data.get("findings", [])
            for f in batch:
                key = (f.get("type",""), f.get("url", f.get("endpoint","")), f.get("severity",""))
                if key not in seen:
                    seen.add(key)
                    merged.append(f)
        except Exception as ex:
            print(f"  ⚠️  Could not load {fp}: {ex}")
    print(f"  📦 Merged {len(merged)} unique findings from {len(files)} iteration files")
    return merged


def load_poc_data() -> Dict:
    path = os.path.join(WORKSPACE, "nova_poc_report.json")
    if os.path.exists(path):
        with open(path) as fh:
            return json.load(fh)
    return {"pocs": [], "confirmed_pocs": 0}


# ── Score + triage via existing NovaTriage ────────────────────────────────────

def triage_findings(findings: List[Dict]) -> List[Dict]:
    try:
        sys.path.insert(0, os.getcwd())
        triage_mod = importlib.import_module("nova_triage")
        t = triage_mod.NovaTriage(target=TARGET)
        triaged = t.run(findings)
        result = []
        for tf in triaged:
            d = tf.__dict__.copy() if hasattr(tf, "__dict__") else {}
            # Merge back original finding data
            result.append(d)
        print(f"  ✅ Triage: {len(result)} scored findings")
        return result
    except Exception as ex:
        print(f"  ⚠️  Triage module error ({ex}) — using heuristic scoring")
        # Heuristic fallback
        scored = []
        for f in findings:
            sev = str(f.get("severity","")).upper()
            score = {"CRITICAL":9.5,"HIGH":7.5,"MEDIUM":5.0,"LOW":2.0,"INFO":1.0}.get(sev,1.0)
            scored.append({**f, "triage_score": score, "h1_report_ready": score >= 7.0})
        return scored


# ── Per-finding H1 writeup ────────────────────────────────────────────────────

def h1_writeup(finding: Dict, poc_map: Dict, idx: int) -> str:
    vtype      = str(finding.get("type", "Security Issue"))
    sev        = str(finding.get("severity","HIGH")).upper()
    url        = finding.get("url", finding.get("endpoint", TARGET)) or TARGET
    desc       = finding.get("description", finding.get("detail",""))
    evidence   = finding.get("evidence", finding.get("proof",""))
    cve        = finding.get("cve_id", finding.get("cve",""))
    cvss_vec, cvss_score = _cvss_for(finding)
    badge      = _severity_badge(cvss_score)
    poc        = _poc_for(finding, poc_map)
    steps      = _steps_to_reproduce(finding, poc)
    fix        = _remediation_for(finding)
    refs       = _references_for(finding)
    confirmed  = "✅ **PoC Confirmed**" if (poc and poc.get("poc_confirmed")) else "⚠️ Needs Manual Verification"
    curl_poc   = poc.get("poc_curl","") if poc else ""

    lines = [
        f"---",
        f"## Finding #{idx}: {vtype}",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Severity** | {badge} |",
        f"| **CVSS Score** | {cvss_score} |",
        f"| **CVSS Vector** | `{cvss_vec}` |",
        f"| **Endpoint** | `{url}` |",
        f"| **Status** | {confirmed} |",
    ]
    if cve:
        lines.append(f"| **CVE** | [{cve}](https://nvd.nist.gov/vuln/detail/{cve}) |")
    lines += [
        f"",
        f"### Description",
        f"{desc or f'A **{vtype}** vulnerability was identified at `{url}`.'}",
        f"",
        f"### Impact",
        f"{_impact_statement(finding)}",
        f"",
        f"### Steps to Reproduce",
        f"{steps}",
    ]
    if evidence:
        lines += [f"", f"### Evidence", f"```", f"{str(evidence)[:500]}", f"```"]
    if curl_poc:
        lines += [f"", f"### Curl PoC (copy-paste ready)", f"```bash", f"{curl_poc}", f"```"]
    lines += [
        f"",
        f"### Remediation",
        f"{fix}",
        f"",
        f"### References",
    ]
    for r in refs:
        lines.append(f"- {r}")
    return "\n".join(lines)


def _impact_statement(finding: Dict) -> str:
    vtype = (finding.get("type","") + " " + finding.get("description","")).lower()
    sev   = str(finding.get("severity","")).upper()
    tgt   = TARGET or "the target"
    if "csrf"    in vtype: return f"An attacker can forge requests on behalf of authenticated users of `{tgt}`, leading to account takeover, fund transfer, or data modification without the victim's knowledge."
    if "sqli"    in vtype or "sql" in vtype: return f"Full database compromise — an attacker can read, modify, or delete all data stored in the database backing `{tgt}`, including user credentials and payment data."
    if "xss"     in vtype: return f"An attacker can execute arbitrary JavaScript in the victim's browser session on `{tgt}`, enabling session hijacking, credential theft, and malware delivery."
    if "ssrf"    in vtype: return f"An attacker can pivot through `{tgt}`'s server to access internal cloud metadata, internal services, and potentially the entire internal network."
    if "idor"    in vtype: return f"An authenticated attacker can access, modify, or delete any other user's data on `{tgt}` — violating confidentiality and integrity of all user records."
    if "rce"     in vtype: return f"Complete server compromise — arbitrary code execution on `{tgt}`'s infrastructure, leading to data exfiltration, ransomware, or lateral movement."
    if "race"    in vtype: return f"An attacker can exploit the race window to redeem vouchers multiple times, double-spend credits, or bypass business logic limits on `{tgt}`."
    if "secret"  in vtype: return f"Exposed credentials grant an attacker direct API access to the associated service, bypassing all authentication controls on `{tgt}`."
    if "jwt"     in vtype: return f"An attacker can forge JWT tokens to impersonate any user including administrators on `{tgt}`, leading to full account takeover."
    if "redirect"in vtype: return f"An attacker can craft a `{tgt}` URL that redirects victims to a phishing page, enabling credential harvesting and social engineering."
    if "cve"     in vtype: return f"The affected component is publicly known to be vulnerable. Public exploits exist and could be used to compromise `{tgt}` without significant skill."
    return f"This {sev} severity vulnerability poses a significant risk to the confidentiality, integrity, or availability of `{tgt}` and its users."


# ── Executive summary ─────────────────────────────────────────────────────────

def build_executive_summary(h1_findings: List[Dict], all_findings: List[Dict], poc_map: Dict, iterations: int) -> str:
    total   = len(all_findings)
    crit    = sum(1 for f in all_findings if str(f.get("severity","")).upper()=="CRITICAL")
    high    = sum(1 for f in all_findings if str(f.get("severity","")).upper()=="HIGH")
    med     = sum(1 for f in all_findings if str(f.get("severity","")).upper()=="MEDIUM")
    h1_cnt  = len(h1_findings)
    poc_cnt = poc_map.get("confirmed_pocs", 0)
    conf_r  = poc_map.get("confirmation_rate", 0)

    # Attack chain summary
    chains: Dict[str,List] = {}
    for f in h1_findings:
        chain = f.get("chain_id","")
        if chain:
            chains.setdefault(chain, []).append(f.get("type","?"))

    lines = [
        f"## 🦅 Nova Arsenal — Bug Bounty Hunt Report",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Target** | `{TARGET}` |",
        f"| **Program** | {PROGRAM} |",
        f"| **Hunt Date** | {DATE} |",
        f"| **Iterations** | {iterations} learning passes |",
        f"| **Run** | [View Actions Run]({RUN_URL}) |",
        f"",
        f"---",
        f"",
        f"## 📊 Executive Summary",
        f"",
        f"Nova performed {iterations} autonomous learning passes against `{TARGET}`, progressively deepening her attack coverage with each iteration.",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | **{crit}** |",
        f"| 🟠 High | **{high}** |",
        f"| 🟡 Medium | **{med}** |",
        f"| **Total raw findings** | **{total}** |",
        f"| **H1-ready (P1/P2)** | **{h1_cnt}** |",
        f"| **PoC confirmed** | **{poc_cnt}** ({conf_r}% confirmation rate) |",
        f"",
    ]

    if chains:
        lines += ["## ⛓️ Attack Chains", ""]
        for cid, types in list(chains.items())[:5]:
            lines.append(f"- **Chain {cid}**: {' → '.join(types)}")
        lines.append("")

    if h1_findings:
        lines += ["## 🎯 H1-Ready Findings Summary", "", "| # | Type | Severity | Endpoint | PoC |", "|---|------|----------|----------|-----|"]
        for i, f in enumerate(h1_findings, 1):
            _, score = _cvss_for(f)
            badge    = _severity_badge(score)
            ep       = (f.get("url", f.get("endpoint","")) or "")[:60]
            has_poc  = "✅" if any(p.get("url","") == f.get("url","") for p in poc_map.get("pocs",[])) else "⚠️"
            lines.append(f"| {i} | {f.get('type','?')[:40]} | {badge} ({score}) | `{ep}` | {has_poc} |")
        lines.append("")

    return "\n".join(lines)


# ── GitHub Issue poster ───────────────────────────────────────────────────────

def post_github_issue(title: str, body: str) -> Optional[str]:
    if not GH_TOKEN or not GH_REPO:
        print("  ⚠️  GITHUB_TOKEN or GITHUB_REPOSITORY not set — skipping issue post")
        return None
    api_url = f"https://api.github.com/repos/{GH_REPO}/issues"
    payload = json.dumps({
        "title":  title,
        "body":   body[:65000],   # GitHub issue body limit
        "labels": ["nova-findings", "nova-h1-ready"],
    }).encode()
    req = urllib.request.Request(
        api_url, data=payload, method="POST",
        headers={
            "Authorization": f"Bearer {GH_TOKEN}",
            "Accept":        "application/vnd.github+json",
            "Content-Type":  "application/json",
            "User-Agent":    "Nova-Arsenal/2.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            resp = json.loads(r.read())
            url  = resp.get("html_url","")
            print(f"  ✅ GitHub Issue created: {url}")
            return url
    except Exception as ex:
        print(f"  ⚠️  GitHub Issue post failed: {ex}")
        return None


# ── Main ─────────────────────────────────────────────────────────────────────

def generate(iterations: int = 5) -> Dict:
    print("\n" + "═"*68)
    print("  📄 NOVA REPORT GENERATOR — HackerOne-Ready Report")
    print("═"*68)

    all_findings = load_all_findings()
    poc_map      = load_poc_data()

    if not all_findings:
        print("  ⚠️  No findings to report.")
        return {}

    # Score via triage
    scored = triage_findings(all_findings)

    # Select H1-ready (P1/P2: score >= 7.0)
    h1_ready = sorted(
        [f for f in scored if float(f.get("triage_score", 0)) >= 7.0],
        key=lambda f: float(f.get("triage_score",0)),
        reverse=True,
    )
    print(f"  🎯 {len(h1_ready)} H1-ready findings (P1/P2, score ≥ 7.0) from {len(scored)} total")

    # Build report
    sections = [build_executive_summary(h1_ready, all_findings, poc_map, iterations)]
    sections.append("\n---\n\n## 📋 Detailed Findings\n")

    for i, f in enumerate(h1_ready, 1):
        sections.append(h1_writeup(f, poc_map, i))

    # Append raw full-log section header (workflow will append trimmed log)
    sections.append("\n---\n\n## 📝 Raw Scan Output\n\n*(See attached workflow log for full output.)*\n")

    report_md = "\n".join(sections)

    # Save markdown
    md_path = os.path.join(WORKSPACE, "reports", f"nova_h1_report_{TS}.md")
    with open(md_path, "w") as fh:
        fh.write(report_md)

    # Save copy at predictable path for workflow to pick up
    stable_md = os.path.join(WORKSPACE, "nova_h1_report.md")
    with open(stable_md, "w") as fh:
        fh.write(report_md)

    # Save JSON
    json_path = os.path.join(WORKSPACE, "reports", f"nova_h1_report_{TS}.json")
    report_data = {
        "generated":       datetime.utcnow().isoformat(),
        "target":          TARGET,
        "program":         PROGRAM,
        "iterations":      iterations,
        "total_findings":  len(all_findings),
        "h1_ready":        len(h1_ready),
        "confirmed_pocs":  poc_map.get("confirmed_pocs", 0),
        "findings":        h1_ready,
    }
    with open(json_path, "w") as fh:
        json.dump(report_data, fh, indent=2)

    print(f"  💾 Saved: {md_path}")
    print(f"  💾 Saved: {json_path}")

    # Post to GitHub Issues
    crit   = sum(1 for f in h1_ready if str(f.get("severity","")).upper()=="CRITICAL")
    high_c = sum(1 for f in h1_ready if str(f.get("severity","")).upper()=="HIGH")
    confirmed = poc_map.get("confirmed_pocs",0)
    issue_title = (
        f"[Nova H1 Report] {PROGRAM}: {TARGET} | {DATE} | "
        f"{crit} Critical · {high_c} High · {confirmed} PoC Confirmed"
    )
    issue_url = post_github_issue(issue_title, report_md)

    print("\n" + "═"*68)
    print(f"  🎯 REPORT COMPLETE")
    print(f"     H1-Ready : {len(h1_ready)} findings")
    print(f"     Confirmed: {confirmed} PoCs proven")
    print(f"     Markdown : {stable_md}")
    if issue_url:
        print(f"     Issue    : {issue_url}")
    print("═"*68)

    return report_data


if __name__ == "__main__":
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    generate(iters)
