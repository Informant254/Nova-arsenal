#!/usr/bin/env python3
"""
NOVA SOURCE CODE AUDITOR v2.0
Autonomous vulnerability discovery in source code.
v2.0: TypeScript/JS/Python multi-language sinks + Mythos-style file prioritization.
Clones repos, traces data flows, generates PoC exploits.
"""

import json, time, re, os, subprocess, tempfile
from datetime import datetime
from typing import Dict, List, Optional

class NovaSourceAuditor:
    def __init__(self):
        self.findings = []
        self.audit_dir = tempfile.mkdtemp(prefix="nova_audit_")

        # ── TypeScript/JavaScript sinks ──────────────────────────────────────
        self.sinks_ts = {
            "sql_injection": [
                (r'sequelize\.query\s*\(\s*`[^`]*\$\{', "SQLi — Sequelize raw query with template literal"),
                (r'\.query\s*\(\s*["\'].*?\+\s*(?:req\.|request\.)', "SQLi — string concat in query"),
                (r'\.query\s*\(\s*`[^`]*\$\{', "SQLi — template literal in query"),
                (r'knex\.raw\s*\(', "SQLi — knex.raw call"),
                (r'db\.exec\s*\(.*?\+', "SQLi — db.exec with concatenation"),
            ],
            "xss": [
                (r'innerHTML\s*=', "XSS — innerHTML assignment"),
                (r'dangerouslySetInnerHTML', "XSS — React dangerouslySetInnerHTML"),
                (r'document\.write\s*\(', "XSS — document.write"),
                (r'\.html\s*\(.*(?:req\.|params\.|query\.)', "XSS — jQuery .html() with request input"),
                (r'outerHTML\s*=', "XSS — outerHTML assignment"),
                (r'insertAdjacentHTML\s*\(', "XSS — insertAdjacentHTML"),
            ],
            "path_traversal": [
                (r'(?:readFile|readFileSync)\s*\(', "LFI — fs.readFile with potential user input"),
                (r'(?:sendFile|sendfile)\s*\(', "LFI — res.sendFile with potential user input"),
                (r'createReadStream\s*\(', "LFI — createReadStream"),
                (r'path\.join\s*\([^)]*req\.', "Path traversal — path.join with request input"),
                (r'path\.resolve\s*\([^)]*req\.', "Path traversal — path.resolve with request input"),
            ],
            "command_injection": [
                (r'exec\s*\([^)]*(?:req\.|request\.|\+)', "RCE — exec() with user input"),
                (r'execSync\s*\([^)]*(?:req\.|request\.|\+)', "RCE — execSync with user input"),
                (r'spawn\s*\([^)]*(?:req\.|request\.|\+)', "RCE — spawn with user input"),
                (r'child_process', "RCE — child_process usage"),
                (r'eval\s*\([^)]*(?:req\.|request\.|\+)', "RCE — eval with user input"),
                (r'new\s+Function\s*\([^)]*(?:req\.|request\.)', "RCE — new Function() with user input"),
            ],
            "ssrf": [
                (r'fetch\s*\([^)]*(?:req\.|request\.|\+)', "SSRF — fetch with user-controlled URL"),
                (r'axios\s*\.\s*(?:get|post|put|delete)\s*\([^)]*(?:req\.|request\.)', "SSRF — axios with user URL"),
                (r'http\s*\.\s*(?:get|post|request)\s*\([^)]*(?:req\.|request\.)', "SSRF — http.get with user URL"),
                (r'got\s*\([^)]*(?:req\.|request\.)', "SSRF — got() with user URL"),
                (r'superagent.*(?:req\.|request\.)', "SSRF — superagent with user URL"),
            ],
            "open_redirect": [
                (r'res\.redirect\s*\([^)]*(?:req\.|request\.)', "Open Redirect — res.redirect with user input"),
                (r'location\.href\s*=.*(?:req\.|request\.)', "Open Redirect — location.href assignment"),
                (r'window\.location\s*=.*(?:req\.|request\.)', "Open Redirect — window.location assignment"),
            ],
            "insecure_deserialization": [
                (r'JSON\.parse\s*\([^)]*(?:req\.|request\.)', "Deser — JSON.parse with request body"),
                (r'deserialize\s*\([^)]*(?:req\.|request\.)', "Deser — deserialize() with user input"),
                (r'fromJSON\s*\([^)]*(?:req\.|request\.)', "Deser — fromJSON with user input"),
                (r'unserialize\s*\(', "Deser — PHP-style unserialize"),
            ],
            "prototype_pollution": [
                (r'Object\.assign\s*\(\s*(?:\{\s*\}|target|obj)[^)]*(?:req\.|request\.)', "Proto — Object.assign with user input"),
                (r'__proto__\s*=', "Proto — direct __proto__ assignment"),
                (r'(?:merge|deepMerge|extend)\s*\([^)]*(?:req\.|request\.)', "Proto — merge() with user input"),
                (r'constructor\s*\[.*prototype', "Proto — constructor prototype access"),
            ],
            "xxe": [
                (r'libxmljs\d*\.parseXml', "XXE — libxmljs2 parseXml"),
                (r'xml2js\.parseString', "XXE — xml2js parseString"),
                (r'DOMParser\s*\(\s*\)', "XXE — DOMParser instantiation"),
                (r'parseFromString\s*\(', "XXE — parseFromString"),
                (r'new\s+(?:SAXParser|DOMParser|XMLParser)', "XXE — XML parser instantiation"),
            ],
            "jwt_issues": [
                (r'jwt\.verify\s*\([^)]*\)\s*\n?\s*\.catch\s*\(\s*\)', "JWT — verify errors swallowed"),
                (r'algorithm\s*:\s*["\']none["\']', "JWT — none algorithm allowed"),
                (r'algorithms\s*:\s*\[\s*["\']none["\']', "JWT — none in algorithms array"),
                (r'jwt\.sign\s*\([^)]*expiresIn.*["\']999', "JWT — extremely long expiry"),
            ],
        }

        # ── Python sinks ─────────────────────────────────────────────────────
        self.sinks_py = {
            "sql_injection": [
                (r'\.execute\s*\(\s*["\'].*?\%', "SQLi — % formatting in execute"),
                (r'\.execute\s*\(\s*["\'].*?\+', "SQLi — concatenation in execute"),
                (r'cursor\.execute\s*\(.*?format\s*\(', "SQLi — format() in execute"),
                (r'\.execute\s*\(f["\']', "SQLi — f-string in execute"),
                (r'raw\s*\(\s*["\'].*?\+', "SQLi — Django raw() with concat"),
            ],
            "command_injection": [
                (r'os\.system\s*\(.*?\+', "RCE — os.system with concatenation"),
                (r'subprocess\.(?:call|run|Popen)\s*\(.*?\+', "RCE — subprocess with concat"),
                (r'eval\s*\(.*?\+', "RCE — eval with concatenation"),
                (r'exec\s*\(.*?\+', "RCE — exec with concatenation"),
            ],
            "path_traversal": [
                (r'open\s*\(.*?\+', "LFI — file open with concatenation"),
                (r'open\s*\(.*?request\b', "LFI — file open with request data"),
            ],
            "ssrf": [
                (r'requests\.(?:get|post|put|delete)\s*\(.*?\+', "SSRF — requests with URL concat"),
                (r'urllib.*?urlopen\s*\(.*?\+', "SSRF — urllib with URL concat"),
            ],
            "insecure_deserialization": [
                (r'pickle\.loads\s*\(', "Deser — pickle.loads (always dangerous)"),
                (r'yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)', "Deser — yaml.load without SafeLoader"),
                (r'marshal\.loads\s*\(', "Deser — marshal.loads"),
            ],
            "xss": [
                (r'Markup\s*\(.*?\+', "XSS — Flask Markup() with concat"),
                (r'render_template_string\s*\(.*?\+', "SSTI — render_template_string with concat"),
            ],
        }

        # ── Taint sources (multi-language) ────────────────────────────────────
        self.taint_sources_ts = [
            (r'req\s*\.\s*(?:body|params|query|headers|cookies)\b', "Express req input"),
            (r'request\s*\.\s*(?:body|params|query|headers)\b', "Express request input"),
            (r'ctx\s*\.\s*(?:body|params|query|request)\b', "Koa ctx input"),
            (r'event\s*\.\s*(?:body|queryStringParameters|pathParameters)\b', "Lambda event input"),
            (r'socket\s*\.\s*on\s*\(["\'](?:data|message)', "WebSocket data"),
        ]
        self.taint_sources_py = [
            (r'request\s*\.\s*(?:form|args|json|data|get_json|files)\b', "Flask/Django request"),
            (r'req\s*\.\s*(?:body|query|params)\b', "Node/Express-style"),
            (r'input\s*\(', "Python input()"),
            (r'sys\.argv', "CLI argument"),
            (r'os\.environ', "Environment variable"),
        ]

    # ── Mythos-style file prioritization (1-5) ───────────────────────────────

    def prioritize_file(self, filepath: str, content: str) -> int:
        c = content.lower()
        score_5 = [
            r'req\.(body|params|query)', r'request\.(form|args|json)',
            r'execute\s*\(', r'sequelize\.query', r'eval\s*\(',
            r'pickle\.loads', r'yaml\.load', r'exec\s*\(',
            r'file.*upload|multipart', r'jwt\.(sign|verify)',
            r'login|auth|password|credential',
        ]
        score_4 = [
            r'redirect|location\.href', r'readfile|sendfile|createreadstream',
            r'cors|access.control', r'crypto|cipher|hash|hmac',
            r'webhook|callback.*url', r'admin|superuser',
        ]
        for pat in score_5:
            if re.search(pat, c, re.IGNORECASE):
                return 5
        for pat in score_4:
            if re.search(pat, c, re.IGNORECASE):
                return 4
        if re.search(r'router|route|endpoint|handler|controller|middleware', c, re.IGNORECASE):
            return 3
        if re.search(r'model|schema|entity|util|helper', c, re.IGNORECASE):
            return 2
        return 1

    # ── Scanning ──────────────────────────────────────────────────────────────

    def scan_file(self, filepath: str) -> List[Dict]:
        findings = []
        ext = os.path.splitext(filepath)[1].lower()
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except Exception:
            return findings

        lines = source.split("\n")
        filename = os.path.basename(filepath)
        priority = self.prioritize_file(filepath, source)

        # Select sink + taint set by language
        if ext in ('.ts', '.js', '.tsx', '.jsx', '.mjs', '.cjs'):
            sinks = self.sinks_ts
            taint_patterns = self.taint_sources_ts
        elif ext == '.py':
            sinks = self.sinks_py
            taint_patterns = self.taint_sources_py
        else:
            sinks = {**self.sinks_ts, **self.sinks_py}
            taint_patterns = self.taint_sources_ts + self.taint_sources_py

        # Find all taint source lines
        taint_lines = set()
        for i, line in enumerate(lines, 1):
            for pat, _ in taint_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    taint_lines.add(i)

        if not taint_lines:
            return findings

        # Find sinks and check for nearby taint
        seen = set()
        for i, line in enumerate(lines, 1):
            for vuln_type, patterns in sinks.items():
                for pat, desc in patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        nearby_taint = any(abs(t - i) <= 40 for t in taint_lines)
                        confidence = "HIGH" if nearby_taint else "MEDIUM"
                        key = (filename, i, vuln_type)
                        if key not in seen:
                            seen.add(key)
                            findings.append({
                                "file": filename,
                                "line": i,
                                "type": vuln_type,
                                "description": desc,
                                "snippet": line.strip()[:120],
                                "confidence": confidence,
                                "priority_score": priority,
                                "severity": "CRITICAL" if vuln_type in
                                    ("sql_injection", "command_injection", "insecure_deserialization", "xxe")
                                    else "HIGH",
                            })
                        break
        return findings

    def scan_directory(self, target_dir: str) -> List[Dict]:
        print(f"\n🔍 Scanning: {target_dir}")
        all_findings = []
        extensions = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".cs", ".mjs"}
        skip = {"node_modules", ".git", "dist", "build", "vendor", "coverage", ".nyc_output"}
        scanned = 0

        # Collect + prioritize files first (Mythos pattern)
        file_scores = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".")]
            for fname in files:
                if os.path.splitext(fname)[1].lower() in extensions:
                    fp = os.path.join(root, fname)
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        score = self.prioritize_file(fp, content)
                        file_scores.append((score, fp, content))
                    except Exception:
                        pass

        # Scan highest-priority files first
        file_scores.sort(key=lambda x: -x[0])

        for priority_score, filepath, _ in file_scores:
            if priority_score < 2:
                continue  # Skip constants-only files (score 1)
            findings = self.scan_file(filepath)
            all_findings.extend(findings)
            scanned += 1
            if findings:
                print(f"   🔥 [{priority_score}/5] {os.path.basename(filepath)}: {len(findings)} finding(s)")

        print(f"   📊 Scanned {scanned} files (priority ≥2), found {len(all_findings)} potential vulnerabilities")
        return all_findings

    def match_cves(self, findings: List[Dict]) -> List[Dict]:
        cve_map = {
            "sql_injection": {"cve": "CWE-89", "cvss": 9.8},
            "xss": {"cve": "CWE-79", "cvss": 7.4},
            "command_injection": {"cve": "CWE-78", "cvss": 9.8},
            "path_traversal": {"cve": "CWE-22", "cvss": 7.5},
            "ssrf": {"cve": "CWE-918", "cvss": 8.6},
            "insecure_deserialization": {"cve": "CWE-502", "cvss": 8.8},
            "open_redirect": {"cve": "CWE-601", "cvss": 6.1},
            "prototype_pollution": {"cve": "CWE-1321", "cvss": 7.3},
            "xxe": {"cve": "CWE-611", "cvss": 9.1},
            "jwt_issues": {"cve": "CWE-345", "cvss": 7.5},
        }
        enriched = []
        for f in findings:
            vt = f.get("type", "")
            info = cve_map.get(vt, {"cve": "N/A", "cvss": 5.0})
            enriched.append({**f, "cve": info["cve"], "cvss": info["cvss"]})
        return enriched

    def generate_poc(self, finding: Dict) -> str:
        vuln_type = finding.get("type", "")
        snippet = finding.get("snippet", "")
        poc_map = {
            "sql_injection":   "curl \"http://target/search?q=1' OR '1'='1\" -v",
            "xss":             "curl \"http://target/path?param=<script>alert(1)</script>\" -v",
            "path_traversal":  "curl \"http://target/file?name=../../../etc/passwd\" -v",
            "ssrf":            "curl \"http://target/fetch?url=http://169.254.169.254/latest/meta-data/\" -v",
            "command_injection": "curl \"http://target/exec?cmd=id\" -v",
            "open_redirect":   "curl \"http://target/redirect?next=https://evil.com\" -v",
            "xxe":             'curl -X POST http://target/xml -d \'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><x>&x;</x>\'',
            "prototype_pollution": 'curl -X POST http://target/api -H "Content-Type: application/json" -d \'{"__proto__":{"polluted":true}}\'',
        }
        return poc_map.get(vuln_type, f"# Manual review required for {vuln_type}\n# Snippet: {snippet[:80]}")

    def generate_report(self, findings: List[Dict], repo_url: str):
        enriched = self.match_cves(findings)
        report = {
            "generated": datetime.now().isoformat(),
            "repo": repo_url,
            "total_findings": len(enriched),
            "critical": [f for f in enriched if f.get("severity") == "CRITICAL"],
            "high": [f for f in enriched if f.get("severity") == "HIGH"],
            "findings": enriched,
        }
        out = f"nova_audit_{repo_url.replace('https://','').replace('/','_')}.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  💾 Audit report → {out}")
        return report

    def clone_repo(self, repo_url: str) -> Optional[str]:
        clone_dir = os.path.join(self.audit_dir, "repo")
        result = subprocess.run(
            ["git", "clone", "--depth=1", repo_url, clone_dir],
            capture_output=True, text=True, timeout=120
        )
        return clone_dir if result.returncode == 0 else None

    def run_audit(self, repo_url: str):
        print(f"\n🦅 NOVA SOURCE AUDITOR v2.0 — {repo_url}")
        clone_dir = self.clone_repo(repo_url)
        if not clone_dir:
            print("❌ Clone failed")
            return None
        findings = self.scan_directory(clone_dir)
        return self.generate_report(findings, repo_url)
