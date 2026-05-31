#!/usr/bin/env python3
"""
NOVA GIT SCANNER v1.0
Daybreak-style git commit history scanning.
Finds secrets, credential leaks, regressions, and sensitive data
committed to git history — even if later deleted from working tree.
"""

import os
import re
import json
import subprocess
from typing import Dict, List, Optional
from datetime import datetime


SECRET_PATTERNS = [
    ("AWS Access Key",        r'AKIA[0-9A-Z]{16}',                              "CRITICAL"),
    ("AWS Secret Key",        r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9+/]{40})', "CRITICAL"),
    ("GitHub Token",          r'gh[pousr]_[A-Za-z0-9]{36,}',                    "CRITICAL"),
    ("GitHub Classic Token",  r'ghp_[A-Za-z0-9]{36}',                           "CRITICAL"),
    ("Slack Token",           r'xox[baprs]-[0-9A-Za-z\-]{10,}',                 "CRITICAL"),
    ("Stripe Secret Key",     r'sk_live_[0-9a-zA-Z]{24,}',                      "CRITICAL"),
    ("Stripe Publishable Key",r'pk_live_[0-9a-zA-Z]{24,}',                      "HIGH"),
    ("Google API Key",        r'AIza[0-9A-Za-z\-_]{35}',                        "HIGH"),
    ("Twilio Auth Token",     r'(?i)twilio.{0,20}auth.{0,20}["\']([0-9a-f]{32})', "HIGH"),
    ("RSA Private Key",       r'-----BEGIN RSA PRIVATE KEY-----',                "CRITICAL"),
    ("EC Private Key",        r'-----BEGIN EC PRIVATE KEY-----',                 "CRITICAL"),
    ("Generic Private Key",   r'-----BEGIN PRIVATE KEY-----',                    "CRITICAL"),
    ("JWT Secret",            r'(?i)(jwt[_\-]?secret|signing[_\-]?key)\s*[=:]\s*["\']?([A-Za-z0-9+/]{8,})', "HIGH"),
    ("Database URL",          r'(?i)(mongodb|postgres|mysql|redis)://[^@\s]+:[^@\s]+@', "CRITICAL"),
    ("Generic Password",      r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "HIGH"),
    ("Generic Secret",        r'(?i)(secret|api_key|apikey|auth_token)\s*[=:]\s*["\']([^"\']{8,})["\']', "HIGH"),
    ("Bearer Token",          r'(?i)bearer\s+([A-Za-z0-9\-_]{20,})',             "MEDIUM"),
    ("Heroku API Key",        r'(?i)heroku.{0,20}["\']([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})["\']', "HIGH"),
    ("SendGrid Key",          r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',   "HIGH"),
    ("Mailgun Key",           r'key-[0-9a-zA-Z]{32}',                           "HIGH"),
    ("HackerOne Token",       r'(?i)hackerone.{0,20}["\']([A-Za-z0-9]{20,})["\']', "MEDIUM"),
]

REGRESSION_PATTERNS = [
    (r'(?i)\beval\s*\(', "eval() usage — possible code injection regression"),
    (r'(?i)innerHTML\s*=', "innerHTML assignment — XSS regression risk"),
    (r'(?i)exec\s*\(.*\+', "exec() with concatenation — command injection regression"),
    (r'(?i)\.query\s*\(`', "Raw SQL query with template literal — SQLi regression"),
    (r'(?i)TODO.*vuln|FIXME.*vuln|HACK.*auth|XXX.*bypass', "Developer TODO flagging security issue"),
    (r'(?i)disable.*ssl|verify\s*=\s*false|ssl_verify.*false', "SSL/TLS verification disabled"),
    (r'(?i)debug\s*=\s*true', "Debug mode enabled in commit"),
    (r'(?i)cors.*\*|allow.*origin.*\*', "Wildcard CORS — overly permissive"),
]

SKIP_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
                   '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.wav', '.pdf',
                   '.zip', '.tar', '.gz', '.lock'}


def _run_git(args: List[str], cwd: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git"] + args, cwd=cwd,
            capture_output=True, text=True, timeout=30
        )
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


class NovaGitScanner:
    def __init__(self):
        self.findings: List[Dict] = []

    def is_git_repo(self, directory: str) -> bool:
        return _run_git(["rev-parse", "--git-dir"], directory) is not None

    def scan_directory(self, directory: str, max_commits: int = 200) -> List[Dict]:
        print("\n📜 NOVA GIT SCANNER — Scanning commit history...")
        print("=" * 60)

        if not self.is_git_repo(directory):
            print("  ⚠️  Not a git repository. Skipping git history scan.")
            return []

        commit_log = _run_git(
            ["log", f"--max-count={max_commits}", "--pretty=format:%H|%an|%ae|%ad|%s", "--date=short"],
            directory
        )
        if not commit_log:
            print("  ⚠️  No commits found.")
            return []

        commits = [line.split("|", 4) for line in commit_log.strip().splitlines() if line]
        print(f"  📊 Scanning {len(commits)} commits (max {max_commits})")

        all_findings = []
        for commit_parts in commits:
            if len(commit_parts) < 5:
                continue
            sha, author, email, date, message = commit_parts
            findings = self._scan_commit(directory, sha, author, date, message)
            all_findings.extend(findings)

        # Scan working tree for secrets too
        wt_findings = self._scan_working_tree(directory)
        all_findings.extend(wt_findings)

        self.findings = all_findings
        self._print_summary(all_findings)
        return all_findings

    def _scan_commit(self, directory: str, sha: str, author: str, date: str, message: str) -> List[Dict]:
        diff = _run_git(["show", "--no-color", "-U0", sha], directory)
        if not diff:
            return []

        findings = []
        current_file = "unknown"
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
                ext = os.path.splitext(current_file)[1].lower()
                if ext in SKIP_EXTENSIONS:
                    current_file = "__skip__"
            if current_file == "__skip__":
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue
            added_line = line[1:]
            for name, pattern, severity in SECRET_PATTERNS:
                m = re.search(pattern, added_line)
                if m:
                    masked = re.sub(r'([A-Za-z0-9+/]{4})[A-Za-z0-9+/]{8,}', r'\1****', added_line)
                    findings.append({
                        "type": "secret_in_history",
                        "secret_type": name,
                        "severity": severity,
                        "commit": sha[:8],
                        "author": author,
                        "date": date,
                        "file": current_file,
                        "line_masked": masked.strip()[:120],
                        "message": "Secret found in git history — rotate immediately",
                    })
                    break
            for desc, pattern in REGRESSION_PATTERNS:
                if re.search(pattern, added_line):
                    findings.append({
                        "type": "regression_risk",
                        "description": desc,
                        "severity": "MEDIUM",
                        "commit": sha[:8],
                        "author": author,
                        "date": date,
                        "file": current_file,
                        "snippet": added_line.strip()[:100],
                    })
                    break
        return findings

    def _scan_working_tree(self, directory: str) -> List[Dict]:
        findings = []
        skip_dirs = {'.git', 'node_modules', 'dist', 'build', 'vendor', '.nyc_output'}
        scan_extensions = {'.ts', '.js', '.py', '.env', '.json', '.yaml', '.yml',
                           '.conf', '.config', '.sh', '.bash', '.zsh', '.properties'}
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()
                base = os.path.basename(fname).lower()
                if ext not in scan_extensions and not base.startswith('.env'):
                    continue
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        for i, line in enumerate(f, 1):
                            for name, pattern, severity in SECRET_PATTERNS[:10]:
                                if re.search(pattern, line):
                                    masked = re.sub(r'([A-Za-z0-9+/]{4})[A-Za-z0-9+/]{8,}', r'\1****', line)
                                    findings.append({
                                        "type": "secret_in_working_tree",
                                        "secret_type": name,
                                        "severity": severity,
                                        "file": os.path.relpath(fpath, directory),
                                        "line": i,
                                        "line_masked": masked.strip()[:120],
                                        "message": "Secret in working tree",
                                    })
                                    break
                except Exception:
                    pass
        return findings

    def _print_summary(self, findings: List[Dict]):
        secrets = [f for f in findings if "secret" in f.get("type", "")]
        regressions = [f for f in findings if f.get("type") == "regression_risk"]
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        print(f"\n  📊 Git Scan Summary:")
        print(f"     Secrets found  : {len(secrets)} ({len(critical)} CRITICAL)")
        print(f"     Regressions    : {len(regressions)}")
        if secrets:
            print("\n  🔑 Secret findings:")
            for s in secrets[:5]:
                print(f"     [{s.get('severity','?')}] {s.get('secret_type','?')} in {s.get('file','?')} (commit {s.get('commit','working tree')})")

    def save(self, output_path: str):
        report = {
            "generated": datetime.now().isoformat(),
            "total": len(self.findings),
            "critical": [f for f in self.findings if f.get("severity") == "CRITICAL"],
            "secrets": [f for f in self.findings if "secret" in f.get("type", "")],
            "regressions": [f for f in self.findings if f.get("type") == "regression_risk"],
            "all": self.findings,
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  💾 Git scan report → {output_path}")
        return report


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = NovaGitScanner()
    findings = scanner.scan_directory(target)
    scanner.save("nova_git_scan_report.json")
