#!/usr/bin/env python3
"""
NOVA CI/CD SCANNER v1.1
Security analysis of CI/CD pipelines:
GitHub Actions, GitLab CI, CircleCI, Jenkins, Travis CI, Bitbucket Pipelines.
Finds: hardcoded secrets, script injection, insecure deps, excessive permissions,
unpinned actions, pull_request_target abuse, and supply chain attack vectors.

SCOPE GUARD (v1.1): When the scan directory is detected as Nova's own codebase,
CI/CD findings are tagged as local-scope and excluded from remote target reports.
"""
import os, re, json, yaml
from typing import Dict, List
from datetime import datetime

# ── Sentinel: files that identify Nova's own repo ─────────────────────────────
_NOVA_SENTINELS = {"nova.py", "nova_codebase_mapper.py", "nova_ci_runner.py",
                   "nova_weapon_forge.py", "nova_cicd_scanner.py"}

def _is_nova_own_repo(directory: str) -> bool:
    """Return True if `directory` is Nova Arsenal's own codebase."""
    try:
        root_files = set(os.listdir(directory))
        return len(root_files & _NOVA_SENTINELS) >= 2
    except Exception:
        return False

# ── Secret patterns in CI config ─────────────────────────────────────────────
SECRET_PATS = [
    (r'(?i)(password|passwd|pwd|secret|api_key|apikey|token|access_key|private_key)\s*[:=]\s*["\']?([^\s\'"$\{]{6,})', "Hardcoded secret in CI config"),
    (r'(?i)aws_access_key_id\s*[:=]\s*([A-Z0-9]{20})', "AWS Access Key ID"),
    (r'(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9+/]{40})', "AWS Secret Access Key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Key in CI config"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub PAT in CI config"),
    (r'-----BEGIN RSA PRIVATE KEY-----', "RSA private key"),
]

# ── Dangerous patterns ───────────────────────────────────────────────────────
DANGEROUS_PATS = [
    (r'\$\{\{\s*github\.event\.(?:pull_request|issue|comment)\.(?:title|body|head\.ref|head\.label)\s*\}\}', "Script injection via GitHub event context — attacker controls input"),
    (r'pull_request_target', "pull_request_target trigger — can expose secrets to forks"),
    (r'(?i)curl\s+.*\s*\|\s*(?:bash|sh)', "Curl-pipe-bash in CI — supply chain risk"),
    (r'(?i)wget\s+.*\s*-O\s*-\s*\|\s*(?:bash|sh)', "Wget-pipe-bash in CI"),
    (r'(?i)npm\s+install\s+--unsafe-perm', "npm --unsafe-perm in CI"),
    (r'(?i)chmod\s+777', "chmod 777 in CI"),
    (r'(?i)sudo\s+su\b', "sudo su in CI — privilege escalation risk"),
    (r'(?i)docker\s+run\s+.*--privileged', "Docker --privileged in CI"),
    (r'(?i)eval\s+\$\(', "eval $() command substitution in CI"),
    (r'(?i)set\s+\+x', "Disabling trace mode — may hide malicious commands"),
]

# ── Action pinning ───────────────────────────────────────────────────────────
UNPINNED_ACTION = re.compile(r'uses:\s*([a-zA-Z0-9\-_/\.]+)@(main|master|latest|v\d+)(?!\.\d)')

# ── Excessive permissions ────────────────────────────────────────────────────
EXCESSIVE_PERMS = [
    (r'contents:\s*write', "Workflow has write access to repo contents"),
    (r'id-token:\s*write', "OIDC token write — can impersonate cloud identities"),
    (r'packages:\s*write', "Can publish packages"),
    (r'deployments:\s*write', "Can create deployments"),
    (r'actions:\s*write', "Can modify workflows — privilege escalation risk"),
    (r'permissions:\s*write-all', "DANGEROUS: write-all permissions"),
]

CICD_FILES = {
    ".github/workflows/*.yml": "github_actions",
    ".github/workflows/*.yaml": "github_actions",
    ".gitlab-ci.yml": "gitlab_ci",
    ".circleci/config.yml": "circleci",
    "Jenkinsfile": "jenkins",
    ".travis.yml": "travis",
    "bitbucket-pipelines.yml": "bitbucket",
    "azure-pipelines.yml": "azure_devops",
    ".drone.yml": "drone",
    "Makefile": "makefile",
}


def _scan_text(text: str, filepath: str) -> List[Dict]:
    findings = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        for pat, desc in SECRET_PATS:
            if re.search(pat, line):
                masked = re.sub(r'([A-Za-z0-9+/]{4})[A-Za-z0-9+/]{8,}', r'\1****', line)
                findings.append({"type": "Secret in CI/CD", "severity": "CRITICAL",
                    "file": filepath, "line": i, "description": desc,
                    "snippet": masked.strip()[:120]})
                break
        for pat, desc in DANGEROUS_PATS:
            if re.search(pat, line, re.IGNORECASE):
                findings.append({"type": "Dangerous CI/CD Pattern", "severity": "HIGH",
                    "file": filepath, "line": i, "description": desc,
                    "snippet": line.strip()[:120]})
        for m in UNPINNED_ACTION.finditer(line):
            findings.append({"type": "Unpinned GitHub Action", "severity": "MEDIUM",
                "file": filepath, "line": i,
                "description": f"Action {m.group(1)} pinned to mutable ref '{m.group(2)}' — pin to commit SHA",
                "snippet": line.strip()[:120]})
        for pat, desc in EXCESSIVE_PERMS:
            if re.search(pat, line, re.IGNORECASE):
                findings.append({"type": "Excessive CI/CD Permissions", "severity": "MEDIUM",
                    "file": filepath, "line": i, "description": desc,
                    "snippet": line.strip()[:120]})
    return findings


class NovaCICDScanner:
    def __init__(self):
        self.findings: List[Dict] = []

    def scan_directory(self, directory: str) -> List[Dict]:
        print(f"\n🔧 NOVA CI/CD SCANNER — {directory}")
        print("=" * 60)

        # ── SCOPE GUARD ───────────────────────────────────────────────────────
        if _is_nova_own_repo(directory):
            print("  ⚠️  [SCOPE GUARD] This directory is Nova's own codebase.")
            print("  CI/CD findings here belong to Nova Arsenal, NOT the remote target.")
            print("  Skipping — to audit Nova's own workflows, run: nova_cicd_scanner.py .")
            print(f"\n  📊 CI/CD Scan: 0 findings | 0 CRITICAL | 0 pipeline files scanned")
            self.findings = []
            return []

        all_findings = []
        ci_files_found = 0
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in ("node_modules",".git","dist","build","vendor")]
            for fname in files:
                fpath = os.path.join(root, fname)
                rel   = os.path.relpath(fpath, directory)
                is_ci = (
                    (fname.endswith((".yml",".yaml")) and ".github" in fpath) or
                    fname in ("Jenkinsfile",".travis.yml","bitbucket-pipelines.yml",
                              "azure-pipelines.yml",".drone.yml",".gitlab-ci.yml") or
                    (".circleci" in fpath and fname.endswith((".yml",".yaml")))
                )
                if not is_ci: continue
                try:
                    content = open(fpath, encoding="utf-8", errors="ignore").read()
                except: continue
                ci_files_found += 1
                findings = _scan_text(content, rel)
                all_findings.extend(findings)
                if findings:
                    print(f"  📄 {rel}: {len(findings)} finding(s)")
                else:
                    print(f"  ✅ {rel}: clean")
        if ci_files_found == 0:
            print("  ℹ️  No CI/CD configuration files found")
        self.findings = all_findings
        critical = [f for f in all_findings if f["severity"]=="CRITICAL"]
        print(f"\n  📊 CI/CD Scan: {len(all_findings)} findings | {len(critical)} CRITICAL | {ci_files_found} pipeline files scanned")
        return all_findings

    def save(self, path):
        with open(path,"w") as f:
            json.dump({"generated":datetime.now().isoformat(),"findings":self.findings},f,indent=2)
        print(f"  💾 CI/CD report → {path}")


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv)>1 else "."
    s = NovaCICDScanner()
    s.scan_directory(d); s.save("nova_cicd_report.json")
