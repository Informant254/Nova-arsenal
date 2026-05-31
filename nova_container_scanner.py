#!/usr/bin/env python3
"""
NOVA CONTAINER SCANNER v1.0
Security analysis of Dockerfiles, docker-compose, and Kubernetes manifests.
Finds: running as root, SUID binaries, exposed secrets, dangerous capabilities,
missing security contexts, insecure base images, and misconfigs.
"""
import os, re, json, yaml
from typing import Dict, List
from datetime import datetime

DOCKERFILE_CHECKS = [
    (r'^FROM\s+\w[^\s]*:latest', "Base image pinned to :latest — non-deterministic builds", "MEDIUM"),
    (r'^FROM\s+scratch', "FROM scratch — ensure binary is statically compiled", "INFO"),
    (r'(?i)\bUSER\s+root\b', "Container runs as root", "HIGH"),
    (r'(?i)\bADD\s+https?://', "ADD with URL — use COPY + separate RUN curl instead", "MEDIUM"),
    (r'(?i)\bRUN\s+.*curl\s+.*\|\s*(bash|sh)', "Curl-pipe-bash in Dockerfile", "HIGH"),
    (r'(?i)\bRUN\s+.*wget\s+.*-O\s*-\s*\|\s*(bash|sh)', "Wget-pipe-bash in Dockerfile", "HIGH"),
    (r'(?i)chmod\s+[74][74][74]', "World-writable/executable permissions set", "HIGH"),
    (r'(?i)EXPOSE\s+22\b', "SSH port 22 exposed", "MEDIUM"),
    (r'(?i)(password|passwd|secret|api_key|token)\s*=\s*\S+', "Hardcoded secret in Dockerfile ENV/ARG", "CRITICAL"),
    (r'(?i)--privileged', "Container privileged flag", "CRITICAL"),
    (r'(?i)--cap-add\s+ALL', "All Linux capabilities added", "HIGH"),
    (r'(?i)--security-opt\s+seccomp=unconfined', "Seccomp disabled", "HIGH"),
    (r'(?i)--security-opt\s+apparmor=unconfined', "AppArmor disabled", "HIGH"),
    (r'(?i)\.ssh\b', "SSH directory included in image", "HIGH"),
    (r'(?i)\bENV\s+(AWS_|SECRET|PASSWORD|TOKEN|KEY)', "Sensitive env var in Dockerfile", "HIGH"),
    (r'(?i)\bARG\s+(AWS_|SECRET|PASSWORD|TOKEN|KEY)', "Sensitive build arg in Dockerfile (appears in image history)", "HIGH"),
    (r'(?i)--no-check-certificate', "SSL verification disabled", "MEDIUM"),
    (r'(?i)apt-get\s+install\s+.*\s+-y\s+.*ssh', "SSH installed in container", "MEDIUM"),
    (r'(?i)RUN\s+.*pip\s+install\s+--trusted-host', "pip trusted-host bypasses SSL", "MEDIUM"),
    (r'(?i)npm\s+install\s+.*--unsafe-perm', "npm --unsafe-perm", "MEDIUM"),
]

COMPOSE_CHECKS = [
    (r'(?i)privileged:\s*true', "Privileged container", "CRITICAL"),
    (r'(?i)network_mode:\s*host', "Host network mode — bypasses network isolation", "HIGH"),
    (r'(?i)pid:\s*host', "Host PID namespace — container can see host processes", "HIGH"),
    (r'(?i)cap_add:\s*\n\s*-\s*ALL', "All capabilities added", "HIGH"),
    (r'(?i)/var/run/docker\.sock', "Docker socket mounted — container escape risk", "CRITICAL"),
    (r'(?i)/etc/passwd', "Sensitive host file mounted", "HIGH"),
    (r'(?i)/proc:', "Host /proc mounted", "HIGH"),
    (r'(?i)(password|secret|api_key|token)\s*:\s*\S+(?!\$)', "Hardcoded secret in compose", "CRITICAL"),
    (r'(?i)read_only:\s*false', "Root filesystem not read-only", "INFO"),
    (r'(?i)no-new-privileges:\s*false', "no-new-privileges disabled", "MEDIUM"),
    (r'(?i)ports:\s*\n\s*-\s*"?0\.0\.0\.0', "Service bound to all interfaces", "MEDIUM"),
]

K8S_CHECKS = [
    (r'(?i)allowPrivilegeEscalation:\s*true', "Privilege escalation allowed", "HIGH"),
    (r'(?i)privileged:\s*true', "Privileged container", "CRITICAL"),
    (r'(?i)runAsRoot:\s*true', "RunAsRoot: true", "HIGH"),
    (r'(?i)hostNetwork:\s*true', "Host network — bypasses network isolation", "HIGH"),
    (r'(?i)hostPID:\s*true', "Host PID namespace", "HIGH"),
    (r'(?i)hostIPC:\s*true', "Host IPC namespace", "HIGH"),
    (r'(?i)capabilities:\s*\n\s*add:\s*\n\s*-\s*ALL', "All capabilities added", "HIGH"),
    (r'(?i)/var/run/docker\.sock', "Docker socket mounted", "CRITICAL"),
    (r'(?i)automountServiceAccountToken:\s*true', "ServiceAccount token auto-mounted", "MEDIUM"),
    (r'(?i)imagePullPolicy:\s*Always', "imagePullPolicy: Always — potential image substitution", "INFO"),
    (r'(?i)(password|secret|apiKey|token)\s*:\s*[^\$\{\(][^\n]{4,}', "Hardcoded secret in K8s manifest", "CRITICAL"),
    (r'(?i)securityContext:\s*\{\s*\}', "Empty security context — no restrictions applied", "MEDIUM"),
    (r'(?i)readOnlyRootFilesystem:\s*false', "Root filesystem not read-only", "INFO"),
    (r'(?i)runAsNonRoot:\s*false', "Running as root allowed", "HIGH"),
]

INSECURE_BASES = {
    "ubuntu:latest", "debian:latest", "centos:latest", "alpine:latest",
    "node:latest", "python:latest", "openjdk:latest", "ruby:latest",
    "php:latest", "golang:latest", "nginx:latest", "httpd:latest",
}


class NovaContainerScanner:
    def __init__(self):
        self.findings: List[Dict] = []

    def _scan_file(self, fpath: str, content: str, checks: List[tuple]) -> List[Dict]:
        findings = []
        lines = content.splitlines()
        rel = os.path.relpath(fpath)
        for i, line in enumerate(lines, 1):
            for pat, desc, sev in checks:
                if re.search(pat, line, re.MULTILINE):
                    findings.append({"type": "Container Misconfiguration", "severity": sev,
                        "file": rel, "line": i, "description": desc,
                        "snippet": line.strip()[:120]})
                    break
        return findings

    def scan_directory(self, directory: str) -> List[Dict]:
        print(f"\n🐳 NOVA CONTAINER SCANNER — {directory}")
        print("=" * 60)
        all_findings = []
        files_scanned = 0
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in (".git","node_modules","dist","build")]
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    content = open(fpath, encoding="utf-8", errors="ignore").read()
                except: continue
                if fname == "Dockerfile" or fname.startswith("Dockerfile."):
                    findings = self._scan_file(fpath, content, DOCKERFILE_CHECKS)
                    # Check insecure base images
                    for m in re.finditer(r'^FROM\s+(\S+)', content, re.MULTILINE):
                        img = m.group(1).lower()
                        if img in INSECURE_BASES:
                            findings.append({"type": "Insecure Base Image", "severity": "MEDIUM",
                                "file": os.path.relpath(fpath), "line": content[:content.find(m.group(0))].count('\n')+1,
                                "description": f"Base image {img} pinned to mutable :latest tag",
                                "snippet": m.group(0)})
                    all_findings.extend(findings)
                    files_scanned += 1
                    if findings: print(f"  📄 {fname}: {len(findings)} finding(s)")
                    else: print(f"  ✅ {fname}: clean")
                elif fname in ("docker-compose.yml","docker-compose.yaml","compose.yml","compose.yaml") or \
                     fname.startswith("docker-compose."):
                    findings = self._scan_file(fpath, content, COMPOSE_CHECKS)
                    all_findings.extend(findings)
                    files_scanned += 1
                    if findings: print(f"  📄 {os.path.relpath(fpath)}: {len(findings)} finding(s)")
                elif fname.endswith((".yml",".yaml")) and any(k in content for k in
                     ("apiVersion","kind: Pod","kind: Deployment","kind: DaemonSet","kind: StatefulSet")):
                    findings = self._scan_file(fpath, content, K8S_CHECKS)
                    all_findings.extend(findings)
                    files_scanned += 1
                    if findings: print(f"  📄 {os.path.relpath(fpath)}: {len(findings)} finding(s)")
        if files_scanned == 0:
            print("  ℹ️  No container/K8s files found")
        self.findings = all_findings
        critical = [f for f in all_findings if f["severity"]=="CRITICAL"]
        print(f"\n  📊 Container Scan: {len(all_findings)} findings | {len(critical)} CRITICAL | {files_scanned} files")
        return all_findings

    def save(self, path):
        with open(path,"w") as f:
            json.dump({"generated":datetime.now().isoformat(),"findings":self.findings},f,indent=2)
        print(f"  💾 Container report → {path}")


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv)>1 else "."
    s = NovaContainerScanner()
    s.scan_directory(d); s.save("nova_container_report.json")
