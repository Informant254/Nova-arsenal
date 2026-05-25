#!/usr/bin/env python3
"""
NOVA SOURCE CODE AUDITOR v1.0
Autonomous vulnerability discovery in source code.
Clones repos, traces data flows, generates PoC exploits.
Inspired by Sandyaa, xvulnhuntr, and VulnMiner.
"""

import json, time, re, os, subprocess, tempfile
from datetime import datetime
from typing import Dict, List, Optional

class NovaSourceAuditor:
    def __init__(self):
        self.findings = []
        self.audit_dir = tempfile.mkdtemp(prefix="nova_audit_")
        
        # Dangerous sink patterns - same ones Nova already knows
        self.sinks = {
            "sql_injection": [
                (r'\.execute\s*\(\s*[\"\'].*?\$', "SQL injection - user input in SQL query"),
                (r'\.query\s*\(\s*[\"\'].*?\+', "SQL injection - string concatenation in query"),
                (r'\.raw\s*\(\s*[\"\'].*?\+', "SQL injection - raw query with concatenation"),
                (r'cursor\.execute\(.*?format\(', "SQL injection - format string in query"),
            ],
            "command_injection": [
                (r'os\.system\s*\(.*?\+', "Command injection - os.system with concatenation"),
                (r'subprocess\.call\s*\(.*?\+', "Command injection - subprocess with user input"),
                (r'exec\s*\(.*?\+', "Command injection - exec with concatenation"),
                (r'eval\s*\(.*?\+', "Command injection - eval with user input"),
            ],
            "xss": [
                (r'innerHTML\s*=', "XSS - innerHTML assignment"),
                (r'document\.write\s*\(', "XSS - document.write with user input"),
                (r'\.html\s*\(.*?\+', "XSS - jQuery html() with concatenation"),
                (r'dangerouslySetInnerHTML', "XSS - React dangerouslySetInnerHTML"),
            ],
            "path_traversal": [
                (r'open\s*\(.*?\+', "Path traversal - file open with user input"),
                (r'readFile\s*\(.*?\+', "Path traversal - readFile with concatenation"),
                (r'sendFile\s*\(.*?\+', "Path traversal - sendFile with user input"),
            ],
            "ssrf": [
                (r'requests\.get\s*\(.*?\+', "SSRF - requests.get with user-controlled URL"),
                (r'fetch\s*\(.*?\+', "SSRF - fetch with user-controlled URL"),
                (r'urllib.*?urlopen.*?\+', "SSRF - urllib with user input"),
            ],
            "insecure_deserialization": [
                (r'pickle\.loads\s*\(', "Insecure deserialization - pickle.loads"),
                (r'yaml\.load\s*\(', "Insecure deserialization - yaml.load without SafeLoader"),
                (r'json\.loads\s*\(.*?\+', "Insecure deserialization - json.loads with user input"),
            ],
        }
        
        # Taint sources - where user input enters the system
        self.taint_sources = [
            (r'req\.body', "HTTP request body"),
            (r'req\.query', "HTTP query parameters"),
            (r'req\.params', "HTTP route parameters"),
            (r'req\.headers', "HTTP headers"),
            (r'request\.form', "HTTP form data"),
            (r'request\.args', "HTTP URL arguments"),
            (r'request\.json', "HTTP JSON body"),
            (r'input\s*\(', "User input function"),
            (r'readline', "Console input"),
            (r'sys\.argv', "Command line arguments"),
            (r'os\.environ', "Environment variables"),
        ]

    def clone_repo(self, repo_url: str) -> Optional[str]:
        """Clone a GitHub repository for analysis."""
        print(f"\n📦 Cloning: {repo_url}")
        try:
            repo_name = repo_url.split("/")[-1].replace(".git", "")
            target_dir = os.path.join(self.audit_dir, repo_name)
            subprocess.run(["git", "clone", "--depth", "1", repo_url, target_dir], 
                          capture_output=True, check=True, timeout=60)
            print(f"   ✅ Cloned to: {target_dir}")
            return target_dir
        except Exception as e:
            print(f"   ❌ Clone failed: {str(e)[:80]}")
            return None

    def scan_file(self, filepath: str) -> List[Dict]:
        """Scan a single source file for vulnerabilities."""
        findings = []
        
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except:
            return findings
        
        lines = source.split("\n")
        filename = os.path.basename(filepath)
        
        # Step 1: Find all taint sources (user input)
        taint_locations = []
        for i, line in enumerate(lines, 1):
            for pattern, description in self.taint_sources:
                if re.search(pattern, line, re.IGNORECASE):
                    taint_locations.append({
                        "line": i,
                        "source": description,
                        "code": line.strip()[:100],
                    })
        
        if not taint_locations:
            return findings  # No user input - nothing to exploit
        
        # Step 2: Find all dangerous sinks
        sink_locations = []
        for i, line in enumerate(lines, 1):
            for vuln_type, patterns in self.sinks.items():
                for pattern, description in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        sink_locations.append({
                            "line": i,
                            "type": vuln_type,
                            "description": description,
                            "code": line.strip()[:100],
                        })
        
        # Step 3: Match taint sources to sinks (data flow)
        for taint in taint_locations:
            for sink in sink_locations:
                # If taint comes before sink in the same file, potential flow
                if taint["line"] <= sink["line"]:
                    # Check if the tainted variable appears near the sink
                    var_match = re.search(r'(?:req\.|request\.|input\(|sys\.argv|os\.environ)(\w+)', taint["code"])
                    var_name = var_match.group(0) if var_match else ""
                    
                    if var_name and var_name in sink["code"]:
                        finding = {
                            "file": filename,
                            "vulnerability_type": sink["type"],
                            "taint_source": taint["source"],
                            "taint_line": taint["line"],
                            "taint_code": taint["code"],
                            "sink_line": sink["line"],
                            "sink_code": sink["code"],
                            "description": sink["description"],
                            "confidence": "HIGH",
                            "severity": "CRITICAL" if sink["type"] in ["sql_injection", "command_injection"] else "HIGH",
                        }
                        findings.append(finding)
        
        return findings

    def scan_directory(self, target_dir: str) -> List[Dict]:
        """Scan an entire directory for vulnerabilities."""
        print(f"\n🔍 Scanning: {target_dir}")
        all_findings = []
        
        extensions = [".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs"]
        scanned = 0
        
        for root, dirs, files in os.walk(target_dir):
            # Skip hidden directories and node_modules
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    filepath = os.path.join(root, file)
                    findings = self.scan_file(filepath)
                    all_findings.extend(findings)
                    scanned += 1
                    
                    if findings:
                        print(f"   🔥 {file}: {len(findings)} finding(s)")
        
        print(f"   📊 Scanned {scanned} files, found {len(all_findings)} potential vulnerabilities")
        return all_findings

    def match_cves(self, findings: List[Dict]) -> List[Dict]:
        """Match findings against known CVE patterns."""
        cve_patterns = {
            "sql_injection": "CWE-89",
            "command_injection": "CWE-78",
            "xss": "CWE-79",
            "path_traversal": "CWE-22",
            "ssrf": "CWE-918",
            "insecure_deserialization": "CWE-502",
        }
        
        for finding in findings:
            vuln_type = finding.get("vulnerability_type", "")
            finding["cwe"] = cve_patterns.get(vuln_type, "Unknown")
            finding["cvss_base"] = "9.8" if finding.get("severity") == "CRITICAL" else "7.5"
        
        return findings

    def generate_poc(self, finding: Dict) -> str:
        """Generate a proof-of-concept exploit."""
        vuln_type = finding["vulnerability_type"]
        
        if vuln_type == "sql_injection":
            return "' OR 1=1--"
        elif vuln_type == "command_injection":
            return "; id"
        elif vuln_type == "xss":
            return "<script>alert('NOVA')</script>"
        elif vuln_type == "path_traversal":
            return "../../../etc/passwd"
        elif vuln_type == "ssrf":
            return "http://169.254.169.254/latest/meta-data/"
        elif vuln_type == "insecure_deserialization":
            return '{"__class__": "subprocess.Popen", "args": ["id"]}'
        return ""

    def generate_report(self, findings: List[Dict], repo_url: str):
        """Generate comprehensive audit report."""
        # Deduplicate by file + line
        seen = set()
        unique = []
        for f in findings:
            key = (f["file"], f["sink_line"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        
        critical = [f for f in unique if f["severity"] == "CRITICAL"]
        high = [f for f in unique if f["severity"] == "HIGH"]
        
        report = {
            "audit_date": datetime.now().isoformat(),
            "repository": repo_url,
            "files_scanned": len(set(f["file"] for f in unique)),
            "findings": {
                "critical": len(critical),
                "high": len(high),
                "total": len(unique),
            },
            "vulnerabilities": unique,
        }
        
        filename = f"nova_audit_{repo_url.split('/')[-1].replace('.git', '')}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"""
╔══════════════════════════════════════════════════════════╗
║     SOURCE CODE AUDIT COMPLETE                          ║
╠══════════════════════════════════════════════════════════╣
║  Repository: {repo_url[:40]:<40} ║
║  Critical: {len(critical):<3}  |  High: {len(high):<3}  |  Total: {len(unique):<3}                ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        if critical:
            print("💀 CRITICAL VULNERABILITIES:")
            for f in critical[:5]:
                print(f"   🔥 {f['file']}:{f['sink_line']} — {f['description']}")
                print(f"      CWE: {f.get('cwe', 'N/A')} | CVSS: {f.get('cvss_base', 'N/A')}")
                print(f"      PoC: {self.generate_poc(f)}")
        
        print(f"\n📁 Report: {filename}")
        return report

    def run_audit(self, repo_url: str):
        """Execute full source code audit."""
        print("""
╔══════════════════════════════════════════════════════════╗
║   🦅 NOVA SOURCE CODE AUDITOR v1.0                     ║
║   Autonomous Vulnerability Discovery                    ║
║   Clone → Scan → Match CVEs → Generate PoC            ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        # Clone repository
        target_dir = self.clone_repo(repo_url)
        if not target_dir:
            print("❌ Cannot proceed without repository")
            return
        
        # Scan for vulnerabilities
        findings = self.scan_directory(target_dir)
        
        # Match against CVEs
        findings = self.match_cves(findings)
        
        # Generate report
        self.generate_report(findings, repo_url)

if __name__ == "__main__":
    import sys
    auditor = NovaSourceAuditor()
    
    # Default: audit Juice Shop source
    target = sys.argv[1] if len(sys.argv) > 1 else "https://github.com/juice-shop/juice-shop.git"
    auditor.run_audit(target)
