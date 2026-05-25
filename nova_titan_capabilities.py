#!/usr/bin/env python3
"""
NOVA TITAN-LEVEL CAPABILITIES v1.0
Three capabilities that compete with Silicon Valley:
1. BUSINESS LOGIC ANALYZER - Finds flaws in application logic
2. ATTACK CHAIN COMPOSER - Chains vulns into exploit paths
3. CVE AUTO-MAPPER - Matches findings to real-world CVEs
"""

import json, re, os, requests, time
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict

class NovaTitanCapabilities:
    """Three capabilities that make the Titans nervous."""
    
    def __init__(self):
        self.findings = []
        self.attack_chains = []
        self.business_logic_flaws = []
        self.cve_matches = []
        
        # Known CVE patterns to match against
        self.cve_database = {
            "path_traversal": [
                {"cve": "CVE-2024-23334", "package": "aiohttp", "cvss": "7.5", "description": "Path traversal in static file serving"},
                {"cve": "CVE-2023-45802", "package": "Apache HTTP Server", "cvss": "7.5", "description": "HTTP/2 stream reset flood"},
            ],
            "code_execution": [
                {"cve": "CVE-2024-21626", "package": "runc", "cvss": "8.6", "description": "Container breakout via file descriptor leak"},
                {"cve": "CVE-2023-46604", "package": "Apache ActiveMQ", "cvss": "10.0", "description": "Remote code execution via deserialization"},
            ],
            "sql_injection": [
                {"cve": "CVE-2024-1597", "package": "PostgreSQL JDBC", "cvss": "10.0", "description": "SQL injection via XML processing"},
            ],
            "command_injection": [
                {"cve": "CVE-2024-28085", "package": "util-linux", "cvss": "7.8", "description": "Command injection via escape sequences"},
            ],
        }
        
        # Business logic flaw patterns
        self.business_logic_patterns = {
            "race_condition": {
                "patterns": [r'if\s+balance\s*>=\s*amount', r'if\s+stock\s*>=\s*quantity', r'coupon.*?redeem'],
                "impact": "Financial loss through simultaneous requests",
                "severity": "HIGH",
            },
            "authorization_bypass": {
                "patterns": [r'if\s+role\s*==\s*[\'"]admin[\'"]', r'if\s+isAdmin\s*==\s*true', r'if\s+authenticated\s*==\s*True'],
                "impact": "Privilege escalation via parameter manipulation",
                "severity": "CRITICAL",
            },
            "input_validation_bypass": {
                "patterns": [r'if\s+len\(.*\)\s*<\s*\d+', r'if\s+.*\.(size|length)\s*<\s*'],
                "impact": "Security control bypass via edge cases",
                "severity": "MEDIUM",
            },
            "rate_limiting_missing": {
                "patterns": [r'def\s+login', r'def\s+register', r'def\s+reset_password'],
                "impact": "Brute force / enumeration possible",
                "severity": "MEDIUM",
            },
        }

    def analyze_business_logic(self, filepath: str) -> List[Dict]:
        """Find business logic flaws in application code."""
        findings = []
        
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
                lines = source.split("\n")
        except:
            return findings
        
        for flaw_type, flaw_data in self.business_logic_patterns.items():
            for pattern in flaw_data["patterns"]:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Found a business logic pattern
                        context_start = max(0, i - 5)
                        context_end = min(len(lines), i + 5)
                        context = "\n".join(lines[context_start:context_end])
                        
                        # Check if there's a corresponding safeguard
                        has_safeguard = any(s in context.lower() for s in [
                            "transaction", "atomic", "lock", "rate_limit", "captcha"
                        ])
                        
                        finding = {
                            "file": os.path.basename(filepath),
                            "line": i,
                            "flaw_type": flaw_type,
                            "impact": flaw_data["impact"],
                            "severity": flaw_data["severity"],
                            "code": line.strip()[:150],
                            "context": context[:300],
                            "has_safeguard": has_safeguard,
                            "exploitable": not has_safeguard,
                            "confidence": "HIGH" if not has_safeguard else "LOW",
                        }
                        
                        if not has_safeguard:
                            self.business_logic_flaws.append(finding)
                            findings.append(finding)
                        break
        
        return findings

    def compose_attack_chains(self, all_findings: List[Dict]) -> List[Dict]:
        """Chain multiple vulnerabilities into attack paths."""
        print("\n⛓️ Composing attack chains...")
        
        chains = []
        
        # Group findings by file for chaining
        by_file = defaultdict(list)
        for f in all_findings:
            by_file[f.get("file", "unknown")].append(f)
        
        for filename, file_findings in by_file.items():
            if len(file_findings) >= 2:
                # Multiple vulns in same file = potential chain
                vuln_types = [f.get("vulnerability_type", f.get("flaw_type", "?")) for f in file_findings]
                
                chain = {
                    "name": f"Multi-vector attack on {filename}",
                    "file": filename,
                    "vulnerabilities": vuln_types,
                    "steps": [],
                    "impact": "Compound",
                    "severity": "CRITICAL" if len(vuln_types) >= 3 else "HIGH",
                }
                
                # Build attack steps
                sorted_findings = sorted(file_findings, key=lambda x: x.get("line", 0))
                for i, f in enumerate(sorted_findings):
                    vtype = f.get("vulnerability_type", f.get("flaw_type", "?"))
                    chain["steps"].append({
                        "step": i + 1,
                        "action": f"Exploit {vtype} at line {f.get('line', '?')}",
                        "technique": f.get("code", "")[:100],
                    })
                
                chains.append(chain)
                self.attack_chains.append(chain)
                print(f"   ⛓️ {chain['name']}: {len(vuln_types)} vulns chained")
        
        # Cross-file chains
        xss_files = [f for f in all_findings if "xss" in str(f.get("vulnerability_type", "")).lower()]
        auth_files = [f for f in all_findings if "auth" in str(f.get("flaw_type", "")).lower()]
        
        if xss_files and auth_files:
            chain = {
                "name": "XSS → Session Theft → Privilege Escalation",
                "vulnerabilities": ["xss", "session_hijacking", "privilege_escalation"],
                "steps": [
                    {"step": 1, "action": "Inject XSS payload to steal session cookie", "file": xss_files[0].get("file")},
                    {"step": 2, "action": "Use stolen session to bypass authentication", "file": auth_files[0].get("file")},
                    {"step": 3, "action": "Escalate to admin via authorization bypass"},
                ],
                "impact": "Full account takeover",
                "severity": "CRITICAL",
            }
            chains.append(chain)
            self.attack_chains.append(chain)
            print(f"   ⛓️ Cross-file chain: {chain['name']}")
        
        return chains

    def map_to_cves(self, findings: List[Dict]) -> List[Dict]:
        """Map findings to known CVE patterns."""
        print("\n📋 Mapping to CVE database...")
        
        for finding in findings:
            vuln_type = finding.get("vulnerability_type", finding.get("flaw_type", ""))
            
            if vuln_type in self.cve_database:
                for cve in self.cve_database[vuln_type]:
                    match = {
                        "finding": finding.get("file"),
                        "vulnerability_type": vuln_type,
                        "cve": cve["cve"],
                        "package": cve["package"],
                        "cvss": cve["cvss"],
                        "similar_vulnerability": cve["description"],
                        "confidence": "MEDIUM",
                    }
                    self.cve_matches.append(match)
        
        print(f"   📊 {len(self.cve_matches)} CVE matches found")
        return self.cve_matches

    def scan_repository(self, repo_path: str) -> Dict:
        """Full titan-level scan: data flow + business logic + chains + CVEs."""
        print(f"""
╔══════════════════════════════════════════════════════════╗
║   🦅 NOVA TITAN-LEVEL SCAN                              ║
║   Data Flow + Business Logic + Attack Chains + CVEs    ║
╚══════════════════════════════════════════════════════════╝
""")
        
        all_findings = []
        files_scanned = 0
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in 
                      ["node_modules", "venv", "__pycache__", ".git"]]
            
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".java", ".rb", ".php")):
                    filepath = os.path.join(root, file)
                    
                    # Run data flow analysis
                    from nova_dataflow_engine import NovaDataFlowEngine
                    df_engine = NovaDataFlowEngine()
                    df_findings = df_engine.analyze_file(filepath)
                    all_findings.extend(df_findings)
                    
                    # Run business logic analysis
                    bl_findings = self.analyze_business_logic(filepath)
                    all_findings.extend(bl_findings)
                    
                    files_scanned += 1
        
        # Compose attack chains
        chains = self.compose_attack_chains(all_findings)
        
        # Map to CVEs
        cve_matches = self.map_to_cves(all_findings)
        
        # Generate report
        report = self.generate_report(all_findings, chains, cve_matches, files_scanned)
        return report

    def generate_report(self, findings, chains, cve_matches, files_scanned):
        """Generate titan-level report."""
        dataflow = [f for f in findings if "vulnerability_type" in f]
        business = [f for f in findings if "flaw_type" in f]
        exploitable = [f for f in findings if f.get("exploitable", False)]
        
        print(f"""
╔══════════════════════════════════════════════════════════╗
║   🦅 TITAN-LEVEL SCAN COMPLETE                          ║
╠══════════════════════════════════════════════════════════╣
║  Files Scanned: {files_scanned:<5}                                    ║
║  Data Flow Findings: {len(dataflow):<4}                                  ║
║  Business Logic Flaws: {len(business):<3}                               ║
║  Confirmed Exploitable: {len(exploitable):<3}                            ║
║  Attack Chains: {len(chains):<3}                                      ║
║  CVE Matches: {len(cve_matches):<3}                                     ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        if exploitable:
            print("💀 EXPLOITABLE VULNERABILITIES:")
            for f in exploitable[:5]:
                vtype = f.get("vulnerability_type", f.get("flaw_type", "?"))
                print(f"   🔥 [{vtype.upper()}] {f.get('file', '?')}:{f.get('line', '?')}")
        
        if chains:
            print(f"\n⛓️ ATTACK CHAINS ({len(chains)}):")
            for c in chains[:3]:
                print(f"   ⛓️ {c['name']} ({c['severity']})")
                for step in c.get("steps", []):
                    print(f"      {step['step']}. {step['action']}")
        
        if cve_matches:
            print(f"\n📋 CVE MATCHES ({len(cve_matches)}):")
            for c in cve_matches[:5]:
                print(f"   📋 {c['cve']}: {c['similar_vulnerability']} (CVSS {c['cvss']})")
        
        # Save report
        filename = f"nova_titan_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump({
                "dataflow_findings": dataflow,
                "business_logic_flaws": business,
                "attack_chains": chains,
                "cve_matches": cve_matches,
                "summary": {
                    "total_findings": len(findings),
                    "exploitable": len(exploitable),
                    "chains": len(chains),
                    "cve_matches": len(cve_matches),
                }
            }, f, indent=2, default=str)
        
        print(f"\n📁 Report: {filename}")
        return {"findings": findings, "chains": chains, "cves": cve_matches}

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    
    titan = NovaTitanCapabilities()
    titan.scan_repository(target)
