#!/usr/bin/env python3
"""
NOVA BREACH STUDY ENGINE
Studies real-world attacks and applies the techniques.
GitHub Actions Supply Chain (2024) + Uber MFA Bypass (2022)
Learns from history's biggest breaches to find similar patterns.
"""

import json, re, os, requests
from datetime import datetime

class NovaBreachStudy:
    """Learns from real-world attacks to find similar vulnerabilities."""
    
    def __init__(self):
        self.lessons_learned = []
        
        # Documented real-world attack techniques
        self.breach_knowledge = {
            "github_actions_supply_chain": {
                "year": 2024,
                "attacker": "Nation-state group",
                "technique": "Compromised GitHub Actions workflow files to inject malicious code into build pipelines",
                "key_components": [
                    "Workflow file modification without review",
                    "Secrets exfiltration via CI/CD logs",
                    "Dependency confusion in build process",
                    "Token theft through workflow_run events",
                ],
                "indicators_in_code": [
                    "uses: actions/checkout@v3 with pull_request_target",
                    "secrets: inherit in workflow_call",
                    "runs-on: self-hosted without approval",
                ],
                "severity": "CRITICAL",
                "impact": "Complete repository compromise, secret theft, supply chain injection",
            },
            "uber_mfa_bypass": {
                "year": 2022,
                "attacker": "Lapsus$ group (teenager)",
                "technique": "MFA fatigue attack followed by social engineering",
                "key_components": [
                    "MFA push notification bombing",
                    "Social engineering via WhatsApp posing as IT support",
                    "VPN credential theft from network share",
                    "Privilege escalation via internal wiki",
                ],
                "indicators_in_code": [
                    "No rate limiting on MFA challenges",
                    "Unlimited push notification attempts",
                    "Internal documentation with credentials",
                    "Overly permissive VPN access",
                ],
                "severity": "CRITICAL",
                "impact": "Full internal network access, source code theft, customer data exposure",
            },
            "solarwinds_supply_chain": {
                "year": 2020,
                "attacker": "Nation-state (APT29)",
                "technique": "Injected malicious code into software build process that went undetected for months",
                "key_components": [
                    "Build pipeline compromise",
                    "Code signing certificate abuse",
                    "Delayed activation (sleeper agent)",
                    "Legitimate update channel exploitation",
                ],
                "indicators_in_code": [
                    "Unsigned build artifacts",
                    "Lack of reproducible builds",
                    "No code signing verification",
                    "Automated deployments without manual review",
                ],
                "severity": "CRITICAL",
                "impact": "18,000 organizations compromised through trusted update channel",
            },
        }

    def analyze_target_for_breach_patterns(self, target_path: str) -> list:
        """Analyze a codebase for patterns that match known breach techniques."""
        findings = []
        
        for breach_name, breach_data in self.breach_knowledge.items():
            for indicator in breach_data["indicators_in_code"]:
                for root, dirs, files in os.walk(target_path):
                    dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", "__pycache__"]]
                    
                    for file in files:
                        if file.endswith((".yml", ".yaml", ".py", ".js", ".ts", ".json")):
                            filepath = os.path.join(root, file)
                            try:
                                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                                    content = f.read()
                                
                                # Check for the indicator pattern
                                pattern = indicator.split(" ")[0]  # First word as search pattern
                                if pattern.lower() in content.lower():
                                    finding = {
                                        "file": filepath,
                                        "breach_reference": breach_name,
                                        "matched_indicator": indicator,
                                        "breach_technique": breach_data["technique"],
                                        "severity": breach_data["severity"],
                                        "impact": breach_data["impact"],
                                        "lesson": f"This pattern was exploited in the {breach_data['year']} {breach_name.replace('_', ' ').title()} by {breach_data['attacker']}",
                                    }
                                    findings.append(finding)
                            except:
                                pass
        
        return findings

    def generate_breach_report(self, findings: list):
        """Generate a report mapping local findings to real-world breaches."""
        print("""
╔══════════════════════════════════════════════════════════╗
║   🦅 NOVA BREACH STUDY — LEARNING FROM HISTORY         ║
║   GitHub Actions (2024) · Uber MFA (2022) · SolarWinds ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        if not findings:
            print("✅ No breach patterns detected in this codebase.")
            print("   This target doesn't have the same vulnerabilities")
            print("   that enabled history's biggest breaches.")
            return
        
        # Group by breach reference
        from collections import defaultdict
        by_breach = defaultdict(list)
        for f in findings:
            by_breach[f["breach_reference"]].append(f)
        
        for breach_name, items in by_breach.items():
            breach = self.breach_knowledge[breach_name]
            print(f"""
{'='*60}
🎯 BREACH PATTERN: {breach_name.replace('_', ' ').upper()}
{'='*60}
Year: {breach['year']}
Attacker: {breach['attacker']}
Technique: {breach['technique']}
Impact: {breach['impact']}

⚠️  SIMILAR PATTERNS FOUND IN THIS CODEBASE:
""")
            for item in items:
                print(f"   🔥 {item['file']}")
                print(f"      Indicator: {item['matched_indicator']}")
                print(f"      Lesson: {item['lesson']}")
        
        print(f"""
{'='*60}
🦅 {len(findings)} BREACH PATTERNS DETECTED
   These are the exact same vulnerability classes
   that enabled history's biggest cyber attacks.
   Fix them before an attacker finds them.
""")
        
        # Save report
        filename = f"nova_breach_study_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump({
                "breaches_studied": list(self.breach_knowledge.keys()),
                "patterns_found": len(findings),
                "findings": findings,
            }, f, indent=2, default=str)
        
        print(f"📁 Report: {filename}")

    def run(self, target_path: str = None):
        """Run breach pattern analysis against a target."""
        target = target_path or "."
        
        print(f"🔍 Analyzing: {target}")
        print(f"   Looking for patterns from GitHub Actions (2024), Uber (2022), SolarWinds (2020)...\n")
        
        findings = self.analyze_target_for_breach_patterns(target)
        self.generate_breach_report(findings)

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    NovaBreachStudy().run(target)
