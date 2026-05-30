#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🚀 NOVA PIPELINE v1.0 — UNIFIED HUNT ORCHESTRATOR               ║
║                                                                      ║
║   ONE COMMAND → FULL AUTONOMOUS HUNT                                ║
║   python nova_pipeline.py --target https://target.com               ║
║                                                                      ║
║   Phase 0:  Setup       → tools, workspace, brain, LLM             ║
║   Phase 1:  Recon       → subdomains, hosts, URLs, JS, ports       ║
║   Phase 2:  Think       → Chain-of-Thought over all evidence       ║
║   Phase 3:  Hypothesize → ranked vuln hypotheses + Bayesian tests  ║
║   Phase 4:  Attack      → all attack chains (SSRF,SQLi,XSS,JWT...) ║
║   Phase 5:  Synthesize  → PoC confirmation                         ║
║   Phase 6:  Feedback    → validate, chain, extract credentials     ║
║   Phase 7:  Binary      → AFL++/angr/Frida/GDB (if enabled)        ║
║   Phase 8:  Memory      → learn, update brain                      ║
║   Phase 9:  Evolve      → self-improve code (if enabled)           ║
║   Phase 10: Report      → HTML + MD + JSON professional report     ║
║   Phase 11: Notify      → Telegram/Discord/Slack                   ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import argparse, importlib, json, os, sys, time
from datetime import datetime
from typing import Any, Dict, List, Optional

WORKSPACE = os.path.expanduser("~/nova_workspace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def _try(mod: str):
    try: return importlib.import_module(mod)
    except: return None

def _banner(target: str, start: str):
    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║  🦅 NOVA ARSENAL — UNIFIED HUNT PIPELINE                           ║
║  Target : {target[:58]:<58}║
║  Started: {start:<58}║
╚══════════════════════════════════════════════════════════════════════╝
""")


class PipelineResult:
    def __init__(self, target: str):
        self.target    = target
        self.started   = datetime.utcnow().isoformat()
        self.phases:   Dict[str,Any]  = {}
        self.findings: List[Dict]     = []
        self.errors:   List[str]      = []

    def record(self, name: str, result: Any, elapsed: float):
        self.phases[name] = {"result": result, "elapsed": round(elapsed,2), "ok": bool(result)}
        if isinstance(result, dict):
            for f in (result.get("findings",[]) or result.get("confirmed",[])):
                if isinstance(f, dict):
                    f.setdefault("phase", name)
                    self.findings.append(f)

    def summary(self) -> Dict:
        sev = {}
        for f in self.findings:
            s = f.get("severity","info").lower(); sev[s] = sev.get(s,0)+1
        return {"target":self.target,"started":self.started,"phases":list(self.phases.keys()),
                "total":len(self.findings),"critical":sev.get("critical",0),
                "high":sev.get("high",0),"medium":sev.get("medium",0),
                "low":sev.get("low",0),"info":sev.get("info",0)}


class NovaPipeline:
    """Unified orchestrator — runs all Nova modules in sequence."""

    def __init__(self, target: str, verbose: bool = True,
                 enable_evolution: bool = False, enable_binary: bool = False):
        self.target           = target.rstrip("/")
        self.verbose          = verbose
        self.enable_evolution = enable_evolution
        self.enable_binary    = enable_binary
        self.result           = PipelineResult(target)
        self.start_ts         = time.time()
        self._brain           = None
        self._session_id      = "unknown"
        self._llm             = None
        self._recon_data      = {}
        self._detected_techs  = []
        self._cot_queue       = []
        os.makedirs(WORKSPACE, exist_ok=True)

        # Load all modules
        self.m = {
            "memory":     _try("nova_memory_system"),
            "recon":      _try("nova_recon"),
            "cot":        _try("nova_chain_of_thought"),
            "hypothesis": _try("nova_hypothesis_engine"),
            "attack":     _try("nova_attack"),
            "synth":      _try("nova_exploit_synthesizer"),
            "feedback":   _try("nova_feedback_cortex"),
            "adaptive":   _try("nova_adaptive_brain"),
            "binary":     _try("nova_binary_hunter"),
            "evolution":  _try("nova_evolution"),
            "report":     _try("nova_report"),
            "notify":     _try("nova_notify"),
            "swarm":      _try("nova_swarm_parallel"),
            "jwt":        _try("nova_jwt_forge"),
            "race":       _try("nova_race_engine"),
            "proto":      _try("nova_proto_polluter"),
            "session":    _try("nova_session_hijacker"),
            "reasoning":  _try("nova_reasoning_core"),
            "llm":        _try("nova_llm_bridge"),
            "toolbox":    _try("nova_toolbox"),
        }
        loaded = sum(1 for v in self.m.values() if v is not None)
        print(f"  🔌 {loaded}/{len(self.m)} Nova modules loaded")

    def _phase(self, name: str) -> float:
        print(f"\n{'═'*68}\n  🔷 Phase: {name.upper()}\n{'═'*68}")
        return time.time()

    # ─── PHASE 0: SETUP ──────────────────────────────────────────────
    def phase_setup(self) -> Dict:
        t = self._phase("0 — Setup")
        if self.m["memory"]:
            try:
                self._brain      = self.m["memory"].get_brain()
                self._session_id = self._brain.start_hunt(self.target, "nova_pipeline")
                s = self._brain.stats()
                print(f"  🧠 Brain: {s['findings_total']} total findings, {s['patterns_learned']} patterns")
                print(f"  🔖 Session: {self._session_id}")
            except Exception as e: self.result.errors.append(f"brain:{e}")

        if self.m["toolbox"]:
            try:
                tb = self.m["toolbox"].get_toolbox()
                tb.ensure_mission_tools(f"web api recon attack full {self.target}", max_tools=15)
            except Exception: pass

        if self.m["reasoning"]:
            try: self._llm = self.m["reasoning"].NovaReasoningCore()
            except Exception: pass
        elif self.m["llm"]:
            try: self._llm = self.m["llm"].NovaLLMBridge()
            except Exception: pass
        print(f"  🤖 LLM: {'available' if self._llm else 'not loaded'}")

        if self.m["notify"]:
            try: self.m["notify"].NovaNotifier().hunt_start(self.target, self._session_id)
            except Exception: pass

        r = {"session_id":self._session_id,"brain":self._brain is not None,"llm":self._llm is not None}
        self.result.record("setup", r, time.time()-t); return r

    # ─── PHASE 1: RECON ──────────────────────────────────────────────
    def phase_recon(self) -> Dict:
        t = self._phase("1 — Recon")
        if self.m["recon"]:
            try:
                recon = self.m["recon"].NovaRecon(self.target, verbose=self.verbose)
                self._recon_data = recon.run_full()
                print(f"  ✅ {len(self._recon_data.get('subdomains',[]))} subdomains, "
                      f"{len(self._recon_data.get('live_hosts',[]))} live, "
                      f"{len(self._recon_data.get('urls',[]))} URLs")
            except Exception as e:
                self.result.errors.append(f"recon:{e}")
                self._recon_data = {"target":self.target,"live_hosts":[{"url":self.target}],
                                    "urls":[self.target],"params":[],"subdomains":[]}
        else:
            self._recon_data = {"target":self.target,"live_hosts":[{"url":self.target}],
                                "urls":[self.target],"params":[],"subdomains":[]}
        self.result.record("recon", self._recon_data, time.time()-t)
        return self._recon_data

    # ─── PHASE 2: CHAIN-OF-THOUGHT ───────────────────────────────────
    def phase_think(self) -> Dict:
        t = self._phase("2 — Chain-of-Thought")
        cot_result = {}
        if self.m["cot"]:
            try:
                import urllib.request
                cot  = self.m["cot"].NovaChainOfThought(self.target, llm=self._llm, verbose=self.verbose)
                obs  = []
                for host in (self._recon_data.get("live_hosts",[]) or [{"url":self.target}])[:5]:
                    url = host.get("url","") or host
                    try:
                        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
                        with urllib.request.urlopen(req, timeout=8) as r:
                            obs.append({"type":"http_response","url":url,"status":r.status,
                                        "headers":dict(r.headers),"body":r.read(20000).decode("utf-8","replace")})
                    except Exception: pass
                if obs:
                    cot_result = cot.run_reasoning_session(obs)
                    self._cot_queue    = cot_result.get("queue",[])
                    self._detected_techs = [k.replace("tech:","") for k in cot_result.get("facts",{}) if k.startswith("tech:")]
                    print(f"  🧠 CoT: {len(cot_result.get('findings',[]))} findings, {len(self._cot_queue)} queued, techs:{self._detected_techs}")
            except Exception as e: self.result.errors.append(f"cot:{e}")
        self.result.record("think", cot_result, time.time()-t); return cot_result

    # ─── PHASE 3: HYPOTHESIZE ────────────────────────────────────────
    def phase_hypothesize(self) -> Dict:
        t = self._phase("3 — Hypothesis Engine")
        r = {}
        if self.m["hypothesis"]:
            try:
                eng  = self.m["hypothesis"].HypothesisEngine(self.target, verbose=self.verbose)
                eps  = [h.get("url","") for h in self._recon_data.get("live_hosts",[])] or [self.target]
                r    = eng.run(techs=self._detected_techs or ["unknown"], endpoints=eps[:10])
                print(f"  🔬 {r.get('confirmed',0)} confirmed / {r.get('total',0)} hypotheses")
            except Exception as e: self.result.errors.append(f"hypothesis:{e}")
        self.result.record("hypothesize", r, time.time()-t); return r

    # ─── PHASE 4: ATTACK CHAINS ──────────────────────────────────────
    def phase_attack(self) -> Dict:
        t = self._phase("4 — Attack Chains")
        findings = []

        # Main attack orchestrator
        if self.m["attack"]:
            try:
                a = self.m["attack"].NovaAttack(self.target, verbose=self.verbose)
                findings.extend(a.run_all_chains(self._recon_data))
            except Exception as e: self.result.errors.append(f"attack:{e}")

        # Adaptive brain
        if self.m["adaptive"]:
            try:
                ab = self.m["adaptive"].NovaAdaptiveBrain(self.target)
                for url in [h.get("url","") for h in self._recon_data.get("live_hosts",[])][:3]:
                    try:
                        af = ab.scan(url)
                        findings.extend(af if isinstance(af,list) else af.get("findings",[]) if isinstance(af,dict) else [])
                    except Exception: pass
            except Exception as e: self.result.errors.append(f"adaptive:{e}")

        # JWT attacks
        if self.m["jwt"]:
            try:
                jf = self.m["jwt"].NovaJWTForge(self.target).hunt()
                findings.extend(jf if isinstance(jf,list) else jf.get("findings",[]) if isinstance(jf,dict) else [])
            except Exception: pass

        # Race conditions
        if self.m["race"]:
            try:
                rf = self.m["race"].NovaRaceEngine(self.target).hunt()
                findings.extend(rf.get("findings",[]) if isinstance(rf,dict) else [])
            except Exception: pass

        # Prototype pollution
        if self.m["proto"]:
            try:
                pf = self.m["proto"].NovaPolluter(self.target).hunt()
                findings.extend(pf.get("findings",[]) if isinstance(pf,dict) else [])
            except Exception: pass

        # Session hijacker
        if self.m["session"]:
            try:
                sf = self.m["session"].NovaSessionHijacker(self.target).hunt()
                findings.extend(sf.get("findings",[]) if isinstance(sf,dict) else [])
            except Exception: pass

        print(f"  ⚡ Attack chains: {len(findings)} findings")
        r = {"findings": findings}
        self.result.record("attack", r, time.time()-t); return r

    # ─── PHASE 5: SYNTHESIZE ─────────────────────────────────────────
    def phase_synthesize(self) -> Dict:
        t = self._phase("5 — Exploit Synthesis")
        r = {}
        if self.m["synth"] and self.result.findings:
            try:
                s  = self.m["synth"].NovaExploitSynthesizer(self.target)
                r  = s.synthesize(self.result.findings)
                confirmed = r.get("confirmed",[]) if isinstance(r,dict) else []
                print(f"  ⚡ {len(confirmed)} findings confirmed with PoC")
            except Exception as e: self.result.errors.append(f"synth:{e}")
        self.result.record("synthesize", r, time.time()-t); return r

    # ─── PHASE 6: FEEDBACK ───────────────────────────────────────────
    def phase_feedback(self) -> Dict:
        t = self._phase("6 — Feedback Cortex")
        r = {}
        if self.m["feedback"] and self.result.findings:
            try:
                c = self.m["feedback"].NovaFeedbackCortex(self.target)
                r = c.process(self.result.findings)
                chained = r.get("chained_exploits",[]) if isinstance(r,dict) else []
                if chained: print(f"  🔗 {len(chained)} chained exploits discovered")
            except Exception as e: self.result.errors.append(f"feedback:{e}")
        self.result.record("feedback", r, time.time()-t); return r

    # ─── PHASE 7: BINARY ─────────────────────────────────────────────
    def phase_binary(self, binary_path: str = None) -> Dict:
        t = self._phase("7 — Binary Hunt")
        r = {}
        if not self.enable_binary:
            print("  ⏭  Binary hunt skipped (pass --binary-hunt to enable)")
        elif self.m["binary"] and binary_path:
            try:
                r = self.m["binary"].NovaBinaryHunter(verbose=self.verbose).hunt(binary_path, fuzz_time=60)
                print(f"  💥 Binary: {len(r.get('findings',[]))} findings")
            except Exception as e: self.result.errors.append(f"binary:{e}")
        self.result.record("binary", r, time.time()-t); return r

    # ─── PHASE 8: MEMORY ─────────────────────────────────────────────
    def phase_memory(self) -> Dict:
        t = self._phase("8 — Memory Update")
        r = {}
        if self._brain:
            try:
                self._brain.end_hunt(self._session_id, self.result.findings,
                                      duration_sec=time.time()-self.start_ts)
                for name,ph in self.result.phases.items():
                    if isinstance(ph.get("result"),dict):
                        tool = ph["result"].get("tool","")
                        if tool: self._brain.record_tool_run(tool, len(ph["result"].get("findings",[])), ph.get("elapsed",0))
                r = self._brain.stats()
                print(f"  🧠 Brain updated: {r['findings_total']} total findings, {r['patterns_learned']} patterns")
            except Exception as e: self.result.errors.append(f"memory:{e}")
        self.result.record("memory", r, time.time()-t); return r

    # ─── PHASE 9: EVOLVE ─────────────────────────────────────────────
    def phase_evolve(self) -> Dict:
        t = self._phase("9 — Self-Evolution")
        r = {}
        if not self.enable_evolution:
            print("  ⏭  Evolution skipped (pass --evolve to enable)")
        elif self.m["evolution"]:
            try:
                evo = self.m["evolution"].NovaEvolution()
                r   = evo.evolve_from_hunt(json.dumps(self.result.summary()))
                print(f"  🧬 Evolved: {r.get('files_evolved',0)} files improved")
            except Exception as e: self.result.errors.append(f"evo:{e}")
        self.result.record("evolve", r, time.time()-t); return r

    # ─── PHASE 10: REPORT ────────────────────────────────────────────
    def phase_report(self) -> Dict:
        t = self._phase("10 — Report Generation")
        dur = time.time()-self.start_ts
        dur_str = f"{int(dur//60)}m {int(dur%60)}s"
        tools = list({f.get("tool","nova") for f in self.result.findings if f.get("tool")})
        paths = {}
        if self.m["report"]:
            try:
                paths = self.m["report"].generate_report(
                    target=self.target, findings=self.result.findings,
                    duration=dur_str, mission="Nova Pipeline — Full Hunt",
                    tools_used=tools)
                print(f"  📋 {paths.get('html','N/A')}")
            except Exception as e:
                self.result.errors.append(f"report:{e}")
                p = os.path.join(WORKSPACE,"reports",f"nova_pipeline_{int(time.time())}.json")
                os.makedirs(os.path.dirname(p),exist_ok=True)
                with open(p,"w") as f: json.dump({"target":self.target,"findings":self.result.findings,"summary":self.result.summary()},f,indent=2)
                paths = {"json":p}
        self.result.record("report", {"paths":paths}, time.time()-t); return paths

    # ─── PHASE 11: NOTIFY ────────────────────────────────────────────
    def phase_notify(self, report_paths: Dict) -> Dict:
        t = self._phase("11 — Notifications")
        if self.m["notify"]:
            try:
                self.m["notify"].NovaNotifier().hunt_complete(
                    target=self.target, findings=self.result.findings,
                    report_path=report_paths.get("html",""))
                print("  📣 Notifications sent")
            except Exception as e: self.result.errors.append(f"notify:{e}")
        self.result.record("notify", {}, time.time()-t); return {}

    # ─── SUMMARY ─────────────────────────────────────────────────────
    def _print_summary(self):
        s   = self.result.summary()
        dur = time.time()-self.start_ts
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║  🦅 NOVA HUNT COMPLETE                                              ║
║  Target:   {self.target[:57]:<57}║
║  Duration: {int(dur//60)}m {int(dur%60)}s{'':<54}║
║  Phases:   {len(s['phases']):<57}║
║                                                                      ║
║  🔴 Critical : {s['critical']:<53}║
║  🟠 High     : {s['high']:<53}║
║  🟡 Medium   : {s['medium']:<53}║
║  🔵 Low      : {s['low']:<53}║
║  📊 Total    : {s['total']:<53}║
╚══════════════════════════════════════════════════════════════════════╝
""")
        if self.result.errors:
            print(f"  ⚠️  Errors: " + " | ".join(self.result.errors[:4]))

    # ─── FULL PIPELINE ───────────────────────────────────────────────
    def run(self, binary_path: str = None) -> Dict:
        _banner(self.target, datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
        self.phase_setup()
        self.phase_recon()
        self.phase_think()
        self.phase_hypothesize()
        self.phase_attack()
        self.phase_synthesize()
        self.phase_feedback()
        self.phase_binary(binary_path)
        self.phase_memory()
        if self.enable_evolution: self.phase_evolve()
        paths = self.phase_report()
        self.phase_notify(paths)
        self._print_summary()

        # Save full result
        out = os.path.join(WORKSPACE,"reports",f"nova_pipeline_{int(time.time())}.json")
        os.makedirs(os.path.dirname(out),exist_ok=True)
        with open(out,"w") as f:
            json.dump({"target":self.result.target,"summary":self.result.summary(),
                       "findings":self.result.findings,"errors":self.result.errors,
                       "report":paths}, f, indent=2, default=str)
        print(f"  💾 Pipeline result: {out}")
        return self.result.summary()


def main():
    p = argparse.ArgumentParser(description="🚀 Nova Pipeline — Full autonomous hunt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\nExamples:\n  python nova_pipeline.py --target https://target.com\n  python nova_pipeline.py --target https://target.com --evolve\n  python nova_pipeline.py --target https://target.com --binary-hunt --binary /usr/bin/prog")
    p.add_argument("--target",      required=True)
    p.add_argument("--evolve",      action="store_true")
    p.add_argument("--binary",      help="Binary path for binary hunting")
    p.add_argument("--binary-hunt", action="store_true")
    p.add_argument("--quiet",       action="store_true")
    args = p.parse_args()
    pipeline = NovaPipeline(args.target, verbose=not args.quiet,
                             enable_evolution=args.evolve,
                             enable_binary=args.binary_hunt or bool(args.binary))
    result = pipeline.run(binary_path=args.binary)
    print(f"\n  Total findings: {result['total']}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
