#!/usr/bin/env python3
"""
 ███╗   ██╗ ██████╗ ██╗   ██╗  █████╗
 ████╗  ██║██╔═══██╗██║   ██║ ██╔══██╗
 ██╔██╗ ██║██║   ██║██║   ██║ ███████║
 ██║╚██╗██║██║   ██║╚██╗ ██╔╝ ██╔══██║
 ██║ ╚████║╚██████╔╝ ╚████╔╝  ██║  ██║
 ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝   ╚═╝  ╚═╝  ARSENAL v4.0

Natural-language dispatch — the single entry point that ties
ALL Nova capabilities together:
  python3 nova.py "Your task in plain English"

Architecture: NLP intent parser → dispatch() → specialist modules
All modules share a common findings schema and feed into nova_vuln_tracker.
"""
import sys, os, json, re, time, urllib.request
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

# ── Configuration ──────────────────────────────────────────────────────────────
NOVA_DIR      = Path(__file__).parent
WORKSPACE     = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
OLLAMA_URL    = os.getenv("NOVA_LLM_URL",   "http://localhost:11434")
OLLAMA_MODEL  = os.getenv("NOVA_LLM_MODEL", "qwen3:8b")
MAX_STEPS     = int(os.getenv("NOVA_MAX_STEPS", "40"))
DEFAULT_TARGET= os.getenv("NOVA_TARGET",    "http://localhost:3000")
WORKSPACE.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(NOVA_DIR))

# ── Lazy module loader ─────────────────────────────────────────────────────────
def _load(module_name: str, class_name: str = None):
    try:
        import importlib
        mod = importlib.import_module(module_name)
        return getattr(mod, class_name) if class_name else mod
    except Exception as e:
        print(f"  ⚠️  {module_name}: {e}")
        return None

# ── Ollama helper ──────────────────────────────────────────────────────────────
def _ask_llm(prompt: str, system: str = "", temperature: float = 0.1) -> str:
    try:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = json.dumps({
            "model": OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": 1000}
        }).encode()
        req = urllib.request.Request(f"{OLLAMA_URL}/api/chat",
            data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read()).get("message",{}).get("content","").strip()
    except Exception:
        return ""

# ── Intent Parser ──────────────────────────────────────────────────────────────
KEYWORD_MODES = {
    # ── Active scanning ──────────────────────────────────────────────────────
    "full_stack":       ["full stack","full-stack","everything","all modules","complete scan",
                         "mythos","v4","comprehensive","do everything","full power"],
    "daybreak":         ["daybreak","ai assessment","h1 report","hackerone report",
                         "ai threat","bounty report","scope check","daybreak pipeline"],
    "orchestrate":      ["orchestrate","multi agent","agent network","agent handoff",
                         "autonomous agent","run agents","agent pipeline"],
    "triage":           ["triage","prioritise","prioritize","rank findings","sort findings",
                         "what to report","best findings","top findings","h1 ready"],
    "hunt":             ["hunt","bug bounty","bounty","find bugs","exploit","pentest","hack"],
    "recon":            ["recon","reconn","subdomain","enumerate","discover","footprint","crt.sh"],
    "fuzz":             ["fuzz","fuzzing","brute force","directory","endpoint","wordlist"],
    "sqli":             ["sql","sqli","sql injection","database injection","blind sql"],
    "xss":              ["xss","cross site script","reflected xss","stored xss","dom xss"],
    "ssrf":             ["ssrf","server side request","internal network","metadata","169.254"],
    "idor":             ["idor","insecure direct","broken object","access control","horizontal",
                         "privilege escalation","bola"],
    "graphql":          ["graphql","graph ql","introspection","gql","apollo"],
    "csrf":             ["csrf","cross site request","samesite","origin header","referer"],
    "race":             ["race condition","toctou","concurrent","time of check","parallel request"],
    "jwt":              ["jwt","json web token","bearer token","alg none","key confusion"],
    "proto_pollution":  ["prototype pollution","proto","__proto__","constructor.prototype"],
    "business_logic":   ["business logic","negative price","coupon","workflow bypass","price manipulation",
                         "integer overflow","negative value","coupon stack"],
    "llm_injection":    ["llm","prompt injection","ai injection","jailbreak","system prompt",
                         "chatgpt","claude","copilot","ai security"],
    # ── Static / code analysis ──────────────────────────────────────────────
    "sast":             ["sast","static analysis","source code","code audit","code review",
                         "source audit","code scan"],
    "sca":              ["sca","dependency","supply chain","npm audit","pip audit","cve package",
                         "library vulnerability","package scan","vulnerable library"],
    "supply_chain":     ["supply chain score","typosquat","maintainer","npm package risk",
                         "package risk","malicious package"],
    "git_scan":         ["git","commit","history","leaked secret","secret in git",
                         "git log","git blame","repo scan"],
    "cicd":             ["ci/cd","cicd","github actions","pipeline","jenkins","travis","circleci",
                         "bitbucket pipeline","azure devops","workflow security"],
    "container":        ["docker","dockerfile","container","kubernetes","k8s","helm","pod",
                         "docker-compose","compose","container security"],
    # ── Planning & modeling ─────────────────────────────────────────────────
    "threat_model":     ["threat model","attack surface","trust boundary","stride",
                         "entry point","data flow","threat"],
    "patch":            ["patch","fix","remediate","auto fix","auto patch","generate fix",
                         "code fix","suggest fix"],
    # ── Detection & reporting ───────────────────────────────────────────────
    "detect":           ["detection","sigma","siem","splunk","elastic","suricata",
                         "detection rule","alert rule","kql"],
    "audit_report":     ["report","audit","compliance","pci","soc2","iso27001",
                         "executive report","cvss score","risk report"],
    "vuln_track":       ["track","tracker","regression","dashboard","trend","history",
                         "database","vulnerability database","vuln db"],
    "zero_day":         ["zero day","0day","cve","nvd","osv","advisory","live cve",
                         "recent vulnerability","latest cve","correlate"],
    # ── Validation & exploitation ───────────────────────────────────────────
    "sandbox":          ["sandbox","validate","confirm","verify exploit","prove","poc",
                         "exploit validation","real vulnerability"],
    # ── Special modes ───────────────────────────────────────────────────────
    "bootstrap":        ["bootstrap","health check","verify install","check modules","status"],
    "continuous":       ["continuous","monitor","watch","loop","scheduled","ongoing"],
    "swarm":            ["swarm","multi agent","parallel","10 agents","mass scan"],
}

def _parse_intent(query: str) -> dict:
    q = query.lower()
    # Try LLM first
    llm_resp = _ask_llm(
        f"Task: {query}\n\nClassify into ONE mode. Output only the mode name.\n"
        f"Modes: {', '.join(KEYWORD_MODES.keys())}",
        system="You are Nova's intent classifier. Output only the mode name, nothing else."
    )
    if llm_resp and llm_resp.strip().lower() in KEYWORD_MODES:
        detected_mode = llm_resp.strip().lower()
    else:
        detected_mode = None
        for mode, kws in KEYWORD_MODES.items():
            if any(kw in q for kw in kws):
                detected_mode = mode
                break
        if not detected_mode:
            detected_mode = "hunt"  # smart default

    # Extract target
    url_match = re.search(r'https?://[^\s]+', query)
    path_match = re.search(r'(?:on|for|in|at|scan|audit)\s+([./~][\w./\-]+|[\w\-]+/[\w./\-]+)', query)
    if url_match:
        target = url_match.group(0)
    elif path_match:
        target = path_match.group(1)
    else:
        target = DEFAULT_TARGET

    return {"mode": detected_mode, "target": target, "original_query": query}


# ── Shared findings schema ─────────────────────────────────────────────────────
def _save_findings(findings: List[Dict], label: str) -> str:
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    path   = WORKSPACE / f"nova_{label}_{ts}.json"
    report = {"generated": datetime.now().isoformat(), "label": label,
              "total": len(findings), "findings": findings}
    path.write_text(json.dumps(report, indent=2))
    return str(path)


def _track_findings(findings: List[Dict], target: str, mode: str):
    """Persist all findings into the vuln tracker database."""
    TrackerCls = _load("nova_vuln_tracker", "NovaVulnTracker")
    if not TrackerCls or not findings:
        return
    try:
        t = TrackerCls()
        t.start_run(target, mode)
        t.ingest_findings(findings, target=target, source_module=mode)
        t.close()
    except Exception as e:
        print(f"  ⚠️  Tracker: {e}")


# ── Dispatch table ─────────────────────────────────────────────────────────────
def dispatch(intent: dict) -> List[Dict]:
    mode   = intent["mode"]
    target = intent["target"]
    query  = intent.get("original_query","")
    findings: List[Dict] = []

    print(f"\n{'━'*60}")
    print(f"  🎯 Mode    : {mode}")
    print(f"  📍 Target  : {target}")
    print(f"{'━'*60}\n")

    # ── Source Audit (SAST) ──────────────────────────────────────────────────
    if mode in ("sast", "hunt", "full_stack"):
        Cls = _load("nova_source_auditor", "NovaSourceAuditor")
        if Cls:
            try:
                auditor = Cls(target if os.path.isdir(target) else ".")
                auditor.audit_directory()
                findings.extend(auditor.findings)
            except Exception as e: print(f"  ⚠️  SAST: {e}")

    # ── File Prioritizer ─────────────────────────────────────────────────────
    if mode in ("sast", "hunt", "full_stack"):
        Cls = _load("nova_file_prioritizer", "NovaFilePrioritizer")
        if Cls:
            try:
                p = Cls(target if os.path.isdir(target) else ".")
                p.prioritize()
                print(f"  📁 File priorities saved")
            except Exception as e: print(f"  ⚠️  Prioritizer: {e}")

    # ── Threat Model ─────────────────────────────────────────────────────────
    if mode in ("threat_model", "full_stack"):
        Cls = _load("nova_threat_model", "NovaThreatModel")
        if Cls:
            try:
                tm  = Cls()
                d   = target if os.path.isdir(target) else "."
                src = {}
                for root,_,files in os.walk(d):
                    for f in files[:30]:
                        try:
                            p = os.path.join(root,f)
                            src[os.path.relpath(p,d)] = open(p,encoding="utf-8",errors="ignore").read(3000)
                        except: pass
                model = tm.build_from_files(src)
                out = WORKSPACE / "nova_threat_model.json"
                out.write_text(json.dumps(model,indent=2))
                print(f"  🗺  Threat model → {out}")
            except Exception as e: print(f"  ⚠️  Threat model: {e}")

    # ── SCA Scanner ──────────────────────────────────────────────────────────
    if mode in ("sca", "supply_chain", "full_stack"):
        Cls = _load("nova_sca_scanner", "NovaSCAScanner")
        if Cls:
            try:
                s = Cls()
                d = target if os.path.isdir(target) else "."
                sca_findings = s.scan_directory(d)
                findings.extend(sca_findings)
                s.save(str(WORKSPACE / "nova_sca_report.json"))
            except Exception as e: print(f"  ⚠️  SCA: {e}")

    # ── Supply Chain Scorer ───────────────────────────────────────────────────
    if mode in ("supply_chain", "full_stack", "sca"):
        Cls = _load("nova_supply_chain_scorer", "NovaSupplyChainScorer")
        if Cls:
            try:
                s = Cls()
                d = target if os.path.isdir(target) else "."
                sc_findings = s.scan_directory(d)
                findings.extend(sc_findings)
                s.save(str(WORKSPACE / "nova_supply_chain_report.json"))
            except Exception as e: print(f"  ⚠️  Supply chain: {e}")

    # ── Git Scanner ───────────────────────────────────────────────────────────
    if mode in ("git_scan", "full_stack"):
        Cls = _load("nova_git_scanner", "NovaGitScanner")
        if Cls:
            try:
                s = Cls(target if os.path.isdir(target) else ".")
                git_findings = s.scan()
                findings.extend(git_findings)
                s.save(str(WORKSPACE / "nova_git_report.json"))
            except Exception as e: print(f"  ⚠️  Git scan: {e}")

    # ── CI/CD Scanner ─────────────────────────────────────────────────────────
    if mode in ("cicd", "full_stack"):
        Cls = _load("nova_cicd_scanner", "NovaCICDScanner")
        if Cls:
            try:
                s = Cls()
                d = target if os.path.isdir(target) else "."
                ci_findings = s.scan_directory(d)
                findings.extend(ci_findings)
                s.save(str(WORKSPACE / "nova_cicd_report.json"))
            except Exception as e: print(f"  ⚠️  CI/CD: {e}")

    # ── Container Scanner ─────────────────────────────────────────────────────
    if mode in ("container", "full_stack"):
        Cls = _load("nova_container_scanner", "NovaContainerScanner")
        if Cls:
            try:
                s = Cls()
                d = target if os.path.isdir(target) else "."
                container_findings = s.scan_directory(d)
                findings.extend(container_findings)
                s.save(str(WORKSPACE / "nova_container_report.json"))
            except Exception as e: print(f"  ⚠️  Container: {e}")

    # ── Zero-Day Correlator ───────────────────────────────────────────────────
    if mode in ("zero_day", "full_stack"):
        Cls = _load("nova_zero_day_correlator", "NovaZeroDayCorrelator")
        if Cls:
            try:
                c = Cls()
                d = target if os.path.isdir(target) else "."
                zd = c.correlate(d, findings)
                findings.extend(zd)
                c.save(str(WORKSPACE / "nova_zero_day_report.json"))
            except Exception as e: print(f"  ⚠️  Zero-day: {e}")

    # ── Patch Generator ───────────────────────────────────────────────────────
    if mode in ("patch", "full_stack") and findings:
        Cls = _load("nova_patch_generator", "NovaPatchGenerator")
        if Cls:
            try:
                pg = Cls()
                patches = pg.generate_patches(findings[:10])
                out = WORKSPACE / "nova_patches.json"
                out.write_text(json.dumps(patches, indent=2))
                print(f"  🔧 Patches → {out}")
            except Exception as e: print(f"  ⚠️  Patch gen: {e}")

    # ── Detection Engineer ────────────────────────────────────────────────────
    if mode in ("detect", "full_stack") and findings:
        Cls = _load("nova_detection_engineer", "NovaDetectionEngineer")
        if Cls:
            try:
                de = Cls()
                rules = de.generate_rules(findings[:10])
                out = WORKSPACE / "nova_detection_rules.json"
                out.write_text(json.dumps(rules, indent=2))
                print(f"  🔔 Detection rules → {out}")
            except Exception as e: print(f"  ⚠️  Detect: {e}")

    # ── Audit Reporter ────────────────────────────────────────────────────────
    if mode in ("audit_report", "full_stack") and findings:
        Cls = _load("nova_audit_reporter", "NovaAuditReporter")
        if Cls:
            try:
                ar = Cls(target)
                report = ar.generate(findings)
                out = WORKSPACE / "nova_audit_report.json"
                out.write_text(json.dumps(report, indent=2))
                print(f"  📋 Audit report → {out}")
            except Exception as e: print(f"  ⚠️  Audit: {e}")

    # ── IDOR Scanner ──────────────────────────────────────────────────────────
    if mode in ("idor", "hunt", "full_stack") and (target.startswith("http") or DEFAULT_TARGET.startswith("http")):
        Cls = _load("nova_idor_scanner", "NovaIDORScanner")
        if Cls:
            try:
                url = target if target.startswith("http") else DEFAULT_TARGET
                s = Cls(url)
                idor_findings = s.run()
                findings.extend(idor_findings)
                s.save(str(WORKSPACE / "nova_idor_report.json"))
            except Exception as e: print(f"  ⚠️  IDOR: {e}")

    # ── GraphQL Tester ────────────────────────────────────────────────────────
    if mode in ("graphql", "hunt", "full_stack") and (target.startswith("http") or DEFAULT_TARGET.startswith("http")):
        Cls = _load("nova_graphql_tester", "NovaGraphQLTester")
        if Cls:
            try:
                url = target if target.startswith("http") else DEFAULT_TARGET
                s = Cls(url)
                gql_findings = s.run()
                findings.extend(gql_findings)
                s.save(str(WORKSPACE / "nova_graphql_report.json"))
            except Exception as e: print(f"  ⚠️  GraphQL: {e}")

    # ── CSRF Tester ───────────────────────────────────────────────────────────
    if mode in ("csrf", "hunt", "full_stack") and (target.startswith("http") or DEFAULT_TARGET.startswith("http")):
        Cls = _load("nova_csrf_tester", "NovaCsrfTester")
        if Cls:
            try:
                url = target if target.startswith("http") else DEFAULT_TARGET
                s = Cls(url)
                csrf_findings = s.run()
                findings.extend(csrf_findings)
                s.save(str(WORKSPACE / "nova_csrf_report.json"))
            except Exception as e: print(f"  ⚠️  CSRF: {e}")

    # ── Business Logic ────────────────────────────────────────────────────────
    if mode in ("business_logic", "hunt", "full_stack") and (target.startswith("http") or DEFAULT_TARGET.startswith("http")):
        Cls = _load("nova_business_logic", "NovaBusinessLogicTester")
        if Cls:
            try:
                url = target if target.startswith("http") else DEFAULT_TARGET
                s = Cls(url)
                bl_findings = s.run()
                findings.extend(bl_findings)
                s.save(str(WORKSPACE / "nova_business_logic_report.json"))
            except Exception as e: print(f"  ⚠️  Business logic: {e}")

    # ── LLM Injection ─────────────────────────────────────────────────────────
    if mode in ("llm_injection",) and (target.startswith("http") or DEFAULT_TARGET.startswith("http")):
        Cls = _load("nova_llm_injection", "NovaLLMInjectionTester")
        if Cls:
            try:
                url = target if target.startswith("http") else DEFAULT_TARGET
                s = Cls(url)
                llm_findings = s.run()
                findings.extend(llm_findings)
                s.save(str(WORKSPACE / "nova_llm_injection_report.json"))
            except Exception as e: print(f"  ⚠️  LLM injection: {e}")

    # ── JWT ───────────────────────────────────────────────────────────────────
    if mode in ("jwt",):
        Cls = _load("nova_jwt_forge", "NovaJWTForge")
        if Cls:
            try:
                j = Cls(target if target.startswith("http") else DEFAULT_TARGET)
                jwt_findings = j.run()
                findings.extend(jwt_findings)
            except Exception as e: print(f"  ⚠️  JWT: {e}")

    # ── SQL Injection ─────────────────────────────────────────────────────────
    if mode in ("sqli", "hunt"):
        Cls = _load("nova_fuzzer", "NovaFuzzer")
        if Cls:
            try:
                url = target if target.startswith("http") else DEFAULT_TARGET
                fuzz = Cls(url)
                sqli = fuzz.run_sqli()
                findings.extend(sqli if isinstance(sqli, list) else [])
            except Exception as e: print(f"  ⚠️  SQLi: {e}")

    # ── Prototype Pollution ───────────────────────────────────────────────────
    if mode in ("proto_pollution",):
        Cls = _load("nova_proto_polluter", "NovaProtoPolluter")
        if Cls:
            try:
                url = target if target.startswith("http") else DEFAULT_TARGET
                pp = Cls(url)
                pp_findings = pp.run()
                findings.extend(pp_findings if isinstance(pp_findings, list) else [])
            except Exception as e: print(f"  ⚠️  Proto pollution: {e}")

    # ── Race Condition ────────────────────────────────────────────────────────
    if mode in ("race",):
        Cls = _load("nova_race_engine", "NovaRaceEngine")
        if Cls:
            try:
                url = target if target.startswith("http") else DEFAULT_TARGET
                rc = Cls(url)
                rc_findings = rc.run()
                findings.extend(rc_findings if isinstance(rc_findings, list) else [])
            except Exception as e: print(f"  ⚠️  Race: {e}")

    # ── Recon ─────────────────────────────────────────────────────────────────
    if mode in ("recon",):
        Cls = _load("nova_recon", "NovaRecon")
        if Cls:
            try:
                r = Cls(target)
                r.run()
            except Exception as e: print(f"  ⚠️  Recon: {e}")

    # ── Fuzz ──────────────────────────────────────────────────────────────────
    if mode in ("fuzz",):
        Cls = _load("nova_fuzzer", "NovaFuzzer")
        if Cls:
            try:
                url = target if target.startswith("http") else DEFAULT_TARGET
                f = Cls(url)
                f.run()
            except Exception as e: print(f"  ⚠️  Fuzz: {e}")

    # ── Sandbox Validate ──────────────────────────────────────────────────────
    if mode in ("sandbox",) and findings:
        Cls = _load("nova_sandbox_validator", "NovaSandboxValidator")
        if Cls:
            try:
                url = target if target.startswith("http") else DEFAULT_TARGET
                sv = Cls(url)
                sv_findings = sv.validate(findings[:10])
                findings.extend(sv_findings if isinstance(sv_findings, list) else [])
            except Exception as e: print(f"  ⚠️  Sandbox: {e}")

    # ── Vuln Tracker ──────────────────────────────────────────────────────────
    if mode in ("vuln_track",):
        Cls = _load("nova_vuln_tracker", "NovaVulnTracker")
        if Cls:
            try:
                t = Cls()
                report = t.report(str(WORKSPACE / "nova_tracker_report.json"))
                md = t.markdown_dashboard()
                (WORKSPACE / "nova_tracker_dashboard.md").write_text(md)
                t.close()
                print(f"  📊 Tracker: {report['trend']['total_open']} open | {report['trend']['total_fixed']} fixed")
            except Exception as e: print(f"  ⚠️  Tracker: {e}")

    # ── Daybreak AI Assessment ────────────────────────────────────────────────
    if mode in ("daybreak", "full_stack"):
        Cls = _load("nova_daybreak", "NovaDaybreak")
        if Cls:
            try:
                # Auto-load scope via nova_scope_manager if available
                scope = None
                ScopeMgr = _load("nova_scope_manager", "NovaScopeManager")
                if ScopeMgr:
                    try:
                        sm    = ScopeMgr()
                        scope = sm.load_scope_for_target(target)
                        if scope:
                            print(f"  🔭 Scope loaded: {scope.get('program','?')} "
                                  f"({len(scope.get('in_scope',[]))} in-scope entries)")
                    except Exception as se:
                        print(f"  ⚠️  Scope manager: {se}")
                db = Cls(target, scope=scope)
                db_findings = db.run()
                findings.extend(db_findings if isinstance(db_findings, list) else [])
                db.save(str(WORKSPACE / "nova_daybreak_report.json"))
            except Exception as e: print(f"  ⚠️  Daybreak: {e}")

    # ── Multi-Agent Orchestrator ───────────────────────────────────────────────
    if mode in ("orchestrate",):
        OrcMod = _load("nova_orchestrator")
        if OrcMod:
            try:
                url    = target if target.startswith("http") else DEFAULT_TARGET
                runner = OrcMod.build_security_network(url)
                result = runner.run(query, start="ReconAgent")
                findings.extend(result.findings)
                print(f"  🧠 Orchestrator: {result.steps} steps, "
                      f"{len(result.findings)} findings")
            except Exception as e: print(f"  ⚠️  Orchestrator: {e}")

    # ── AI Triage & Prioritiser ────────────────────────────────────────────────
    if mode in ("triage",) and findings:
        TriCls = _load("nova_triage", "NovaTriage")
        if TriCls:
            try:
                triage  = TriCls()
                triage.ingest(findings, source=mode)
                ranked  = triage.run()
                triage.print_summary()
                triage.save(str(WORKSPACE / "nova_triage_report.json"))
                # Replace findings with ranked list
                findings = [
                    {"type": f.type, "severity": f.severity,
                     "endpoint": f.endpoint, "file": f.file,
                     "triage_score": f.triage_score,
                     "priority": f.priority_label,
                     "llm_reasoning": f.llm_reasoning,
                     "h1_report_ready": f.h1_report_ready,
                     "chain_id": f.chain_id}
                    for f in ranked
                ]
            except Exception as e: print(f"  ⚠️  Triage: {e}")

    # ── Auto-triage on full_stack if findings found ────────────────────────────
    if mode in ("full_stack",) and findings:
        TriCls = _load("nova_triage", "NovaTriage")
        if TriCls:
            try:
                triage = TriCls(skip_llm=False)
                triage.ingest(findings, source="full_stack")
                ranked = triage.run()
                triage.save(str(WORKSPACE / "nova_triage_report.json"))
                print(f"  🎯 Auto-triage: {len(ranked)} ranked findings saved")
            except Exception as e: print(f"  ⚠️  Auto-triage: {e}")

    # ── Bootstrap ─────────────────────────────────────────────────────────────
    if mode in ("bootstrap",):
        try:
            import nova_bootstrap
            nova_bootstrap.main()
            return []
        except Exception as e: print(f"  ⚠️  Bootstrap: {e}")

    # ── Agentic hunt (default for "hunt" mode) ────────────────────────────────
    if mode in ("hunt",):
        Cls = _load("nova_agent_core", "NovaAgentCore")
        if Cls:
            try:
                agent = Cls(target if target.startswith("http") else DEFAULT_TARGET,
                            max_steps=MAX_STEPS)
                agent_findings = agent.run(query)
                findings.extend(agent_findings if isinstance(agent_findings, list) else [])
            except Exception as e: print(f"  ⚠️  Agent core: {e}")

    # ── Swarm ─────────────────────────────────────────────────────────────────
    if mode in ("swarm",):
        Cls = _load("nova_swarm_v3", "NovaSwarm")
        if Cls:
            try:
                url = target if target.startswith("http") else DEFAULT_TARGET
                s = Cls(url)
                swarm_findings = s.run()
                findings.extend(swarm_findings if isinstance(swarm_findings, list) else [])
            except Exception as e: print(f"  ⚠️  Swarm: {e}")

    # ── Full-stack pipeline (Mythos + Daybreak parity) ────────────────────────
    if mode == "full_stack":
        print("\n  🚀 Running Phase 2: Active API probes...")
        url = target if target.startswith("http") else DEFAULT_TARGET
        for sub_mode in ("idor", "graphql", "csrf", "business_logic"):
            sub_intent = {"mode": sub_mode, "target": url, "original_query": query}
            sub_findings = dispatch(sub_intent)
            findings.extend(sub_findings)
        print("\n  🚀 Running Phase 3: Detection + Reporting...")
        for sub_mode in ("detect", "audit_report", "patch"):
            if findings:
                sub_intent = {"mode": sub_mode, "target": target, "original_query": query}
                dispatch(sub_intent)

    # ── Always track findings ─────────────────────────────────────────────────
    if findings:
        _track_findings(findings, target, mode)
        path = _save_findings(findings, mode)
        critical = [f for f in findings if str(f.get("severity","")).upper() in ("CRITICAL","HIGH")]
        print(f"\n{'━'*60}")
        print(f"  📊 Total findings : {len(findings)}")
        print(f"  🔴 Critical/High  : {len(critical)}")
        print(f"  💾 Saved to       : {path}")
        if critical:
            print(f"\n  Top findings:")
            for f in critical[:5]:
                print(f"    • [{f.get('severity','?')}] {f.get('type','?')} — "
                      f"{f.get('file') or f.get('endpoint','?')} L{f.get('line','')}")
        print(f"{'━'*60}\n")

    return findings


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("Usage: python3 nova.py \"Your security task in plain English\"")
        print("\nExamples:")
        print("  python3 nova.py \"Hunt http://localhost:3000 for SQL injection\"")
        print("  python3 nova.py \"Run full-stack pipeline on ./juice-shop\"")
        print("  python3 nova.py \"Daybreak AI assessment on https://target.com\"")
        print("  python3 nova.py \"Orchestrate multi-agent recon+attack on https://target.com\"")
        print("  python3 nova.py \"Triage and prioritise these findings\"")
        print("  python3 nova.py \"Scan git history for leaked secrets in .\"")
        print("  python3 nova.py \"Build a threat model for ./my-app\"")
        print("  python3 nova.py \"Check supply chain risk for ./package.json\"")
        print("  python3 nova.py \"Test GraphQL endpoint at http://localhost:4000\"")
        print("  python3 nova.py \"Scan CI/CD pipelines in .\"")
        print("  python3 nova.py \"Container security audit for ./Dockerfile\"")
        print("  python3 nova.py \"Show vulnerability tracker dashboard\"")
        print("  python3 nova.py \"Check health of all Nova modules\"")
        sys.exit(0)

    query = " ".join(sys.argv[1:])
    print(f"\n  🔎 Nova Arsenal v4.0 — parsing: \"{query[:80]}\"")
    intent = _parse_intent(query)
    findings = dispatch(intent)
    return 0 if not findings else (1 if any(
        str(f.get("severity","")).upper() in ("CRITICAL","HIGH") for f in findings) else 0)


if __name__ == "__main__":
    sys.exit(main())
