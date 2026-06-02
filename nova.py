#!/usr/bin/env python3
"""
 ███╗   ██╗ ██████╗ ██╗   ██╗  █████╗
 ████╗  ██║██╔═══██╗██║   ██║ ██╔══██╗
 ██╔██╗ ██║██║   ██║██║   ██║ ███████║
 ██║╚██╗██║██║   ██║╚██╗ ██╔╝ ██╔══██║
 ██║ ╚████║╚██████╔╝ ╚████╔╝  ██║  ██║
 ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝   ╚═╝  ╚═╝  ARSENAL v4.2

Natural-language entry point — ties ALL Nova capabilities together.
Every module shares the same LLM router, hook bus, typed context,
persistent session, execution tracer, and full codebase map automatically.

Usage:
  python3 nova.py "Hunt https://target.com for all bugs"
  python3 nova.py "Full stack pipeline on ./juice-shop"
  python3 nova.py "Orchestrate multi-agent attack on https://target.com"
  python3 nova.py "Daybreak AI assessment on https://target.com"
  python3 nova.py "Triage findings and show top H1-ready bugs"
"""

import sys, os, json, re, time, urllib.request, threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

# ── Configuration ──────────────────────────────────────────────────────────────
NOVA_DIR       = Path(__file__).parent
WORKSPACE      = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
OLLAMA_URL     = os.getenv("NOVA_LLM_URL",   "http://localhost:11434")
OLLAMA_MODEL   = os.getenv("NOVA_LLM_MODEL", "qwen3:8b")
MAX_STEPS      = int(os.getenv("NOVA_MAX_STEPS", "40"))
DEFAULT_TARGET = os.getenv("NOVA_TARGET",    "http://localhost:3000")
WORKSPACE.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(NOVA_DIR))

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  PROVIDER LAYER — all 7 modules + codebase mapper loaded at startup        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def _try_import(module: str, attr: str = None):
    try:
        import importlib
        mod = importlib.import_module(module)
        return getattr(mod, attr) if attr else mod
    except Exception:
        return None

# LLM Router (OpenAI → Anthropic → Gemini → Ollama)
_router_mod      = _try_import("nova_llm_router")
get_router       = getattr(_router_mod, "get_router",             None)
_ROUTER          = None  # initialised in _init_provider_layer()

# Hook Bus (lifecycle events)
_hooks_mod       = _try_import("nova_hooks")
get_bus          = getattr(_hooks_mod, "get_bus",                 None)
attach_logging   = getattr(_hooks_mod, "attach_logging_hooks",    None)
attach_telegram  = getattr(_hooks_mod, "attach_telegram_hooks",   None)

# Typed Context
RunContext       = _try_import("nova_context",      "RunContext")

# Session Store
SessionStore     = _try_import("nova_sessions",     "SessionStore")

# Observability
Tracer           = _try_import("nova_observability","Tracer")

# Retry + Circuit Breaker
RetryPolicy      = _try_import("nova_retry",        "RetryPolicy")

# Skills Library
SkillLibrary     = _try_import("nova_skills",       "SkillLibrary")

# ═══════════════════════════════════════════════════════════════════════════════
# CODEBASE MAPPER — Phase 0 of every run
# ═══════════════════════════════════════════════════════════════════════════════
_mapper_mod         = _try_import("nova_codebase_mapper")
get_codebase_map    = getattr(_mapper_mod, "get_codebase_map",       None)
map_to_agent_context= getattr(_mapper_mod, "map_to_agent_context",   None)
NovaCodebaseMapper  = getattr(_mapper_mod, "NovaCodebaseMapper",     None)

# ── Global singletons ──────────────────────────────────────────────────────────
_BUS:      Optional[Any] = None
_CTX:      Optional[Any] = None
_SESSION:  Optional[Any] = None
_TRACER:   Optional[Any] = None
_STORE:    Optional[Any] = None
_CMAP:     Optional[Any] = None   # CodebaseMap — the strategic master map
_PROVIDER_READY = False


def _init_provider_layer(target: str = "", scope: List[str] = None,
                         session_id: Optional[str] = None,
                         verbose: bool = True) -> bool:
    """Initialise all 7 provider-layer singletons once per process."""
    global _BUS, _CTX, _SESSION, _TRACER, _STORE, _ROUTER, _PROVIDER_READY
    if _PROVIDER_READY:
        return True

    # LLM Router
    if get_router:
        try:
            _ROUTER = get_router()
        except Exception:
            pass

    # Hook bus
    if get_bus:
        _BUS = get_bus(verbose=False)
        if attach_logging:
            try:
                attach_logging(_BUS)
            except Exception:
                pass
        tg_token   = os.getenv("NOVA_TELEGRAM_TOKEN")
        tg_chat_id = os.getenv("NOVA_TELEGRAM_CHAT_ID")
        if tg_token and tg_chat_id and attach_telegram:
            try:
                attach_telegram(_BUS, tg_token, tg_chat_id)
            except Exception:
                pass

    # Typed context
    if RunContext:
        _CTX = RunContext(
            target=target,
            scope=scope or ([target.split("//")[-1].split("/")[0]]
                            if target.startswith("http") else []),
            max_steps=MAX_STEPS,
            verbose=False)

    # Session store + session
    if SessionStore:
        _STORE = SessionStore()
        if session_id:
            _SESSION = _STORE.load(session_id)
            if _SESSION and verbose:
                print(f"  📂 Resumed session {session_id[:8]} "
                      f"({len(_SESSION.findings)} previous findings)")
        if not _SESSION:
            _SESSION = _STORE.create(target=target, mission="full")
            if verbose:
                print(f"  📂 Session {_SESSION.session_id[:8]} created")

    # Tracer
    if Tracer:
        _TRACER = Tracer(verbose=False)

    _PROVIDER_READY = True
    return True


# ── Lazy module loader ─────────────────────────────────────────────────────────

def _load(module_name: str, class_name: str = None):
    try:
        import importlib
        mod = importlib.import_module(module_name)
        return getattr(mod, class_name) if class_name else mod
    except Exception:
        return None


# ── Unified LLM call (router → Ollama fallback) ────────────────────────────────

def _ask_llm(prompt: str, system: str = "", temperature: float = 0.1) -> str:
    if _ROUTER:
        try:
            resp = _ROUTER.chat(
                prompt,
                system=system if system else None,
                temperature=temperature)
            return resp.content
        except Exception:
            pass
    try:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = json.dumps({
            "model": OLLAMA_MODEL, "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": 1000}
        }).encode()
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/chat", data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read()).get("message",{}).get("content","").strip()
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 0: CODEBASE MAP — runs before everything else when target is a path
# ─────────────────────────────────────────────────────────────────────────────

def _run_phase0_mapper(target: str, force: bool = False) -> Optional[Any]:
    """
    Map the target directory before any scan runs.
    Returns a CodebaseMap (or None if target is not a directory / mapper unavailable).
    The map is stored in the global _CMAP and injected into every subsequent phase.
    """
    global _CMAP

    if _CMAP and not force:
        return _CMAP

    is_dir = os.path.isdir(target)
    if not is_dir and not os.path.isdir(os.getcwd()):
        return None

    # For URL targets, try to map the current working directory as the companion codebase
    map_target = target if is_dir else os.getcwd()

    if not get_codebase_map and not NovaCodebaseMapper:
        return None

    try:
        print(f"\n  🗺  Phase 0: Codebase Mapper → {map_target}")
        if get_codebase_map:
            cmap = get_codebase_map(map_target, force=force, verbose=True)
        else:
            cmap = NovaCodebaseMapper(map_target, verbose=True).scan()

        _CMAP = cmap

        # Sync map discoveries into the shared context
        if _CTX and cmap:
            try:
                for ep in cmap.endpoints[:50]:
                    _CTX.append("endpoints", ep.get("route",""), dedupe=True)
                for lang in cmap.languages:
                    _CTX.set(f"lang_{lang.lower()}", cmap.languages[lang]["files"])
                _CTX.set("primary_language", cmap.primary_language)
                _CTX.set("frameworks",       cmap.frameworks)
                _CTX.set("auth_patterns",    cmap.auth_patterns)
                _CTX.set("databases",        cmap.databases)
                _CTX.set("codebase_mapped",  True)
            except Exception:
                pass

        # Sync secret findings as high-priority recon findings
        if _CTX and cmap and cmap.secret_findings:
            for s in cmap.secret_findings[:10]:
                try:
                    _CTX.add_finding({
                        "type":     "SecretExposure",
                        "severity": "HIGH",
                        "file":     s.get("file","?"),
                        "line":     s.get("line", 0),
                        "description": f"Potential {s.get('pattern','secret')} detected",
                        "snippet":  s.get("snippet",""),
                        "source":   "codebase_mapper",
                    }, agent="mapper")
                except Exception:
                    pass

        # Emit mapper findings to bus
        if _BUS and cmap:
            try:
                _BUS.fire("MapComplete", {
                    "file_count":      cmap.file_count,
                    "primary_language":cmap.primary_language,
                    "frameworks":      cmap.frameworks,
                    "endpoints":       len(cmap.endpoints),
                    "secrets":         len(cmap.secret_findings),
                    "risky_deps":      len(cmap.risky_deps),
                })
            except Exception:
                pass

        return cmap

    except Exception as e:
        print(f"  ⚠️  Mapper: {e}")
        return None


def _get_map_brief() -> str:
    """Return the attack brief from _CMAP for injection into module calls."""
    if not _CMAP:
        return ""
    if map_to_agent_context:
        try:
            return map_to_agent_context(_CMAP)
        except Exception:
            pass
    try:
        return _CMAP.attack_brief()
    except Exception:
        return ""


# ── Intent Parser ──────────────────────────────────────────────────────────────

KEYWORD_MODES = {
    "full_stack":      ["full stack","full-stack","everything","all modules","complete scan",
                        "mythos","v4","comprehensive","do everything","full power"],
    "daybreak":        ["daybreak","ai assessment","h1 report","hackerone report",
                        "ai threat","bounty report","scope check","daybreak pipeline"],
    "orchestrate":     ["orchestrate","multi agent","agent network","agent handoff",
                        "autonomous agent","run agents","agent pipeline"],
    "triage":          ["triage","prioritise","prioritize","rank findings","sort findings",
                        "what to report","best findings","top findings","h1 ready"],
    "code":            ["code","coding agent","fix tests","implement","refactor","repair",
                        "write code","modify repo","change code","autonomous coding"],
    "hunt":            ["hunt","bug bounty","bounty","find bugs","exploit","pentest","hack"],
    "recon":           ["recon","reconn","subdomain","enumerate","discover","footprint","crt.sh"],
    "map":             ["map codebase","codebase map","map the code","scan codebase",
                        "analyse codebase","analyze codebase","understand the code"],
    "fuzz":            ["fuzz","fuzzing","brute force","directory","endpoint","wordlist"],
    "sqli":            ["sql","sqli","sql injection","database injection","blind sql"],
    "xss":             ["xss","cross site script","reflected xss","stored xss","dom xss"],
    "ssrf":            ["ssrf","server side request","internal network","metadata","169.254"],
    "idor":            ["idor","insecure direct","broken object","access control","horizontal",
                        "privilege escalation","bola"],
    "graphql":         ["graphql","graph ql","introspection","gql","apollo"],
    "csrf":            ["csrf","cross site request","samesite","origin header","referer"],
    "race":            ["race condition","toctou","concurrent","time of check","parallel request"],
    "jwt":             ["jwt","json web token","bearer token","alg none","key confusion"],
    "proto_pollution": ["prototype pollution","proto","__proto__","constructor.prototype"],
    "business_logic":  ["business logic","negative price","coupon","workflow bypass",
                        "price manipulation","integer overflow","coupon stack"],
    "llm_injection":   ["llm","prompt injection","ai injection","jailbreak","system prompt",
                        "chatgpt","claude","copilot","ai security"],
    "sast":            ["sast","static analysis","source code","code audit","code review",
                        "source audit","code scan"],
    "sca":             ["sca","dependency","supply chain","npm audit","pip audit","cve package",
                        "library vulnerability","package scan","vulnerable library"],
    "supply_chain":    ["supply chain score","typosquat","maintainer","npm package risk",
                        "package risk","malicious package"],
    "git_scan":        ["git","commit","history","leaked secret","secret in git",
                        "git log","git blame","repo scan"],
    "cicd":            ["ci/cd","cicd","github actions","pipeline","jenkins","travis","circleci",
                        "bitbucket pipeline","azure devops","workflow security"],
    "container":       ["docker","dockerfile","container","kubernetes","k8s","helm","pod",
                        "docker-compose","compose","container security"],
    "threat_model":    ["threat model","attack surface","trust boundary","stride",
                        "entry point","data flow","threat"],
    "patch":           ["patch","fix","remediate","auto fix","auto patch","generate fix",
                        "code fix","suggest fix"],
    "detect":          ["detection","sigma","siem","splunk","elastic","suricata",
                        "detection rule","alert rule","kql"],
    "audit_report":    ["report","audit","compliance","pci","soc2","iso27001",
                        "executive report","cvss score","risk report"],
    "vuln_track":      ["track","tracker","regression","dashboard","trend","history",
                        "database","vulnerability database","vuln db"],
    "zero_day":        ["zero day","0day","cve","nvd","osv","advisory","live cve",
                        "recent vulnerability","latest cve","correlate"],
    "sandbox":         ["sandbox","validate","confirm","verify exploit","prove","poc",
                        "exploit validation","real vulnerability"],
    "bootstrap":       ["bootstrap","health check","verify install","check modules","status"],
    "continuous":      ["continuous","monitor","watch","loop","scheduled","ongoing"],
    "swarm":           ["swarm","parallel","10 agents","mass scan"],
}


def _parse_intent(query: str) -> dict:
    q = query.lower()
    llm_resp = _ask_llm(
        f"Task: {query}\n\nClassify into ONE mode. Output only the mode name.\n"
        f"Modes: {', '.join(KEYWORD_MODES.keys())}",
        system="You are Nova's intent classifier. Output only the mode name, nothing else.")
    if llm_resp and llm_resp.strip().lower() in KEYWORD_MODES:
        detected_mode = llm_resp.strip().lower()
    else:
        detected_mode = None
        for mode, kws in KEYWORD_MODES.items():
            if any(kw in q for kw in kws):
                detected_mode = mode
                break
        if not detected_mode:
            detected_mode = "hunt"

    url_match  = re.search(r'https?://[^\s]+', query)
    path_match = re.search(
        r'(?:on|for|in|at|scan|audit|map|repo|repository)\s+([./~][\w./\-]+|[\w\-]+/[\w./\-]+)', query)
    if url_match:
        target = url_match.group(0)
    elif path_match:
        target = path_match.group(1)
    else:
        target = "." if detected_mode == "code" else DEFAULT_TARGET

    return {"mode": detected_mode, "target": target, "original_query": query}


# ── Shared findings helpers ────────────────────────────────────────────────────

def _save_findings(findings: List[Dict], label: str) -> str:
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    path   = WORKSPACE / f"nova_{label}_{ts}.json"
    report = {"generated": datetime.now().isoformat(), "label": label,
              "total": len(findings), "findings": findings}
    path.write_text(json.dumps(report, indent=2, default=str))
    return str(path)


def _emit_findings(findings: List[Dict], source: str):
    """Fan out findings to: hook bus, typed context, session, vuln tracker."""
    if not findings:
        return

    if _BUS:
        for f in findings:
            try:
                _BUS.fire_finding(f, agent=source)
            except Exception:
                pass

    if _CTX:
        for f in findings:
            try:
                _CTX.add_finding(f, agent=source)
            except Exception:
                pass

    if _SESSION:
        for f in findings:
            try:
                _SESSION.add_finding(f)
            except Exception:
                pass

    TrackerCls = _load("nova_vuln_tracker", "NovaVulnTracker")
    if TrackerCls:
        try:
            t = TrackerCls()
            t.start_run(_CTX.target if _CTX else source, source)
            t.ingest_findings(findings,
                              target=_CTX.target if _CTX else source,
                              source_module=source)
            t.close()
        except Exception:
            pass


def _span(name: str, kind: str = "agent"):
    if _TRACER:
        try:
            return _TRACER.span(name, kind=kind)
        except Exception:
            pass
    import contextlib
    return contextlib.nullcontext()


# ─────────────────────────────────────────────────────────────────────────────
# MAP-AWARE MODULE WRAPPERS
# ─────────────────────────────────────────────────────────────────────────────
# These helpers pass the codebase map into modules that can accept it,
# providing strategic context to make every scan smarter.

def _map_aware_sast(target: str, findings: List[Dict]):
    """SAST — prioritise files flagged by the mapper as high-value."""
    Cls = _load("nova_source_auditor", "NovaSourceAuditor")
    if not Cls:
        return
    try:
        d = target if os.path.isdir(target) else "."
        a = Cls(d)
        # Inject high-value files from map to scan first
        if _CMAP and hasattr(a, "set_priority_files"):
            prio = [h.get("file","") for h in
                    _CMAP.attack_surface.get("high_value",[])
                    if h.get("file","")]
            if prio:
                a.set_priority_files(prio)
        a.audit_directory()
        _emit_findings(a.findings, "sast")
        findings.extend(a.findings)
    except Exception as e:
        print(f"  ⚠️  SAST: {e}")


def _map_aware_threat_model(target: str):
    """Threat model — seed with mapper's entry points, auth patterns, and data models."""
    Cls = _load("nova_threat_model", "NovaThreatModel")
    if not Cls:
        return
    try:
        tm = Cls()
        d  = target if os.path.isdir(target) else "."
        src: Dict[str, str] = {}

        # If we have a codebase map, read the specific entry-point files
        # instead of random-walking the directory
        if _CMAP and _CMAP.entry_points:
            for ep in _CMAP.entry_points[:15]:
                full = Path(d) / ep
                if full.exists():
                    try:
                        src[ep] = full.read_text(encoding="utf-8", errors="ignore")[:3000]
                    except Exception:
                        pass
        # Fallback: walk first 30 files
        if not src:
            for root, _, files in os.walk(d):
                for f in files[:30]:
                    try:
                        p = os.path.join(root, f)
                        src[os.path.relpath(p, d)] = open(
                            p, encoding="utf-8", errors="ignore").read(3000)
                    except Exception:
                        pass

        # Inject map metadata as synthetic context
        if _CMAP:
            src["__nova_map__"] = json.dumps({
                "frameworks":    _CMAP.frameworks,
                "auth_patterns": _CMAP.auth_patterns,
                "databases":     _CMAP.databases,
                "data_models":   _CMAP.data_models,
                "entry_points":  _CMAP.entry_points,
            }, default=str)

        model = tm.build_from_files(src)
        out   = WORKSPACE / "nova_threat_model.json"
        out.write_text(json.dumps(model, indent=2, default=str))
        print(f"  🗺  Threat model → {out}")
    except Exception as e:
        print(f"  ⚠️  Threat model: {e}")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  DISPATCH — 13 phases, all sharing the same provider layer + codebase map  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def dispatch(intent: dict) -> List[Dict]:
    mode   = intent["mode"]
    target = intent["target"]
    query  = intent.get("original_query", "")
    findings: List[Dict] = []

    print(f"\n{'━'*64}")
    print(f"  🦅 Nova Arsenal v4.2")
    print(f"  🎯 Mode    : {mode}")
    print(f"  📍 Target  : {target}")
    if _ROUTER:
        try:
            print(f"  🔀 Provider: {_ROUTER.available_providers()}")
        except Exception:
            pass
    if _CMAP:
        print(f"  🗺  Map     : {_CMAP.file_count} files | "
              f"{_CMAP.primary_language} | "
              f"{len(_CMAP.endpoints)} endpoints | "
              f"{len(_CMAP.secret_findings)} secrets")
    print(f"{'━'*64}\n")

    # Fire PreRun hook
    if _BUS:
        try:
            _BUS.fire("PreRun", {
                "mode": mode, "target": target, "query": query,
                "codebase_mapped": _CMAP is not None,
            })
        except Exception:
            pass

    # Session: record task
    if _SESSION:
        try:
            _SESSION.add_message("user", query, agent="nova")
        except Exception:
            pass

    t_start = time.monotonic()

    if mode == "code":
        with _span("CodeAgent", "agent"):
            Cls = _load("nova_code_agent", "NovaCodeAgent")
            if not Cls:
                return [{"type": "CodeAgent", "severity": "INFO", "description": "nova_code_agent.py is unavailable"}]
            test_command = os.getenv("NOVA_CODE_TEST_COMMAND", "")
            no_edit = os.getenv("NOVA_CODE_NO_EDIT", "false").lower() == "true"
            report = Cls(repo=target, task=query or "Autonomous coding task", test_command=test_command, allow_edits=not no_edit).run()
            finding = {
                "type": "CodeAgentRun",
                "severity": "INFO",
                "description": f"Autonomous code run {report.get('status', 'completed')}",
                "file": report.get("report_path", ""),
                "report": report,
            }
            _emit_findings([finding], "code_agent")
            return [finding]

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 0 (already ran before dispatch) — inject secrets from map as findings
    # ════════════════════════════════════════════════════════════════════════════
    if _CMAP and mode in ("full_stack", "sast", "hunt", "map"):
        sec_findings = []
        for s in _CMAP.secret_findings:
            sec_findings.append({
                "type":        "SecretExposure",
                "severity":    "HIGH",
                "file":        s.get("file",""),
                "line":        s.get("line", 0),
                "description": f"Potential {s.get('pattern','secret')} in source",
                "snippet":     s.get("snippet",""),
                "source":      "codebase_mapper",
            })
        if sec_findings:
            _emit_findings(sec_findings, "mapper")
            findings.extend(sec_findings)
            print(f"  🔑 Mapper: {len(sec_findings)} potential secrets injected as findings")

        # Risky deps as findings
        dep_findings = []
        for d in _CMAP.risky_deps:
            dep_findings.append({
                "type":        "VulnerableDependency",
                "severity":    "HIGH",
                "description": f"{d['package']} {d['version']} — {d['risk']}",
                "cve":         d.get("cve",""),
                "file":        "package.json / requirements.txt",
                "source":      "codebase_mapper",
            })
        if dep_findings:
            _emit_findings(dep_findings, "mapper")
            findings.extend(dep_findings)
            print(f"  ⚠️  Mapper: {len(dep_findings)} CVE-affected dependencies")

    # standalone map mode
    if mode == "map":
        if _CMAP:
            out = WORKSPACE / f"nova_codebase_map_latest.json"
            out.write_text(json.dumps(_CMAP.to_dict(), indent=2, default=str))
            print(f"\n{_CMAP.summary()}")
            print(f"\n{_CMAP.attack_brief()}")
            print(f"\n  💾 Map saved → {out}")
        return findings

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 1: STATIC ANALYSIS
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("sast", "hunt", "full_stack"):
        with _span("SAST", "tool"):
            _map_aware_sast(target, findings)

    if mode in ("sast", "hunt", "full_stack"):
        with _span("FilePrioritizer", "tool"):
            Cls = _load("nova_file_prioritizer", "NovaFilePrioritizer")
            if Cls:
                try:
                    Cls(target if os.path.isdir(target) else ".").prioritize()
                except Exception as e:
                    print(f"  ⚠️  File prioritizer: {e}")

    if mode in ("sca", "supply_chain", "full_stack"):
        with _span("SCA", "tool"):
            Cls = _load("nova_sca_scanner", "NovaSCAScanner")
            if Cls:
                try:
                    s = Cls()
                    d = target if os.path.isdir(target) else "."
                    r = s.scan_directory(d)
                    _emit_findings(r, "sca")
                    findings.extend(r)
                    s.save(str(WORKSPACE / "nova_sca_report.json"))
                except Exception as e:
                    print(f"  ⚠️  SCA: {e}")

    if mode in ("supply_chain", "full_stack", "sca"):
        with _span("SupplyChain", "tool"):
            Cls = _load("nova_supply_chain_scorer", "NovaSupplyChainScorer")
            if Cls:
                try:
                    s = Cls()
                    r = s.scan_directory(target if os.path.isdir(target) else ".")
                    _emit_findings(r, "supply_chain")
                    findings.extend(r)
                    s.save(str(WORKSPACE / "nova_supply_chain_report.json"))
                except Exception as e:
                    print(f"  ⚠️  Supply chain: {e}")

    if mode in ("git_scan", "full_stack"):
        with _span("GitScanner", "tool"):
            Cls = _load("nova_git_scanner", "NovaGitScanner")
            if Cls:
                try:
                    s = Cls(target if os.path.isdir(target) else ".")
                    r = s.scan()
                    _emit_findings(r, "git_scan")
                    findings.extend(r)
                    s.save(str(WORKSPACE / "nova_git_report.json"))
                except Exception as e:
                    print(f"  ⚠️  Git scan: {e}")

    if mode in ("cicd", "full_stack"):
        with _span("CICDScanner", "tool"):
            Cls = _load("nova_cicd_scanner", "NovaCICDScanner")
            if Cls:
                try:
                    s = Cls()
                    r = s.scan_directory(target if os.path.isdir(target) else ".")
                    _emit_findings(r, "cicd")
                    findings.extend(r)
                    s.save(str(WORKSPACE / "nova_cicd_report.json"))
                except Exception as e:
                    print(f"  ⚠️  CI/CD: {e}")

    if mode in ("container", "full_stack"):
        with _span("ContainerScanner", "tool"):
            Cls = _load("nova_container_scanner", "NovaContainerScanner")
            if Cls:
                try:
                    s = Cls()
                    r = s.scan_directory(target if os.path.isdir(target) else ".")
                    _emit_findings(r, "container")
                    findings.extend(r)
                    s.save(str(WORKSPACE / "nova_container_report.json"))
                except Exception as e:
                    print(f"  ⚠️  Container: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 2: THREAT MODELING (map-aware — uses entry points from mapper)
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("threat_model", "full_stack"):
        with _span("ThreatModel", "agent"):
            _map_aware_threat_model(target)

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 3: PASSIVE RECON
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("recon",):
        with _span("Recon", "agent"):
            Cls = _load("nova_recon", "NovaRecon")
            if Cls:
                try:
                    r = Cls(target)
                    r.run()
                    if hasattr(r, "findings"):
                        _emit_findings(r.findings, "recon")
                        findings.extend(r.findings)
                except Exception as e:
                    print(f"  ⚠️  Recon: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 4: ACTIVE VULNERABILITY TESTING
    # Endpoints from the codebase map are injected as seeds where modules accept them
    # ════════════════════════════════════════════════════════════════════════════

    _url = target if target.startswith("http") else DEFAULT_TARGET

    # Seed URL list from codebase map (endpoints discovered in source code)
    _map_endpoints: List[str] = []
    if _CMAP:
        base = _url.rstrip("/")
        _map_endpoints = list(dict.fromkeys(
            base + ep["route"]
            for ep in _CMAP.endpoints if ep.get("route","").startswith("/")
        ))[:100]
        if _map_endpoints:
            print(f"  🗺  Seeding {len(_map_endpoints)} endpoints from codebase map")

    def _inject_endpoints(scanner_obj, attr: str = "seed_urls"):
        """Try to inject pre-discovered endpoints into a scanner."""
        if _map_endpoints and hasattr(scanner_obj, attr):
            try:
                setattr(scanner_obj, attr, _map_endpoints)
            except Exception:
                pass

    if mode in ("idor", "hunt", "full_stack"):
        with _span("IDORScanner", "tool"):
            Cls = _load("nova_idor_scanner", "NovaIDORScanner")
            if Cls:
                try:
                    s = Cls(_url)
                    _inject_endpoints(s)
                    r = s.run()
                    _emit_findings(r, "idor")
                    findings.extend(r)
                    s.save(str(WORKSPACE / "nova_idor_report.json"))
                except Exception as e:
                    print(f"  ⚠️  IDOR: {e}")

    if mode in ("graphql", "hunt", "full_stack"):
        with _span("GraphQL", "tool"):
            Cls = _load("nova_graphql_tester", "NovaGraphQLTester")
            if Cls:
                try:
                    s = Cls(_url)
                    r = s.run()
                    _emit_findings(r, "graphql")
                    findings.extend(r)
                    s.save(str(WORKSPACE / "nova_graphql_report.json"))
                except Exception as e:
                    print(f"  ⚠️  GraphQL: {e}")

    if mode in ("csrf", "hunt", "full_stack"):
        with _span("CSRF", "tool"):
            Cls = _load("nova_csrf_tester", "NovaCsrfTester")
            if Cls:
                try:
                    s = Cls(_url)
                    _inject_endpoints(s)
                    r = s.run()
                    _emit_findings(r, "csrf")
                    findings.extend(r)
                    s.save(str(WORKSPACE / "nova_csrf_report.json"))
                except Exception as e:
                    print(f"  ⚠️  CSRF: {e}")

    if mode in ("business_logic", "hunt", "full_stack"):
        with _span("BusinessLogic", "tool"):
            Cls = _load("nova_business_logic", "NovaBusinessLogicTester")
            if Cls:
                try:
                    s = Cls(_url)
                    _inject_endpoints(s)
                    r = s.run()
                    _emit_findings(r, "business_logic")
                    findings.extend(r)
                    s.save(str(WORKSPACE / "nova_business_logic_report.json"))
                except Exception as e:
                    print(f"  ⚠️  Business logic: {e}")

    if mode in ("jwt",):
        with _span("JWT", "tool"):
            Cls = _load("nova_jwt_forge", "NovaJWTForge")
            if Cls:
                try:
                    s = Cls(_url)
                    r = s.run()
                    _emit_findings(r, "jwt")
                    findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  JWT: {e}")

    if mode in ("sqli", "hunt"):
        with _span("SQLi", "tool"):
            Cls = _load("nova_fuzzer", "NovaFuzzer")
            if Cls:
                try:
                    s = Cls(_url)
                    _inject_endpoints(s)
                    r = s.run_sqli()
                    r = r if isinstance(r, list) else []
                    _emit_findings(r, "sqli")
                    findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  SQLi: {e}")

    if mode in ("fuzz",):
        with _span("Fuzzer", "tool"):
            Cls = _load("nova_fuzzer", "NovaFuzzer")
            if Cls:
                try:
                    s = Cls(_url)
                    _inject_endpoints(s)
                    s.run()
                except Exception as e:
                    print(f"  ⚠️  Fuzz: {e}")

    if mode in ("proto_pollution",):
        with _span("ProtoPollution", "tool"):
            Cls = _load("nova_proto_polluter", "NovaProtoPolluter")
            if Cls:
                try:
                    s = Cls(_url)
                    r = s.run()
                    r = r if isinstance(r, list) else []
                    _emit_findings(r, "proto_pollution")
                    findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  Proto pollution: {e}")

    if mode in ("race",):
        with _span("RaceCondition", "tool"):
            Cls = _load("nova_race_engine", "NovaRaceEngine")
            if Cls:
                try:
                    s = Cls(_url)
                    _inject_endpoints(s)
                    r = s.run()
                    r = r if isinstance(r, list) else []
                    _emit_findings(r, "race")
                    findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  Race: {e}")

    if mode in ("ssrf",):
        with _span("SSRF", "tool"):
            Cls = _load("nova_fuzzer", "NovaFuzzer")
            if Cls:
                try:
                    s = Cls(_url)
                    _inject_endpoints(s)
                    r = s.run_ssrf() if hasattr(s, "run_ssrf") else []
                    r = r if isinstance(r, list) else []
                    _emit_findings(r, "ssrf")
                    findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  SSRF: {e}")

    if mode in ("llm_injection",):
        with _span("LLMInjection", "tool"):
            Cls = _load("nova_llm_injection", "NovaLLMInjectionTester")
            if Cls:
                try:
                    s = Cls(_url)
                    r = s.run()
                    _emit_findings(r, "llm_injection")
                    findings.extend(r)
                    s.save(str(WORKSPACE / "nova_llm_injection_report.json"))
                except Exception as e:
                    print(f"  ⚠️  LLM injection: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 5: CVE CORRELATION
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("zero_day", "full_stack"):
        with _span("ZeroDayCorrelator", "tool"):
            Cls = _load("nova_zero_day_correlator", "NovaZeroDayCorrelator")
            if Cls:
                try:
                    c = Cls()
                    r = c.correlate(target if os.path.isdir(target) else ".", findings)
                    _emit_findings(r, "zero_day")
                    findings.extend(r)
                    c.save(str(WORKSPACE / "nova_zero_day_report.json"))
                except Exception as e:
                    print(f"  ⚠️  Zero-day: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 6: EXPLOIT VALIDATION
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("sandbox",) and findings:
        with _span("SandboxValidator", "tool"):
            Cls = _load("nova_sandbox_validator", "NovaSandboxValidator")
            if Cls:
                try:
                    s = Cls(_url)
                    r = s.validate(findings[:10])
                    r = r if isinstance(r, list) else []
                    _emit_findings(r, "sandbox")
                    findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  Sandbox: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 7: MULTI-AGENT ORCHESTRATION (map injected into every agent)
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("orchestrate",):
        with _span("Orchestrator", "agent"):
            OrcMod = _load("nova_orchestrator")
            if OrcMod:
                try:
                    runner = OrcMod.build_security_network(
                        _url,
                        scope=[_url.split("//")[-1].split("/")[0]],
                        session=_SESSION,
                        codebase_map=_CMAP,   # ← strategic map injected
                        verbose=True)
                    result = runner.run(query, start="ReconAgent")
                    _emit_findings(result.findings, "orchestrate")
                    findings.extend(result.findings)
                    print(f"  🧠 Orchestrator: {result.steps} steps, "
                          f"${result.cost_usd:.5f}, {result.tokens_used} tokens")
                except Exception as e:
                    print(f"  ⚠️  Orchestrator: {e}")

    if mode in ("swarm",):
        with _span("Swarm", "agent"):
            Cls = _load("nova_swarm_v3", "NovaSwarm")
            if Cls:
                try:
                    s = Cls(_url)
                    r = s.run()
                    r = r if isinstance(r, list) else []
                    _emit_findings(r, "swarm")
                    findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  Swarm: {e}")

    if mode in ("hunt",):
        with _span("AgentCore", "agent"):
            Cls = _load("nova_agent_core", "NovaAgentCore") or _load("nova_agent_core", "NovaAgent")
            if Cls:
                try:
                    agent = Cls(_url, max_steps=MAX_STEPS)
                    # Inject map brief into agent if it supports it
                    if _CMAP and hasattr(agent, "set_codebase_context"):
                        agent.set_codebase_context(_get_map_brief())
                    r = agent.run(query)
                    r = r if isinstance(r, list) else []
                    _emit_findings(r, "hunt")
                    findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  Agent core: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 8: DAYBREAK AI ASSESSMENT (scope-aware + map-guided)
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("daybreak", "full_stack"):
        with _span("Daybreak", "agent"):
            Cls = _load("nova_daybreak", "NovaDaybreak")
            if Cls:
                try:
                    scope = None
                    ScopeMgr = _load("nova_scope_manager", "NovaScopeManager")
                    if ScopeMgr:
                        try:
                            sm    = ScopeMgr()
                            scope = sm.load_scope_for_target(target)
                            if scope:
                                print(f"  🔭 Scope: {scope.get('program','?')} "
                                      f"({len(scope.get('in_scope',[]))} entries)")
                        except Exception:
                            pass
                    db = Cls(target, scope=scope)
                    # Inject map context if Daybreak supports it
                    if _CMAP and hasattr(db, "set_codebase_context"):
                        db.set_codebase_context(_get_map_brief())
                    r  = db.run()
                    r  = r if isinstance(r, list) else []
                    _emit_findings(r, "daybreak")
                    findings.extend(r)
                    db.save(str(WORKSPACE / "nova_daybreak_report.json"))
                except Exception as e:
                    print(f"  ⚠️  Daybreak: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 9: FULL-STACK ACTIVE PROBES
    # ════════════════════════════════════════════════════════════════════════════

    if mode == "full_stack":
        print("\n  🚀 Phase 9: Active API probes...")
        for sub_mode in ("idor", "graphql", "csrf", "business_logic",
                         "race", "jwt", "sqli", "ssrf"):
            sub_intent = {"mode": sub_mode, "target": _url, "original_query": query}
            try:
                sub_findings = dispatch(sub_intent)
                findings.extend(sub_findings)
            except Exception as e:
                print(f"  ⚠️  Sub-dispatch {sub_mode}: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 10: PATCH + DETECTION + REPORTING
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("patch", "full_stack") and findings:
        with _span("PatchGenerator", "tool"):
            Cls = _load("nova_patch_generator", "NovaPatchGenerator")
            if Cls:
                try:
                    pg = Cls()
                    patches = pg.generate_patches(findings[:10])
                    out = WORKSPACE / "nova_patches.json"
                    out.write_text(json.dumps(patches, indent=2, default=str))
                    print(f"  🔧 Patches → {out}")
                except Exception as e:
                    print(f"  ⚠️  Patch gen: {e}")

    if mode in ("detect", "full_stack") and findings:
        with _span("DetectionEngineer", "tool"):
            Cls = _load("nova_detection_engineer", "NovaDetectionEngineer")
            if Cls:
                try:
                    de    = Cls()
                    rules = de.generate_rules(findings[:10])
                    out   = WORKSPACE / "nova_detection_rules.json"
                    out.write_text(json.dumps(rules, indent=2, default=str))
                    print(f"  🔔 Detection rules → {out}")
                except Exception as e:
                    print(f"  ⚠️  Detect: {e}")

    if mode in ("audit_report", "full_stack") and findings:
        with _span("AuditReporter", "tool"):
            Cls = _load("nova_audit_reporter", "NovaAuditReporter")
            if Cls:
                try:
                    ar     = Cls(target)
                    report = ar.generate(findings)
                    out    = WORKSPACE / "nova_audit_report.json"
                    out.write_text(json.dumps(report, indent=2, default=str))
                    print(f"  📋 Audit report → {out}")
                except Exception as e:
                    print(f"  ⚠️  Audit: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 11: TRIAGE + PRIORITISATION
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("triage",) and findings:
        with _span("Triage", "agent"):
            TriCls = _load("nova_triage", "NovaTriage")
            if TriCls:
                try:
                    triage = TriCls()
                    triage.ingest(findings, source=mode)
                    ranked = triage.run()
                    triage.print_summary()
                    triage.save(str(WORKSPACE / "nova_triage_report.json"))
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
                except Exception as e:
                    print(f"  ⚠️  Triage: {e}")

    if mode in ("full_stack",) and findings:
        with _span("AutoTriage", "agent"):
            TriCls = _load("nova_triage", "NovaTriage")
            if TriCls:
                try:
                    triage = TriCls(skip_llm=False)
                    triage.ingest(findings, source="full_stack")
                    ranked = triage.run()
                    triage.save(str(WORKSPACE / "nova_triage_report.json"))
                    print(f"  🎯 Auto-triage: {len(ranked)} ranked findings")
                except Exception as e:
                    print(f"  ⚠️  Auto-triage: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 12: VULN TRACKER DASHBOARD
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("vuln_track",):
        Cls = _load("nova_vuln_tracker", "NovaVulnTracker")
        if Cls:
            try:
                t  = Cls()
                rp = t.report(str(WORKSPACE / "nova_tracker_report.json"))
                md = t.markdown_dashboard()
                (WORKSPACE / "nova_tracker_dashboard.md").write_text(md)
                t.close()
                print(f"  📊 Tracker: {rp['trend']['total_open']} open | "
                      f"{rp['trend']['total_fixed']} fixed")
            except Exception as e:
                print(f"  ⚠️  Tracker: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # SPECIAL MODES
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("bootstrap",):
        try:
            import nova_bootstrap
            nova_bootstrap.main()
            return []
        except Exception as e:
            print(f"  ⚠️  Bootstrap: {e}")

    if mode in ("continuous",):
        Cls = _load("nova_continuous", "NovaContinuous")
        if Cls:
            try:
                c = Cls(target)
                c.run()
            except Exception as e:
                print(f"  ⚠️  Continuous: {e}")

    # ════════════════════════════════════════════════════════════════════════════
    # FINALISE
    # ════════════════════════════════════════════════════════════════════════════

    elapsed_ms = (time.monotonic() - t_start) * 1000

    if _BUS:
        try:
            _BUS.fire("PostRun", {
                "mode": mode, "target": target,
                "findings_count": len(findings),
                "elapsed_ms": elapsed_ms,
            })
        except Exception:
            pass

    if _SESSION and _STORE:
        try:
            if _SESSION.runs:
                run = _SESSION.runs[-1]
                run.ended_at      = datetime.now(timezone.utc).isoformat()
                run.findings_count = len(findings)
            _SESSION.add_message(
                "assistant",
                f"Completed {mode}: {len(findings)} findings in {elapsed_ms:.0f}ms",
                agent="nova")
            _STORE.save(_SESSION)
        except Exception:
            pass

    if _TRACER:
        try:
            if _TRACER._root:
                _TRACER._root.end()
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            _TRACER.save(str(WORKSPACE / f"nova_trace_{ts}.json"))
            _TRACER.export_html(str(WORKSPACE / f"nova_trace_{ts}.html"))
        except Exception:
            pass

    if findings:
        path     = _save_findings(findings, mode)
        critical = [f for f in findings
                    if str(f.get("severity","")).upper() in ("CRITICAL","HIGH")]
        sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}

        print(f"\n{'━'*64}")
        print(f"  📊 Total findings : {len(findings)}")
        print(f"  🔴 Critical/High  : {len(critical)}")
        print(f"  ⏱  Elapsed        : {elapsed_ms/1000:.1f}s")
        if _ROUTER:
            try:
                print(f"  💰 LLM cost       : ${_ROUTER.session_cost():.5f}")
            except Exception:
                pass
        print(f"  💾 Saved          : {path}")
        if _SESSION:
            print(f"  📂 Session        : {_SESSION.session_id[:8]}")
        if _CMAP:
            print(f"  🗺  Map            : {_CMAP.file_count} files | "
                  f"{_CMAP.primary_language} | "
                  f"{len(_CMAP.endpoints)} endpoints")
        if critical:
            print(f"\n  Top findings:")
            for f in sorted(critical,
                            key=lambda x: sev_order.get(
                                str(x.get("severity","INFO")).upper(), 4))[:5]:
                icon = {"CRITICAL":"🔴","HIGH":"🟠"}.get(
                    f.get("severity","").upper(),"•")
                print(f"  {icon} [{f.get('severity','?')}] {f.get('type','?')}"
                      f" — {f.get('file') or f.get('endpoint','?')}")
        print(f"{'━'*64}\n")

    return findings


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("Usage: python3 nova.py \"Your security task in plain English\"\n")
        examples = [
            "Use the autonomous coding agent to fix failing tests in .",
            "Hunt http://localhost:3000 for all vulnerabilities",
            "Map the codebase at ./juice-shop",
            "Full stack pipeline on ./juice-shop",
            "Orchestrate multi-agent attack on https://target.com",
            "Daybreak AI assessment on https://target.com",
            "SAST code audit of ./src",
            "Scan git history for leaked secrets",
            "Build STRIDE threat model for ./my-app",
            "Triage findings and rank by H1 priority",
            "Show vulnerability tracker dashboard",
            "Health check of all Nova modules",
        ]
        for ex in examples:
            print(f"  python3 nova.py \"{ex}\"")
        sys.exit(0)

    query  = " ".join(a for a in sys.argv[1:] if not a.startswith("--"))
    intent = _parse_intent(query)

    # Parse --session flag
    session_id = None
    for i, arg in enumerate(sys.argv):
        if arg == "--session" and i + 1 < len(sys.argv):
            session_id = sys.argv[i + 1]

    print(f"\n  🦅 Nova Arsenal v4.2")
    print(f"  📝 Task: \"{query[:80]}\"")

    _init_provider_layer(
        target=intent["target"],
        session_id=session_id,
        verbose=True)

    # ═══════════════════════════════════════════════════════════════════════
    # PHASE 0 — Map the codebase BEFORE running any scan
    # This gives every subsequent phase full strategic intelligence:
    #   • All languages, frameworks, dependencies
    #   • Every route/endpoint discovered in source code
    #   • Auth patterns, DB connections, data models
    #   • Pre-detected secrets and CVE-affected deps
    #   • AI-generated attack priority order
    # ═══════════════════════════════════════════════════════════════════════
    if intent["mode"] != "code":
        _run_phase0_mapper(intent["target"])

    findings = dispatch(intent)

    has_critical = any(
        str(f.get("severity","")).upper() in ("CRITICAL","HIGH")
        for f in findings)
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
