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

# ── Extended providers (previously orphaned modules) ─────────────────────────
# Brain / Memory System
_brain_mod        = _try_import("nova_memory_system")
get_brain         = getattr(_brain_mod,        "get_brain",        None)
# Notifications
_notif_mod        = _try_import("nova_notifications")
NovaNotifications = getattr(_notif_mod,        "NovaNotifications",None)
# Error Handler
_err_mod          = _try_import("nova_error_handler")
NovaErrorHandler  = getattr(_err_mod,          "NovaErrorHandler", None)
# Findings DB
_fdb_mod          = _try_import("nova_findings_db")
NovaFindingsDB    = getattr(_fdb_mod,          "NovaFindingsDB",   None)
# Context Engine + Enricher
NovaContextEngine  = _try_import("nova_context_engine",  "NovaContextEngine")
ContextEnricher    = _try_import("nova_context_enricher","ContextEnricher")
# RAG Builder
_rag_mod  = _try_import("nova_rag_builder")
get_rag   = getattr(_rag_mod, "get_rag", None)
# Output / Result Parsers
NovaOutputParser = _try_import("nova_output_parser",  "NovaOutputParser")
ResultFindingsDB = _try_import("nova_result_parser",  "FindingsDatabase")
# LLM Bridge (alternate LLM client over HTTP)
_bridge_mod  = _try_import("nova_llm_bridge")
get_bridge   = getattr(_bridge_mod, "get_bridge", None)
# Memory
TargetMemory = _try_import("nova_memory", "TargetMemory")
# Weapon Forge — dedicated exploit writer
_forge_mod      = _try_import("nova_weapon_forge")
NovaWeaponForge = getattr(_forge_mod, "NovaWeaponForge", None)
get_weapon_forge= getattr(_forge_mod, "get_weapon_forge", None)
# Auto-Exploit Loop — autonomous Critical/High exploit pipeline
_auto_ex_mod       = _try_import("nova_auto_exploit_loop")
AutoExploitLoop    = getattr(_auto_ex_mod, "AutoExploitLoop",       None)
get_auto_exploit   = getattr(_auto_ex_mod, "get_auto_exploit_loop", None)

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
# Extended singletons
_BRAIN:    "Optional[Any]" = None   # NovaBrain — cross-session memory
_NOTIF:    "Optional[Any]" = None   # NovaNotifications
_ERR:      "Optional[Any]" = None   # NovaErrorHandler
_FDB:      "Optional[Any]" = None   # NovaFindingsDB
_CTX_ENG:  "Optional[Any]" = None   # NovaContextEngine
_RAG:      "Optional[Any]" = None   # NovaRAGBuilder
_FORGE:    "Optional[Any]" = None   # NovaWeaponForge singleton
_AUTO_EX:  "Optional[Any]" = None   # AutoExploitLoop singleton


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

    # ── Extended providers (previously orphaned modules) ────────────────────
    global _BRAIN, _NOTIF, _ERR, _FDB, _CTX_ENG, _RAG
    if get_brain:
        try:
            _BRAIN = get_brain()
        except Exception:
            pass
    if NovaNotifications:
        try:
            _NOTIF = NovaNotifications()
        except Exception:
            pass
    if NovaErrorHandler:
        try:
            _ERR = NovaErrorHandler()
        except Exception:
            pass
    if NovaFindingsDB:
        try:
            _FDB = NovaFindingsDB(str(WORKSPACE / "nova_findings.db"))
        except Exception:
            pass
    if NovaContextEngine:
        try:
            _CTX_ENG = NovaContextEngine()
        except Exception:
            pass
    if get_rag:
        try:
            _RAG = get_rag(str(NOVA_DIR))
        except Exception:
            pass
    global _FORGE, _AUTO_EX
    if get_weapon_forge:
        try:
            _FORGE = get_weapon_forge(target=target, dry_run=True)
        except Exception:
            pass
    if get_auto_exploit:
        try:
            _AUTO_EX = get_auto_exploit(target=target,
                                         session_id=session_id or "")
        except Exception:
            pass

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
    # ── Newly wired modes ────────────────────────────────────────────────────
    "multi_target":    ["multi target","multiple targets","bulk scan","target list","batch scan"],
    "attack":          ["attack chain","full attack","unified attack","exploit chain","chained exploit"],
    "wild_hunt":       ["wild hunt","open bounty","bug bounty full","h1 hunt","hackerone hunt"],
    "ibb":             ["ibb","intigriti","internet bug bounty","ibb hunt","ibb program"],
    "0din":            ["0din","0day hunt","zero-day hunt","0din hunter","lfm"],
    "github_scan":     ["github scan","github code search","github secrets","code search","gh recon"],
    "ecosystem":       ["ecosystem audit","npm graph","dep graph","package ecosystem","dep map"],
    "pypi":            ["pypi","malicious pypi","python package hunt","pip hunt","typosquatting"],
    "browser":         ["browser agent","headless browser","playwright scan","selenium","visual scan"],
    "pipeline":        ["nova pipeline","staged scan","scan pipeline","full pipeline mode"],
    "nextgen":         ["nextgen","next gen agent","autonomous agent mode","next generation"],
    "kali":            ["kali","kali linux","pentest","penetration test","kali agent","metasploit"],
    "portswigger":     ["portswigger","web security academy","burp lab","burp suite","web academy"],
    "weapon_forge":    ["weapon forge","forge exploit","write exploit","generate exploit",
                        "exploit code","exploit writer","create exploit","build exploit"],
    "auto_exploit":    ["auto exploit","auto-exploit","autonomous exploit",
                        "exploit automatically","confirm exploit"],
    "report":          ["generate report","html report","export findings","write report","markdown report"],
    "auth":            ["auth scan","authenticated scan","login bypass","auth bypass","broken auth"],
    "dataflow":        ["dataflow","data flow","taint","source sink","taint analysis"],
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
        r'(?:on|for|in|at|scan|audit|map)\s+([./~][\w./\-]+|[\w\-]+/[\w./\-]+)', query)
    if url_match:
        target = url_match.group(0)
    elif path_match:
        target = path_match.group(1)
    else:
        target = DEFAULT_TARGET

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
    # INTELLIGENCE PHASES — wire orphaned intelligence modules into hunt/full_stack
    # ════════════════════════════════════════════════════════════════════════════

    if mode in ("hunt", "full_stack", "daybreak", "dataflow"):
        with _span("DataFlowEngine", "tool"):
            Cls = _load("nova_dataflow_engine", "NovaDataFlowEngine")
            if Cls:
                try:
                    df = Cls(target if os.path.isdir(target) else ".")
                    r  = df.analyze() if hasattr(df, "analyze") else []
                    if isinstance(r, list) and r:
                        _emit_findings(r, "dataflow")
                        findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  DataFlow: {e}")

    if mode in ("auth", "hunt", "full_stack"):
        with _span("AuthScanner", "tool"):
            Cls = _load("nova_auth_scanner", "NovaAuthenticatedScanner")
            if Cls:
                try:
                    s = Cls(target)
                    r = s.scan() if hasattr(s, "scan") else []
                    if isinstance(r, list) and r:
                        _emit_findings(r, "auth_scan")
                        findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  Auth scanner: {e}")

    if mode in ("hunt", "full_stack", "daybreak"):
        with _span("HypothesisEngine", "agent"):
            Cls = _load("nova_hypothesis_engine", "HypothesisEngine")
            if Cls:
                try:
                    he = Cls(target)
                    if hasattr(he, "generate"):
                        he.generate(context=_CTX)
                    if hasattr(he, "findings") and he.findings:
                        _emit_findings(he.findings, "hypothesis")
                        findings.extend(he.findings)
                except Exception as e:
                    print(f"  ⚠️  Hypothesis engine: {e}")

    if mode in ("hunt", "full_stack", "daybreak"):
        with _span("ChainOfThought", "agent"):
            Cls = _load("nova_chain_of_thought", "NovaChainOfThought")
            if Cls:
                try:
                    cot = Cls()
                    if hasattr(cot, "reason") and query:
                        cot.reason(task=query, target=target)
                except Exception as e:
                    print(f"  ⚠️  Chain-of-thought: {e}")

    if mode in ("hunt", "full_stack") and findings:
        with _span("VulnSynthesis", "agent"):
            Cls = _load("nova_vuln_synthesis", "NovaVulnSynthesis")
            if Cls:
                try:
                    vs    = Cls()
                    synth = vs.synthesize(findings, target=target) if hasattr(vs, "synthesize") else []
                    if isinstance(synth, list) and synth:
                        _emit_findings(synth, "synthesis")
                        findings.extend(synth)
                except Exception as e:
                    print(f"  ⚠️  Vuln synthesis: {e}")

    if mode in ("hunt", "full_stack") and findings:
        with _span("LiveVerify", "tool"):
            Cls = _load("nova_live_verify", "LiveVerificationEngine")
            if Cls:
                try:
                    lv = Cls(target)
                    if hasattr(lv, "verify_bulk"):
                        lv.verify_bulk(findings)
                except Exception as e:
                    print(f"  ⚠️  Live verify: {e}")

    if mode in ("hunt", "full_stack"):
        with _span("URLSmuggling", "tool"):
            mod = _load("nova_url_smuggling")
            if mod:
                try:
                    fn = getattr(mod, "run", None) or getattr(mod, "scan", None) or getattr(mod, "test", None)
                    if fn:
                        r = fn(target)
                        if isinstance(r, list) and r:
                            _emit_findings(r, "url_smuggling")
                            findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  URL smuggling: {e}")

    # Report generation — always run on hunt/full_stack if findings exist
    if mode in ("report", "hunt", "full_stack") and findings:
        mod = _load("nova_report")
        if mod:
            try:
                bh = getattr(mod, "_build_html",     None)
                bm = getattr(mod, "_build_markdown", None)
                meta = {"mode": mode, "generated": datetime.now().isoformat()}
                if bh:
                    html = bh(target, findings, meta)
                    hp = WORKSPACE / f"nova_report_{mode}.html"
                    hp.write_text(html, encoding="utf-8")
                    print(f"  📄 HTML report → {hp}")
                if bm:
                    md = bm(target, findings, meta)
                    mp = WORKSPACE / f"nova_report_{mode}.md"
                    mp.write_text(md, encoding="utf-8")
                    print(f"  📄 MD report   → {mp}")
            except Exception as e:
                print(f"  ⚠️  Report: {e}")

    # Store session in brain memory
    if _BRAIN and mode in ("hunt", "full_stack", "daybreak"):
        try:
            store_fn = getattr(_BRAIN, "store_session", getattr(_BRAIN, "add", None))
            if store_fn:
                store_fn(target=target, mode=mode, findings=findings)
        except Exception:
            pass

    # ── AUTO-EXPLOIT LOOP ─────────────────────────────────────────────────────
    # Fires on Critical/High findings when NOVA_AUTO_EXPLOIT=1.
    # Pipeline: forge PoC → validate → live-verify → confirm → alert → memorise
    if findings and mode in ("hunt","full_stack","daybreak","swarm","pipeline",
                              "nextgen","wild_hunt","ibb","0din","attack"):
        if AutoExploitLoop:
            try:
                import os as _os
                loop = AutoExploitLoop(target=target, session_id="")
                if _os.getenv("NOVA_AUTO_EXPLOIT","0") == "1":
                    loop.enable()
                confirmed = loop.run(findings)
                if confirmed:
                    print(f"\n  🔴 AUTO-EXPLOIT: {len(confirmed)} finding(s) CONFIRMED EXPLOITABLE")
                    for c in confirmed:
                        ex = c.get("auto_exploit",{})
                        print(f"     ⚔️  [{c.get('severity','?')}] {c.get('type','?')} "
                              f"→ {ex.get('exploit_file','(dry-run)')}")
                    _emit_findings(confirmed, "auto_exploit_loop")
            except Exception:
                pass  # auto-exploit is non-blocking

    # ── WEAPON FORGE — auto-forge on Critical findings (dry-run by default) ────
    if findings and mode in ("hunt","full_stack","attack","kali"):
        trigger_findings = [f for f in findings
                            if str(f.get("severity","")).upper() == "CRITICAL"]
        if trigger_findings and NovaWeaponForge:
            try:
                forge = NovaWeaponForge(target=target, dry_run=True)
                forged = forge.batch_forge(trigger_findings[:3])
                if forged:
                    print(f"\n  ⚔️  WEAPON FORGE: {len(forged)} exploit(s) generated (dry-run)")
                    for fw in forged:
                        if fw.get("ok"):
                            print(f"     → {fw['vuln_type']} ({fw['code_lines']} lines) "
                                  f"[{fw['severity']}]")
            except Exception:
                pass  # non-blocking

    # ════════════════════════════════════════════════════════════════════════════
    # NEW SPECIALIST MODES — previously orphaned, now fully wired
    # ════════════════════════════════════════════════════════════════════════════

    # ── Weapon Forge mode (direct exploit generation) ─────────────────────────
    if mode in ("weapon_forge", "forge", "exploit_write"):
        ForgeClass = _load("nova_weapon_forge", "NovaWeaponForge")
        if ForgeClass:
            try:
                forge = ForgeClass(target=target, dry_run=False)
                cve_match = re.search(r"CVE-\d{4}-\d+", query, re.I)
                if cve_match:
                    r = forge.forge_from_cve(cve_match.group())
                else:
                    r = forge.forge_from_description(query)
                if r.get("ok"):
                    findings.append({
                        "type": "ExploitGenerated",
                        "severity": r.get("severity","INFO"),
                        "description": f"Exploit forged: {r['filename']}",
                        "vuln_type": r.get("vuln_type",""),
                        "code_lines": r.get("code_lines",0),
                        "filepath": r.get("filepath",""),
                        "source": "nova_weapon_forge",
                    })
                    print(f"  ⚔️  Weapon forged: {r['filename']} ({r['code_lines']} lines)")
            except Exception as e:
                print(f"  ⚠️  Weapon Forge: {e}")

    if mode in ("wild_hunt",):
        Cls = _load("nova_wild_hunt", "NovaWildHunt")
        if Cls:
            try:
                w = Cls(target)
                r = w.hunt() if hasattr(w, "hunt") else (w.run() if hasattr(w, "run") else [])
                _emit_findings(r, "wild_hunt")
                findings.extend(r)
            except Exception as e:
                print(f"  ⚠️  Wild hunt: {e}")

    if mode in ("ibb",):
        Cls = _load("nova_ibb_hunter", "NovaIBBHunter")
        if Cls:
            try:
                h = Cls(target)
                r = h.hunt() if hasattr(h, "hunt") else (h.run() if hasattr(h, "run") else [])
                _emit_findings(r, "ibb")
                findings.extend(r)
            except Exception as e:
                print(f"  ⚠️  IBB hunter: {e}")

    if mode in ("0din",):
        Cls = _load("nova_0din_hunter", "Nova0DINHunter")
        if Cls:
            try:
                h = Cls(target)
                r = h.hunt() if hasattr(h, "hunt") else (h.run() if hasattr(h, "run") else [])
                _emit_findings(r, "0din")
                findings.extend(r)
            except Exception as e:
                print(f"  ⚠️  0DIN hunter: {e}")

    if mode in ("github_scan",):
        with _span("GitHubScanner", "tool"):
            Cls = _load("nova_github_scanner", "NovaGitHubScanner")
            if Cls:
                try:
                    s = Cls(target)
                    r = s.scan() if hasattr(s, "scan") else []
                    _emit_findings(r, "github_scan")
                    findings.extend(r)
                    if hasattr(s, "save"):
                        s.save(str(WORKSPACE / "nova_github_scan_report.json"))
                except Exception as e:
                    print(f"  ⚠️  GitHub scanner: {e}")

    if mode in ("ecosystem", "sca", "full_stack"):
        with _span("EcosystemAuditor", "tool"):
            Cls = _load("nova_ecosystem_auditor", "NovaEcosystemAuditor")
            if Cls:
                try:
                    ea = Cls(target if os.path.isdir(target) else ".")
                    r  = ea.audit() if hasattr(ea, "audit") else (ea.scan() if hasattr(ea, "scan") else [])
                    if isinstance(r, list) and r:
                        _emit_findings(r, "ecosystem")
                        findings.extend(r)
                except Exception as e:
                    print(f"  ⚠️  Ecosystem auditor: {e}")

    if mode in ("pypi",):
        Cls = _load("nova_pypi_hunter", "NovaPyPIHunter")
        if Cls:
            try:
                h = Cls(target)
                r = h.hunt() if hasattr(h, "hunt") else (h.run() if hasattr(h, "run") else [])
                _emit_findings(r, "pypi")
                findings.extend(r)
            except Exception as e:
                print(f"  ⚠️  PyPI hunter: {e}")

    if mode in ("browser",):
        Cls = _load("nova_browser_agent", "NovaBrowserAgent")
        if Cls:
            try:
                b = Cls(target)
                r = b.scan() if hasattr(b, "scan") else (b.run() if hasattr(b, "run") else [])
                _emit_findings(r, "browser")
                findings.extend(r)
            except Exception as e:
                print(f"  ⚠️  Browser agent: {e}")

    if mode in ("multi_target",):
        mod = _load("nova_multi_target_orchestrator")
        if mod:
            try:
                targets = [t.strip() for t in re.split(r"[,\s]+", target) if t.strip()]
                OrcCls  = (getattr(mod, "MultiTargetOrchestrator", None)
                           or getattr(mod, "TargetQueue", None))
                if OrcCls:
                    o = OrcCls(targets)
                    r = o.run() if hasattr(o, "run") else []
                    if isinstance(r, list) and r:
                        _emit_findings(r, "multi_target")
                        findings.extend(r)
            except Exception as e:
                print(f"  ⚠️  Multi-target: {e}")

    if mode in ("attack",):
        Cls = _load("nova_unified_attack", "NovaUnifiedAttack")
        if Cls:
            try:
                a = Cls(target)
                r = a.run() if hasattr(a, "run") else (a.attack() if hasattr(a, "attack") else [])
                _emit_findings(r, "attack")
                findings.extend(r)
            except Exception as e:
                print(f"  ⚠️  Unified attack: {e}")

    if mode in ("swarm",):
        # Wire v2 and parallel alongside the existing v3
        Cls2 = _load("nova_swarm_v2",      "NovaSwarmV2")
        if Cls2:
            try:
                s2 = Cls2(target)
                r2 = s2.run() if hasattr(s2, "run") else []
                if isinstance(r2, list) and r2:
                    _emit_findings(r2, "swarm_v2")
                    findings.extend(r2)
            except Exception as e:
                print(f"  ⚠️  Swarm v2: {e}")
        ClsP = _load("nova_swarm_parallel")
        if ClsP:
            try:
                run_fn = getattr(ClsP, "run", None)
                if run_fn:
                    rp = run_fn(target)
                    if isinstance(rp, list) and rp:
                        _emit_findings(rp, "swarm_parallel")
                        findings.extend(rp)
            except Exception as e:
                print(f"  ⚠️  Swarm parallel: {e}")

    if mode in ("pipeline",):
        Cls = _load("nova_pipeline", "NovaPipeline")
        if Cls:
            try:
                p = Cls(target)
                r = p.run() if hasattr(p, "run") else []
                if isinstance(r, list) and r:
                    _emit_findings(r, "pipeline")
                    findings.extend(r)
            except Exception as e:
                print(f"  ⚠️  Pipeline: {e}")

    if mode in ("nextgen",):
        Cls = _load("nova_nextgen_agentic", "NovaNextGenAgentic")
        if Cls:
            try:
                a = Cls(target)
                r = a.run() if hasattr(a, "run") else []
                if isinstance(r, list) and r:
                    _emit_findings(r, "nextgen")
                    findings.extend(r)
            except Exception as e:
                print(f"  ⚠️  NextGen agentic: {e}")

    if mode in ("kali",):
        Cls = _load("nova_kali_agent", "NovaKaliAgent")
        if Cls:
            try:
                kb_cls = _load("nova_kali_knowledge_base", "KaliKnowledgeBase")
                kb     = kb_cls() if kb_cls else None
                a = Cls(target, knowledge_base=kb) if kb else Cls(target)
                r = a.run() if hasattr(a, "run") else []
                if isinstance(r, list) and r:
                    _emit_findings(r, "kali")
                    findings.extend(r)
            except Exception as e:
                print(f"  ⚠️  Kali agent: {e}")

    if mode in ("portswigger", "training"):
        Cls = _load("nova_portswigger_academy", "NovaPortSwigger")
        if Cls:
            try:
                p = Cls()
                fn = getattr(p, "run", getattr(p, "learn", getattr(p, "start", None)))
                if fn:
                    fn(query=query)
            except Exception as e:
                print(f"  ⚠️  PortSwigger academy: {e}")

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
    _run_phase0_mapper(intent["target"])

    findings = dispatch(intent)

    has_critical = any(
        str(f.get("severity","")).upper() in ("CRITICAL","HIGH")
        for f in findings)
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
