#!/usr/bin/env python3
"""
Nova Arsenal — Interactive CLI v2.0
====================================
Full interactive shell with tab-completion, live finding counts,
and all 54 dispatch modes accessible by name or natural-language query.

Usage:
    python3 nova_cli.py                    # interactive REPL
    python3 nova_cli.py "hunt target.com"  # one-shot
    python3 nova_cli.py --mode hunt --target http://localhost:3000
    python3 nova_cli.py status             # health check
    python3 nova_cli.py modes              # list all modes
    python3 nova_cli.py sessions           # session browser
"""

import os, sys, re, json, time, importlib, threading, readline
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

# ── Colours ────────────────────────────────────────────────────────────────────
R   = "\033[0m";  B   = "\033[1m";  DIM = "\033[2m"
RED = "\033[91m"; GRN = "\033[92m"; YLW = "\033[93m"
BLU = "\033[94m"; MAG = "\033[95m"; CYN = "\033[96m"

NOVA_VERSION = "4.2"

BANNER = f"""{CYN}{B}
 ███╗   ██╗ ██████╗ ██╗   ██╗  █████╗
 ████╗  ██║██╔═══██╗██║   ██║ ██╔══██╗
 ██╔██╗ ██║██║   ██║██║   ██║ ███████║
 ██║╚██╗██║██║   ██║╚██╗ ██╔╝ ██╔══██║
 ██║ ╚████║╚██████╔╝ ╚████╔╝  ██║  ██║
 ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝   ╚═╝  ╚═╝  ARSENAL v{NOVA_VERSION}
{R}
{DIM}  AI-Powered Security Framework  ·  github.com/Informant254/Nova-arsenal{R}
"""

# ── Mode catalogue ─────────────────────────────────────────────────────────────
# (name, emoji, description, example_target)
MODES: List[tuple] = [
    # Discovery & Recon
    ("recon",          "🔭", "Passive recon — subdomains, crt.sh, footprint",   "target.com"),
    ("map",            "🗺 ", "Deep codebase map — routes, secrets, frameworks", "./myapp"),
    ("github_scan",    "🐙", "GitHub code & secret scanner",                    "target.com"),
    # Static Analysis
    ("sast",           "🔬", "Multi-language static analysis (SAST)",           "./src"),
    ("dataflow",       "🌊", "Taint / data-flow analysis",                      "./src"),
    ("sca",            "📦", "Dependency CVE scan (SCA)",                       "./project"),
    ("supply_chain",   "⛓ ", "Supply-chain risk scoring",                       "./project"),
    ("git_scan",       "📜", "Git history — leaked secrets & credentials",      "./repo"),
    ("cicd",           "⚙️ ", "CI/CD pipeline security audit",                   "./repo"),
    ("container",      "🐳", "Docker / Kubernetes security scan",               "./repo"),
    ("ecosystem",      "🌱", "Full package-ecosystem audit",                    "./project"),
    ("pypi",           "🐍", "Malicious PyPI package hunter",                   "packagename"),
    # Active Testing
    ("hunt",           "🦅", "Full agentic ReAct hunt loop (recommended)",      "http://target"),
    ("auth",           "🔐", "Authenticated scanner — auth bypass & sessions",  "http://target"),
    ("idor",           "🚪", "IDOR / broken-access-control testing",            "http://target"),
    ("sqli",           "💉", "SQL injection testing (sqlmap + AI)",             "http://target"),
    ("xss",            "📝", "Cross-site scripting (XSS) testing",              "http://target"),
    ("ssrf",           "🔄", "Server-Side Request Forgery testing",             "http://target"),
    ("csrf",           "🎭", "CSRF vulnerability testing",                      "http://target"),
    ("graphql",        "🕸 ", "GraphQL introspection & injection testing",       "http://target"),
    ("jwt",            "🎫", "JWT algorithm confusion & forgery",               "http://target"),
    ("proto_pollution","☣️ ", "Prototype pollution testing",                     "http://target"),
    ("race",           "🏁", "Race condition & TOCTOU testing",                 "http://target"),
    ("business_logic", "🧮", "Business-logic & workflow bypass testing",        "http://target"),
    ("llm_injection",  "🤖", "LLM / prompt-injection testing",                 "http://target"),
    ("fuzz",           "🌀", "Directory & endpoint fuzzing",                    "http://target"),
    ("browser",        "🌐", "Headless-browser visual scanner",                 "http://target"),
    # Intelligence & Synthesis
    ("daybreak",       "🌅", "AI-powered Daybreak full assessment",             "http://target"),
    ("threat_model",   "🗡 ", "STRIDE threat-model generation",                  "./myapp"),
    ("zero_day",       "💀", "Live CVE / zero-day correlation",                 "http://target"),
    ("patch",          "🩹", "Auto patch-generation from findings",             "./src"),
    ("detect",         "🚨", "SIEM / Sigma detection-rule generation",          "(findings)"),
    # Orchestration & Swarm
    ("orchestrate",    "🎯", "Multi-agent orchestration pipeline",              "http://target"),
    ("swarm",          "🐝", "Parallel agent swarm (v2 + v3 + parallel)",      "http://target"),
    ("multi_target",   "🎪", "Bulk multi-target parallel scan",                 "t1,t2,t3"),
    ("pipeline",       "🚀", "Full staged scan pipeline",                       "http://target"),
    ("nextgen",        "⚡", "Next-gen autonomous agent mode",                  "http://target"),
    # Bug Bounty
    ("wild_hunt",      "🏴", "Open bug-bounty wild hunt",                       "http://target"),
    ("ibb",            "🎖 ", "Internet Bug Bounty (IBB) hunter",               "http://target"),
    ("0din",           "👁 ", "0DIN zero-day hunter",                           "http://target"),
    ("attack",         "⚔️ ", "Unified chained attack",                         "http://target"),
    # Kali
    ("kali",           "🐉", "Kali Linux agent (plan → approve → execute)",    "http://target"),
    # Full Stack
    ("full_stack",     "💥", "Everything — all phases combined",                "http://target"),
    # Reporting
    ("triage",         "🩺", "AI triage — rank & prioritise findings",          "(findings)"),
    ("audit_report",   "📋", "Enterprise compliance audit report",              "(findings)"),
    ("report",         "📄", "HTML + Markdown report from findings",            "(findings)"),
    ("vuln_track",     "📊", "Vulnerability tracker dashboard (SQLite)",        "(db)"),
    ("sandbox",        "🧪", "Exploit sandbox validation",                      "(findings)"),
    # Training
    ("portswigger",    "🎓", "PortSwigger Web Security Academy labs",           "topic/lab"),
    # Continuous
    ("continuous",     "🔁", "24/7 continuous monitoring loop",                "http://target"),
    # System
    ("bootstrap",      "❤️ ", "Health check — verify all modules",              "(none)"),
]

MODE_NAMES = [m[0] for m in MODES]

NOVA_DIR  = Path(__file__).parent
WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)


# ── Tab-completion ─────────────────────────────────────────────────────────────

class NovaCompleter:
    COMMANDS = ["help", "modes", "status", "sessions", "history",
                "set target ", "set session ", "clear", "exit", "quit"]

    def __init__(self):
        self._matches: List[str] = []

    def complete(self, text: str, state: int) -> Optional[str]:
        if state == 0:
            pool = MODE_NAMES + self.COMMANDS + ["http://", "https://", "./"]
            self._matches = [c for c in pool if c.lower().startswith(text.lower())]
        try:
            return self._matches[state]
        except IndexError:
            return None


def _setup_readline() -> Path:
    c = NovaCompleter()
    readline.set_completer(c.complete)
    readline.parse_and_bind("tab: complete")
    hist = Path("~/.nova_history").expanduser()
    try:
        if hist.exists():
            readline.read_history_file(str(hist))
        readline.set_history_length(500)
    except Exception:
        pass
    return hist


# ── Spinner ────────────────────────────────────────────────────────────────────

class Spinner:
    FRAMES = ["⣾","⣽","⣻","⢿","⡿","⣟","⣯","⣷"]

    def __init__(self, label: str = ""):
        self.label   = label
        self._stop   = threading.Event()
        self._t      = threading.Thread(target=self._spin, daemon=True)
        self._ts     = time.monotonic()

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            elapsed = time.monotonic() - self._ts
            sys.stdout.write(
                f"\r  {CYN}{self.FRAMES[i%8]}{R}  {self.label}  {DIM}{elapsed:.1f}s{R}   ")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1

    def __enter__(self):
        self._t.start(); return self

    def __exit__(self, *_):
        self._stop.set(); self._t.join()
        sys.stdout.write("\r" + " "*72 + "\r"); sys.stdout.flush()


# ── Results display ────────────────────────────────────────────────────────────

def _sev_icon(s: str) -> str:
    return {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}.get(
        str(s).upper(), "•")

def _print_summary(findings: List[Dict], elapsed: float, label: str):
    if not findings:
        print(f"\n  {DIM}No findings for '{label}'{R}\n"); return

    from collections import Counter
    cnt   = Counter(str(f.get("severity","INFO")).upper() for f in findings)
    order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]

    print(f"\n  {'━'*58}")
    print(f"  {B}📊 {label}{R}   {DIM}{elapsed:.1f}s{R}")
    print(f"  {'─'*58}")
    for sev in order:
        n = cnt.get(sev, 0)
        if n:
            bar = "█" * min(n, 28)
            print(f"  {_sev_icon(sev)}  {sev:<10}  {B}{n:>4}{R}  {DIM}{bar}{R}")
    print(f"  {'─'*58}")
    crhi = cnt.get("CRITICAL",0) + cnt.get("HIGH",0)
    print(f"  Total: {B}{len(findings)}{R}   Critical+High: {RED}{B}{crhi}{R}")

    top = sorted(
        [f for f in findings if str(f.get("severity","")).upper() in ("CRITICAL","HIGH")],
        key=lambda x: 0 if str(x.get("severity","")).upper()=="CRITICAL" else 1)[:5]
    if top:
        print(f"\n  {B}Top findings:{R}")
        for f in top:
            loc  = (f.get("file") or f.get("endpoint") or f.get("url","?"))[:45]
            desc = (f.get("description") or f.get("type","?"))[:55]
            print(f"  {_sev_icon(f.get('severity',''))}  {desc}  {DIM}→ {loc}{R}")
    print(f"  {'━'*58}\n")


# ── Core runner ────────────────────────────────────────────────────────────────

def _run(query: str, target: Optional[str] = None,
         session_id: Optional[str] = None) -> List[Dict]:
    sys.path.insert(0, str(NOVA_DIR))
    try:
        import nova as nm
        intent = nm._parse_intent(query)
        if target:
            intent["target"] = target
        nm._init_provider_layer(target=intent["target"],
                                session_id=session_id, verbose=False)
        nm._run_phase0_mapper(intent["target"])
        return nm.dispatch(intent)
    except Exception as e:
        print(f"\n  {RED}Error: {e}{R}")
        return []


# ── Built-in commands ──────────────────────────────────────────────────────────

def cmd_modes():
    GROUPS = [
        ("🔭  Discovery & Recon",        ["recon","map","github_scan"]),
        ("🔬  Static Analysis",           ["sast","dataflow","sca","supply_chain",
                                           "git_scan","cicd","container","ecosystem","pypi"]),
        ("🦅  Active Testing",            ["hunt","auth","idor","sqli","xss","ssrf","csrf",
                                           "graphql","jwt","proto_pollution","race",
                                           "business_logic","llm_injection","fuzz","browser"]),
        ("🌅  Intelligence",              ["daybreak","threat_model","zero_day","patch","detect"]),
        ("🐝  Orchestration & Swarm",     ["orchestrate","swarm","multi_target","pipeline","nextgen"]),
        ("🏴  Bug Bounty",               ["wild_hunt","ibb","0din","attack"]),
        ("🐉  Kali & Pentest",           ["kali"]),
        ("💥  Full Stack",               ["full_stack"]),
        ("📋  Reporting & Tracking",     ["triage","audit_report","report","vuln_track","sandbox"]),
        ("🎓  Training",                 ["portswigger"]),
        ("🔁  Continuous & System",      ["continuous","bootstrap"]),
    ]
    m_map = {m[0]: m for m in MODES}
    print(f"\n  {B}{CYN}Nova Arsenal — {len(MODES)} Modes{R}\n")
    for group, names in GROUPS:
        print(f"  {B}{YLW}{group}{R}")
        for name in names:
            if name not in m_map: continue
            _, emoji, desc, ex = m_map[name]
            print(f"  {emoji}  {B}{name:<22}{R} {desc}")
            print(f"       {DIM}e.g.  {name} {ex}{R}")
        print()


def cmd_status():
    sys.path.insert(0, str(NOVA_DIR))
    print(f"\n  {B}Nova Arsenal v{NOVA_VERSION} — Module Health{R}\n")
    checks = [
        ("nova_llm_router",    "get_router"),
        ("nova_hooks",         "get_bus"),
        ("nova_orchestrator",  "Agent"),
        ("nova_agent_core",    "NovaAgentCore"),
        ("nova_tool_kit",      "NovaToolKit"),
        ("nova_context",       "RunContext"),
        ("nova_sessions",      "SessionStore"),
        ("nova_observability", "Tracer"),
        ("nova_codebase_mapper","NovaCodebaseMapper"),
        ("nova_source_auditor","NovaSourceAuditor"),
        ("nova_sca_scanner",   "NovaSCAScanner"),
        ("nova_vuln_tracker",  "NovaVulnTracker"),
        ("nova_threat_model",  "NovaThreatModel"),
        ("nova_memory_system", "NovaBrain"),
        ("nova_notifications", "NovaNotifications"),
        ("nova_findings_db",   "NovaFindingsDB"),
        ("nova_knowledge_rag", None),
        ("nova_payload_engine",None),
        ("nova_evolver",       None),
    ]
    ok = fail = 0
    for mod, cls in checks:
        try:
            m = importlib.import_module(mod)
            if cls: getattr(m, cls)
            print(f"  {GRN}✓{R}  {mod}")
            ok += 1
        except Exception as e:
            print(f"  {RED}✗{R}  {mod}  {DIM}({e}){R}")
            fail += 1
    print(f"\n  {ok} OK  |  {fail} failed\n")


def cmd_sessions() -> Optional[str]:
    sys.path.insert(0, str(NOVA_DIR))
    try:
        from nova_sessions import SessionStore
        store    = SessionStore()
        sessions = store.list() if hasattr(store, "list") else []
        if not sessions:
            print(f"\n  {DIM}No sessions found.{R}\n"); return None
        print(f"\n  {B}Sessions ({len(sessions)}){R}\n")
        for i, s in enumerate(sessions[:20], 1):
            sid    = (s.session_id if hasattr(s,"session_id") else str(s))[:8]
            tgt    = getattr(s, "target", "?")[:40]
            nf     = getattr(s, "findings_count", len(getattr(s,"findings",[])))
            ts     = str(getattr(s, "created_at", "?"))[:16]
            print(f"  {B}{i:>2}.{R}  {CYN}{sid}{R}  {tgt:<42}  "
                  f"{nf} findings  {DIM}{ts}{R}")
        print()
        choice = input("  Resume session # (or Enter to skip): ").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(sessions):
                s   = sessions[idx]
                sid = s.session_id if hasattr(s,"session_id") else str(s)
                print(f"\n  {GRN}Session {sid[:8]} loaded.{R}\n")
                return sid
    except Exception as e:
        print(f"  {RED}Error: {e}{R}")
    return None


def cmd_history():
    n = readline.get_current_history_length()
    s = max(1, n-19)
    print(f"\n  {B}History (last {min(20,n)}){R}\n")
    for i in range(s, n+1):
        print(f"  {DIM}{i:>3}{R}  {readline.get_history_item(i)}")
    print()


def cmd_help():
    print(f"""
  {B}Nova Arsenal v{NOVA_VERSION} — Help{R}

  {B}Natural language:{R}
    > hunt http://localhost:3000 for SQL injection
    > map the codebase at ./juice-shop
    > full stack scan on ./myapp
    > kali agent pentest http://target.com

  {B}Direct mode:{R}
    > <mode> [target]          e.g. hunt http://target.com
    > modes                    list all {len(MODES)} modes
    > status                   module health check
    > sessions                 browse & resume sessions
    > history                  command history

  {B}Inline flags:{R}
    --target <url/path>        override target
    --session <id>             resume session
    --no-map                   skip Phase-0 codebase mapper

  {B}Prompt shortcuts:{R}
    set target <url>           change default target
    set session <id>           change active session

  {B}Environment variables:{R}
    NOVA_LLM_URL               Ollama URL  (default: http://localhost:11434)
    NOVA_LLM_MODEL             Ollama model (default: qwen3:8b)
    OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY
    NOVA_TARGET                Default target
    NOVA_WORKSPACE             Output directory (default: ~/nova_workspace)
    NOVA_TELEGRAM_TOKEN/CHAT_ID  Real-time alerts

  {B}Exit:{R}  exit | quit | Ctrl-D
""")


# ── REPL ───────────────────────────────────────────────────────────────────────

def repl():
    hist_file = _setup_readline()
    print(BANNER)
    print(f"  Type {B}help{R} or {B}?{R} for commands · {B}modes{R} to list all modes · "
          f"Tab to complete · Ctrl-D to exit\n")

    cur_target  = os.getenv("NOVA_TARGET", "http://localhost:3000")
    cur_session: Optional[str] = None

    while True:
        try:
            sess_tag = f"{DIM}[{cur_session[:6]}]{R}" if cur_session else ""
            tgt_tag  = cur_target.replace("http://","").replace("https://","")[:28]
            prompt   = f"\n  {CYN}{B}nova{R}{DIM}({tgt_tag}){R}{sess_tag} › "
            raw      = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {DIM}Goodbye.{R}"); break
        if not raw: continue

        lo = raw.lower()

        # Built-ins
        if lo in ("help","?","h"):          cmd_help();    continue
        if lo in ("modes","mode list"):     cmd_modes();   continue
        if lo in ("status","health"):       cmd_status();  continue
        if lo in ("sessions","session"):
            sid = cmd_sessions()
            if sid: cur_session = sid
            continue
        if lo == "history":                 cmd_history(); continue
        if lo in ("clear","cls"):
            os.system("clear"); print(BANNER); continue
        if lo in ("exit","quit","q"):
            print(f"  {DIM}Goodbye.{R}"); break

        if lo.startswith("set target "):
            cur_target = raw[11:].strip()
            print(f"  {GRN}Target → {cur_target}{R}"); continue
        if lo.startswith("set session "):
            cur_session = raw[12:].strip()
            print(f"  {GRN}Session → {cur_session}{R}"); continue

        # Parse inline flags
        target  = cur_target
        session = cur_session
        query   = raw
        for flag, attr in [("--target","target"),("--session","session")]:
            m = re.search(rf"{flag}\s+(\S+)", raw)
            if m:
                if attr == "target": target = m.group(1)
                else: session = m.group(1)
                query = re.sub(rf"{flag}\s+\S+", "", query).strip()
        query = query.replace("--no-map","").strip()

        # Bare mode name → expand
        if query in MODE_NAMES:
            query = f"{query} {target}"

        # Run
        t0 = time.monotonic()
        with Spinner(f"{B}{query[:55]}{R}"):
            findings = _run(query, target=target, session_id=session)
        _print_summary(findings, time.monotonic()-t0, query[:35])

        if findings:
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            slug = re.sub(r"[^a-z0-9]","_", query[:20].lower())
            out  = WORKSPACE / f"nova_cli_{slug}_{ts}.json"
            out.write_text(json.dumps({"query":query,"target":target,
                                       "findings":findings},
                                      indent=2, default=str))
            print(f"  {DIM}💾 → {out}{R}")

    try: readline.write_history_file(str(hist_file))
    except Exception: pass


# ── One-shot ───────────────────────────────────────────────────────────────────

def one_shot(args: List[str]):
    query = target = session = mode = None
    target = os.getenv("NOVA_TARGET","http://localhost:3000")
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--target","-t") and i+1 < len(args):   target=args[i+1]; i+=2
        elif a in ("--session","-s") and i+1 < len(args): session=args[i+1]; i+=2
        elif a in ("--mode","-m") and i+1 < len(args):    mode=args[i+1]; i+=2
        elif a == "modes":   cmd_modes();   return
        elif a == "status":  cmd_status();  return
        elif a == "sessions":cmd_sessions();return
        elif a == "help":    cmd_help();    return
        else:                query=a; i+=1

    if not query:
        query = f"{mode} {target}" if mode else None
    if not query:
        repl(); return

    print(BANNER)
    t0 = time.monotonic()
    with Spinner(f"{query[:60]}"):
        findings = _run(query, target=target, session_id=session)
    _print_summary(findings, time.monotonic()-t0, query[:35])


def main():
    if len(sys.argv) < 2: repl()
    else: one_shot(sys.argv[1:])

if __name__ == "__main__":
    main()
