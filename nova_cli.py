#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🦅 NOVA CLI v1.0 — Unified Command-Line Interface                         ║
║                                                                              ║
║  Wraps every Nova module with structured subcommands, rich output,          ║
║  session management, provider selection, and real-time finding display.     ║
║                                                                              ║
║  Usage:                                                                      ║
║    nova hunt   https://target.com [options]                                 ║
║    nova recon  https://target.com                                           ║
║    nova full   https://target.com                                           ║
║    nova orch   https://target.com                                           ║
║    nova triage                                                              ║
║    nova sast   ./src                                                        ║
║    nova status                                                              ║
║    nova session list                                                        ║
║    nova session resume <id>                                                 ║
║    nova providers                                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# ── Paths ──────────────────────────────────────────────────────────────────────
NOVA_DIR  = Path(__file__).parent
WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(NOVA_DIR))

# ── Colour helpers (no deps — colorama if available, else ANSI) ────────────────
try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    def _c(text, colour): return f"{colour}{text}{Style.RESET_ALL}"
except ImportError:
    class _Fore:
        RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
        CYAN="\033[96m"; MAGENTA="\033[95m"; WHITE="\033[97m"
        BLUE="\033[94m"; RESET="\033[0m"
    Fore = _Fore()
    def _c(text, colour): return f"{colour}{text}\033[0m"

def red(t):     return _c(t, Fore.RED)
def yellow(t):  return _c(t, Fore.YELLOW)
def green(t):   return _c(t, Fore.GREEN)
def cyan(t):    return _c(t, Fore.CYAN)
def magenta(t): return _c(t, Fore.MAGENTA)
def white(t):   return _c(t, Fore.WHITE)
def blue(t):    return _c(t, Fore.BLUE)

SEV_ICONS = {
    "CRITICAL": red("🔴 CRITICAL"),
    "HIGH":     _c("🟠 HIGH",    Fore.YELLOW),
    "MEDIUM":   yellow("🟡 MEDIUM"),
    "LOW":      blue("🔵 LOW"),
    "INFO":     white("⚪ INFO"),
}

def _banner():
    print(cyan("""
 ███╗   ██╗ ██████╗ ██╗   ██╗  █████╗
 ████╗  ██║██╔═══██╗██║   ██║ ██╔══██╗
 ██╔██╗ ██║██║   ██║██║   ██║ ███████║
 ██║╚██╗██║██║   ██║╚██╗ ██╔╝ ██╔══██║
 ██║ ╚████║╚██████╔╝ ╚████╔╝  ██║  ██║
 ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝   ╚═╝  ╚═╝"""))
    print(magenta("  ARSENAL v4.1  ") + white("— Autonomous AI Security Agent"))
    print(white("  " + "─"*52))


def _hr():
    print(white("  " + "═"*60))


def _print_finding(f: dict, index: int):
    sev  = str(f.get("severity", "INFO")).upper()
    icon = SEV_ICONS.get(sev, f"• {sev}")
    typ  = f.get("type", "?")
    ep   = f.get("endpoint") or f.get("file") or "?"
    desc = f.get("description", "")[:80]
    cvss = f.get("cvss")
    cvss_str = f"  CVSS: {cvss}" if cvss else ""
    print(f"  {index:>3}. {icon}  {cyan(typ)}")
    print(f"       📍 {ep}{cvss_str}")
    if desc:
        print(f"       {white(desc)}")


def _print_findings_table(findings: List[dict], title: str = "Findings"):
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_f  = sorted(findings, key=lambda f: sev_order.get(
        str(f.get("severity", "INFO")).upper(), 4))
    _hr()
    print(f"  {magenta('📊')} {white(title)} — {len(findings)} total")
    _hr()
    for i, f in enumerate(sorted_f, 1):
        _print_finding(f, i)
        if i < len(sorted_f):
            print()
    _hr()
    # Severity summary
    counts: dict = {}
    for f in findings:
        s = str(f.get("severity", "INFO")).upper()
        counts[s] = counts.get(s, 0) + 1
    parts = [f"{SEV_ICONS.get(k, k)}: {v}" for k, v in
             sorted(counts.items(), key=lambda x: sev_order.get(x[0], 9))]
    print("  " + "  |  ".join(parts))


# ── Lazy imports ───────────────────────────────────────────────────────────────

def _try(module: str, attr: str = None):
    try:
        import importlib
        m = importlib.import_module(module)
        return getattr(m, attr) if attr else m
    except Exception:
        return None


def _dispatch(query: str, session_id: Optional[str] = None,
              provider: Optional[str] = None, verbose: bool = True) -> List[dict]:
    """Run nova.py dispatch with optional provider override."""
    if provider:
        os.environ["NOVA_FORCE_PROVIDER"] = provider

    nova_mod = _try("nova")
    if not nova_mod:
        print(red("  ✗ Failed to import nova.py"))
        return []

    nova_mod._init_provider_layer(verbose=verbose, session_id=session_id)
    intent   = nova_mod._parse_intent(query)
    findings = nova_mod.dispatch(intent)
    return findings or []


# ── Sub-command handlers ───────────────────────────────────────────────────────

def cmd_hunt(args):
    """nova hunt <target> — full agentic hunt"""
    _banner()
    print(f"  🎯 {green('Hunting')} → {cyan(args.target)}\n")
    t0 = time.monotonic()
    findings = _dispatch(
        f"Hunt {args.target} for all vulnerabilities",
        session_id=args.session,
        provider=args.provider,
        verbose=args.verbose)
    _print_findings_table(findings, f"Hunt Results — {args.target}")
    print(f"\n  ⏱  {(time.monotonic()-t0):.1f}s")
    return 1 if any(f.get("severity","").upper() in ("CRITICAL","HIGH") for f in findings) else 0


def cmd_full(args):
    """nova full <target|path> — full-stack everything"""
    _banner()
    print(f"  🚀 {green('Full-stack pipeline')} → {cyan(args.target)}\n")
    t0 = time.monotonic()
    findings = _dispatch(
        f"Full stack scan everything on {args.target}",
        session_id=args.session,
        provider=args.provider,
        verbose=args.verbose)
    _print_findings_table(findings, "Full-Stack Results")
    print(f"\n  ⏱  {(time.monotonic()-t0):.1f}s")
    return 1 if any(f.get("severity","").upper() in ("CRITICAL","HIGH") for f in findings) else 0


def cmd_recon(args):
    """nova recon <target> — passive recon"""
    _banner()
    print(f"  🔭 {green('Recon')} → {cyan(args.target)}\n")
    findings = _dispatch(f"Recon {args.target}", session_id=args.session, verbose=args.verbose)
    _print_findings_table(findings, "Recon Results")
    return 0


def cmd_orch(args):
    """nova orch <target> — multi-agent orchestrator"""
    _banner()
    print(f"  🧠 {green('Orchestrating agents')} → {cyan(args.target)}\n")
    t0 = time.monotonic()
    findings = _dispatch(
        f"Orchestrate multi-agent hunt on {args.target}",
        session_id=args.session,
        provider=args.provider,
        verbose=args.verbose)
    _print_findings_table(findings, "Orchestrator Results")
    print(f"\n  ⏱  {(time.monotonic()-t0):.1f}s")
    return 1 if any(f.get("severity","").upper() in ("CRITICAL","HIGH") for f in findings) else 0


def cmd_triage(args):
    """nova triage — triage + rank all findings"""
    _banner()
    print(f"  🎯 {green('Triaging findings...')}\n")

    # Collect all findings from workspace
    all_findings: List[dict] = []
    for f in sorted(WORKSPACE.glob("nova_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:20]:
        try:
            data = json.loads(f.read_text())
            if "findings" in data and isinstance(data["findings"], list):
                all_findings.extend(data["findings"])
        except Exception:
            pass

    if not all_findings:
        print(yellow("  ⚠  No findings in workspace. Run a scan first."))
        return 0

    findings = _dispatch(
        "Triage and prioritise these findings",
        session_id=args.session, verbose=args.verbose)
    if not findings:
        findings = all_findings

    _print_findings_table(findings, "Triage — H1-Ready Ranking")
    return 0


def cmd_sast(args):
    """nova sast <path> — static analysis"""
    _banner()
    print(f"  🔬 {green('SAST')} → {cyan(args.target)}\n")
    findings = _dispatch(f"SAST code audit of {args.target}",
                         session_id=args.session, verbose=args.verbose)
    _print_findings_table(findings, "SAST Results")
    return 0


def cmd_sca(args):
    """nova sca <path> — dependency / supply chain audit"""
    _banner()
    print(f"  📦 {green('SCA + Supply Chain')} → {cyan(args.target)}\n")
    findings = _dispatch(f"SCA dependency scan of {args.target}",
                         session_id=args.session, verbose=args.verbose)
    _print_findings_table(findings, "SCA Results")
    return 0


def cmd_scan(args):
    """nova scan <mode> <target> — run any specific scan mode"""
    _banner()
    print(f"  ⚡ {green(args.mode)} → {cyan(args.target)}\n")
    findings = _dispatch(f"{args.mode} {args.target}",
                         session_id=args.session,
                         provider=getattr(args, "provider", None),
                         verbose=args.verbose)
    _print_findings_table(findings, f"{args.mode.upper()} Results")
    return 1 if any(f.get("severity","").upper() in ("CRITICAL","HIGH") for f in findings) else 0


def cmd_code(args):
    """nova code <task> — autonomous coding-agent loop"""
    _banner()
    print(f"  🤖 {green('Autonomous coding')} → {cyan(args.repo)}")
    print(f"  📝 {white(args.task)}\n")
    Agent = _try("nova_code_agent", "NovaCodeAgent")
    if not Agent:
        print(red("  ✗ nova_code_agent.py is unavailable"))
        return 1
    report = Agent(
        repo=args.repo,
        task=args.task,
        test_command=args.test_command or "",
        max_retries=args.max_retries,
        allow_edits=not args.no_edit,
    ).run()
    print(f"  Status:       {green(report.get('status', 'unknown'))}")
    print(f"  Files mapped: {report.get('mapped_files', 0)}")
    print(f"  Patch applied:{' yes' if report.get('patch_applied') else ' no'}")
    if report.get("changed_files"):
        print("  Changed files:")
        for path in report["changed_files"]:
            print(f"    - {path}")
    print(f"  Report:       {cyan(report.get('report_path', ''))}")
    failed = any(check.get("returncode", 0) != 0 for check in report.get("checks", []) if check.get("command") == report.get("test_command"))
    return 1 if failed else 0


def cmd_providers(args):
    """nova providers — show available LLM providers"""
    _banner()
    RouterCls = _try("nova_llm_router", "LLMRouter")
    if not RouterCls:
        print(yellow("  ⚠  nova_llm_router not found"))
        return 1
    try:
        router = RouterCls()
        avail  = router.available_providers()
        print(f"  {green('Available LLM providers:')}")
        for p in avail:
            print(f"    ✅ {cyan(p)}")
        all_p = ["openai", "anthropic", "gemini", "ollama"]
        missing = [p for p in all_p if p not in avail]
        if missing:
            print(f"\n  {yellow('Not configured:')}")
            for p in missing:
                env = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY",
                       "gemini": "GEMINI_API_KEY", "ollama": "NOVA_LLM_URL"}.get(p, "")
                print(f"    ✗ {p}" + (f"  (set {env})" if env else ""))
        # Test each provider
        if args.test:
            print(f"\n  {green('Testing providers...')}")
            for p in avail:
                try:
                    from nova_llm_router import Provider
                    t0  = time.monotonic()
                    resp = router.chat("Reply: OK", provider=getattr(Provider, p.upper(), None))
                    ms   = (time.monotonic() - t0) * 1000
                    print(f"    ✅ {p}: {resp.content[:20]!r}  [{ms:.0f}ms]  [${resp.cost_usd:.5f}]")
                except Exception as e:
                    print(f"    ✗ {p}: {e}")
    except Exception as e:
        print(red(f"  Error: {e}"))
    return 0


def cmd_status(args):
    """nova status — health-check every Nova module"""
    _banner()
    print(f"  {green('System Status')}\n")

    checks = [
        # (display_name, module, class_or_attr)
        ("nova_llm_router",    "nova_llm_router",    "LLMRouter"),
        ("nova_hooks",         "nova_hooks",          "HookBus"),
        ("nova_context",       "nova_context",        "RunContext"),
        ("nova_sessions",      "nova_sessions",       "SessionStore"),
        ("nova_retry",         "nova_retry",          "RetryPolicy"),
        ("nova_observability", "nova_observability",  "Tracer"),
        ("nova_skills",        "nova_skills",         "SkillLibrary"),
        ("nova_orchestrator",  "nova_orchestrator",   "Runner"),
        ("nova_triage",        "nova_triage",         "NovaTriage"),
        ("nova_daybreak",      "nova_daybreak",       "NovaDaybreak"),
        ("nova_agent_core",    "nova_agent_core",     "NovaAgent"),
        ("nova_code_agent",    "nova_code_agent",     "NovaCodeAgent"),
        ("nova_swarm_v3",      "nova_swarm_v3",       "NovaSwarmV3"),
        ("nova_recon",         "nova_recon",          "NovaRecon"),
        ("nova_fuzzer",        "nova_fuzzer",         "NovaFuzzer"),
        ("nova_idor_scanner",  "nova_idor_scanner",   "NovaIDORScanner"),
        ("nova_graphql_tester","nova_graphql_tester", "NovaGraphQLTester"),
        ("nova_csrf_tester",   "nova_csrf_tester",    "NovaCsrfTester"),
        ("nova_business_logic","nova_business_logic", "NovaBusinessLogicTester"),
        ("nova_jwt_forge",     "nova_jwt_forge",      "NovaJWTForge"),
        ("nova_race_engine",   "nova_race_engine",    "NovaRaceEngine"),
        ("nova_source_auditor","nova_source_auditor", "NovaSourceAuditor"),
        ("nova_sca_scanner",   "nova_sca_scanner",    "NovaSCAScanner"),
        ("nova_git_scanner",   "nova_git_scanner",    "NovaGitScanner"),
        ("nova_cicd_scanner",  "nova_cicd_scanner",   "NovaCICDScanner"),
        ("nova_container_scanner","nova_container_scanner","NovaContainerScanner"),
        ("nova_threat_model",  "nova_threat_model",   "NovaThreatModel"),
        ("nova_patch_generator","nova_patch_generator","NovaPatchGenerator"),
        ("nova_detection_engineer","nova_detection_engineer","NovaDetectionEngineer"),
        ("nova_audit_reporter","nova_audit_reporter", "NovaAuditReporter"),
        ("nova_vuln_tracker",  "nova_vuln_tracker",   "NovaVulnTracker"),
        ("nova_zero_day_correlator","nova_zero_day_correlator","NovaZeroDayCorrelator"),
        ("nova_memory_system", "nova_memory_system",  "NovaBrain"),
        ("nova_scope_manager", "nova_scope_manager",  "NovaScopeManager"),
        ("nova_mcp_client",    "nova_mcp_client",     "MCPClient"),
    ]

    ok = bad = 0
    for display, module, attr in checks:
        obj = _try(module, attr)
        if obj:
            print(f"  ✅  {green(display):<38}")
            ok += 1
        else:
            print(f"  ✗   {yellow(display):<38}  {yellow('not found')}")
            bad += 1

    print()

    # LLM providers
    RouterCls = _try("nova_llm_router", "LLMRouter")
    if RouterCls:
        try:
            r = RouterCls()
            print(f"  🔀  {green('LLM Providers:')} {', '.join(r.available_providers())}")
        except Exception:
            pass

    # Workspace
    print(f"  📁  {green('Workspace:')} {WORKSPACE}")

    # Session count
    if Path(WORKSPACE / "sessions").exists():
        n = len(list((WORKSPACE / "sessions").glob("*.json")))
        print(f"  📂  {green('Sessions:')} {n} saved")

    _hr()
    print(f"  {green(str(ok))} modules ready, {(yellow(str(bad)) if bad else green('0'))} missing")
    return 0 if bad == 0 else 1


def cmd_session(args):
    """nova session list|resume|delete"""
    SessionStore_ = _try("nova_sessions", "SessionStore")
    if not SessionStore_:
        print(red("  ✗ nova_sessions not available"))
        return 1

    store = SessionStore_()

    if args.session_cmd == "list":
        sessions = store.list_sessions(target=getattr(args, "target", None))
        if not sessions:
            print(yellow("  No sessions found."))
            return 0
        _banner()
        print(f"  {green('Sessions:')}\n")
        for s in sessions:
            print(f"  {cyan(s['session_id'][:8])}  "
                  f"{white(s['target'][:40]):<42}"
                  f"  findings: {yellow(str(s['findings'])):<6}"
                  f"  ${s['total_cost_usd']:.5f}"
                  f"  {s['updated_at'][:16]}")
        return 0

    elif args.session_cmd == "resume":
        session = store.load(args.session_id)
        if not session:
            print(red(f"  ✗ Session {args.session_id} not found"))
            return 1
        print(f"  {green('Session')} {cyan(args.session_id[:8])}")
        print(f"  Target:   {session.target}")
        print(f"  Findings: {len(session.findings)}")
        print(f"  Runs:     {len(session.runs)}")
        print(f"  Cost:     ${session.total_cost_usd:.5f}")
        print(f"\n  To resume: nova hunt {session.target} --session {args.session_id}")
        return 0

    elif args.session_cmd == "delete":
        store.delete(args.session_id)
        print(green(f"  ✓ Session {args.session_id} deleted"))
        return 0

    elif args.session_cmd == "export":
        session = store.load(args.session_id)
        if not session:
            print(red(f"  ✗ Session {args.session_id} not found"))
            return 1
        out = Path(args.output) if hasattr(args, "output") and args.output \
              else WORKSPACE / f"session_{args.session_id[:8]}_export.json"
        out.write_text(json.dumps(session.to_dict(), indent=2, default=str))
        print(green(f"  ✓ Exported to {out}"))
        return 0

    return 0


def cmd_report(args):
    """nova report — generate consolidated report from workspace findings"""
    _banner()
    all_findings: List[dict] = []
    for f in sorted(WORKSPACE.glob("nova_*.json"),
                    key=lambda p: p.stat().st_mtime, reverse=True)[:30]:
        try:
            data = json.loads(f.read_text())
            if "findings" in data and isinstance(data["findings"], list):
                all_findings.extend(data["findings"])
        except Exception:
            pass

    if not all_findings:
        print(yellow("  ⚠  No findings in workspace yet."))
        return 0

    # Deduplicate
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get("type", ""), f.get("endpoint") or f.get("file", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    _print_findings_table(deduped, "Consolidated Report")

    # Save markdown
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_f  = sorted(deduped, key=lambda x: sev_order.get(
        str(x.get("severity", "INFO")).upper(), 4))

    md_lines = [
        f"# Nova Arsenal — Security Report",
        f"Generated: {datetime.now().isoformat()}",
        f"Total findings: {len(deduped)}\n",
        "| # | Severity | Type | Location | CVSS |",
        "|---|----------|------|----------|------|",
    ]
    for i, f in enumerate(sorted_f, 1):
        sev = f.get("severity", "INFO")
        typ = f.get("type", "?")
        loc = (f.get("endpoint") or f.get("file") or "?")[:60]
        cvss = f.get("cvss", "")
        md_lines.append(f"| {i} | {sev} | {typ} | `{loc}` | {cvss} |")

    out = WORKSPACE / f"nova_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    out.write_text("\n".join(md_lines))
    print(f"\n  📄 Markdown report → {green(str(out))}")
    return 0


# ── Argument Parser ────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nova",
        description="🦅 Nova Arsenal v4.1 — Autonomous AI Security Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nova code   "Fix the failing tests" --repo . --test-command "pytest"
  nova hunt   https://target.com
  nova full   https://target.com --provider openai
  nova recon  https://target.com
  nova orch   https://target.com --session abc123
  nova sast   ./src
  nova sca    ./
  nova scan   jwt https://target.com
  nova scan   sqli https://target.com
  nova triage
  nova report
  nova status
  nova providers --test
  nova session list
  nova session resume abc123
  nova session delete abc123
""")

    # Shared options
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--session",  "-s", metavar="ID",
                        help="Resume a previous session by ID")
    shared.add_argument("--provider", "-p",
                        choices=["openai", "anthropic", "gemini", "ollama"],
                        help="Force a specific LLM provider")
    shared.add_argument("--verbose",  "-v", action="store_true",
                        help="Verbose output")
    shared.add_argument("--quiet",    "-q", action="store_false", dest="verbose",
                        help="Suppress verbose output")
    shared.set_defaults(verbose=True)

    subs = p.add_subparsers(dest="command", metavar="COMMAND")

    # code
    pc = subs.add_parser("code", parents=[shared],
                         help="Autonomous coding agent: inspect, patch, test, retry")
    pc.add_argument("task", help="Coding task, e.g. 'Fix failing tests'")
    pc.add_argument("--repo", default=".", help="Repository path (default: .)")
    pc.add_argument("--test-command", default="", help="Verification command to run")
    pc.add_argument("--max-retries", type=int, default=1, help="Repair retries after test failure")
    pc.add_argument("--no-edit", action="store_true", help="Plan and inspect without applying patches")

    # hunt
    ph = subs.add_parser("hunt", parents=[shared],
                         help="Full agentic bug bounty hunt")
    ph.add_argument("target", help="URL to hunt (https://target.com)")

    # full
    pf = subs.add_parser("full", parents=[shared],
                          help="Full-stack: all 27 modules")
    pf.add_argument("target", help="URL or path")

    # recon
    pr = subs.add_parser("recon", parents=[shared],
                          help="Passive recon (subdomains, endpoints, JS)")
    pr.add_argument("target", help="URL to recon")

    # orch
    po = subs.add_parser("orch", parents=[shared],
                          help="Multi-agent orchestrator (ReconAgent→AttackAgent→ReportAgent)")
    po.add_argument("target", help="URL")

    # triage
    pt = subs.add_parser("triage", parents=[shared],
                          help="Triage and rank findings for H1 submission")

    # sast
    ps = subs.add_parser("sast", parents=[shared],
                          help="Static code analysis")
    ps.add_argument("target", nargs="?", default=".",
                    help="Directory to scan (default: .)")

    # sca
    psc = subs.add_parser("sca", parents=[shared],
                           help="Dependency / supply-chain audit")
    psc.add_argument("target", nargs="?", default=".",
                     help="Directory to scan (default: .)")

    # scan (generic)
    pg = subs.add_parser("scan", parents=[shared],
                          help="Run a specific scan mode")
    pg.add_argument("mode",   choices=list(
        __import__("nova", fromlist=["KEYWORD_MODES"]).KEYWORD_MODES.keys()
        if True else []), metavar="MODE",
        help="Scan mode (sqli, xss, idor, csrf, jwt, race, graphql, ...)")
    pg.add_argument("target", help="URL or path")

    # providers
    pp = subs.add_parser("providers", help="List and test LLM providers")
    pp.add_argument("--test", "-t", action="store_true",
                    help="Send test message to each provider")

    # status
    subs.add_parser("status", help="Health-check all Nova modules")

    # report
    subs.add_parser("report", help="Generate consolidated report from workspace findings")

    # session
    pse = subs.add_parser("session", help="Session management")
    session_subs = pse.add_subparsers(dest="session_cmd", metavar="ACTION")
    sl = session_subs.add_parser("list", help="List all sessions")
    sl.add_argument("--target", help="Filter by target")
    sr = session_subs.add_parser("resume", help="Show details of a session")
    sr.add_argument("session_id", help="Session ID (or first 8 chars)")
    sd = session_subs.add_parser("delete", help="Delete a session")
    sd.add_argument("session_id")
    se = session_subs.add_parser("export", help="Export session to JSON")
    se.add_argument("session_id")
    se.add_argument("--output", "-o", help="Output path")

    return p


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    # Try to import KEYWORD_MODES for the scan subcommand choices
    try:
        import nova as _nova_mod
        # Patch the scan subparser choices dynamically
        pass
    except Exception:
        pass

    parser = _build_parser()
    args   = parser.parse_args()

    if not args.command:
        _banner()
        parser.print_help()
        return 0

    handlers = {
        "code":      cmd_code,
        "hunt":      cmd_hunt,
        "full":      cmd_full,
        "recon":     cmd_recon,
        "orch":      cmd_orch,
        "triage":    cmd_triage,
        "sast":      cmd_sast,
        "sca":       cmd_sca,
        "scan":      cmd_scan,
        "providers": cmd_providers,
        "status":    cmd_status,
        "report":    cmd_report,
        "session":   cmd_session,
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args) or 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
