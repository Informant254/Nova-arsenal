#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🦅  NOVA CI RUNNER — Full Arsenal Mode                        ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Two ways to talk to Nova:                                      ║
║                                                                  ║
║  1. DIRECT NATURAL LANGUAGE (single targeted mode):             ║
║     python3 nova.py "Hunt https://target.com for IDOR bugs"     ║
║     python3 nova.py "Full stack scan on https://target.com"     ║
║     python3 nova.py "SQLi test https://target.com"              ║
║     python3 nova.py "Kali agent run on https://target.com"      ║
║     python3 nova.py "Daybreak AI assessment of example.com"     ║
║                                                                  ║
║  2. CI RUNNER (all 23 modes, bypasses single-mode limit):       ║
║     python3 nova_ci_runner.py https://target.com                ║
║     → Runs EVERY module Nova has, in the right order           ║
║     → Real-time Telegram alerts on every Critical/High find    ║
║                                                                  ║
║  Natural language keywords → modes (how nova.py routes):        ║
║    "hunt / find bugs / pentest"         → hunt                 ║
║    "full stack / everything / all"      → full_stack           ║
║    "recon / subdomain / enumerate"      → recon                ║
║    "sqli / sql injection"               → sqli                 ║
║    "ssrf / server side request"         → ssrf                 ║
║    "xss / cross site"                  → xss                  ║
║    "idor / access control / bola"       → idor                 ║
║    "jwt / bearer / alg none"           → jwt                  ║
║    "graphql / introspection"           → graphql               ║
║    "csrf / samesite"                   → csrf                  ║
║    "race condition / concurrent"       → race                  ║
║    "prototype / __proto__"             → proto_pollution        ║
║    "business logic / price manip"      → business_logic        ║
║    "llm / prompt injection / ai"       → llm_injection         ║
║    "orchestrate / multi agent"         → orchestrate           ║
║    "swarm"                             → swarm                 ║
║    "kali / kali agent"                 → kali                  ║
║    "daybreak / h1 report / bounty"     → daybreak              ║
║    "triage / rank / prioritize"        → triage                ║
║    "sast / code audit / static"        → sast                  ║
║    "docker / container / k8s"          → container             ║
║    "git / leaked secret / history"     → git_scan              ║
║    "threat model / stride"             → threat_model          ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import time
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime

# ── Path setup ────────────────────────────────────────────────────────────────
NOVA_DIR  = Path(__file__).parent
sys.path.insert(0, str(NOVA_DIR))

import nova  # main nova module — all globals live here

TARGET    = sys.argv[1] if len(sys.argv) > 1 else nova.DEFAULT_TARGET
WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)

TG_TOKEN  = os.getenv("NOVA_TELEGRAM_TOKEN", "")
TG_CHAT   = os.getenv("NOVA_TELEGRAM_CHAT_ID", "")

# ── Telegram helper ───────────────────────────────────────────────────────────
def _tg(text: str, parse_mode: str = "Markdown") -> bool:
    """Send a Telegram message. Silent on failure."""
    if not (TG_TOKEN and TG_CHAT):
        return False
    try:
        data = urllib.parse.urlencode({
            "chat_id": TG_CHAT,
            "text": text[:4096],
            "parse_mode": parse_mode
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            data=data
        )
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception:
        return False

# ── Real-time OnFinding hook ──────────────────────────────────────────────────
_alerted: set = set()   # dedup: never spam the same finding twice

def _register_live_alerts():
    """
    Hook into Nova's HookBus OnFinding event.
    Fires a Telegram message immediately when any module finds
    a CRITICAL or HIGH severity vulnerability — mid-hunt.
    """
    bus = getattr(nova, "_BUS", None)
    if not bus:
        return

    @bus.on("OnFinding")
    def _on_finding(ctx: dict):
        finding = ctx.get("finding", ctx)
        sev     = str(finding.get("severity", "")).upper()
        if sev not in ("CRITICAL", "HIGH"):
            return

        # Deduplicate: same severity + type + location = one alert
        key = (sev,
               finding.get("type", ""),
               finding.get("endpoint") or finding.get("file") or "")
        if key in _alerted:
            return
        _alerted.add(key)

        emoji    = "🚨" if sev == "CRITICAL" else "🔴"
        vuln     = finding.get("type", "Unknown vulnerability")
        location = finding.get("endpoint") or finding.get("file") or "?"
        agent    = ctx.get("agent", "?")
        detail   = finding.get("description") or finding.get("detail") or ""
        if len(detail) > 250:
            detail = detail[:250] + "…"

        msg = (f"{emoji} *Nova Live Alert — {sev}*\n\n"
               f"*Vuln:* `{vuln}`\n"
               f"*Location:* `{location}`\n"
               f"*Found by:* `{agent}` module\n"
               f"*Target:* `{TARGET}`")
        if detail:
            msg += f"\n\n_{detail}_"

        _tg(msg)

# ── Logging helper ────────────────────────────────────────────────────────────
def banner(title: str):
    w = 64
    print(f"\n{'═'*w}")
    print(f"  🦅  {title}")
    print(f"{'═'*w}")

def run_mode(mode: str, label: str = ""):
    """
    Call nova.dispatch() directly with an explicit mode dict.
    Bypasses _parse_intent so this mode ALWAYS runs — no LLM
    classification needed, no keyword matching required.
    """
    label = label or mode.upper()
    banner(f"MODULE: {label}")
    t0 = time.monotonic()
    try:
        intent   = {"mode": mode, "target": TARGET, "original_query": f"{mode} {TARGET}"}
        findings = nova.dispatch(intent)
        elapsed  = time.monotonic() - t0
        print(f"\n  ✅ {label}: {len(findings)} findings — {elapsed:.1f}s")
        return findings
    except Exception as e:
        elapsed = time.monotonic() - t0
        print(f"\n  ⚠️  {label} error ({elapsed:.1f}s): {e}")
        return []

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    start = time.monotonic()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   🦅 NOVA CI RUNNER — Full Arsenal Unleashed                   ║
╠══════════════════════════════════════════════════════════════════╣
  Target  : {TARGET}
  Model   : {os.getenv('NOVA_LLM_MODEL', 'llama3.1:8b')}
  Steps   : {os.getenv('NOVA_MAX_STEPS', '40')} per mode
  Modes   : 23 (all modules, bypasses single-intent limit)
  Started : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
╚══════════════════════════════════════════════════════════════════╝
""")

    # ── PHASE 0: Boot provider layer + codebase mapper ────────────────────────
    banner("PHASE 0 — Provider Layer + Codebase Map")
    nova._init_provider_layer(target=TARGET, verbose=True)
    nova._run_phase0_mapper(TARGET)

    # ── Wire real-time Telegram OnFinding alerts ──────────────────────────────
    _register_live_alerts()
    if TG_TOKEN and TG_CHAT:
        print("  📲  Live Telegram alerts: ON (Critical + High findings)")
    else:
        print("  📵  Live Telegram alerts: OFF (set NOVA_TELEGRAM_TOKEN + NOVA_TELEGRAM_CHAT_ID)")

    all_findings: list = []

    # ── PHASE 1: Reconnaissance ───────────────────────────────────────────────
    all_findings += run_mode("recon",
        "RECON — Subdomains, live hosts, endpoints, JS secrets, certs, cloud")

    # ── PHASE 2: Full-stack web vulnerability sweep ───────────────────────────
    # Runs: IDOR, GraphQL, CSRF, Business Logic, ZeroDay CVE, Patch, Detect, Audit
    all_findings += run_mode("full_stack",
        "FULL STACK — All web vuln categories + CVE correlation")

    # ── PHASE 3: Targeted attack modules ─────────────────────────────────────
    all_findings += run_mode("hunt",
        "HUNT — AgentCore autonomous free-roam agent")
    all_findings += run_mode("sqli",
        "SQLi — Injection across all params, forms, headers")
    all_findings += run_mode("ssrf",
        "SSRF — Internal network, metadata endpoints, cloud IMDS")
    all_findings += run_mode("fuzz",
        "FUZZER — Path/param/header brute force")
    all_findings += run_mode("jwt",
        "JWT — alg:none, key confusion, secret brute force, forge")
    all_findings += run_mode("proto_pollution",
        "PROTOTYPE POLLUTION — __proto__, constructor.prototype chains")
    all_findings += run_mode("race",
        "RACE CONDITIONS — Concurrent requests, TOCTOU")
    all_findings += run_mode("llm_injection",
        "LLM INJECTION — Prompt injection, jailbreak, system prompt leak")
    all_findings += run_mode("zero_day",
        "ZERO-DAY — CVE cross-reference on stack + dependencies")
    all_findings += run_mode("xss",
        "XSS — Reflected, stored, DOM-based cross-site scripting")
    all_findings += run_mode("sast",
        "SAST — Static code analysis if source accessible")
    all_findings += run_mode("git_scan",
        "GIT SCAN — Leaked secrets, keys, tokens in git history")

    # ── PHASE 4: Multi-agent systems ─────────────────────────────────────────
    all_findings += run_mode("orchestrate",
        "ORCHESTRATOR — Multi-agent attack network (ReconAgent→AttackAgent→ReportAgent)")
    all_findings += run_mode("swarm",
        "SWARM v3 — Parallel agent swarm, concurrent hunting")
    all_findings += run_mode("pipeline",
        "PIPELINE — Sequential chained attack with feedback loop")
    all_findings += run_mode("nextgen",
        "NEXT-GEN AGENTIC — Experimental reasoning agents")

    # ── PHASE 5: Kali Linux agent ─────────────────────────────────────────────
    all_findings += run_mode("kali",
        "KALI AGENT — Full Kali KB: nmap, sqlmap, nikto, hydra, nuclei, + auto-clone missing tools")

    # ── PHASE 6: Deep AI assessment ───────────────────────────────────────────
    all_findings += run_mode("daybreak",
        "DAYBREAK — Deep AI-driven assessment, scope-aware, H1-guided")

    # ── PHASE 7: Validation + synthesis ──────────────────────────────────────
    all_findings += run_mode("sandbox",
        "SANDBOX VALIDATOR — Live-verify exploits before reporting")
    all_findings += run_mode("patch",
        "PATCH GENERATOR — Auto-generate remediation code per finding")
    all_findings += run_mode("detect",
        "DETECTION RULES — SIEM/WAF/Suricata/Sigma rules for each finding")
    all_findings += run_mode("audit_report",
        "AUDIT REPORT — CVSS-scored, compliance-ready report")

    # ── PHASE 8: Triage + final report ───────────────────────────────────────
    all_findings += run_mode("triage",
        "TRIAGE — CVSS scoring, H1 priority rank, duplicate removal")
    all_findings += run_mode("report",
        "REPORT — Final H1-ready writeups per finding")

    # ── Deduplicate + summarise ───────────────────────────────────────────────
    banner("NOVA CI RUNNER — COMPLETE")

    seen = set()
    deduped = []
    for f in all_findings:
        key = json.dumps(f, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    critical = [f for f in deduped if str(f.get("severity","")).upper() == "CRITICAL"]
    high     = [f for f in deduped if str(f.get("severity","")).upper() == "HIGH"]
    medium   = [f for f in deduped if str(f.get("severity","")).upper() == "MEDIUM"]
    elapsed  = time.monotonic() - start

    print(f"""
  📊 Total (all modes)    : {len(all_findings)}
  🔎 After deduplication  : {len(deduped)}
  🚨 Critical             : {len(critical)}
  🔴 High                 : {len(high)}
  🟡 Medium               : {len(medium)}
  ⏱  Total runtime        : {elapsed/60:.1f} minutes
""")

    # Save consolidated JSON
    ts  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out = WORKSPACE / f"nova_ci_all_findings_{ts}.json"
    out.write_text(json.dumps({
        "generated"    : datetime.utcnow().isoformat(),
        "target"       : TARGET,
        "model"        : os.getenv("NOVA_LLM_MODEL", "unknown"),
        "runtime_secs" : elapsed,
        "total"        : len(deduped),
        "critical"     : len(critical),
        "high"         : len(high),
        "medium"       : len(medium),
        "findings"     : deduped
    }, indent=2, default=str))
    print(f"  💾 Saved: {out}")

    # Top findings
    if critical or high:
        print(f"\n  Top Critical/High Findings:")
        sev_order = {"CRITICAL": 0, "HIGH": 1}
        top = sorted(critical + high,
                     key=lambda x: sev_order.get(str(x.get("severity","")).upper(), 9))
        for f in top[:10]:
            sev      = f.get("severity","?").upper()
            emoji    = "🚨" if sev == "CRITICAL" else "🔴"
            vuln     = f.get("type", "?")
            location = f.get("endpoint") or f.get("file") or "?"
            print(f"  {emoji} [{sev}] {vuln} — {location}")

    # Final Telegram summary
    _tg(
        f"✅ *Nova Hunt Complete*\n\n"
        f"Target: `{TARGET}`\n"
        f"Runtime: {elapsed/60:.1f} min\n"
        f"🚨 Critical: {len(critical)}\n"
        f"🔴 High: {len(high)}\n"
        f"🟡 Medium: {len(medium)}\n"
        f"Modules: all 25 run\n"
        f"Full report in GitHub Issues"
    )

    return 1 if (critical or high) else 0


if __name__ == "__main__":
    sys.exit(main())
