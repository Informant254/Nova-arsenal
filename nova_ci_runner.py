#!/usr/bin/env python3
"""
Nova CI Runner — chains ALL modules/modes in sequence.
Bypasses _parse_intent so every capability runs, not just one.
"""

import sys, os, json, time
from pathlib import Path
from datetime import datetime

# Ensure nova modules are importable from the repo root
NOVA_DIR = Path(__file__).parent
sys.path.insert(0, str(NOVA_DIR))

import nova  # the main nova module

TARGET  = sys.argv[1] if len(sys.argv) > 1 else nova.DEFAULT_TARGET
WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)

def banner(title):
    w = 64
    print(f"\n{'═'*w}")
    print(f"  🦅  {title}")
    print(f"{'═'*w}")

def run_mode(mode, label=None):
    label = label or mode.upper()
    banner(f"NOVA MODULE: {label}")
    t0 = time.monotonic()
    try:
        intent = {"mode": mode, "target": TARGET, "original_query": f"{mode} {TARGET}"}
        findings = nova.dispatch(intent)
        elapsed = time.monotonic() - t0
        print(f"\n  ✅ {label}: {len(findings)} findings in {elapsed:.1f}s")
        return findings
    except Exception as e:
        elapsed = time.monotonic() - t0
        print(f"\n  ⚠️  {label} error after {elapsed:.1f}s: {e}")
        return []

print(f"""
╔══════════════════════════════════════════════════════════════╗
║   🦅 NOVA CI RUNNER — Full Arsenal Unleashed               ║
╠══════════════════════════════════════════════════════════════╣
  Target  : {TARGET}
  Model   : {os.getenv('NOVA_LLM_MODEL', 'llama3.1:8b')}
  Steps   : {os.getenv('NOVA_MAX_STEPS', '80')}
  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
╚══════════════════════════════════════════════════════════════╝
""")

# ── ONE-TIME INIT: provider layer + phase 0 codebase map ──────────────────────
banner("PHASE 0 — Provider Layer + Codebase Mapper")
nova._init_provider_layer(target=TARGET, verbose=True)
nova._run_phase0_mapper(TARGET)

all_findings = []

# ── PHASE 1: RECONNAISSANCE ───────────────────────────────────────────────────
all_findings += run_mode("recon",         "RECON — Subdomains, endpoints, JS, certs")

# ── PHASE 2: FULL STACK (IDOR/GraphQL/CSRF/Business Logic/ZeroDay/Patch/Detect) ──
all_findings += run_mode("full_stack",    "FULL STACK — All web vuln categories")

# ── PHASE 3: INDIVIDUAL ATTACK MODULES ───────────────────────────────────────
all_findings += run_mode("hunt",          "HUNT — AgentCore autonomous agent")
all_findings += run_mode("sqli",          "SQLi — SQL injection across all params")
all_findings += run_mode("ssrf",          "SSRF — Server-side request forgery")
all_findings += run_mode("fuzz",          "FUZZER — Parameter/path fuzzing")
all_findings += run_mode("jwt",           "JWT — Forge, alg:none, secret brute")
all_findings += run_mode("proto_pollution","PROTOTYPE POLLUTION — JS object chain")
all_findings += run_mode("race",          "RACE CONDITIONS — Concurrent requests")
all_findings += run_mode("llm_injection", "LLM INJECTION — Prompt injection attacks")
all_findings += run_mode("zero_day",      "ZERO-DAY CORRELATOR — CVE cross-reference")

# ── PHASE 4: MULTI-AGENT SYSTEMS ─────────────────────────────────────────────
all_findings += run_mode("orchestrate",   "ORCHESTRATOR — Multi-agent attack network")
all_findings += run_mode("swarm",         "SWARM v3 — Parallel agent swarm")
all_findings += run_mode("pipeline",      "PIPELINE — Sequential attack chain")
all_findings += run_mode("nextgen",       "NEXT-GEN AGENTIC — Experimental agents")

# ── PHASE 5: KALI LINUX AGENT ─────────────────────────────────────────────────
all_findings += run_mode("kali",          "KALI AGENT — Full Kali Linux arsenal")

# ── PHASE 6: AI ASSESSMENT ────────────────────────────────────────────────────
all_findings += run_mode("daybreak",      "DAYBREAK — Deep AI security assessment")
all_findings += run_mode("full_stack",    "EXPLOIT VALIDATION — Sandbox + verify chain")

# ── PHASE 7: EXPLOIT SYNTHESIS & WEAPONIZATION ───────────────────────────────
all_findings += run_mode("sandbox",       "SANDBOX VALIDATOR — Verify exploits live")
all_findings += run_mode("patch",         "PATCH GENERATOR — Remediation code")
all_findings += run_mode("detect",        "DETECTION RULES — SIEM/WAF rules")
all_findings += run_mode("audit_report",  "AUDIT REPORTER — Compliance report")

# ── PHASE 8: TRIAGE + FINAL REPORT ───────────────────────────────────────────
all_findings += run_mode("triage",        "TRIAGE — CVSS score + H1 priority rank")
all_findings += run_mode("report",        "REPORT — Final H1-ready writeups")

# ── FINAL SUMMARY ─────────────────────────────────────────────────────────────
banner("NOVA CI RUNNER — COMPLETE")

unique = {json.dumps(f, sort_keys=True, default=str) for f in all_findings}
deduped = [json.loads(u) for u in unique]
critical = [f for f in deduped if str(f.get("severity","")).upper() in ("CRITICAL","HIGH")]

print(f"""
  📊 Total findings (all modes) : {len(all_findings)}
  🔎 After deduplication        : {len(deduped)}
  🔴 Critical + High            : {len(critical)}
  🕐 Finished                   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
""")

# Save consolidated findings
out = WORKSPACE / f"nova_ci_all_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
out.write_text(json.dumps({
    "generated": datetime.now().isoformat(),
    "target": TARGET,
    "model": os.getenv("NOVA_LLM_MODEL", "unknown"),
    "total": len(deduped),
    "critical_high": len(critical),
    "findings": deduped
}, indent=2, default=str))
print(f"  💾 Saved: {out}")

if critical:
    print(f"\n  🔴 Critical/High Findings:")
    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    for f in sorted(critical, key=lambda x: sev_order.get(str(x.get("severity","")).upper(), 4))[:10]:
        icon = "🔴" if f.get("severity","").upper() == "CRITICAL" else "🟠"
        print(f"  {icon} [{f.get('severity','?')}] {f.get('type','?')} — {f.get('endpoint') or f.get('file','?')}")

# Exit 1 if critical/high found (makes GH Actions flag the run)
sys.exit(1 if critical else 0)
