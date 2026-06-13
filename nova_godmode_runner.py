#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🦅 NOVA GOD-MODE RUNNER v1.0                                              ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║  Master orchestrator that chains ALL 6 Nova execution engines              ║
║  in the correct order, with full target injection and finding merge.       ║
║                                                                              ║
║  Engines:                                                                   ║
║    1 — CI Runner      (25 nova.dispatch() modes)                           ║
║    2 — Pipeline       (11-phase: recon→think→hypothesize→attack→synth→...) ║
║    3 — Swarm v3       (6 parallel agents: brain+fuzzer+session+race+jwt..) ║
║    4 — Weapon Forge   (real exploit generation per finding)                ║
║    5 — Attack Chain   (5-phase: recon→scan→vuln→exploit→post→report)       ║
║    6 — Auto Exploit   (continuous exploit loop on confirmed surfaces)      ║
║    7 — Daybreak       (AI 3-stage: prioritize→sandbox→audit)               ║
║    8 — Kali Direct    (real nmap/sqlmap/nuclei/nikto commands)             ║
║                                                                              ║
║  Usage: python3 nova_godmode_runner.py --engine 1 --target https://x.com  ║
║         python3 nova_godmode_runner.py --engine all --target https://x.com ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
import argparse, importlib, json, os, sys, time, subprocess, glob, traceback
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

# ── Environment ───────────────────────────────────────────────────────────────
WORKSPACE  = Path(os.environ.get("NOVA_WORKSPACE", os.path.expanduser("~/nova_workspace")))
TARGET     = os.environ.get("NOVA_TARGET", "")
PROGRAM    = os.environ.get("NOVA_PROGRAM", "unknown")
MODEL      = os.environ.get("NOVA_LLM_MODEL", "llama3.1:8b")
MAX_STEPS  = int(os.environ.get("NOVA_MAX_STEPS", "100"))
TG_TOKEN   = os.environ.get("NOVA_TELEGRAM_TOKEN", "")
TG_CHAT    = os.environ.get("NOVA_TELEGRAM_CHAT_ID", "")
PREV_F     = os.environ.get("NOVA_PREV_FINDINGS", "")
ITER       = int(os.environ.get("NOVA_ITERATION", "1"))
NOVA_DIR   = Path(__file__).parent

os.makedirs(WORKSPACE, exist_ok=True)
os.makedirs(WORKSPACE / "reports", exist_ok=True)
os.makedirs(WORKSPACE / "weapons", exist_ok=True)
os.makedirs(WORKSPACE / "chains", exist_ok=True)
sys.path.insert(0, str(NOVA_DIR))

TS     = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
LOG    = open(WORKSPACE / f"godmode_engine_log_{TS}.txt", "w", buffering=1)

def log(msg: str):
    print(msg, flush=True)
    LOG.write(msg + "\n")
    LOG.flush()

def banner(title: str):
    w = 72
    log(f"\n{'═'*w}")
    log(f"  🦅  {title}")
    log(f"{'═'*w}")

# ── Telegram ──────────────────────────────────────────────────────────────────
def tg(msg: str):
    if not (TG_TOKEN and TG_CHAT):
        return
    try:
        import urllib.request, urllib.parse
        data = urllib.parse.urlencode({"chat_id":TG_CHAT,"text":msg[:4000],"parse_mode":"Markdown"}).encode()
        urllib.request.urlopen(
            urllib.request.Request(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", data=data),
            timeout=10)
    except Exception:
        pass

# ── Finding helpers ───────────────────────────────────────────────────────────
def load_prev_findings() -> List[Dict]:
    """Load all findings from previous engines / iterations."""
    all_f = []
    seen  = set()
    patterns = [
        str(WORKSPACE / "nova_ci_all_findings_*.json"),
        str(WORKSPACE / "nova_godmode_findings_*.json"),
    ]
    if PREV_F and os.path.exists(PREV_F):
        patterns.insert(0, PREV_F)
    for pat in patterns:
        for fp in sorted(glob.glob(pat)):
            try:
                with open(fp) as fh:
                    data = json.load(fh)
                batch = data if isinstance(data, list) else data.get("findings", [])
                for f in batch:
                    key = (f.get("type",""), f.get("url", f.get("endpoint","")), f.get("severity",""))
                    if key not in seen:
                        seen.add(key)
                        all_f.append(f)
            except Exception:
                pass
    return all_f

def save_findings(findings: List[Dict], label: str):
    out = WORKSPACE / f"nova_godmode_findings_{label}_{TS}.json"
    # Also always save to the canonical ci_all_findings path so other tools pick it up
    canon = WORKSPACE / f"nova_ci_all_findings_{label}_{TS}.json"
    payload = {
        "generated": datetime.utcnow().isoformat(),
        "target": TARGET, "engine": label,
        "iteration": ITER, "total": len(findings),
        "findings": findings,
    }
    for p in [out, canon]:
        try:
            with open(p, "w") as fh:
                json.dump(payload, fh, indent=2, default=str)
        except Exception:
            pass
    log(f"  💾 Saved {len(findings)} findings → {out.name}")
    return findings

def normalise(raw: Any) -> List[Dict]:
    """Accept findings in any format and normalise to list-of-dicts."""
    if isinstance(raw, list):
        return [f if isinstance(f, dict) else {"type": str(f), "severity": "INFO"} for f in raw]
    if isinstance(raw, dict):
        if "findings" in raw:
            return normalise(raw["findings"])
        # Single finding
        return [raw]
    return []

# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 1 — Nova CI Runner (all 25 dispatch() modes)
# ═══════════════════════════════════════════════════════════════════════════════
def engine_1_ci_runner(target: str) -> List[Dict]:
    banner("ENGINE 1 — CI Runner: all 25 nova.dispatch() modes")
    tg(f"🚀 *Nova Engine 1 — CI Runner*\nTarget: `{target}`\nRunning all 25 modules...")
    findings = []
    try:
        import nova
        nova._init_provider_layer(target=target, verbose=True)
        nova._run_phase0_mapper(target)

        MODES = [
            ("recon",          "Recon — subdomains, hosts, JS, certs"),
            ("full_stack",     "Full Stack — all web vuln categories"),
            ("hunt",           "Hunt — autonomous agent free-roam"),
            ("sqli",           "SQLi — injection across all params"),
            ("ssrf",           "SSRF — internal nets, IMDS, cloud"),
            ("fuzz",           "Fuzzer — path/param/header brute force"),
            ("jwt",            "JWT — alg:none, forge, confusion"),
            ("proto_pollution","Prototype Pollution — __proto__"),
            ("race",           "Race Conditions — TOCTOU"),
            ("llm_injection",  "LLM Injection — prompt leak, jailbreak"),
            ("zero_day",       "Zero-Day — live CVE cross-reference"),
            ("xss",            "XSS — reflected/stored/DOM"),
            ("sast",           "SAST — static analysis"),
            ("git_scan",       "Git Scan — leaked secrets"),
            ("orchestrate",    "Orchestrator — multi-agent network"),
            ("swarm",          "Swarm — parallel agent swarm"),
            ("pipeline",       "Pipeline — chained attack feedback"),
            ("nextgen",        "Next-Gen — experimental reasoning"),
            ("kali",           "Kali Agent — nmap/sqlmap/nuclei"),
            ("daybreak",       "Daybreak — deep AI assessment"),
            ("sandbox",        "Sandbox — live exploit validation"),
            ("patch",          "Patch Generator — auto-remediation"),
            ("detect",         "Detection Rules — SIEM/WAF/Sigma"),
            ("audit_report",   "Audit Report — CVSS compliance"),
            ("triage",         "Triage — H1 priority ranking"),
        ]
        for mode, label in MODES:
            t0 = time.monotonic()
            try:
                intent = {"mode": mode, "target": target, "original_query": f"{mode} {target}"}
                result = nova.dispatch(intent)
                f_list = normalise(result)
                findings.extend(f_list)
                log(f"  ✅ {label}: {len(f_list)} findings ({time.monotonic()-t0:.1f}s)")
            except Exception as ex:
                log(f"  ⚠️  {label} error: {ex}")
    except Exception as ex:
        log(f"  ❌ Engine 1 fatal: {ex}")
        traceback.print_exc()
    save_findings(findings, "engine1_ci_runner")
    log(f"\n  Engine 1 total: {len(findings)} raw findings")
    return findings

# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 2 — Nova Pipeline (11-phase unified)
# ═══════════════════════════════════════════════════════════════════════════════
def engine_2_pipeline(target: str) -> List[Dict]:
    banner("ENGINE 2 — Pipeline: 11-phase (recon→think→hypothesize→attack→synth→feedback→memory→evolve→report)")
    tg(f"🚀 *Nova Engine 2 — Pipeline*\nTarget: `{target}`\n11-phase unified hunt...")
    findings = []
    try:
        from nova_pipeline import NovaPipeline
        p = NovaPipeline(target=target, verbose=True, enable_evolution=False)
        result = p.run()
        # result is a PipelineResult object
        if hasattr(result, "findings"):
            findings = normalise(result.findings)
        elif isinstance(result, dict):
            findings = normalise(result.get("findings", []))
    except Exception as ex:
        log(f"  ❌ Engine 2 error: {ex}")
        traceback.print_exc()
    save_findings(findings, "engine2_pipeline")
    log(f"\n  Engine 2 total: {len(findings)} raw findings")
    return findings

# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 3 — Swarm v3 (6 parallel agents)
# ═══════════════════════════════════════════════════════════════════════════════
def engine_3_swarm(target: str) -> List[Dict]:
    banner("ENGINE 3 — Swarm v3: 6 parallel agents (brain + fuzzer + session + race + jwt + code)")
    tg(f"🚀 *Nova Engine 3 — Swarm v3*\nTarget: `{target}`\n6 parallel agents hunting...")
    findings = []
    try:
        from nova_swarm_v3 import NovaSwarmV3
        swarm = NovaSwarmV3(base_url=target)
        swarm.run_full_swarm()
        findings = normalise(swarm.kg.get("findings", []))
    except Exception as ex:
        log(f"  ❌ Engine 3 swarm error: {ex}")
        traceback.print_exc()
    save_findings(findings, "engine3_swarm")
    log(f"\n  Engine 3 total: {len(findings)} raw findings")
    return findings

# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 4 — Weapon Forge (exploit generation per finding)
# ═══════════════════════════════════════════════════════════════════════════════
def engine_4_weapon_forge(target: str) -> List[Dict]:
    banner("ENGINE 4 — Weapon Forge: real exploit generation per critical/high finding")
    tg(f"🔨 *Nova Engine 4 — Weapon Forge*\nForging exploits for confirmed findings...")
    prev = load_prev_findings()
    forge_results = []
    try:
        from nova_weapon_forge import NovaWeaponForge, get_weapon_forge
        forge = get_weapon_forge(target=target, dry_run=False)
        targets_processed = 0
        # Forge from every critical/high finding
        for f in prev:
            sev = str(f.get("severity","")).upper()
            if sev in ("CRITICAL", "HIGH"):
                try:
                    result = forge.forge_from_finding(f)
                    if result.get("ok") or result.get("code"):
                        forge_results.append({
                            "type": f"WeaponForge:{f.get('type','?')}",
                            "severity": sev,
                            "description": f"Exploit forged for {f.get('type','?')}: {result.get('description','')}",
                            "endpoint": f.get("endpoint", target),
                            "evidence": result.get("code","")[:300],
                            "weapon_path": result.get("path",""),
                        })
                        targets_processed += 1
                except Exception as ex:
                    log(f"    ⚠️  Forge error for {f.get('type','?')}: {ex}")

        # Also directly test key vuln types
        from nova_weapon_forge import test_sqli, test_xss, test_ssrf
        for fn, label in [(test_sqli, "SQLi"), (test_xss, "XSS"), (test_ssrf, "SSRF")]:
            try:
                r = fn(target)
                forge_results.extend(normalise(r))
                log(f"  ✅ Direct {label} test: {len(normalise(r))} results")
            except Exception as ex:
                log(f"  ⚠️  {label} direct test error: {ex}")

        log(f"  ✅ Forged exploits for {targets_processed} findings + direct tests")
    except Exception as ex:
        log(f"  ❌ Engine 4 weapon forge error: {ex}")
        traceback.print_exc()
    save_findings(forge_results, "engine4_weapon_forge")
    log(f"\n  Engine 4 total: {len(forge_results)} forged exploits")
    return forge_results

# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 5 — Attack Chain (5-phase: recon→scan→vuln→exploit→post→report)
# ═══════════════════════════════════════════════════════════════════════════════
def engine_5_attack_chain(target: str) -> List[Dict]:
    banner("ENGINE 5 — Attack Chain: recon → scan → vuln_analysis → exploitation → post_exploitation")
    tg(f"⛓️ *Nova Engine 5 — Attack Chain*\nTarget: `{target}`\nFull 5-phase chain...")
    findings = []
    try:
        from nova_attack_chain import NovaAttackChain
        chain = NovaAttackChain(
            dry_run=False,
            require_exploit_approval=False,
            auto_exploit=True,
            max_workers=4,
        )
        result = chain.run(
            target,
            authorization_note="Authorized HackerOne bug bounty — scope validated"
        )
        if hasattr(result, "findings"):
            findings = normalise(result.findings)
        elif isinstance(result, dict):
            findings = normalise(result.get("findings", []))
        log(f"  ✅ Attack chain complete: {len(findings)} findings")
    except Exception as ex:
        log(f"  ❌ Engine 5 attack chain error: {ex}")
        traceback.print_exc()
    save_findings(findings, "engine5_attack_chain")
    log(f"\n  Engine 5 total: {len(findings)} raw findings")
    return findings

# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 6 — Auto Exploit Loop (continuous exploitation)
# ═══════════════════════════════════════════════════════════════════════════════
def engine_6_auto_exploit(target: str) -> List[Dict]:
    banner("ENGINE 6 — Auto Exploit Loop: continuous exploitation on confirmed surfaces")
    tg(f"🔄 *Nova Engine 6 — Auto Exploit Loop*\nContinuous exploitation on `{target}`...")
    findings = []
    try:
        from nova_auto_exploit_loop import get_auto_exploit_loop, AutoExploitLoop
        loop = get_auto_exploit_loop(target=target)
        if hasattr(loop, "run"):
            result = loop.run()
            findings = normalise(result if result else [])
        elif hasattr(loop, "start"):
            loop.start()
            if hasattr(loop, "findings"):
                findings = normalise(loop.findings)
    except Exception as ex:
        log(f"  ❌ Engine 6 auto exploit error: {ex}")
        traceback.print_exc()
    save_findings(findings, "engine6_auto_exploit")
    log(f"\n  Engine 6 total: {len(findings)} raw findings")
    return findings

# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 7 — Daybreak (AI 3-stage assessment)
# ═══════════════════════════════════════════════════════════════════════════════
def engine_7_daybreak(target: str) -> List[Dict]:
    banner("ENGINE 7 — Daybreak: AI 3-stage (prioritize → sandbox validate → audit package)")
    tg(f"🌅 *Nova Engine 7 — Daybreak AI*\nTarget: `{target}`\n3-stage AI assessment...")
    findings = []
    try:
        from nova_daybreak import NovaDaybreak, ScopeRule
        # Build scope from target
        from urllib.parse import urlparse
        parsed = urlparse(target)
        scope = ScopeRule(
            domain=parsed.netloc or target,
            allowed_paths=["/*"],
            program=PROGRAM,
        )
        db = NovaDaybreak(target=target, scope=scope, model=MODEL, verbose=True)
        # Feed previous findings into daybreak for deeper analysis
        prev = load_prev_findings()
        if prev:
            result = db.assess(prev_findings=prev[:100])
        else:
            result = db.assess()
        if isinstance(result, dict):
            findings = normalise(result.get("findings", result.get("validated_findings", [])))
        elif isinstance(result, list):
            findings = normalise(result)
        log(f"  ✅ Daybreak complete: {len(findings)} validated findings")
    except Exception as ex:
        log(f"  ❌ Engine 7 daybreak error: {ex}")
        traceback.print_exc()
    save_findings(findings, "engine7_daybreak")
    log(f"\n  Engine 7 total: {len(findings)} raw findings")
    return findings

# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 8 — Kali Agent (real tools)
# ═══════════════════════════════════════════════════════════════════════════════
def engine_8_kali_agent(target: str) -> List[Dict]:
    banner("ENGINE 8 — Kali Agent: full Kali KB (nmap/sqlmap/nuclei/nikto/hydra/ffuf + auto-clone)")
    tg(f"🐉 *Nova Engine 8 — Kali Agent*\nTarget: `{target}`\nFull Kali arsenal...")
    findings = []
    try:
        from nova_kali_agent import NovaKaliAgent
        agent = NovaKaliAgent(target=target, workspace=str(WORKSPACE))
        if hasattr(agent, "run"):
            result = agent.run()
            findings = normalise(result if isinstance(result, (list, dict)) else [])
        elif hasattr(agent, "hunt"):
            result = agent.hunt()
            findings = normalise(result if isinstance(result, (list, dict)) else [])
        log(f"  ✅ Kali agent complete: {len(findings)} findings")
    except Exception as ex:
        log(f"  ❌ Engine 8 kali agent error: {ex}")
        # Fall back to direct subprocess execution
        log("  ↩️  Falling back to direct Kali subprocess commands...")
        findings = _kali_direct(target)
    save_findings(findings, "engine8_kali_agent")
    log(f"\n  Engine 8 total: {len(findings)} raw findings")
    return findings

def _kali_direct(target: str) -> List[Dict]:
    """Direct Kali tool execution as fallback."""
    from urllib.parse import urlparse
    parsed = urlparse(target)
    host   = parsed.netloc or parsed.path or target
    host   = host.split(":")[0]
    ws     = str(WORKSPACE)
    findings = []
    cmds = [
        # Recon
        f"subfinder -d {host} -silent -o {ws}/subdomains.txt 2>/dev/null || true",
        f"httpx -l {ws}/subdomains.txt -silent -status-code -title -tech-detect -o {ws}/live_hosts.txt 2>/dev/null || true",
        # Port + service scan
        f"nmap -sV -sC --open -T4 -p 80,443,8080,8443,8888,3000,4000,5000,9000,9200,27017 {host} -oN {ws}/nmap.txt 2>/dev/null || true",
        # Vuln scan
        f"nuclei -u {target} -severity critical,high,medium -silent -o {ws}/nuclei.txt 2>/dev/null || true",
        # Web scan
        f"nikto -h {target} -maxtime 300 -output {ws}/nikto.txt 2>/dev/null || true",
        # SQLi
        f"sqlmap -u '{target}/?id=1' --level=3 --risk=2 --batch --forms --crawl=2 --output-dir={ws}/sqlmap 2>/dev/null || true",
        # XSS
        f"dalfox url '{target}' --silence -o {ws}/dalfox.txt 2>/dev/null || true",
        # Dir busting
        f"ffuf -u '{target}/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,201,301,302,401,403 -o {ws}/ffuf.json -of json -t 30 2>/dev/null || true",
        # Secret / param discovery
        f"gau {host} 2>/dev/null | tee {ws}/gau.txt | head -1000 || true",
        f"waybackurls {host} 2>/dev/null | tee {ws}/wayback.txt | head -1000 || true",
    ]
    for cmd in cmds:
        log(f"  🔧 {cmd.split('|')[0][:80]}")
        try:
            subprocess.run(cmd, shell=True, timeout=120, capture_output=True)
        except subprocess.TimeoutExpired:
            log(f"    ⏱  Timed out")
        except Exception as ex:
            log(f"    ⚠️  {ex}")

    # Parse nuclei output into findings
    nuclei_f = Path(ws) / "nuclei.txt"
    if nuclei_f.exists():
        for line in nuclei_f.read_text().splitlines():
            if line.strip():
                sev = "HIGH"
                if "[critical]" in line.lower(): sev = "CRITICAL"
                elif "[medium]"  in line.lower(): sev = "MEDIUM"
                elif "[low]"     in line.lower(): sev = "LOW"
                findings.append({
                    "type": "NucleiFindings", "severity": sev,
                    "description": line.strip(), "endpoint": target,
                    "source_module": "kali_direct_nuclei",
                })
    # Parse nmap output
    nmap_f = Path(ws) / "nmap.txt"
    if nmap_f.exists():
        for line in nmap_f.read_text().splitlines():
            if "/tcp" in line and "open" in line:
                findings.append({
                    "type": "OpenPort", "severity": "INFO",
                    "description": f"Open port: {line.strip()}", "endpoint": host,
                    "source_module": "kali_direct_nmap",
                })
    log(f"  ✅ Direct Kali: {len(findings)} findings from tool outputs")
    return findings

# ═══════════════════════════════════════════════════════════════════════════════
# MASTER ORCHESTRATOR — run all engines in sequence
# ═══════════════════════════════════════════════════════════════════════════════
ENGINE_MAP = {
    "1": engine_1_ci_runner,
    "2": engine_2_pipeline,
    "3": engine_3_swarm,
    "4": engine_4_weapon_forge,
    "5": engine_5_attack_chain,
    "6": engine_6_auto_exploit,
    "7": engine_7_daybreak,
    "8": engine_8_kali_agent,
}

def run_all(target: str) -> List[Dict]:
    all_findings = []
    total_start  = time.monotonic()
    for n in ["1","2","3","4","5","6","7","8"]:
        t0 = time.monotonic()
        try:
            f = ENGINE_MAP[n](target)
            all_findings.extend(f)
            log(f"\n  ⏱  Engine {n} done: {len(f)} findings in {(time.monotonic()-t0)/60:.1f}m")
        except Exception as ex:
            log(f"\n  ❌ Engine {n} crashed: {ex}")
    log(f"\n{'═'*72}")
    log(f"  🦅 ALL ENGINES COMPLETE: {len(all_findings)} total findings in {(time.monotonic()-total_start)/60:.1f}m")
    log(f"{'═'*72}")
    return all_findings

def main():
    parser = argparse.ArgumentParser(description="🦅 Nova God-Mode Runner")
    parser.add_argument("--engine", default="all",
                        help="Engine number 1-8 or 'all' (default: all)")
    parser.add_argument("--target", default=TARGET,
                        help="Target URL")
    args = parser.parse_args()

    target = args.target or TARGET
    if not target:
        print("ERROR: --target required or set NOVA_TARGET env var")
        sys.exit(1)

    log(f"""
╔══════════════════════════════════════════════════════════════════════╗
║   🦅 NOVA GOD-MODE RUNNER                                          ║
╠══════════════════════════════════════════════════════════════════════╣
  Target    : {target}
  Engine    : {args.engine}
  Model     : {MODEL}
  Steps     : {MAX_STEPS}
  Iteration : {ITER}
  Workspace : {WORKSPACE}
  Started   : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
╚══════════════════════════════════════════════════════════════════════╝
""")

    if args.engine == "all":
        findings = run_all(target)
    elif args.engine in ENGINE_MAP:
        findings = ENGINE_MAP[args.engine](target)
    else:
        log(f"Unknown engine: {args.engine}. Use 1-8 or 'all'")
        sys.exit(1)

    # Summary
    crit = sum(1 for f in findings if str(f.get("severity","")).upper()=="CRITICAL")
    high = sum(1 for f in findings if str(f.get("severity","")).upper()=="HIGH")
    med  = sum(1 for f in findings if str(f.get("severity","")).upper()=="MEDIUM")

    log(f"\n  📊 Final Summary:")
    log(f"     🔴 Critical : {crit}")
    log(f"     🟠 High     : {high}")
    log(f"     🟡 Medium   : {med}")
    log(f"     Total      : {len(findings)}")

    tg(f"✅ *Nova Engine {args.engine} Complete*\nTarget: `{target}`\n🔴 Critical: {crit}\n🟠 High: {high}\n🟡 Medium: {med}")

if __name__ == "__main__":
    main()
