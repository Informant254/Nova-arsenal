#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🦅 NOVA — NATURAL LANGUAGE COMMAND INTERFACE v4.0                ║
║                                                                      ║
║   Tell Nova what to do in plain English.                            ║
║   She parses your intent and executes at full power.                ║
║                                                                      ║
║   Usage:                                                             ║
║     python3 nova.py "Hunt hackerone.com for SQL injection"          ║
║     python3 nova.py "Run a full swarm on localhost:3000"            ║
║     python3 nova.py "Assess notion.so with Daybreak"                ║
║     python3 nova.py "Build a threat model for ./juice-shop"         ║
║     python3 nova.py "Scan dependencies for CVEs"                    ║
║     python3 nova.py "Scan git history for leaked secrets"           ║
║     python3 nova.py "Patch all confirmed findings"                  ║
║     python3 nova.py "Generate SIEM detection rules"                 ║
║     python3 nova.py "Generate a full enterprise audit report"       ║
║     python3 nova.py "Run full-stack Mythos+Daybreak pipeline"       ║
║     python3 nova.py          ← interactive prompt                   ║
║                                                                      ║
║   Zero confirmation prompts. Fully autonomous.                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import sys
import subprocess
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# ── CONFIG ─────────────────────────────────────────────────────────────────────
OLLAMA_URL   = os.getenv("NOVA_LLM_URL",   "http://localhost:11434")
WORKSPACE    = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))

LLM_MODELS = [
    os.getenv("NOVA_LLM_MODEL", ""),
    "qwen3:8b", "llama3.2", "llama3.1", "mistral", "deepseek-r1:8b", "tinyllama",
]

BANNER = r"""
  ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
  ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
  ██╔██╗ ██║██║   ██║██║   ██║███████║
  ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
  ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
  ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝  A R S E N A L  v4.0

  Natural Language → Full Autonomous Execution
  Mythos + Daybreak capability parity achieved
  ─────────────────────────────────────────────
"""

EXAMPLES = [
    "Hunt hackerone.com for SQL injection and SSRF vulnerabilities",
    "Run a full swarm on localhost:3000 — maximum power",
    "Assess notion.so using the Daybreak 3-stage pipeline",
    "Build a threat model for ./my-app",
    "Scan dependencies for CVEs (SCA)",
    "Scan git history for leaked secrets",
    "Patch all confirmed findings",
    "Generate SIEM detection rules for my findings",
    "Generate a full enterprise audit report",
    "Run full-stack Mythos+Daybreak pipeline on ./juice-shop",
    "Recon target.com — discover all subdomains and open ports",
    "Improve yourself using my recent hunt results",
]

# ── INTENT SCHEMA ───────────────────────────────────────────────────────────────

MODES = {
    "hunt":         "Agentic ReAct loop — LLM drives the hunt step by step",
    "swarm":        "Deploy all 10 parallel agents against the target simultaneously",
    "assess":       "3-stage Daybreak pipeline: threat priority → sandbox validate → evidence report",
    "recon":        "Reconnaissance only — subdomains, ports, tech stack, no exploitation",
    "self_improve": "Read recent run history, propose code improvements, patch & verify",
    "continuous":   "24/7 non-stop hunting loop across all configured targets",
    "code_review":  "Deep static analysis — taint tracing, sink detection, code audit",
    "pipeline":     "Structured 10-phase hunt pipeline (nova_core.py)",
    "threat_model": "Build Daybreak-style editable threat model from repository",
    "sca":          "Software Composition Analysis — scan all dependencies for CVEs",
    "git_scan":     "Scan git commit history for secrets and regression risks",
    "patch":        "Generate auto-patches for all confirmed findings",
    "detect":       "Generate SIEM detection rules (Sigma/Splunk/Elastic/Suricata)",
    "audit_report": "Generate enterprise audit-ready report from all findings",
    "full_stack":   "Complete Mythos+Daybreak pipeline: prioritize → threat model → audit → SCA → git scan → patch → detect → report",
}

MODE_KEYWORDS: Dict[str, List[str]] = {
    "self_improve": [
        "improve yourself", "self-improve", "self improve", "improve nova",
        "update yourself", "update your code", "evolve yourself", "patch yourself",
        "fix yourself", "make yourself better", "improve your code", "evolve",
        "self evolution", "self-evolution", "improve your performance",
    ],
    "swarm": [
        "swarm", "all agents", "parallel agents", "10 agents", "maximum power",
        "full power", "deploy all", "launch swarm", "agent swarm",
    ],
    "assess": [
        "assess", "assessment", "daybreak", "3-stage", "three stage",
        "full assessment", "threat priority", "pentest", "penetration test",
    ],
    "recon": [
        "recon", "reconnaissance", "discover subdomains", "enumerate", "scan ports",
        "map attack surface", "footprint", "subdomain",
    ],
    "continuous": [
        "continuous", "24/7", "non-stop", "forever", "keep hunting",
        "loop", "always on", "run forever", "background hunt",
    ],
    "code_review": [
        "code review", "source audit", "static analysis", "audit code",
        "find injection", "taint", "code audit", "review source",
    ],
    "pipeline": [
        "pipeline", "10 phase", "ten phase", "structured hunt", "nova core",
    ],
    "threat_model": [
        "threat model", "threat modeling", "attack surface", "trust boundary",
        "map attack", "model threats", "entry points", "build threat",
    ],
    "sca": [
        "sca", "dependency", "dependencies", "packages", "supply chain",
        "vulnerable package", "npm audit", "pip audit", "software composition",
        "scan packages", "scan deps",
    ],
    "git_scan": [
        "git scan", "git history", "commit history", "leaked secret",
        "secret in git", "scan commits", "historical secrets", "git secrets",
        "scan git", "leaked credentials",
    ],
    "patch": [
        "patch", "fix", "remediate", "generate fix", "auto fix",
        "generate patch", "fix findings", "remediation", "auto-patch",
    ],
    "detect": [
        "detection rule", "siem", "sigma", "splunk", "elastic", "suricata",
        "detection engineering", "alert rule", "generate rule", "detection rules",
    ],
    "audit_report": [
        "audit report", "enterprise report", "compliance report", "full report",
        "generate report", "cvss report", "remediation report",
        "executive summary", "compliance",
    ],
    "full_stack": [
        "full stack", "full-stack", "complete pipeline", "full scan",
        "mythos pipeline", "daybreak pipeline", "all capabilities",
        "complete audit", "full assessment", "everything", "full nova",
    ],
}

# ── KEYWORD PARSER (offline fallback) ──────────────────────────────────────────

def _extract_target(text: str) -> Optional[str]:
    patterns = [
        r'https?://[^\s\'"]+',
        r'\b(?:[\w-]+\.)+(?:com|io|org|net|gov|edu|co|app|dev|sh|ai|gg|me|us|uk)[^\s\'"]*',
        r'\./[\w\-/\.]+',
        r'/[\w\-/\.]{2,}',
    ]
    for p in patterns:
        m = re.search(p, text)
        if m:
            t = m.group(0).rstrip('.,;')
            if t.startswith('.') or t.startswith('/'):
                return t
            return t if t.startswith("http") else "https://" + t
    return None

def _keyword_parse(task: str) -> dict:
    t = task.lower()
    mode = "hunt"
    for m, keywords in MODE_KEYWORDS.items():
        if any(kw in t for kw in keywords):
            mode = m
            break
    target = _extract_target(task)
    if not target and mode not in ("self_improve", "continuous", "audit_report"):
        target = os.getenv("NOVA_TARGET", ".")
    return {
        "mode": mode,
        "target": target,
        "objective": task,
        "steps": int(os.getenv("NOVA_MAX_STEPS", "40")),
        "parser": "keyword",
    }

# ── LLM PARSER ─────────────────────────────────────────────────────────────────

PARSE_PROMPT = """You are Nova's instruction parser. Extract the intent from the user's message.
Return ONLY a valid JSON object — no markdown, no explanation.

Schema:
{
  "mode": "hunt|swarm|assess|recon|self_improve|continuous|code_review|pipeline|threat_model|sca|git_scan|patch|detect|audit_report|full_stack",
  "target": "URL, domain, or local path (null if not applicable)",
  "objective": "clear 1-sentence description of what Nova should do",
  "steps": 40
}

Mode guide:
- hunt:         Agentic step-by-step hunt against a specific target
- swarm:        All 10 agents in parallel
- assess:       Daybreak 3-stage pipeline
- recon:        Subdomains + ports + tech stack only, no exploitation
- self_improve: Nova reads her own logs and improves her own code
- continuous:   24/7 loop
- code_review:  Static source code analysis
- pipeline:     10-phase structured pipeline
- threat_model: Build attack surface + trust boundary + attack path threat model
- sca:          Software Composition Analysis - find vulnerable dependencies
- git_scan:     Scan git history for leaked secrets and regressions
- patch:        Auto-generate patches for confirmed findings
- detect:       Generate SIEM detection rules (Sigma/Splunk/Elastic/Suricata)
- audit_report: Enterprise compliance audit report with CVSS scoring
- full_stack:   Run full Mythos+Daybreak pipeline end-to-end

Examples:
"Hunt hackerone.com for SQL injection"
-> {"mode":"hunt","target":"https://hackerone.com","objective":"Find SQL injection vulnerabilities on hackerone.com","steps":40}

"Build a threat model for ./juice-shop"
-> {"mode":"threat_model","target":"./juice-shop","objective":"Build attack surface and threat model for juice-shop","steps":0}

"Scan git history for leaked secrets"
-> {"mode":"git_scan","target":".","objective":"Scan git commit history for leaked secrets and credentials","steps":0}

"Run full Mythos+Daybreak pipeline on ./app"
-> {"mode":"full_stack","target":"./app","objective":"Complete security assessment using all Nova v4.0 capabilities","steps":0}
"""

def _llm_parse(task: str) -> Optional[dict]:
    models = [m for m in LLM_MODELS if m]
    for model in models:
        try:
            payload = json.dumps({
                "model": model,
                "messages": [
                    {"role": "system", "content": PARSE_PROMPT},
                    {"role": "user",   "content": task},
                ],
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.0, "num_predict": 256},
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{OLLAMA_URL.rstrip('/')}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=25) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
            content = raw.get("message", {}).get("content", "").strip()
            if not content:
                continue
            parsed = json.loads(content)
            if "mode" in parsed and parsed["mode"] in MODES:
                parsed["parser"] = f"llm:{model}"
                if parsed.get("target") and not parsed["target"].startswith(("http", ".", "/")):
                    parsed["target"] = "https://" + parsed["target"]
                if not parsed.get("steps"):
                    parsed["steps"] = int(os.getenv("NOVA_MAX_STEPS", "40"))
                return parsed
        except Exception:
            continue
    return None

# ── INTENT PARSER (LLM → keyword fallback) ─────────────────────────────────────

def parse_instruction(task: str) -> dict:
    print(f"\n  🧠 Parsing: \"{task[:90]}\"")
    result = _llm_parse(task)
    if result:
        print(f"  ✅ LLM understood → mode={result['mode']}, target={result.get('target') or '—'}")
    else:
        print(f"  ⚡ Ollama offline → keyword fallback")
        result = _keyword_parse(task)
        print(f"  ✅ Keyword parsed → mode={result['mode']}, target={result.get('target') or '—'}")
    return result

# ── DISPATCHER ──────────────────────────────────────────────────────────────────

def _sep():
    print("  " + "─" * 64)

def dispatch(plan: dict) -> int:
    mode      = plan.get("mode", "hunt")
    target    = plan.get("target") or "."
    objective = plan.get("objective") or "Find and exploit all critical vulnerabilities"
    steps     = int(plan.get("steps") or 40)
    py        = sys.executable
    ts        = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    WORKSPACE.mkdir(parents=True, exist_ok=True)
    target_path = os.path.expanduser(target) if target else "."

    _sep()
    print(f"  🚀  MODE       {mode.upper()}")
    if target:  print(f"  🎯  TARGET     {target}")
    print(f"  📋  OBJECTIVE  {objective[:90]}")
    if steps:   print(f"  ⚙️   STEPS      {steps}")
    _sep()
    print()

    if mode == "self_improve":
        print("  🔄 Launching self-improvement engine...\n")
        return subprocess.call([py, "nova_self_improvement.py"])

    elif mode == "swarm":
        print("  🐝 Launching 10-agent parallel swarm...\n")
        env = {**os.environ, "TARGET_URL": target}
        return subprocess.call([py, "launch_swarm.py"], env=env)

    elif mode == "assess":
        print("  🌅 Launching Daybreak 3-stage assessment...\n")
        env = {**os.environ, "NOVA_TARGET": target}
        return subprocess.call([py, "nova_daybreak.py"], env=env)

    elif mode == "recon":
        print("  🔍 Launching recon engine...\n")
        try:
            return subprocess.call([py, "nova_wild_hunt.py", "--target", target])
        except Exception:
            env = {**os.environ, "NOVA_TARGET": target}
            return subprocess.call([py, "nova_wild_hunt.py"], env=env)

    elif mode == "continuous":
        print("  ♾️  Launching 24/7 continuous hunting loop...\n")
        return subprocess.call([py, "nova_continuous_v3.py"])

    elif mode == "code_review":
        print("  🔎 Launching source code analysis (v2.0)...\n")
        return subprocess.call([py, "nova_source_auditor.py", target_path])

    elif mode == "pipeline":
        print("  🔩 Launching 10-phase pipeline...\n")
        env = {**os.environ, "NOVA_TARGET": target}
        return subprocess.call([py, "nova_core.py"], env=env)

    elif mode == "threat_model":
        print("  🗺  Building Daybreak-style threat model...\n")
        from nova_threat_model import NovaThreatModel
        tm = NovaThreatModel()
        scan_dir = target_path if os.path.isdir(target_path) else "."
        tm.build_from_directory(scan_dir)
        out = os.path.join(str(WORKSPACE), f"nova_threat_model_{ts}.json")
        tm.save(out)
        md_out = out.replace(".json", ".md")
        with open(md_out, "w") as f:
            f.write(tm.to_markdown())
        print(f"\n  📄 Markdown report → {md_out}")
        return 0

    elif mode == "sca":
        print("  📦 Running Software Composition Analysis...\n")
        from nova_sca_scanner import NovaSCAScanner
        scanner = NovaSCAScanner()
        scan_dir = target_path if os.path.isdir(target_path) else "."
        scanner.scan_directory(scan_dir)
        out = os.path.join(str(WORKSPACE), f"nova_sca_{ts}.json")
        scanner.save(out)
        return 0

    elif mode == "git_scan":
        print("  📜 Scanning git commit history...\n")
        from nova_git_scanner import NovaGitScanner
        scanner = NovaGitScanner()
        scan_dir = target_path if os.path.isdir(target_path) else "."
        scanner.scan_directory(scan_dir)
        out = os.path.join(str(WORKSPACE), f"nova_git_{ts}.json")
        scanner.save(out)
        return 0

    elif mode == "patch":
        print("  🔧 Generating patches for all confirmed findings...\n")
        import glob as _glob
        from nova_patch_generator import NovaPatchGenerator
        finding_files = (
            _glob.glob(os.path.join(str(WORKSPACE), "nova_*_report.json")) +
            _glob.glob(os.path.join(str(WORKSPACE), "nova_audit_*.json"))
        )
        all_findings = []
        for ff in finding_files:
            try:
                with open(ff) as f:
                    d = json.load(f)
                items = d if isinstance(d, list) else (d.get("findings") or d.get("all") or [])
                all_findings.extend(items)
            except Exception:
                pass
        if not all_findings:
            print("  ⚠️  No findings found in workspace. Run a scan first.")
            return 1
        gen = NovaPatchGenerator()
        patches = gen.generate_for_findings(all_findings)
        out = os.path.join(str(WORKSPACE), f"nova_patches_{ts}.json")
        gen.save(patches, out)
        return 0

    elif mode == "detect":
        print("  🛡  Generating SIEM detection rules...\n")
        import glob as _glob
        from nova_detection_engineer import NovaDetectionEngineer
        finding_files = _glob.glob(os.path.join(str(WORKSPACE), "nova_*_report.json"))
        all_findings = []
        for ff in finding_files:
            try:
                with open(ff) as f:
                    d = json.load(f)
                items = d if isinstance(d, list) else (d.get("findings") or d.get("all") or [])
                all_findings.extend(items[:5])
            except Exception:
                pass
        eng = NovaDetectionEngineer()
        eng.generate_rules(all_findings or [{"type": "sqli", "endpoint": "/", "param": "q"}])
        out = os.path.join(str(WORKSPACE), f"nova_detection_{ts}.json")
        eng.save(out)
        return 0

    elif mode == "audit_report":
        print("  📋 Generating enterprise audit report...\n")
        import glob as _glob
        from nova_audit_reporter import NovaAuditReporter
        finding_files = (
            _glob.glob(os.path.join(str(WORKSPACE), "nova_*_report.json")) +
            _glob.glob(os.path.join(str(WORKSPACE), "nova_sca_*.json")) +
            _glob.glob(os.path.join(str(WORKSPACE), "nova_git_*.json"))
        )
        org = os.getenv("NOVA_ORG_NAME", "Target Organization")
        reporter = NovaAuditReporter(org_name=org)
        reporter.load_from_files(*finding_files)
        json_out = os.path.join(str(WORKSPACE), f"nova_audit_{ts}.json")
        md_out   = os.path.join(str(WORKSPACE), f"nova_audit_{ts}.md")
        reporter.generate(json_out, md_out)
        return 0

    elif mode == "full_stack":
        print("  🚀 NOVA FULL-STACK PIPELINE — Mythos + Daybreak capabilities")
        print("  " + "=" * 62)
        scan_dir = target_path if os.path.isdir(target_path) else "."

        print("\n  [1/7] 📊 File Prioritization (Mythos 1-5 scoring)...")
        from nova_file_prioritizer import NovaFilePrioritizer
        prioritizer = NovaFilePrioritizer(verbose=True)
        prioritizer.prioritize_directory(scan_dir)
        prioritizer.save_ranking(os.path.join(str(WORKSPACE), f"nova_priority_{ts}.json"))

        print("\n  [2/7] 🗺  Threat Modeling (Daybreak-style)...")
        from nova_threat_model import NovaThreatModel
        tm = NovaThreatModel()
        tm.build_from_directory(scan_dir)
        tm.save(os.path.join(str(WORKSPACE), f"nova_threat_model_{ts}.json"))

        print("\n  [3/7] 🔍 Source Code Audit (multi-language, TypeScript-aware)...")
        from nova_source_auditor import NovaSourceAuditor
        auditor = NovaSourceAuditor()
        findings = auditor.scan_directory(scan_dir)
        findings = auditor.match_cves(findings)

        print("\n  [4/7] 📦 SCA — Dependency Vulnerability Scan...")
        from nova_sca_scanner import NovaSCAScanner
        sca = NovaSCAScanner()
        sca_findings = sca.scan_directory(scan_dir)
        sca.save(os.path.join(str(WORKSPACE), f"nova_sca_{ts}.json"))

        print("\n  [5/7] 📜 Git History Secret Scan...")
        from nova_git_scanner import NovaGitScanner
        git_scanner = NovaGitScanner()
        git_findings = git_scanner.scan_directory(scan_dir)
        git_scanner.save(os.path.join(str(WORKSPACE), f"nova_git_{ts}.json"))

        all_findings = findings + sca_findings + git_findings
        print(f"\n  [6/7] 🔧 Patch Generation ({len(all_findings)} total findings)...")
        from nova_patch_generator import NovaPatchGenerator
        patcher = NovaPatchGenerator()
        patches = patcher.generate_for_findings(all_findings[:30])
        patcher.save(patches, os.path.join(str(WORKSPACE), f"nova_patches_{ts}.json"))

        print("\n  [7/7] 🛡  Detection Rules + Enterprise Audit Report...")
        from nova_detection_engineer import NovaDetectionEngineer
        eng = NovaDetectionEngineer()
        eng.generate_rules(findings[:15])
        eng.save(os.path.join(str(WORKSPACE), f"nova_detection_{ts}.json"))

        from nova_audit_reporter import NovaAuditReporter
        reporter = NovaAuditReporter(org_name=os.getenv("NOVA_ORG_NAME", target))
        reporter.load_findings(all_findings)
        reporter.generate(
            os.path.join(str(WORKSPACE), f"nova_audit_{ts}.json"),
            os.path.join(str(WORKSPACE), f"nova_audit_{ts}.md"),
        )
        print(f"\n  ✅ FULL-STACK PIPELINE COMPLETE — all results in {WORKSPACE}")
        return 0

    else:
        print("  🦅 Launching agentic ReAct hunt...\n")
        return subprocess.call([
            py, "nova_agent_core.py",
            "--target", target,
            "--objective", objective,
            "--steps", str(steps),
        ])

# ── LOGGING ─────────────────────────────────────────────────────────────────────

def _log(task: str, plan: dict):
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    log_path = WORKSPACE / "nova_dispatch_log.json"
    try:
        existing = json.loads(log_path.read_text()) if log_path.exists() else []
    except Exception:
        existing = []
    existing.append({
        "ts": datetime.utcnow().isoformat(),
        "input": task,
        "plan": plan,
    })
    try:
        log_path.write_text(json.dumps(existing[-200:], indent=2))
    except Exception:
        pass

# ── MAIN ────────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    if len(sys.argv) > 1:
        task = " ".join(sys.argv[1:]).strip()
    else:
        print("  What should Nova do?\n")
        for ex in EXAMPLES:
            print(f"    • {ex}")
        print()
        try:
            task = input("  Nova> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Exiting.")
            sys.exit(0)

    if not task:
        print("  Usage: python3 nova.py \"Your instruction in plain English\"")
        sys.exit(1)

    plan = parse_instruction(task)
    _log(task, plan)
    exit_code = dispatch(plan)
    print(f"\n  ✅ Done. Exit code: {exit_code}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
