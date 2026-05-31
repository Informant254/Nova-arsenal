#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🦅 NOVA — NATURAL LANGUAGE COMMAND INTERFACE v1.0                ║
║                                                                      ║
║   Tell Nova what to do in plain English.                            ║
║   She parses your intent and executes at full power.                ║
║                                                                      ║
║   Usage:                                                             ║
║     python3 nova.py "Hunt hackerone.com for SQL injection"          ║
║     python3 nova.py "Run a full swarm on localhost:3000"            ║
║     python3 nova.py "Assess notion.so with Daybreak"                ║
║     python3 nova.py "Improve yourself using recent run results"     ║
║     python3 nova.py "Recon target.com — subdomains and ports"       ║
║     python3 nova.py "Run 24/7 continuous hunting"                   ║
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

# Model preference order — fastest that can parse intent reliably
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
  ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝  A R S E N A L

  Natural Language → Full Autonomous Execution
  ─────────────────────────────────────────────
"""

EXAMPLES = [
    "Hunt hackerone.com for SQL injection and SSRF vulnerabilities",
    "Run a full swarm on localhost:3000 — maximum power",
    "Assess notion.so using the Daybreak 3-stage pipeline",
    "Recon target.com — discover all subdomains and open ports",
    "Improve yourself using my recent hunt results",
    "Run 24/7 continuous hunting on open bug bounty targets",
    "Do a code review audit of the source code for injection sinks",
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
        "full assessment", "threat priority", "audit", "pentest", "penetration test",
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
}

# ── KEYWORD PARSER (offline fallback) ──────────────────────────────────────────

def _extract_target(text: str) -> Optional[str]:
    """Extract URL or domain from free text."""
    patterns = [
        r'https?://[^\s\'"]+',
        r'\b(?:[\w-]+\.)+(?:com|io|org|net|gov|edu|co|app|dev|sh|ai|gg|me|us|uk)[^\s\'"]*',
    ]
    for p in patterns:
        m = re.search(p, text)
        if m:
            t = m.group(0).rstrip('.,;')
            return t if t.startswith("http") else "https://" + t
    return None

def _keyword_parse(task: str) -> dict:
    """Offline keyword-based intent parser."""
    t = task.lower()
    mode = "hunt"
    for m, keywords in MODE_KEYWORDS.items():
        if any(kw in t for kw in keywords):
            mode = m
            break
    target = _extract_target(task)
    if not target and mode not in ("self_improve", "continuous"):
        target = "http://localhost:3000"
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
  "mode": "hunt|swarm|assess|recon|self_improve|continuous|code_review|pipeline",
  "target": "URL or domain (null if not applicable)",
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

Examples:
"Hunt hackerone.com for SQL injection"
→ {"mode":"hunt","target":"https://hackerone.com","objective":"Find SQL injection vulnerabilities on hackerone.com","steps":40}

"Improve yourself"
→ {"mode":"self_improve","target":null,"objective":"Collect recent run signals and generate code improvement proposals","steps":0}

"Full swarm on localhost"
→ {"mode":"swarm","target":"http://localhost:3000","objective":"Deploy full 10-agent swarm","steps":0}
"""

def _llm_parse(task: str) -> Optional[dict]:
    """Use local Ollama to parse natural language instruction."""
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
                # Ensure target has scheme
                if parsed.get("target") and not parsed["target"].startswith("http"):
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
    target    = plan.get("target") or "http://localhost:3000"
    objective = plan.get("objective") or "Find and exploit all critical vulnerabilities"
    steps     = int(plan.get("steps") or 40)
    py        = sys.executable

    _sep()
    print(f"  🚀  MODE       {mode.upper()}")
    if target:  print(f"  🎯  TARGET     {target}")
    print(f"  📋  OBJECTIVE  {objective[:90]}")
    if steps:   print(f"  ⚙️   STEPS      {steps}")
    print(f"  🔌  TOOLS      {len([l for l in ['bash','browser','http','file','grep','install','self_review','self_remember','repo_index'] if True])} available")
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
        print("  🔎 Launching source code analysis...\n")
        env = {**os.environ, "NOVA_TARGET": target}
        return subprocess.call([py, "nova_code_reasoner_v2.py"], env=env)

    elif mode == "pipeline":
        print("  🔩 Launching 10-phase pipeline...\n")
        env = {**os.environ, "NOVA_TARGET": target}
        return subprocess.call([py, "nova_core.py"], env=env)

    else:  # hunt — default
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
