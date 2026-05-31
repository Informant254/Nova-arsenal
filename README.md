<div align="center">

```
███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
████╗  ██║██╔═══██╗██║   ██║██╔══██╗
██╔██╗ ██║██║   ██║██║   ██║███████║
██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
         A R S E N A L
```

**Autonomous AI-Powered Bug Bounty & Security Research System**

*Tell Nova what you want. She figures out how. She does it herself.*

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-green)](https://ollama.com)
[![Playwright](https://img.shields.io/badge/Playwright-Chromium-orange)](https://playwright.dev)
[![Cost](https://img.shields.io/badge/LLM%20Cost-%240%2Frun-brightgreen)](#)
[![License](https://img.shields.io/badge/Use-Educational-red)](LICENSE)

</div>

---

## Table of Contents

1. [What Nova Is](#1-what-nova-is)
2. [Architecture Overview](#2-architecture-overview)
3. [Installation](#3-installation)
4. [Talking to Nova in Plain English](#4-talking-to-nova-in-plain-english)
5. [Capabilities](#5-capabilities)
   - [Natural Language Interface](#51-natural-language-interface-novapy)
   - [Agentic Mode — ReAct Loop](#52-agentic-mode--react-loop)
   - [Self-Improvement & Repo Intelligence](#53-self-improvement--repo-intelligence)
   - [24/7 Continuous Mode with Self-Evolution](#54-247-continuous-mode-with-self-evolution)
   - [Swarm Mode](#55-swarm-mode)
   - [Attack Modules](#56-attack-modules)
   - [Intelligence Layer](#57-intelligence-layer)
   - [Reconnaissance](#58-reconnaissance)
   - [Code Analysis](#59-code-analysis)
   - [Memory & Learning](#510-memory--learning)
   - [Reporting & Deployment](#511-reporting--deployment)
6. [Module Reference](#6-module-reference)
7. [Configuration & Environment Variables](#7-configuration--environment-variables)
8. [Compared to Frontier Agents](#8-compared-to-frontier-agents)
9. [HackerOne Integration](#9-hackerone-integration)
10. [Extending Nova](#10-extending-nova)

---

## 1. What Nova Is

Nova is a **fully autonomous, locally-run AI security researcher**. You talk to her in plain English. She decides what to do and does it — no configuration, no menus, no confirmation prompts.

```
You:  "Hunt hackerone.com for SQL injection and SSRF vulnerabilities"
Nova: parses intent → picks agentic hunt mode → launches ReAct loop →
      maps attack surface → finds and exploits vulns → writes report
```

She can:
- Parse any plain-English instruction and execute the right attack mode
- Drive a real **Linux shell** and **headless Chromium browser** autonomously
- Route each reasoning step to the **best available Ollama model** (never stuck on TinyLlama)
- **Read her own run history and improve her own code** — entirely locally
- Chain vulnerabilities together: SQLi → credential dump → JWT forge → admin access
- Get smarter after every hunt via **NovaBrain persistent memory**
- Run 24/7 in a continuous loop that self-improves between cycles

Everything runs **100% locally**. Zero cloud cost. Zero API keys for LLM.

---

## 2. Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                            NOVA ARSENAL v3.0                                   │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    NATURAL LANGUAGE ENTRY POINT                         │   │
│  │                       nova.py  ←  YOU ARE HERE                         │   │
│  │   "Hunt X"  "Improve yourself"  "Assess Y"  "Run swarm on Z"          │   │
│  │         │                                                               │   │
│  │   LLM intent parser → keyword fallback → dispatch to correct mode      │   │
│  └────────────────────────────┬────────────────────────────────────────────┘   │
│                                │                                                │
│      ┌─────────────────────────┼────────────────────────────────────┐          │
│      │                         │                                     │          │
│  ┌───▼──────────┐  ┌───────────▼────────┐  ┌──────────────────────▼───────┐   │
│  │ nova_agent_  │  │  nova_continuous_  │  │   launch_swarm.py            │   │
│  │ core.py      │  │  v3.py             │  │   (10-agent parallel)        │   │
│  │ (ReAct loop) │  │  (24/7 + self-     │  └──────────────────────────────┘   │
│  └──────────────┘  │   improvement)     │                                      │
│                     └────────────────────┘                                      │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                         INTELLIGENCE LAYER                               │  │
│  │  nova_model_router  nova_chain_of_thought  nova_hypothesis_engine       │  │
│  │  nova_rag_builder   nova_reasoning_core    nova_adaptive_brain          │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                         AGENTIC TOOL KIT                                 │  │
│  │  bash_exec  http_request  browser_*  file_*  grep_code  install_tool   │  │
│  │  self_review ✦  self_remember ✦  query_repo_index ✦                    │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  ┌────────────────────────────┐   ┌─────────────────────────────────────────┐  │
│  │   SELF-IMPROVEMENT ✦       │   │             MEMORY LAYER                │  │
│  │  nova_self_improvement.py  │   │  NovaBrain  FeedbackCortex              │  │
│  │  nova_repo_intelligence.py │   │  SelfImprovementMemory                  │  │
│  └────────────────────────────┘   └─────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────┘
```

### The ReAct Loop (inside nova_agent_core.py)

```
  System prompt: TASK + all tools + RAG context from past hunts
       │
       ▼
  ╔═══════════════════════════════════════════════════════════╗
  ║                   NOVA AGENT LOOP                        ║
  ║                                                           ║
  ║  OBSERVE ──▶ THINK ──▶ ACT ──▶ OBSERVE ──▶ ...          ║
  ║                │                                          ║
  ║                └─ LLM picks one tool per step:           ║
  ║                   bash_exec / http_request               ║
  ║                   browser_open / browser_eval            ║
  ║                   file_read / file_write                 ║
  ║                   grep_code / install_tool               ║
  ║                   self_review / self_remember ✦          ║
  ║                   query_repo_index ✦                     ║
  ║                                                           ║
  ║  Every REFLECT_EVERY steps: reflect + log to             ║
  ║  verification_log + self-correct strategy                ║
  ╚═══════════════════════════════════════════════════════════╝
       │
   mission_complete → JSON report + NovaBrain update
```

### 24/7 Continuous Loop with Self-Improvement

```
  ┌──────────────────────────────────────────────────────┐
  │              nova_continuous_v3.py                    │
  │                                                       │
  │  for each cycle:                                      │
  │    1. pick_target()  +  pick_technique()             │
  │    2. scan_target() — source→sink taint trace        │
  │    3. save_brain()  — persist findings               │
  │                                                       │
  │    every SELF_IMPROVE_EVERY cycles (default: 5):     │
  │    ┌─────────────────────────────────────────────┐   │
  │    │  collect_run_signals()                      │   │
  │    │    └── reads agent_report_*.json            │   │
  │    │    └── reads verification_log, reflections  │   │
  │    │  generate_improvement_plan()  [Ollama]      │   │
  │    │    └── 3-6 small testable proposals         │   │
  │    │    └── fallback if Ollama offline           │   │
  │    │  remember_outcome()                         │   │
  │    │    └── persists to self_improvement_memory  │   │
  │    └─────────────────────────────────────────────┘   │
  └──────────────────────────────────────────────────────┘
```

---

## 3. Installation

### One-Command Setup (Recommended)

```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
chmod +x nova_setup.sh && ./nova_setup.sh
```

Handles everything: Ollama, models, Python venv, Playwright, system tools, RAG build.

### Manual Setup

#### Models (pull in priority order)

```bash
ollama pull xploiter/the-xploiter  # security-specialized — most important
ollama pull deepseek-r1:14b        # chain-of-thought (8b if low VRAM)
ollama pull devstral-small         # best for code + self-improvement patches
ollama pull qwen3:8b               # fast NL parsing + light checks
```

#### Python

```bash
python3 -m venv ~/nova_workspace/.venv
source ~/nova_workspace/.venv/bin/activate
pip install -r requirements.txt
python3 -m playwright install chromium
```

#### Verify

```bash
python3 nova_model_router.py          # routing table
python3 nova_repo_intelligence.py     # repo index build
python3 nova.py "test"                # NL parse smoke test
```

---

## 4. Talking to Nova in Plain English

```bash
source ~/nova_workspace/.venv/bin/activate

# ── Hunt ────────────────────────────────────────────────────────
python3 nova.py "Hunt hackerone.com for SQL injection and SSRF vulnerabilities"
python3 nova.py "Find critical bugs on localhost:3000"
python3 nova.py "Test target.com for auth bypass and IDOR"
python3 nova.py "Look for JWT vulnerabilities on api.example.com"

# ── Swarm ────────────────────────────────────────────────────────
python3 nova.py "Run a full swarm on localhost:3000 — maximum power"
python3 nova.py "Deploy all agents against juice shop"

# ── Assess ───────────────────────────────────────────────────────
python3 nova.py "Assess notion.so using the Daybreak pipeline"
python3 nova.py "Full security assessment of api.target.com"
python3 nova.py "Pentest target.com"

# ── Recon ────────────────────────────────────────────────────────
python3 nova.py "Recon target.com — discover all subdomains and open ports"
python3 nova.py "Map the attack surface of example.com"
python3 nova.py "Enumerate subdomains for hackerone.com"

# ── Self-Improvement ─────────────────────────────────────────────
python3 nova.py "Improve yourself using my recent hunt results"
python3 nova.py "Evolve — read your run history and get better"
python3 nova.py "Update your code to fix recurring failures"

# ── Continuous ───────────────────────────────────────────────────
python3 nova.py "Run 24/7 continuous hunting"
python3 nova.py "Hunt non-stop across all targets"

# ── Code Review ──────────────────────────────────────────────────
python3 nova.py "Do a code review and find injection sinks"
python3 nova.py "Static analysis of the source for taint flows"

# ── Interactive mode (no argument) ───────────────────────────────
python3 nova.py
```

**How the NL parser works:**

```
Your text
    │
    ▼ (local Ollama — ~1 second)
JSON intent: { mode, target, objective, steps }
    │
    ▼ (if Ollama offline)
Keyword fallback: pattern matches on your text
    │
    ▼
Dispatch → correct module runs autonomously
```

Every dispatch is logged to `~/nova_workspace/nova_dispatch_log.json`.

---

## 5. Capabilities

### 5.1 Natural Language Interface — `nova.py`

**The main entry point.** One command, any wording.

```
Modes Nova understands:
  hunt         → nova_agent_core.py (ReAct agentic loop)
  swarm        → launch_swarm.py (10-agent parallel)
  assess       → nova_daybreak.py (3-stage pipeline)
  recon        → nova_wild_hunt.py (subdomain + port + tech)
  self_improve → nova_self_improvement.py
  continuous   → nova_continuous_v3.py (24/7 loop)
  code_review  → nova_code_reasoner_v2.py
  pipeline     → nova_core.py (10-phase structured)
```

The LLM parser uses `qwen3:8b` (or whatever fast model you have) with a strict JSON schema and zero temperature. If Ollama is not running, keyword matching handles all the same cases.

---

### 5.2 Agentic Mode — ReAct Loop

**File:** `nova_agent_core.py`

The LLM decides every single step. No hardcoded pipeline.

```bash
# Via nova.py (recommended)
python3 nova.py "Hunt localhost:3000 for all critical vulnerabilities"

# Direct
python3 nova_agent_core.py --target http://localhost:3000 --steps 40
```

**Full tool table:**

| Tool | What it does |
|---|---|
| `bash_exec` | Any shell command — nmap, sqlmap, nuclei, curl, custom scripts |
| `http_request` | Full HTTP: method, headers, cookies, body, redirects, auth |
| `browser_open` | Real headless Chromium — handles JavaScript SPAs |
| `browser_source` | Full page HTML/JS — find secrets, endpoints, hidden fields |
| `browser_click` | Click CSS-selector elements |
| `browser_fill` | Fill and submit forms |
| `browser_eval` | Execute JavaScript — read cookies, localStorage, DOM state |
| `file_read` | Read any file — source, configs, past findings |
| `file_write` | Write findings, exploit scripts, reports |
| `grep_code` | Search codebase — secrets, API keys, dangerous sinks |
| `install_tool` | Install missing packages on demand (pip/apt/go) |
| `self_review` | **Read recent run reports — what failed, what worked** |
| `self_remember` | **Persist a lesson to long-term improvement memory** |
| `query_repo_index` | **Look up functions/classes/tests in Nova's own codebase** |
| `mission_complete` | Signal completion with findings summary |

**Reflection loop:** Every `REFLECT_EVERY` steps (default: 5) the LLM pauses, logs its progress, and self-corrects strategy — preventing drift in long hunts.

**Permission profiles:**

| Profile | What's allowed |
|---|---|
| `full` | All tools — default hunt mode |
| `read_only` | No file writes, no shell, no installs — safe review |
| `no_network` | No HTTP requests — offline code analysis |

```bash
NOVA_PERMISSION_PROFILE=read_only python3 nova.py "Review recent findings"
```

**Secret redaction:** All tool outputs pass through `redact()` before the LLM sees them. Patterns like `api_key=`, `password=`, `token=` become `[REDACTED]`.

---

### 5.3 Self-Improvement & Repo Intelligence

> **Nova can read her own logs, understand her own codebase, and propose code patches — all without cloud calls.**

#### `nova_self_improvement.py`

```bash
# Via nova.py
python3 nova.py "Improve yourself"

# Direct
python3 nova_self_improvement.py
```

**Internal flow:**

```
1. collect_run_signals()
     Reads: agent_report_*.json (recent hunts)
            verification_log (what commands failed)
            reflections (what the agent thought)
            open proposals (unfinished improvements)
            persistent lessons (past memory)

2. generate_improvement_plan()  ← local Ollama only
     Sends compact signal summary to Ollama
     Gets back: 3-6 proposals, each with:
       • id, title, rationale (evidence-based)
       • target_files: ["nova_agent_core.py"]
       • verification: ["python3 -m py_compile nova_*.py"]
       • status: pending
     Falls back to heuristic proposals if Ollama offline

3. remember_outcome()
     Saves: what was tried, did it work, lessons learned
     File:  ~/nova_workspace/nova_self_improvement_memory.json
```

**Callable as agent tools during any hunt:**

```
{"action": "self_review",   "args": {}}
{"action": "self_remember", "args": {"lesson": "JWT none bypass works on /rest/user/whoami"}}
```

#### `nova_repo_intelligence.py`

Builds a symbol/test/command index so the LLM can navigate Nova's own codebase without guessing.

```bash
python3 nova_repo_intelligence.py    # build index
```

What it maps:
- Every function and class (Python AST + regex for JS/TS)
- Test files and test directories
- Tech stack from manifests (`package.json`, `pyproject.toml`, `go.mod`)
- Suggested test commands auto-extracted from scripts

Callable during hunts:
```
{"action": "query_repo_index", "args": {"query": "where is JWT verification handled"}}
```

---

### 5.4 24/7 Continuous Mode with Self-Evolution

**File:** `nova_continuous_v3.py`

```bash
# Via nova.py
python3 nova.py "Run 24/7 continuous hunting"

# Direct
python3 nova_continuous_v3.py 50     # 50 scan cycles
```

Every cycle: clones a target repo, picks a bug class, runs taint-flow analysis (source → sink without sanitizer = real bug). Zero false positives by design — only reports confirmed exploitable paths.

**Self-improvement runs automatically every 5 cycles:**

```
After cycle 5:   collect signals → Ollama proposes improvements → remember
After cycle 10:  collect signals → Ollama proposes improvements → remember
...
Final cycle:     forced improvement cycle before shutdown
```

Control the interval:
```bash
NOVA_SELF_IMPROVE_EVERY=3 python3 nova.py "Run continuous hunting"
```

Tracked in `nova_continuous_brain.json`:
- `total_real_bugs`, `critical_bugs`, `false_positives_filtered`
- `self_improve_cycles` — how many improvement cycles have run
- `last_improvement_plan` — proposals from most recent cycle

---

### 5.5 Swarm Mode

```bash
python3 nova.py "Run full swarm on localhost:3000 — maximum power"
```

**10-agent parallel swarm** — all agents share a concurrent knowledge graph:

| Agent | Focus |
|---|---|
| Recon | Maps endpoints, extracts tokens |
| Exploit | SQLi, XSS, SSRF, path traversal |
| Auth | JWT forgery, auth bypass, privilege escalation |
| Code | Source analysis, taint tracing |
| Race | Race conditions, TOCTOU, double-spend |
| Config | Misconfigurations, exposed admin, debug endpoints |
| XSS | Stored + reflected XSS specialist |
| IDOR | Insecure direct object reference |
| Exfil | Data extraction chains |
| Validate | Confirms every finding, removes false positives |

---

### 5.6 Attack Modules

| Module | Attack | Key Method |
|---|---|---|
| `nova_exploit_synthesizer.py` | SQLi, XSS, SSRF, LFI | Union SELECT, stored XSS, SSRF → metadata |
| `nova_jwt_forge.py` | JWT attacks | `none` algo, weak secret brute-force, RS256→HS256 |
| `nova_race_engine.py` | Race conditions | `ThreadPoolExecutor` parallel fire, coupon double-spend |
| `nova_proto_polluter.py` | Prototype pollution | `__proto__`, `constructor.prototype`, gadget chains |
| `nova_deserialize_dropper.py` | Deserialization | Node.js `node-serialize` IIFE → RCE |
| `nova_session_hijacker.py` | Session attacks | CSRF extraction, session fixation, cookie theft via XSS |
| `nova_url_smuggling.py` | HTTP smuggling | CL.TE + TE.CL, cache poisoning |
| `nova_fuzzer_fix.py` | Fuzzing | Mutation-based, boundary, type confusion |
| `nova_browser_agent.py` | Browser attacks | JS-aware auth bypass, challenge automation |

---

### 5.7 Intelligence Layer

| Module | Purpose |
|---|---|
| `nova_model_router.py` | Routes each task to best available Ollama model |
| `nova_chain_of_thought.py` | Observe→Hypothesize→Probe→Conclude with Bayesian confidence |
| `nova_hypothesis_engine.py` | Bayesian hypothesis testing — auto-confirms at ≥ 0.85 |
| `nova_rag_builder.py` | RAG from 100+ past hunts — augments every attack prompt |
| `nova_reasoning_core.py` | Unified LLM backbone (streaming, retry, model fallback) |
| `nova_adaptive_brain.py` | Profiles endpoints before attacking — maps normal behavior |

**Model routing:**
```
security reasoning  → xploiter/the-xploiter
chain-of-thought    → deepseek-r1:32b / 14b / 8b
code + patching     → devstral-small
NL parsing, fast    → qwen3:8b
general planning    → qwen3:30b
```

---

### 5.8 Reconnaissance

| Module | Capability |
|---|---|
| `nova_wild_hunt.py` | Subdomain brute-force, tech fingerprint, port scan, CVE mapping |
| `nova_scope_manager.py` | Live H1 scope sync (1hr cache), scope diff detection |
| `nova_github_scanner.py` | GitHub commit history secret scanning |
| `nova_active_ibb.py` | HackerOne invite-based program recon |
| `nova_0din_hunter.py` | 0din bug bounty platform targeting |

**Pre-mapped targets:** `konghq.com` (50+ subdomains), `verily.com` (60+), `notion.so`, `api.target.com`

---

### 5.9 Code Analysis

| Module | Capability |
|---|---|
| `nova_code_reasoner_v2.py` | Maps runtime stack traces to source, identifies dangerous sinks |
| `nova_source_auditor.py` | Static analysis — hardcoded secrets, dangerous functions, CVEs |
| `nova_dataflow_engine.py` | Full taint trace: `req.body` → `.query()` → confirmed sink |
| `nova_repo_intelligence.py` | Symbol index, test mapping, stack detection for LLM navigation |

---

### 5.10 Memory & Learning

**NovaBrain** (`nova_memory_system.py`) — persists across every hunt:
technique success rates, payload hit counts, WAF bypass patterns, tech fingerprint → weakness map.

**Feedback Cortex** (`nova_feedback_cortex.py`) — validates findings with regex patterns (`root:.*:0:0:` = real LFI), extracts tokens from successful responses, updates confidence scores.

**Self-Improvement Memory** (`nova_self_improvement.py`) — separate from NovaBrain, tracks Nova's own code evolution: what patches were proposed, applied, verified, rejected.

---

### 5.11 Reporting & Deployment

| Module | Output |
|---|---|
| `nova_daybreak.py` | 3-stage: AI threat priority → sandbox validate → HackerOne submission JSON |
| `nova_report.py` | HTML (color-coded severity), Markdown, JSON |
| `nova_agentic_deploy.py` | Sandboxed Ollama evaluation of agent payloads before deployment |
| `nova_continuous_v3.py` | 24/7 loop with auto-save to `nova_continuous_brain.json` |

---

## 6. Module Reference

| Module | Version | Category | Description |
|---|---|---|---|
| **`nova.py`** | **1.0** | **Entry Point** | **Natural language command interface** |
| `nova_agent_core.py` | 1.0 | Entry Point | ReAct agentic loop |
| `nova_core.py` | 3.0 | Entry Point | 10-phase pipeline |
| `launch_swarm.py` | 1.0 | Entry Point | 10-agent parallel swarm |
| `nova_continuous_v3.py` | 3.0 | Entry Point | 24/7 loop + self-improvement |
| `nova_setup.sh` | 1.0 | Entry Point | One-command installation |
| **`nova_self_improvement.py`** | **1.0** | **Self-Improvement** | **Run-signal collection → Ollama proposals → memory** |
| **`nova_repo_intelligence.py`** | **1.0** | **Self-Improvement** | **Symbol/test/command index for LLM navigation** |
| `nova_tool_kit.py` | 1.0 | Agentic | All tool executors + permission profiles + secret redaction |
| `nova_model_router.py` | 1.0 | Intelligence | Task → best Ollama model |
| `nova_reasoning_core.py` | 2.0 | Intelligence | Unified LLM backbone |
| `nova_llm_bridge.py` | 2.0 | Intelligence | NL mission planner |
| `nova_rag_builder.py` | 1.0 | Intelligence | RAG from past hunts |
| `nova_chain_of_thought.py` | 1.0 | Intelligence | Hypothesis chain engine |
| `nova_hypothesis_engine.py` | 1.0 | Intelligence | Bayesian testing |
| `nova_adaptive_brain.py` | 1.0 | Intelligence | Context-aware strategy |
| `nova_exploit_synthesizer.py` | 1.0 | Attack | SQLi, XSS, SSRF, LFI |
| `nova_jwt_forge.py` | 1.0 | Attack | JWT forgery |
| `nova_race_engine.py` | 1.0 | Attack | Race conditions |
| `nova_proto_polluter.py` | 1.0 | Attack | Prototype pollution |
| `nova_deserialize_dropper.py` | 1.0 | Attack | Deserialization RCE |
| `nova_session_hijacker.py` | 1.0 | Attack | Session attacks |
| `nova_url_smuggling.py` | 1.0 | Attack | HTTP smuggling |
| `nova_fuzzer_fix.py` | 1.0 | Attack | Fuzzer |
| `nova_browser_agent.py` | 1.1 | Attack | Browser-based attacks |
| `nova_code_reasoner_v2.py` | 2.0 | Code Analysis | Source vulnerability analysis |
| `nova_source_auditor.py` | 1.0 | Code Analysis | Static analysis |
| `nova_dataflow_engine.py` | 1.0 | Code Analysis | Taint tracing |
| `nova_memory_system.py` | 1.0 | Memory | NovaBrain persistence |
| `nova_feedback_cortex.py` | 1.0 | Memory | Self-learning validation |
| `nova_wild_hunt.py` | 1.0 | Recon | Real-world recon |
| `nova_scope_manager.py` | 1.0 | Recon | HackerOne scope sync |
| `nova_github_scanner.py` | 1.0 | Recon | Secret scanning |
| `nova_daybreak.py` | 1.0 | Reporting | 3-stage assessment |
| `nova_report.py` | 1.0 | Reporting | HTML/MD/JSON reports |
| `nova_agentic_deploy.py` | 1.0 | Reporting | Payload sandbox evaluation |

---

## 7. Configuration & Environment Variables

```json
// nova_config.json — copy to ~/nova_workspace/nova_config.json to override
{
  "llm": { "model": "auto", "fallback_model": "llama3.2", "timeout": 120 },
  "attack": { "severity_threshold": "low", "max_payloads_per_param": 50 },
  "evolution": { "enabled": true, "require_tests": true }
}
```

| Variable | Default | Purpose |
|---|---|---|
| `NOVA_LLM_URL` | `http://localhost:11434` | Ollama base URL |
| `NOVA_LLM_MODEL` | `""` (auto-route) | Force a specific model |
| `NOVA_LLM_TIMEOUT` | `120` | LLM timeout (seconds) |
| `NOVA_MAX_STEPS` | `30` | Max agentic loop steps |
| `NOVA_REFLECT_EVERY` | `5` | Reflection interval |
| `NOVA_HISTORY_LIMIT` | `30` | Max conversation history |
| `NOVA_PERMISSION_PROFILE` | `full` | `full` / `read_only` / `no_network` |
| `NOVA_WORKSPACE` | `~/nova_workspace` | Output directory |
| `NOVA_TOOL_TIMEOUT` | `60` | Per-tool max timeout |
| `NOVA_SELF_IMPROVE_EVERY` | `5` | Continuous mode: cycles between improvements |

---

## 8. Compared to Frontier Agents

| Capability | Claude Mythos | OpenAI Daybreak | **Nova v3.0** |
|---|---|---|---|
| **Cost per run** | $25–$125/MTok | ~$100–200/mo | **$0** |
| **Plain English commands** | ✅ | ✅ | ✅ `nova.py` |
| **Tool use** | ✅ | ✅ | ✅ 14 tools |
| **Browser** | ✅ Chromium | ✅ | ✅ Playwright |
| **Shell access** | ✅ | ✅ | ✅ |
| **LLM drives loop** | ✅ | ✅ | ✅ ReAct |
| **Reflection / self-correction** | ✅ | ✅ | ✅ Every N steps |
| **Security-specialized model** | ❌ | ❌ | ✅ xploiter |
| **Chain-of-thought** | ✅ | ✅ | ✅ DeepSeek-R1 |
| **Prior hunt knowledge (RAG)** | ❌ | ❌ | ✅ 100+ hunts |
| **Reads own codebase** | ✅ | ✅ | ✅ repo_intelligence |
| **Self-improvement** | ❌ | ❌ | ✅ self_improvement |
| **Auto self-improves in background** | ❌ | ❌ | ✅ continuous v3 |
| **Secret redaction in outputs** | ✅ | ✅ | ✅ |
| **Permission profiles** | ✅ | ✅ | ✅ |
| **H1 scope enforcement** | Manual | ✅ | ✅ live sync |
| **Persistent memory** | ❌ session | ❌ | ✅ NovaBrain |
| **Privacy** | ❌ cloud | ❌ cloud | ✅ 100% local |
| **24/7 autonomous** | ❌ | Limited | ✅ |

---

## 9. HackerOne Integration

```bash
mkdir -p ~/.nova
cat > ~/.nova/scope_config.json << 'EOF'
{ "h1_username": "your_handle", "h1_api_token": "your_h1_api_token" }
EOF

python3 nova_scope_manager.py --sync

# Then Nova auto-enforces scope in every hunt
python3 nova.py "Hunt my H1 program targets for high-severity vulnerabilities"
```

---

## 10. Extending Nova

### Add a new hunt mode

1. Create `nova_mymode.py`
2. Add it to `nova.py` `MODES` dict and `dispatch()` function
3. Add keywords to `MODE_KEYWORDS`

### Add a new agent tool

1. Add schema to `TOOL_SCHEMAS` in `nova_tool_kit.py`
2. Write `exec_mytool()` function
3. Register in `execute_tool()` dispatcher
4. Add to `WRITE_TOOLS` / `SHELL_TOOLS` if needed for permission control

### Teach Nova a new bypass

```python
from nova_memory_system import NovaBrain
brain = NovaBrain()
brain.record_waf_bypass("cloudflare", payload="<ScRiPt>alert(1)</ScRiPt>")
brain.record_technique_result("sqli_unicode_bypass", success=True)
```

### Trigger manual self-improvement

```bash
python3 nova.py "Improve yourself"
# or direct:
python3 nova_self_improvement.py
```

---

## Repository Map

```
Nova-arsenal/
│
├── nova.py                      ← ★ START HERE — plain English interface
│
├── ENTRY POINTS
│   ├── nova_agent_core.py       ← Agentic ReAct loop
│   ├── nova_core.py             ← 10-phase pipeline
│   ├── launch_swarm.py          ← 10-agent parallel swarm
│   ├── nova_continuous_v3.py    ← 24/7 hunting + auto self-improvement
│   └── nova_setup.sh            ← One-command installation
│
├── SELF-IMPROVEMENT
│   ├── nova_self_improvement.py ← Run signals → Ollama proposals → memory
│   └── nova_repo_intelligence.py← Symbol/test index for LLM codebase nav
│
├── AGENTIC TOOL KIT
│   └── nova_tool_kit.py         ← All 14 tools + permissions + redaction
│
├── INTELLIGENCE
│   ├── nova_model_router.py
│   ├── nova_reasoning_core.py
│   ├── nova_llm_bridge.py
│   ├── nova_rag_builder.py
│   ├── nova_chain_of_thought.py
│   ├── nova_hypothesis_engine.py
│   └── nova_adaptive_brain.py
│
├── ATTACK MODULES
│   ├── nova_exploit_synthesizer.py
│   ├── nova_jwt_forge.py
│   ├── nova_race_engine.py
│   ├── nova_proto_polluter.py
│   ├── nova_deserialize_dropper.py
│   ├── nova_session_hijacker.py
│   ├── nova_url_smuggling.py
│   └── nova_fuzzer_fix.py
│
├── RECON
│   ├── nova_wild_hunt.py
│   ├── nova_scope_manager.py
│   └── nova_github_scanner.py
│
├── CODE ANALYSIS
│   ├── nova_code_reasoner_v2.py
│   ├── nova_source_auditor.py
│   └── nova_dataflow_engine.py
│
├── MEMORY
│   ├── nova_memory_system.py
│   └── nova_feedback_cortex.py
│
├── REPORTING
│   ├── nova_daybreak.py
│   ├── nova_report.py
│   └── nova_agentic_deploy.py
│
└── CONFIG
    ├── nova_config.json
    └── requirements.txt
```

---

<div align="center">

**Nova is a research and educational tool.**  
Only test targets you have explicit written permission to assess.  
Always respect program scope rules.

*Built for the solo researcher who cannot afford frontier agent API costs.*

</div>
