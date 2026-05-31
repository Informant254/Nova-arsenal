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

*Give Nova a target. Walk away. Come back to findings.*

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
4. [Quick Start](#4-quick-start)
5. [Capabilities](#5-capabilities)
   - [Agentic Mode — ReAct Loop](#51-agentic-mode--react-loop)
   - [Self-Improvement & Repo Intelligence ✦ New](#52-self-improvement--repo-intelligence)
   - [Swarm Mode](#53-swarm-mode)
   - [Attack Modules](#54-attack-modules)
   - [Intelligence Layer](#55-intelligence-layer)
   - [Reconnaissance](#56-reconnaissance)
   - [Code Analysis](#57-code-analysis)
   - [Memory & Learning](#58-memory--learning)
   - [Reporting & Deployment](#59-reporting--deployment)
6. [Module Reference](#6-module-reference)
7. [Configuration & Environment Variables](#7-configuration--environment-variables)
8. [Compared to Frontier Agents](#8-compared-to-frontier-agents)
9. [HackerOne Integration](#9-hackerone-integration)
10. [Extending Nova](#10-extending-nova)

---

## 1. What Nova Is

Nova is a **fully autonomous, locally-run AI security researcher**. She can:

- Plan and execute complete bug bounty hunts from a single command
- Use a **real Linux shell** and **headless Chromium browser** freely — the same way Claude Code and OpenAI Daybreak agents do
- Route each reasoning task to the **best available Ollama model** — never stuck on TinyLlama
- **Write and improve her own code** — reads her own run reports, identifies weaknesses, proposes patches, tests them
- Chain vulnerabilities together — SQLi → credential dump → JWT forge → admin access
- Learn from every hunt and get smarter over time via **NovaBrain persistent memory**
- Run 24/7 in continuous hunting mode

Built on **OWASP Juice Shop** as the practice target, with a real-world hunt engine for live bug bounty programs.

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           NOVA ARSENAL v3.0                                  │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                         ENTRY POINTS                                   │  │
│  │   nova_agent_core.py    nova_core.py    launch_swarm.py               │  │
│  │   (agentic / ReAct)     (pipeline)      (10-agent parallel)           │  │
│  └──────────────────────────────┬─────────────────────────────────────────┘  │
│                                  │                                             │
│  ┌───────────────────────────────▼────────────────────────────────────────┐  │
│  │                       INTELLIGENCE LAYER                                │  │
│  │                                                                          │  │
│  │  nova_model_router.py      ← Routes each task to best Ollama model     │  │
│  │  nova_reasoning_core.py    ← Unified LLM backbone (all modules)        │  │
│  │  nova_llm_bridge.py        ← NL mission planner + expert prompts       │  │
│  │  nova_chain_of_thought.py  ← Observe→Hypothesize→Probe→Conclude        │  │
│  │  nova_hypothesis_engine.py ← Bayesian hypothesis testing               │  │
│  │  nova_rag_builder.py       ← RAG from 100+ past hunts                  │  │
│  │  nova_adaptive_brain.py    ← Context-aware strategy adaptation         │  │
│  └───────────────────────────────┬────────────────────────────────────────┘  │
│                                   │                                            │
│  ┌────────────────────────────────▼───────────────────────────────────────┐  │
│  │                       AGENTIC EXECUTION LAYER                           │  │
│  │                                                                          │  │
│  │  ┌─────────────────────┐  ┌─────────────────────┐  ┌────────────────┐  │  │
│  │  │    TOOL KIT          │  │  SELF-IMPROVEMENT   │  │  REPO INTEL    │  │  │
│  │  │  bash_exec          │  │  nova_self_          │  │  nova_repo_    │  │  │
│  │  │  http_request       │  │  improvement.py      │  │  intelligence  │  │  │
│  │  │  browser_open/click │  │                      │  │  .py           │  │  │
│  │  │  browser_fill/eval  │  │  • collect signals   │  │                │  │  │
│  │  │  browser_source     │  │  • generate plan     │  │  • symbol idx  │  │  │
│  │  │  file_read/write    │  │  • patch & verify    │  │  • test idx    │  │  │
│  │  │  grep_code          │  │  • remember result   │  │  • stack detect│  │  │
│  │  │  install_tool       │  │                      │  │  • cmd suggest │  │  │
│  │  │  self_review        │  └─────────────────────┘  └────────────────┘  │  │
│  │  │  self_remember      │                                                  │  │
│  │  │  query_repo_index   │                                                  │  │
│  │  └─────────────────────┘                                                  │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                        ATTACK MODULES                                    │  │
│  │  SQLi  XSS  JWT  Race  Proto-Pollution  Deserialization  Session  SSRF  │  │
│  │  Path-Traversal  HTTP-Smuggling  IDOR  CORS  SSTI  XXE  Open-Redirect  │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                      MEMORY & LEARNING LAYER                             │  │
│  │  NovaBrain  FeedbackCortex  ExploitMemory  SelfImprovementMemory        │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### The ReAct Agentic Loop

```
  ┌─────────────────────────────────────────────────────────────────┐
  │   TASK + TOOLS + RAG CONTEXT injected into system prompt        │
  └──────────────────────────────┬──────────────────────────────────┘
                                  │
                                  ▼
  ╔═════════════════════════════════════════════════════════════════╗
  ║                     NOVA AGENT LOOP                            ║
  ║                                                                 ║
  ║  ┌──────────┐    ┌───────────┐    ┌─────────────────────────┐  ║
  ║  │ OBSERVE  │───▶│   THINK   │───▶│         ACT             │  ║
  ║  │          │    │           │    │                         │  ║
  ║  │ Tool     │    │ LLM picks │    │ bash_exec               │  ║
  ║  │ result   │    │ next tool │    │ http_request            │  ║
  ║  │ fed back │    │ freely    │    │ browser_open/click/fill │  ║
  ║  │ into ctx │    │           │    │ file_read / file_write  │  ║
  ║  └────▲─────┘    └───────────┘    │ grep_code               │  ║
  ║       │                           │ install_tool            │  ║
  ║       └───────────────────────────│ self_review ✦           │  ║
  ║                                   │ self_remember ✦         │  ║
  ║       Every REFLECT_EVERY steps:  │ query_repo_index ✦      │  ║
  ║       LLM reflects on progress,   └─────────────────────────┘  ║
  ║       logs to verification_log,                                 ║
  ║       and self-corrects strategy.                               ║
  ╚═════════════════════════════════════════════════════════════════╝
                                  │
                              (when done)
  ┌─────────────────────────────────────────────────────────────────┐
  │           mission_complete → JSON report + memory update        │
  └─────────────────────────────────────────────────────────────────┘
```

### 10-Agent Parallel Swarm

```
                 ┌──────────────────────────────────┐
                 │      SHARED KNOWLEDGE GRAPH       │
                 │  endpoints / tokens / paths        │
                 │  findings / exploit_queue          │
                 └──────────────────┬───────────────┘
                                    │ (concurrent read/write)
       ┌────────────────────────────┼────────────────────────────┐
       │                ┌───────────┴──────────┐                 │
  ┌────▼────┐      ┌────▼────┐          ┌──────▼───┐       ┌────▼────┐
  │  RECON  │      │ EXPLOIT │          │   AUTH   │       │  CODE   │
  └─────────┘      └─────────┘          └──────────┘       └─────────┘
  ┌─────────┐      ┌─────────┐          ┌──────────┐       ┌─────────┐
  │  RACE   │      │ CONFIG  │          │   XSS    │       │  IDOR   │
  └─────────┘      └─────────┘          └──────────┘       └─────────┘
  ┌─────────┐      ┌──────────────────────────────────────────────────┐
  │  EXFIL  │      │              VALIDATE (deduplicates all)         │
  └─────────┘      └──────────────────────────────────────────────────┘
```

---

## 3. Installation

### Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Core runtime |
| Ollama | Latest | Local LLM inference |
| Git | Any | Clone repo |
| 8–32 GB RAM | — | Model inference |
| Linux / macOS / WSL2 | — | Full tool support |

### Option A — One-Command Setup (Recommended)

```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
chmod +x nova_setup.sh && ./nova_setup.sh
```

The script handles everything: Ollama install, model pulls, Python venv, Playwright browser, system tools, and RAG build.

### Option B — Manual Step-by-Step

#### Step 1 — Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
```

#### Step 2 — Pull Models (in order of priority)

Nova routes each task to the best installed model automatically.

```bash
# Security-specialized brain (most important)
ollama pull xploiter/the-xploiter

# Chain-of-thought reasoning — pick size based on your VRAM
ollama pull deepseek-r1:32b    # 32 GB+ VRAM
ollama pull deepseek-r1:14b    # 16 GB  VRAM
ollama pull deepseek-r1:8b     #  8 GB  VRAM

# Best for code auditing and self-improvement
ollama pull devstral-small

# Fast lightweight checks
ollama pull qwen3:8b

# Best general purpose (optional — needs ~20 GB VRAM)
ollama pull qwen3:30b
```

Check what's routing where:
```bash
python3 nova_model_router.py
```

#### Step 3 — Python Dependencies

```bash
python3 -m venv ~/nova_workspace/.venv
source ~/nova_workspace/.venv/bin/activate
pip install -r requirements.txt
```

#### Step 4 — Playwright Browser

```bash
pip install playwright
python3 -m playwright install chromium
```

#### Step 5 — System Security Tools

```bash
# Debian/Ubuntu
sudo apt-get install -y nmap curl wget jq git

# Go-based recon tools (requires Go 1.21+)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

#### Step 6 — Build RAG Knowledge Base

```bash
python3 nova_rag_builder.py .
```

#### Step 7 — Verify

```bash
python3 nova_model_router.py     # routing table
python3 nova_repo_intelligence.py # repo index check
python3 -c "from nova_tool_kit import execute_tool; print(execute_tool('bash_exec',{'command':'echo OK'}))"
```

---

## 4. Quick Start

```bash
# Start OWASP Juice Shop (practice target)
docker run -d -p 3000:3000 bkimminich/juice-shop

source ~/nova_workspace/.venv/bin/activate

# ── Agentic Mode (LLM drives the entire hunt) ───────────────────
python3 nova_agent_core.py \
  --target http://localhost:3000 \
  --objective "Map the full attack surface, exploit all critical vulnerabilities, write a report" \
  --steps 40

# ── Pipeline Mode (structured 10-phase hunt) ────────────────────
python3 nova_core.py

# ── 10-Agent Parallel Swarm ─────────────────────────────────────
python3 launch_swarm.py

# ── Specific Modules ────────────────────────────────────────────
python3 nova_jwt_forge.py
python3 nova_proto_polluter.py
python3 nova_race_engine.py
python3 nova_daybreak.py

# ── Self-Improvement (Nova improves her own code) ───────────────
python3 nova_self_improvement.py

# ── Real Bug Bounty Target ──────────────────────────────────────
python3 nova_agent_core.py \
  --target https://target.com \
  --objective "Enumerate all API endpoints, find auth bypass and IDOR vulnerabilities"
```

---

## 5. Capabilities

### 5.1 Agentic Mode — ReAct Loop

**File:** `nova_agent_core.py`

The LLM decides every step of the hunt. No hardcoded pipeline.

```bash
python3 nova_agent_core.py --target http://localhost:3000 --steps 40
```

**Complete tool table** (what the LLM can freely call):

| Tool | Description |
|---|---|
| `bash_exec` | Run any shell command — nmap, sqlmap, nuclei, curl, custom scripts |
| `http_request` | Full HTTP control: method, headers, cookies, body, redirects |
| `browser_open` | Open URL in real headless Chromium — handles JavaScript SPAs |
| `browser_source` | Get full page HTML/JS source — find secrets, endpoints, hidden fields |
| `browser_click` | Click elements by CSS selector |
| `browser_fill` | Fill and submit forms |
| `browser_eval` | Execute JavaScript in the page — read cookies, localStorage, DOM |
| `file_read` | Read source code, configs, logs, past findings |
| `file_write` | Write findings, exploit scripts, reports to disk |
| `grep_code` | Search codebase for patterns — secrets, API keys, vulnerable sinks |
| `install_tool` | Install missing tools on demand (pip / apt / go) |
| `self_review` | **Read recent run reports and identify what went wrong** |
| `self_remember` | **Persist a lesson or outcome to long-term improvement memory** |
| `query_repo_index` | **Look up symbols, functions, and test commands in Nova's own codebase** |
| `mission_complete` | Signal completion with summary |

**Reflection loop:** Every `REFLECT_EVERY` steps (default: 5), the agent pauses, reflects on what it's learned so far, and logs its thinking to `verification_log`. This prevents drift and keeps long hunts on track.

**Permission profiles** control what tools the agent can use:

```bash
NOVA_PERMISSION_PROFILE=read_only   # bash + http blocked (safe for review tasks)
NOVA_PERMISSION_PROFILE=full        # all tools enabled (default hunt mode)
NOVA_PERMISSION_PROFILE=no_network  # http_request blocked (offline code analysis)
```

**Environment variables:**

```bash
NOVA_LLM_MODEL=deepseek-r1:14b   # force a specific model
NOVA_MAX_STEPS=50                 # max agent steps
NOVA_REFLECT_EVERY=5              # reflect every N steps
NOVA_HISTORY_LIMIT=30             # conversation history limit
NOVA_LLM_TIMEOUT=120              # LLM request timeout
NOVA_PERMISSION_PROFILE=full      # tool permission level
NOVA_LLM_URL=http://localhost:11434
NOVA_WORKSPACE=~/nova_workspace
```

---

### 5.2 Self-Improvement & Repo Intelligence

> **This is what closes the last gap between Nova and Claude Code.**
> Claude Code can read its own context, understand the codebase, and improve itself.
> Nova now can too — without any cloud calls.

#### `nova_self_improvement.py`

Nova reads her own run history, identifies failures, and generates a concrete improvement backlog — entirely locally.

```bash
# Run standalone to generate an improvement plan
python3 nova_self_improvement.py
```

**What it does:**

```
┌─────────────────────────────────────────────────────────────────┐
│                 NOVA SELF-IMPROVEMENT LOOP                      │
│                                                                  │
│  1. collect_run_signals()                                        │
│       └── reads recent agent_report_*.json from workspace       │
│       └── reads verification logs, reflections, open proposals  │
│       └── reads nova_self_improvement_memory.json               │
│                                                                  │
│  2. generate_improvement_plan()                                  │
│       └── sends signals to local Ollama (no cloud)              │
│       └── Ollama proposes 3-6 small, testable improvements      │
│       └── fallback heuristics if Ollama unavailable             │
│                                                                  │
│  3. Each proposal contains:                                      │
│       • id, title, rationale (evidence-based)                   │
│       • target_files: ["nova_agent_core.py"]                    │
│       • verification: ["python3 -m py_compile nova_*.py"]       │
│       • status: pending → done / rejected                       │
│                                                                  │
│  4. remember_outcome()                                           │
│       └── records what was tried and whether it worked          │
│       └── persists to nova_self_improvement_memory.json         │
└─────────────────────────────────────────────────────────────────┘
```

**As agent tools** (callable during a hunt):

```json
{"action": "self_review",   "args": {}}
{"action": "self_remember", "args": {"lesson": "JWT none bypass confirmed on /rest/user/whoami"}}
```

**Persistent files created:**
- `~/nova_workspace/nova_self_improvement_plan.json` — current improvement backlog
- `~/nova_workspace/nova_self_improvement_memory.json` — past lessons and outcomes

#### `nova_repo_intelligence.py`

Builds a lightweight symbol and test index of the entire Nova codebase — without any external APIs. Local Ollama models can navigate the repo with much less guessing.

```bash
python3 nova_repo_intelligence.py    # build index
```

**What it indexes:**

| Data | How |
|---|---|
| Function and class names | Python AST parser + regex fallback for JS/TS |
| Test files | Detected by path markers: `test/`, `spec/`, `cypress/`, `e2e/` |
| Tech stack | Manifest detection: `package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml` |
| Suggested test commands | Auto-extracted from `package.json` scripts and build tools |
| Import graph | Top-30 imports per file for dependency awareness |

**Callable as an agent tool:**

```json
{"action": "query_repo_index", "args": {"query": "where is JWT verification handled"}}
```

This lets Nova know — before she writes a patch — exactly which file and line number to edit, and which test command to run afterward.

**Built-in secret redaction:** All tool outputs are passed through `redact()` before being returned to the LLM — patterns like `api_key=`, `password=`, `token=` are replaced with `[REDACTED]` so secrets never appear in LLM context or logs.

---

### 5.3 Swarm Mode

#### 6-Agent Swarm (`nova_swarm_v3.py`)

```bash
python3 nova_swarm_v3.py
```

| Agent | Responsibility |
|---|---|
| Recon | Maps endpoints, extracts tokens, builds attack surface |
| Exploit | SQLi, XSS, SSRF, path traversal |
| Auth | JWT forgery, auth bypass, privilege escalation |
| Code | Source analysis, taint tracing (via `nova_code_reasoner_v2`) |
| Race | Race conditions, TOCTOU, coupon double-spend |
| Validate | Confirms every finding, removes false positives |

#### 10-Agent Parallel Swarm (`launch_swarm.py`)

```bash
python3 launch_swarm.py
```

Adds: Config, XSS-specialist, IDOR, Exfil, and Validate agents. All run in parallel threads sharing a concurrent knowledge graph with built-in deduplication.

---

### 5.4 Attack Modules

Each module runs standalone or as part of any swarm/pipeline.

| Module | Attack Type | Key Technique |
|---|---|---|
| `nova_exploit_synthesizer.py` | SQLi, XSS, SSRF, LFI | Union SELECT, stored XSS, SSRF to metadata |
| `nova_jwt_forge.py` | JWT attacks | `none` algo bypass, weak secret bruteforce, RS256→HS256 |
| `nova_race_engine.py` | Race conditions | ThreadPoolExecutor parallel requests, coupon double-spend |
| `nova_proto_polluter.py` | Prototype pollution | `__proto__`, `constructor.prototype`, gadget chains |
| `nova_deserialize_dropper.py` | Deserialization | Node.js `node-serialize` IIFE payloads for RCE |
| `nova_session_hijacker.py` | Session attacks | CSRF extraction, session fixation, cookie theft via XSS |
| `nova_url_smuggling.py` | HTTP smuggling | CL.TE + TE.CL variants, cache poisoning |
| `nova_fuzzer_fix.py` | Parameter fuzzing | Mutation-based, boundary values, type confusion |
| `nova_browser_agent.py` | Browser-based attacks | JS-aware auth bypass, challenge automation |

---

### 5.5 Intelligence Layer

#### Model Router — `nova_model_router.py`

Every task is routed to the best available Ollama model. No more TinyLlama for everything.

```
🔴 Security   → xploiter/the-xploiter  (attack chain expert)
🟠 Reasoning  → deepseek-r1:32b        (shows chain of thought)
🟡 Coding     → devstral-small         (code audit, patches, self-improvement)
🔵 Fast       → qwen3:8b               (parsing, quick checks)
⚪ General    → qwen3:30b              (planning, reporting)
```

Falls back through the tier automatically if a preferred model isn't installed.

#### Chain-of-Thought Engine — `nova_chain_of_thought.py`

```
OBSERVE → HYPOTHESIZE → PROBE → CONCLUDE → CHAIN
```

Maintains a `ReasoningChain` of `Thought` objects — each with a Bayesian confidence score, evidence list, and implications that trigger the next investigation.

#### Hypothesis Engine — `nova_hypothesis_engine.py`

Each hypothesis has prior confidence (0–1), a probe list, and updates via Bayes. Auto-confirms at ≥ 0.85, auto-dismisses at ≤ 0.10. The `priority` score = `confidence × severity_weight` for ranking.

#### RAG Knowledge Base — `nova_rag_builder.py`

Ingests all past hunt data into a queryable knowledge base. Before each attack phase, Nova retrieves the top-5 most relevant past findings — so she reasons from experience, not just training data.

Sources ingested: all `nova_h1_hunt_*.json`, submission folders, mission reports, `nova_verified_findings.json`, plus 10 built-in OWASP patterns.

#### Adaptive Brain — `nova_adaptive_brain.py`

Before attacking, profiles each endpoint — maps normal vs. error responses, extracts dynamic tokens, builds a context-specific attack strategy rather than blindly spraying payloads.

---

### 5.6 Reconnaissance

| Module | Capability |
|---|---|
| `nova_wild_hunt.py` | DNS subdomain brute-force, tech fingerprinting, port scanning, CVE mapping |
| `nova_scope_manager.py` | Live HackerOne scope sync with 1-hour cache, scope diff detection |
| `nova_github_scanner.py` | Scans commit history for accidentally committed secrets |
| `nova_active_ibb.py` | HackerOne Invite-Based Bug Bounty automated recon |
| `nova_0din_hunter.py` | 0din bug bounty platform targeting |

**Already mapped targets stored as `nova_h1_hunt_*.json`:**
`konghq.com` (50+ subdomains), `verily.com` (60+ subdomains), `notion.so`, `api.target.com`

---

### 5.7 Code Analysis

| Module | Capability |
|---|---|
| `nova_code_reasoner_v2.py` | Maps runtime stack traces to source lines, identifies dangerous sinks, taint-traces `req.body` → `.query()` |
| `nova_source_auditor.py` | Static analysis — hardcoded secrets, dangerous functions, dependency CVEs |
| `nova_dataflow_engine.py` | Full data-flow taint analysis from user input to sinks |
| `nova_repo_intelligence.py` | Symbol index, test file mapping, stack detection — for LLM navigation |

---

### 5.8 Memory & Learning

#### NovaBrain — `nova_memory_system.py`

Persists across every hunt, restart, and self-evolution:

- Technique success rates (scored, ranked over time)
- Payload hit counts per vulnerability type
- WAF bypass patterns that worked per WAF
- Technology fingerprints and their known weaknesses
- Hunt totals (critical/high counts, duration, targets)

#### Feedback Cortex — `nova_feedback_cortex.py`

After every exploit attempt: validates partial successes with pattern matching (e.g. `root:.*:0:0:` for path traversal confirmation), extracts credentials/tokens from successful responses, and updates graph brain confidence scores.

#### Self-Improvement Memory — `nova_self_improvement.py`

Separate from NovaBrain — tracks Nova's own code improvements:
- What patches were proposed
- Which were applied and verified
- What failed and why
- Lessons to carry forward

#### 24/7 Continuous Mode — `nova_continuous_v3.py`

```bash
python3 nova_continuous_v3.py
```

Runs indefinitely — hunts, learns, sleeps, hunts again. After each cycle updates NovaBrain, adjusts technique weights, generates incremental reports.

---

### 5.9 Reporting & Deployment

#### Daybreak 3-Stage Assessment — `nova_daybreak.py`

```
Stage 1 — AI Threat Prioritization
  LLM scores each target endpoint 0–10, assigns attack type and confidence.

Stage 2 — Scoped Sandbox Validation
  Tests only Stage 1 high-priority targets. Human checkpoint before critical escalation.
  HackerOne scope enforced at every step.

Stage 3 — Audit-Ready Evidence Package
  Full PoC, CVSS 3.1 score, CWE, reproduction steps, HackerOne submission JSON.
```

#### Report Generator — `nova_report.py`

Outputs three formats: **HTML** (color-coded severity), **Markdown** (H1-ready), **JSON** (machine-readable).

#### Agentic Deploy Evaluator — `nova_agentic_deploy.py`

Local Ollama-powered sandbox evaluation of agent payloads before deployment. Checks for excessive privilege requests, out-of-scope testing, data exfiltration attempts — no cloud calls.

---

## 6. Module Reference

| Module | Version | Category | Description |
|---|---|---|---|
| `nova_agent_core.py` | 1.0 | Agentic | ReAct loop — LLM drives the hunt |
| `nova_tool_kit.py` | 1.0 | Agentic | Tool execution engine (bash/browser/http/file/self) |
| `nova_repo_intelligence.py` | 1.0 | **Self-Improvement** | **Symbol+test index — LLM codebase navigation** |
| `nova_self_improvement.py` | 1.0 | **Self-Improvement** | **Run-signal collection, patch proposals, memory** |
| `nova_model_router.py` | 1.0 | Intelligence | Task-based Ollama model routing |
| `nova_reasoning_core.py` | 2.0 | Intelligence | Unified LLM backbone |
| `nova_llm_bridge.py` | 2.0 | Intelligence | NL mission planner + expert system prompts |
| `nova_rag_builder.py` | 1.0 | Intelligence | RAG knowledge base from past hunts |
| `nova_chain_of_thought.py` | 1.0 | Intelligence | Observe→Hypothesize→Probe→Conclude |
| `nova_hypothesis_engine.py` | 1.0 | Intelligence | Bayesian hypothesis testing |
| `nova_adaptive_brain.py` | 1.0 | Intelligence | Context-aware endpoint profiling |
| `nova_core.py` | 3.0 | Orchestration | 10-phase pipeline orchestrator |
| `nova_swarm_v3.py` | 3.0 | Orchestration | 6-agent swarm with shared knowledge graph |
| `nova_swarm_parallel.py` | 1.0 | Orchestration | 10-agent parallel swarm |
| `nova_exploit_synthesizer.py` | 1.0 | Attack | SQLi, XSS, SSRF, LFI, path traversal |
| `nova_jwt_forge.py` | 1.0 | Attack | JWT forgery — none algo, weak secret, key confusion |
| `nova_race_engine.py` | 1.0 | Attack | Race conditions, TOCTOU, double-spend |
| `nova_proto_polluter.py` | 1.0 | Attack | Prototype pollution → auth bypass / RCE |
| `nova_deserialize_dropper.py` | 1.0 | Attack | Node.js deserialization → RCE |
| `nova_session_hijacker.py` | 1.0 | Attack | Session fixation, CSRF, cookie theft |
| `nova_url_smuggling.py` | 1.0 | Attack | HTTP request smuggling |
| `nova_fuzzer_fix.py` | 1.0 | Attack | Parameter fuzzer |
| `nova_browser_agent.py` | 1.1 | Attack | Browser-based JS-aware attacks |
| `nova_code_reasoner_v2.py` | 2.0 | Code Analysis | Source code vulnerability analysis |
| `nova_source_auditor.py` | 1.0 | Code Analysis | Static analysis, hardcoded secrets |
| `nova_dataflow_engine.py` | 1.0 | Code Analysis | Taint tracing user input → sinks |
| `nova_memory_system.py` | 1.0 | Memory | NovaBrain — persistent cross-hunt learning |
| `nova_feedback_cortex.py` | 1.0 | Memory | Self-learning finding validation |
| `nova_wild_hunt.py` | 1.0 | Recon | Real-world subdomain + CVE recon |
| `nova_scope_manager.py` | 1.0 | Recon | HackerOne live scope sync |
| `nova_github_scanner.py` | 1.0 | Recon | GitHub secret + token scanner |
| `nova_daybreak.py` | 1.0 | Reporting | 3-stage Daybreak assessment |
| `nova_report.py` | 1.0 | Reporting | HTML/MD/JSON professional reports |
| `nova_agentic_deploy.py` | 1.0 | Reporting | Sandboxed payload evaluation |
| `nova_continuous_v3.py` | 3.0 | Reporting | 24/7 continuous hunting loop |

---

## 7. Configuration & Environment Variables

`nova_config.json` holds all defaults. Copy to `~/nova_workspace/nova_config.json` to override.

```json
{
  "llm": {
    "model":          "auto",
    "fallback_model": "llama3.2",
    "timeout":        120,
    "url":            "http://localhost:11434"
  },
  "attack": {
    "enabled_chains": ["sqli","xss","ssrf","cors","jwt","prototype_pollution","race_condition"],
    "severity_threshold": "low",
    "max_payloads_per_param": 50
  },
  "evolution": {
    "enabled": true,
    "require_tests": true,
    "backup_before": true
  }
}
```

**Full environment variable reference:**

| Variable | Default | Purpose |
|---|---|---|
| `NOVA_LLM_URL` | `http://localhost:11434` | Ollama base URL |
| `NOVA_LLM_MODEL` | `""` (auto-route) | Force a specific model |
| `NOVA_LLM_TIMEOUT` | `120` | LLM request timeout (seconds) |
| `NOVA_MAX_STEPS` | `30` | Max agentic loop steps |
| `NOVA_REFLECT_EVERY` | `5` | Reflection interval (steps) |
| `NOVA_HISTORY_LIMIT` | `30` | Max conversation history entries |
| `NOVA_PERMISSION_PROFILE` | `full` | Tool access level: `full` / `read_only` / `no_network` |
| `NOVA_WORKSPACE` | `~/nova_workspace` | Working directory for outputs |
| `NOVA_TOOL_TIMEOUT` | `60` | Max per-tool timeout (seconds) |

---

## 8. Compared to Frontier Agents

| Capability | Claude Mythos | OpenAI Daybreak | Nova v3.0 |
|---|---|---|---|
| **Cost per run** | $25–$125/MTok | ~$100–200/mo | **$0** |
| **Tool use** | ✅ Free tool calls | ✅ Free tool calls | ✅ Free tool calls |
| **Browser** | ✅ Real Chromium | ✅ Real browser | ✅ Playwright Chromium |
| **Shell access** | ✅ Full Linux | ✅ Full Linux | ✅ Full Linux |
| **LLM drives loop** | ✅ | ✅ | ✅ ReAct loop |
| **Reflection / self-correction** | ✅ | ✅ | ✅ Every N steps |
| **Model quality** | Opus-class | GPT-4o-class | Best Ollama per task |
| **Security-specialized model** | ❌ | ❌ | ✅ xploiter/the-xploiter |
| **Chain-of-thought** | ✅ | ✅ | ✅ DeepSeek-R1 |
| **Prior hunt knowledge (RAG)** | ❌ | ❌ | ✅ 100+ past hunts |
| **Reads own codebase** | ✅ | ✅ | ✅ nova_repo_intelligence |
| **Self-improvement** | ❌ | ❌ | ✅ nova_self_improvement |
| **Secret redaction in outputs** | ✅ | ✅ | ✅ Built into tool kit |
| **Permission profiles** | ✅ | ✅ | ✅ read_only / full / no_network |
| **Scope enforcement** | Manual | ✅ | ✅ H1 live scope sync |
| **Persistent memory** | ❌ session only | ❌ | ✅ NovaBrain |
| **Privacy** | ❌ sends to cloud | ❌ sends to cloud | ✅ 100% local |
| **24/7 hunting** | ❌ | Limited | ✅ Continuous mode |

---

## 9. HackerOne Integration

```bash
# Configure credentials
mkdir -p ~/.nova
cat > ~/.nova/scope_config.json << 'EOF'
{
  "h1_username": "your_h1_handle",
  "h1_api_token": "your_h1_api_token"
}
EOF

# Sync scope for all enrolled programs
python3 nova_scope_manager.py --sync

# Hunt within scope
python3 nova_agent_core.py \
  --target https://target.h1program.com \
  --objective "Find high-severity vulnerabilities within HackerOne scope"
```

Nova's scope manager enforces in-scope / out-of-scope rules at every step and syncs live from the H1 API with a 1-hour local cache.

---

## 10. Extending Nova

### Add a New Attack Module

1. Create `nova_myattack.py` with a class taking `base_url`, returning a findings list
2. Import it in `nova_core.py` and add a phase
3. Add it to the swarm in `nova_swarm_parallel.py` as an Agent subclass

### Add a New Tool to Agentic Mode

1. Add a schema entry to `TOOL_SCHEMAS` in `nova_tool_kit.py`
2. Write the executor function with the `exec_` prefix
3. Register it in the `execute_tool()` dispatcher
4. Add to `permission_denied()` if it needs access control

### Train Nova on New Findings

```bash
# After a successful hunt, rebuild RAG with new data
python3 nova_rag_builder.py . --force-rebuild
```

### Trigger a Self-Improvement Cycle

```bash
# Review last N runs and generate an improvement plan
python3 nova_self_improvement.py

# Inside a running agent hunt (tools available):
# {"action": "self_review",   "args": {}}
# {"action": "self_remember", "args": {"lesson": "..."}}
```

### Teach Nova a New WAF Bypass

```python
from nova_memory_system import NovaBrain
brain = NovaBrain()
brain.record_waf_bypass("cloudflare", payload="<ScRiPt>alert(1)</ScRiPt>")
brain.record_technique_result("sqli_unicode_bypass", success=True)
```

---

## Repository Map

```
Nova-arsenal/
│
├── ENTRY POINTS
│   ├── nova_agent_core.py           ← Agentic mode (LLM drives hunt)
│   ├── nova_core.py                 ← Pipeline mode (10 phases)
│   ├── launch_swarm.py              ← 10-agent parallel swarm
│   └── nova_setup.sh                ← One-command installation
│
├── SELF-IMPROVEMENT  ✦ new
│   ├── nova_self_improvement.py     ← Run-signal → patch proposals → memory
│   └── nova_repo_intelligence.py    ← Symbol/test index for LLM navigation
│
├── AGENTIC LAYER
│   └── nova_tool_kit.py             ← bash/browser/http/file/self tools + permission profiles
│
├── INTELLIGENCE
│   ├── nova_model_router.py         ← Task → best Ollama model
│   ├── nova_reasoning_core.py       ← Unified LLM backbone
│   ├── nova_llm_bridge.py           ← NL mission planner
│   ├── nova_rag_builder.py          ← Past-hunt knowledge base
│   ├── nova_chain_of_thought.py     ← Hypothesis engine
│   ├── nova_hypothesis_engine.py    ← Bayesian testing
│   └── nova_adaptive_brain.py       ← Context-aware strategy
│
├── ATTACK MODULES
│   ├── nova_exploit_synthesizer.py  ← SQLi, XSS, SSRF, LFI
│   ├── nova_jwt_forge.py            ← JWT attacks
│   ├── nova_race_engine.py          ← Race conditions
│   ├── nova_proto_polluter.py       ← Prototype pollution
│   ├── nova_deserialize_dropper.py  ← Deserialization RCE
│   ├── nova_session_hijacker.py     ← Session attacks
│   ├── nova_url_smuggling.py        ← HTTP smuggling
│   └── nova_fuzzer_fix.py           ← Parameter fuzzer
│
├── RECON
│   ├── nova_wild_hunt.py            ← Real-world recon engine
│   ├── nova_scope_manager.py        ← HackerOne scope sync
│   └── nova_github_scanner.py       ← Secret scanning
│
├── CODE ANALYSIS
│   ├── nova_code_reasoner_v2.py     ← Source vulnerability analysis
│   ├── nova_source_auditor.py       ← Static analysis
│   └── nova_dataflow_engine.py      ← Taint tracing
│
├── MEMORY
│   ├── nova_memory_system.py        ← NovaBrain persistence
│   └── nova_feedback_cortex.py      ← Self-learning validation
│
├── REPORTING
│   ├── nova_daybreak.py             ← 3-stage assessment pipeline
│   ├── nova_report.py               ← HTML/MD/JSON generator
│   ├── nova_agentic_deploy.py       ← Payload sandbox evaluator
│   └── nova_continuous_v3.py        ← 24/7 hunting loop
│
└── CONFIG
    ├── nova_config.json             ← Main configuration
    └── requirements.txt             ← Python dependencies
```

---

<div align="center">

**Nova is a research and educational tool.**  
Only hunt targets you have explicit written permission to test.  
Always respect program scope rules.

*Built for the solo researcher who cannot afford $125/MTok frontier agents.*

</div>
