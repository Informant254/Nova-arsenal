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
[![License](https://img.shields.io/badge/License-Educational-red)](LICENSE)
[![Cost](https://img.shields.io/badge/LLM%20Cost-%240%2Frun-brightgreen)](#)

</div>

---

## Table of Contents

1. [What Nova Is](#1-what-nova-is)
2. [Architecture Overview](#2-architecture-overview)
3. [Installation](#3-installation)
4. [Quick Start](#4-quick-start)
5. [Capabilities](#5-capabilities)
   - [Agentic Mode (New)](#51-agentic-mode--react-loop)
   - [Swarm Mode](#52-swarm-mode)
   - [Attack Modules](#53-attack-modules)
   - [Intelligence Layer](#54-intelligence-layer)
   - [Reconnaissance](#55-reconnaissance)
   - [Code Analysis](#56-code-analysis)
   - [Memory & Learning](#57-memory--learning)
   - [Reporting & Deployment](#58-reporting--deployment)
6. [Module Reference](#6-module-reference)
7. [Configuration](#7-configuration)
8. [Compared to Frontier Agents](#8-compared-to-frontier-agents)
9. [HackerOne Integration](#9-hackerone-integration)
10. [Extending Nova](#10-extending-nova)

---

## 1. What Nova Is

Nova is a **fully autonomous, locally-run AI security researcher**. She can:

- Plan and execute complete bug bounty hunts from a single command
- Use a **real Linux shell** and **headless Chromium browser** freely — the same way Claude Code and OpenAI Daybreak agents do
- Reason with a local Ollama model (zero cloud cost, zero API keys)
- Chain vulnerabilities together — SQLi → credential dump → JWT forge → admin access
- Learn from every hunt and get smarter over time
- Run 24/7 and alert you when she finds something critical

Built on **OWASP Juice Shop** as the practice target, with a real-world hunt engine for live bug bounty programs.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NOVA ARSENAL v3.0                               │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    ENTRY POINTS                                  │   │
│  │  nova_core.py   nova_agent_core.py   launch_swarm.py           │   │
│  │  (pipeline)     (agentic/ReAct)      (10-agent parallel)        │   │
│  └────────────────────────┬────────────────────────────────────────┘   │
│                            │                                             │
│  ┌─────────────────────────▼────────────────────────────────────────┐  │
│  │                  INTELLIGENCE LAYER                               │  │
│  │                                                                    │  │
│  │  nova_model_router.py     ← Routes each task to best Ollama model│  │
│  │  nova_reasoning_core.py   ← Unified LLM backbone (all modules)  │  │
│  │  nova_llm_bridge.py       ← Mission planner + NL interface       │  │
│  │  nova_chain_of_thought.py ← Observe→Hypothesize→Probe→Conclude  │  │
│  │  nova_hypothesis_engine.py← Bayesian hypothesis testing          │  │
│  │  nova_rag_builder.py      ← RAG from 100+ past hunts             │  │
│  │  nova_adaptive_brain.py   ← Context-aware strategy adaptation    │  │
│  └─────────────────────────┬────────────────────────────────────────┘  │
│                             │                                            │
│  ┌──────────────────────────▼───────────────────────────────────────┐  │
│  │                    EXECUTION LAYER                                │  │
│  │                                                                    │  │
│  │  ┌───────────────┐   ┌─────────────────┐   ┌──────────────────┐  │  │
│  │  │  TOOL KIT      │   │  ATTACK MODULES  │   │  RECON ENGINE    │  │  │
│  │  │  bash_exec    │   │  SQLi / XSS      │   │  subdomains      │  │  │
│  │  │  http_request │   │  JWT Forge       │   │  URL discovery   │  │  │
│  │  │  browser_*    │   │  Race Engine     │   │  tech fingerprint│  │  │
│  │  │  file_*       │   │  Proto Polluter  │   │  port scan       │  │  │
│  │  │  grep_code    │   │  Deserialization │   │  JS analysis     │  │  │
│  │  │  install_tool │   │  Session Hijack  │   │  source map hunt │  │  │
│  │  └───────────────┘   └─────────────────┘   └──────────────────┘  │  │
│  └──────────────────────────┬───────────────────────────────────────┘  │
│                              │                                           │
│  ┌───────────────────────────▼──────────────────────────────────────┐  │
│  │                   MEMORY & LEARNING LAYER                         │  │
│  │                                                                    │  │
│  │  nova_memory_system.py   ← NovaBrain — persists across hunts     │  │
│  │  nova_feedback_cortex.py ← Validates findings, updates scores    │  │
│  │  nova_exploit_memory.json← What worked, what didn't              │  │
│  │  nova_brain_memory.json  ← Technique scores, payload scores      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### The ReAct Agentic Loop (nova_agent_core.py)

```
  ┌──────────────────────────────────────────────────────────┐
  │  TASK + TOOLS + RAG CONTEXT injected into system prompt  │
  └──────────────────────┬───────────────────────────────────┘
                         │
                         ▼
  ╔══════════════════════════════════════════════════════════╗
  ║                  NOVA AGENT LOOP                        ║
  ║                                                          ║
  ║  ┌─────────┐    ┌──────────┐    ┌──────────────────┐   ║
  ║  │ OBSERVE │───▶│  THINK   │───▶│    ACT           │   ║
  ║  │         │    │          │    │                  │   ║
  ║  │ Results │    │ LLM picks│    │ bash_exec        │   ║
  ║  │ fed back│    │ next tool│    │ http_request     │   ║
  ║  │ into ctx│    │ freely   │    │ browser_open     │   ║
  ║  └────▲────┘    └──────────┘    │ file_read/write  │   ║
  ║       │                         │ grep_code        │   ║
  ║       └─────────────────────────│ install_tool     │   ║
  ║                                 └──────────────────┘   ║
  ╚══════════════════════════════════════════════════════════╝
                         │
                         ▼ (when done)
  ┌──────────────────────────────────────────────────────────┐
  │              mission_complete → JSON report              │
  └──────────────────────────────────────────────────────────┘
```

### 10-Agent Parallel Swarm

```
                    ┌────────────────────────────┐
                    │   SHARED KNOWLEDGE GRAPH   │
                    │  endpoints / tokens / paths │
                    │  findings / exploit_queue   │
                    └─────────────┬──────────────┘
                                  │ (read/write)
          ┌───────────────────────┼───────────────────────┐
          │           ┌───────────┴──────────┐            │
          │           │                      │            │
     ┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌──▼──────┐ ┌──▼──────┐
     │  RECON  │ │ EXPLOIT │ │  AUTH   │ │  CODE   │ │  RACE   │
     │ Agent   │ │ Agent   │ │ Agent   │ │ Agent   │ │ Agent   │
     └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
     ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
     │ CONFIG  │ │   XSS   │ │  IDOR   │ │ EXFIL   │ │VALIDATE │
     │ Agent   │ │ Agent   │ │ Agent   │ │ Agent   │ │ Agent   │
     └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
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
# 1. Clone
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal

# 2. Run setup (handles everything below automatically)
chmod +x nova_setup.sh
./nova_setup.sh
```

The setup script will:
- Install Ollama if missing and start the server
- Auto-detect your VRAM and pull the right model sizes
- Create a Python virtual environment with all dependencies
- Install Playwright + headless Chromium browser
- Install system security tools (nmap, nuclei, subfinder, httpx)
- Build Nova's RAG knowledge base from all past hunt data
- Verify every component is wired correctly

### Option B — Manual Step-by-Step

#### Step 1 — Install Ollama

```bash
# Linux / macOS
curl -fsSL https://ollama.com/install.sh | sh

# Start the server
ollama serve &
```

#### Step 2 — Pull Models

Nova routes each task to the best available model. Pull in order of importance:

```bash
# Most important — security-specialized brain
ollama pull xploiter/the-xploiter

# Best chain-of-thought reasoning (pick one based on your VRAM)
ollama pull deepseek-r1:32b    # 32 GB+ VRAM
ollama pull deepseek-r1:14b    # 16 GB VRAM
ollama pull deepseek-r1:8b     # 8 GB VRAM

# Best for code auditing and payload generation
ollama pull devstral-small

# Fast lightweight checks
ollama pull qwen3:8b

# Best general purpose (optional, needs ~20 GB VRAM)
ollama pull qwen3:30b
```

Verify models are loaded:
```bash
ollama list
python3 nova_model_router.py    # Shows routing table
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
sudo apt-get update && sudo apt-get install -y nmap curl wget jq git

# Go-based tools (requires Go 1.21+)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

#### Step 6 — Build RAG Knowledge Base

```bash
# Ingest all past hunt data into Nova's knowledge base
python3 nova_rag_builder.py .
```

#### Step 7 — Verify Installation

```bash
# Check model routing
python3 nova_model_router.py

# Quick smoke test
python3 - <<'EOF'
from nova_tool_kit import bash_exec, http_request
print(bash_exec("echo 'Tool kit OK'")["stdout"])
print("Ollama:", __import__("requests").get("http://localhost:11434/api/tags", timeout=3).status_code)
EOF
```

---

## 4. Quick Start

### Start OWASP Juice Shop (Practice Target)

```bash
# Docker (recommended)
docker run -d -p 3000:3000 bkimminich/juice-shop

# Or from this repo (Node.js 24 required)
npm install && npm start
```

### Run Nova

```bash
source ~/nova_workspace/.venv/bin/activate

# ── MODE 1: True Agentic Hunt (recommended) ─────────────────────
# The LLM drives the entire hunt, calling tools freely
python3 nova_agent_core.py \
  --target http://localhost:3000 \
  --objective "Map the full attack surface, exploit all critical vulnerabilities, write a report" \
  --steps 40

# ── MODE 2: Pipeline Mode (structured 10-phase hunt) ────────────
python3 nova_core.py

# ── MODE 3: 10-Agent Parallel Swarm ─────────────────────────────
python3 launch_swarm.py

# ── MODE 4: Specific Module ─────────────────────────────────────
python3 nova_jwt_forge.py             # JWT-specific hunt
python3 nova_proto_polluter.py        # Prototype pollution
python3 nova_race_engine.py           # Race conditions
python3 nova_daybreak.py              # 3-stage Daybreak assessment

# ── REAL TARGET (Bug Bounty) ────────────────────────────────────
python3 nova_agent_core.py \
  --target https://target.com \
  --objective "Enumerate all API endpoints, find auth bypass and IDOR vulnerabilities" \
  --steps 60

python3 nova_wild_hunt.py --target target.com
```

---

## 5. Capabilities

### 5.1 Agentic Mode — ReAct Loop

**File:** `nova_agent_core.py`

The core architectural upgrade. Instead of a hardcoded pipeline, the LLM decides every step.

```bash
python3 nova_agent_core.py --target http://localhost:3000 --steps 40
```

**How it works:**
1. LLM receives the task, full tool list, and RAG context from past hunts
2. LLM outputs: `{"thought": "...", "action": "tool_name", "args": {...}}`
3. Nova executes the tool and feeds the result back
4. Repeat until `mission_complete` or max steps

**Available tools the LLM can call freely:**

| Tool | Description |
|---|---|
| `bash_exec` | Run any shell command — nmap, sqlmap, nuclei, curl, scripts |
| `http_request` | Full HTTP control: method, headers, cookies, body, redirects |
| `browser_open` | Open URL in real headless Chromium (handles SPAs and JavaScript) |
| `browser_source` | Get full page HTML/JS source — find secrets, endpoints, hidden fields |
| `browser_click` | Click page elements by CSS selector |
| `browser_fill` | Fill forms in the browser |
| `browser_eval` | Execute JavaScript in the browser — read cookies, localStorage |
| `file_read` | Read source code, configs, logs, past findings |
| `file_write` | Write findings, exploit scripts, reports |
| `grep_code` | Search codebase for patterns — secrets, API keys, vulnerable code |
| `install_tool` | Install missing tools on demand (pip/apt/go) |
| `mission_complete` | Signal completion with summary |

**Environment variables:**

```bash
export NOVA_LLM_MODEL=deepseek-r1:14b    # Force specific model
export NOVA_MAX_STEPS=50                  # Max agent steps
export NOVA_LLM_TIMEOUT=120               # LLM request timeout
export NOVA_LLM_URL=http://localhost:11434
```

---

### 5.2 Swarm Mode

Nova can deploy multiple independent agents that share a knowledge graph.

#### 6-Agent Swarm (nova_swarm_v3.py)

```bash
python3 nova_swarm_v3.py
```

```
Agent 1: Recon        → Maps endpoints, extracts tokens, builds attack surface
Agent 2: Exploit      → SQLi, XSS, SSRF, path traversal
Agent 3: Auth         → JWT forgery, auth bypass, privilege escalation
Agent 4: Code         → Source code analysis, taint tracing
Agent 5: Race         → Race conditions, TOCTOU, coupon reuse
Agent 6: Validate     → Confirms findings, removes false positives
```

#### 10-Agent Parallel Swarm (launch_swarm.py)

```bash
python3 launch_swarm.py
```

Adds: Config, XSS-specialist, IDOR, Exfil, and Validate agents. All run in parallel threads, sharing a concurrent knowledge graph with deduplication.

---

### 5.3 Attack Modules

Each module can be run standalone or as part of a pipeline/swarm.

#### SQL Injection — `nova_exploit_synthesizer.py`

```bash
python3 nova_exploit_synthesizer.py
```

Payloads include: tautology, UNION SELECT (full table extraction), blind boolean, time-based, comment variants. Auto-validates success by detecting schema data in responses.

#### XSS — `nova_exploit_synthesizer.py` + `nova_feedback_cortex.py`

Stored and reflected XSS with payloads for: `<script>`, `<img onerror>`, `<svg onload>`, `<iframe src=javascript:>`, cookie theft scripts. Tests feedback, product reviews, usernames, and all string-type fields.

#### JWT Forgery — `nova_jwt_forge.py`

```bash
python3 nova_jwt_forge.py
```

- `none` algorithm bypass
- Weak secret brute-force (common wordlists)
- Key confusion attacks (RS256 → HS256 with public key)
- Algorithm downgrade
- Claims tampering (email, role, isAdmin)

#### Race Conditions — `nova_race_engine.py`

```bash
python3 nova_race_engine.py
```

Uses parallel `ThreadPoolExecutor` to fire simultaneous requests. Targets: coupon redemption double-spend, rate limit bypass, concurrent basket manipulation, TOCTOU on discount codes.

#### Prototype Pollution — `nova_proto_polluter.py`

```bash
python3 nova_proto_polluter.py
```

- `__proto__` injection via JSON body
- `constructor.prototype` pollution
- Deep merge exploitation
- Query string pollution
- Gadget chains for auth bypass and RCE

#### Deserialization — `nova_deserialize_dropper.py`

Targets Node.js `serialize-javascript` and `node-serialize` sinks. Generates IIFE payloads for RCE, tests cookie and body deserialization endpoints.

#### Session Hijacking — `nova_session_hijacker.py`

CSRF token extraction, session fixation, cookie theft via XSS, predictable session ID testing, concurrent session attacks.

#### HTTP Request Smuggling — `nova_url_smuggling.py`

CL.TE and TE.CL attack variants, header injection, cache poisoning via smuggled requests.

#### SSRF — `nova_exploit_synthesizer.py`

Internal metadata endpoint probes (AWS, GCP, Azure), blind SSRF with callback, port scanning via SSRF, file scheme exploitation.

---

### 5.4 Intelligence Layer

#### Model Router — `nova_model_router.py`

Routes every task to the best available Ollama model automatically.

```bash
python3 nova_model_router.py    # Show current routing table
```

```
🔴 Security   → xploiter/the-xploiter  (attack chain expert)
🟠 Reasoning  → deepseek-r1:32b        (chain-of-thought, shows its work)
🟡 Coding     → devstral-small         (code audit, payload generation)
🔵 Fast       → qwen3:8b               (quick checks, parsing)
⚪ General    → qwen3:30b              (planning, reporting)
```

If your top model isn't installed, it automatically falls back through the tier until it finds one that is.

#### Chain-of-Thought Engine — `nova_chain_of_thought.py`

```
Pattern: OBSERVE → HYPOTHESIZE → PROBE → CONCLUDE → CHAIN
```

For each observation, Nova:
1. Forms a ranked list of hypotheses with Bayesian confidence scores
2. Designs targeted probes to test each hypothesis
3. Updates confidence based on evidence
4. Chains confirmed findings to the next hypothesis (SQLi → dump users → crack hashes → admin login)

#### Hypothesis Engine — `nova_hypothesis_engine.py`

Systematic Bayesian hypothesis testing. Each hypothesis has:
- Prior confidence (0–1)
- Ranked probe list
- Evidence for / against
- Auto-confirms at ≥ 0.85 confidence
- Auto-dismisses at ≤ 0.10 confidence

#### RAG Knowledge Base — `nova_rag_builder.py`

```bash
# Build / rebuild from all past hunts
python3 nova_rag_builder.py .

# Demo query
python3 -c "
from nova_rag_builder import get_rag
rag = get_rag()
results = rag.query('sql_injection', endpoint='/rest/products/search', top_k=3)
print(rag.format_context(results))
"
```

Ingests:
- All `nova_h1_hunt_*.json` files (HackerOne recon data)
- All submission evidence folders (`nova_0din_submission/`, `nova_nextgen_submission/`)
- All `nova_*_report.json` and `nova_*_findings.json` files
- `nova_verified_findings.json`, `nova_real_findings.json`
- 10 built-in OWASP Top 10 patterns as baseline

Every attack prompt is augmented with "what worked on similar targets before."

#### Adaptive Brain — `nova_adaptive_brain.py`

Before attacking, profiles each endpoint:
1. Sends probe requests to understand normal behavior
2. Maps valid params, error conditions, response patterns
3. Extracts dynamic tokens (CSRF, nonces)
4. Builds context-aware attack strategy for that specific endpoint

---

### 5.5 Reconnaissance

#### Wild Hunt — `nova_wild_hunt.py`

Full real-world recon for bug bounty targets:

```bash
python3 nova_wild_hunt.py
```

- DNS subdomain brute-force (50+ common prefixes)
- Technology stack fingerprinting (headers, cookies, response patterns)
- Open port scanning
- URL endpoint discovery
- SSL certificate analysis
- CVE → exploit mapping based on detected versions

#### HackerOne Recon — `nova_active_ibb.py` / `nova_0din_hunter.py`

Automated recon specifically for HackerOne and 0din bug bounty programs. Nova has already run hunts against: `konghq.com`, `verily.com`, `notion.so`, `api.target.com` — all results stored as `nova_h1_hunt_*.json`.

#### GitHub Secret Scanner — `nova_github_scanner.py`

Scans public GitHub repos for accidentally committed secrets: API keys, passwords, tokens, connection strings. Checks commit history, not just current files.

#### Scope Manager — `nova_scope_manager.py`

```bash
python3 nova_scope_manager.py
```

Live HackerOne scope sync:
- Fetches all programs you participate in via H1 API
- Pulls in-scope / out-of-scope assets per program
- Local cache with 1-hour TTL
- Scope diff — detects changes since last sync
- Export as Markdown, JSON, or plain list

Requires H1 API credentials in `~/.nova/scope_config.json`.

---

### 5.6 Code Analysis

#### Code Reasoner — `nova_code_reasoner_v2.py`

```bash
python3 nova_code_reasoner_v2.py
```

Fetches Juice Shop source from GitHub, then:
- Maps runtime error stack traces to source file + line number
- Identifies dangerous sinks: `.query()`, `eval()`, `innerHTML`, `exec()`
- Traces data flow from `req.body`/`req.query` to sinks
- Identifies missing authentication checks
- Generates vulnerability hypotheses from code patterns

Sink categories tracked: SQL injection, command injection, path traversal, XSS, JWT misuse, auth bypass.

#### Source Auditor — `nova_source_auditor.py`

Static analysis across the entire repository:
- Finds hardcoded credentials and secrets
- Identifies dangerous function usage
- Maps dependency vulnerabilities (CVE lookup)
- Generates a prioritized audit report

#### Data Flow Engine — `nova_dataflow_engine.py`

Traces how user-supplied input flows through the application:
- Entry points: `req.body`, `req.query`, `req.params`, `req.headers`
- Through transformations: sanitizers, validators, parsers
- To sinks: DB queries, file operations, HTTP calls, template rendering
- Flags paths missing sanitization

---

### 5.7 Memory & Learning

#### NovaBrain — `nova_memory_system.py`

Nova's persistent intelligence survives across all hunts:

```python
from nova_memory_system import NovaBrain
brain = NovaBrain()
brain.record_technique_result("jwt_none_bypass", success=True)
brain.record_payload("' OR 1=1--", hit=True)
brain.get_best_techniques(top_k=5)
brain.get_best_payloads(vuln_type="sql_injection", top_k=10)
```

Tracks:
- Technique success rates (scored, ranked over time)
- Payload hit counts per vulnerability type
- Tool effectiveness scores
- WAF bypass patterns that worked
- Technology fingerprints and their known weaknesses
- Hunt statistics (total hunts, findings, critical/high counts)

#### Feedback Cortex — `nova_feedback_cortex.py`

After every exploit attempt:
1. Validates whether a partial success is real (checks for `/etc/passwd` patterns, SQL errors, etc.)
2. Extracts credentials and tokens from successful responses
3. Updates the graph brain confidence scores
4. Adds successful payloads to the signature database

```
Signature database: nova_signatures.json
Credential store:   nova_credentials.json
Graph brain:        nova_memory.json
```

#### 24/7 Continuous Mode — `nova_continuous_v3.py`

```bash
python3 nova_continuous_v3.py
```

Runs indefinitely — hunts, learns, sleeps, hunts again. After each cycle:
- Updates NovaBrain with what worked
- Adjusts technique weights
- Generates incremental reports
- Optionally alerts on new critical findings

---

### 5.8 Reporting & Deployment

#### Daybreak Assessment — `nova_daybreak.py`

Three-stage assessment pipeline modelled on OpenAI Daybreak:

```
Stage 1 — AI Threat Prioritization
    LLM reasons about the attack surface and ranks targets by risk score (0–10)
    Each target gets: risk_score, attack_type, reason, confidence

Stage 2 — Scoped Sandbox Validation
    Tests only what Stage 1 ranked as high-priority
    Human checkpoint before escalating to critical
    HackerOne scope enforced at every step

Stage 3 — Audit-Ready Evidence Package
    Full PoC with reproduction steps
    CVSS 3.1 score and CWE classification
    HackerOne submission-ready JSON
```

```bash
python3 nova_daybreak.py
```

#### Report Generator — `nova_report.py`

```bash
python3 nova_report.py
```

Generates three formats:
- **HTML** — Full color-coded report with severity badges, PoC evidence, reproduction steps
- **Markdown** — GitHub-compatible, suitable for HackerOne submissions
- **JSON** — Machine-readable, structured for automation

#### Agentic Deploy — `nova_agentic_deploy.py`

Evaluates whether AI agent payloads are safe before deployment using a sandboxed local Ollama evaluation. Tests for: excessive privilege requests, scope violations, data exfiltration attempts.

---

## 6. Module Reference

| Module | Version | Purpose |
|---|---|---|
| `nova_agent_core.py` | 1.0 | True ReAct agentic loop |
| `nova_tool_kit.py` | 1.0 | Tool execution engine (bash/browser/http/file) |
| `nova_model_router.py` | 1.0 | Task-based Ollama model routing |
| `nova_reasoning_core.py` | 2.0 | Unified LLM backbone |
| `nova_llm_bridge.py` | 2.0 | LLM mission planner + NL interface |
| `nova_rag_builder.py` | 1.0 | RAG knowledge base from past hunts |
| `nova_chain_of_thought.py` | 1.0 | Observe→Hypothesize→Probe→Conclude |
| `nova_hypothesis_engine.py` | 1.0 | Bayesian hypothesis testing |
| `nova_adaptive_brain.py` | 1.0 | Context-aware strategy adaptation |
| `nova_core.py` | 3.0 | 10-phase pipeline orchestrator |
| `nova_swarm_v3.py` | 3.0 | 6-agent parallel swarm |
| `nova_swarm_parallel.py` | 1.0 | 10-agent parallel swarm |
| `nova_exploit_synthesizer.py` | 1.0 | SQLi, XSS, SSRF, path traversal |
| `nova_jwt_forge.py` | 1.0 | JWT forgery engine |
| `nova_race_engine.py` | 1.0 | Race condition exploitation |
| `nova_proto_polluter.py` | 1.0 | Prototype pollution engine |
| `nova_deserialize_dropper.py` | 1.0 | Deserialization attacks |
| `nova_session_hijacker.py` | 1.0 | Session hijacking |
| `nova_url_smuggling.py` | 1.0 | HTTP request smuggling |
| `nova_fuzzer_fix.py` | 1.0 | Parameter fuzzer |
| `nova_browser_agent.py` | 1.1 | Browser-based attack agent |
| `nova_code_reasoner_v2.py` | 2.0 | Source code vulnerability analysis |
| `nova_source_auditor.py` | 1.0 | Static code auditing |
| `nova_dataflow_engine.py` | 1.0 | Data flow taint tracing |
| `nova_memory_system.py` | 1.0 | NovaBrain persistent intelligence |
| `nova_feedback_cortex.py` | 1.0 | Self-learning validation |
| `nova_daybreak.py` | 1.0 | 3-stage Daybreak assessment |
| `nova_report.py` | 1.0 | HTML/MD/JSON report generator |
| `nova_scope_manager.py` | 1.0 | HackerOne live scope sync |
| `nova_wild_hunt.py` | 1.0 | Real-world target assessment |
| `nova_github_scanner.py` | 1.0 | GitHub secret scanner |
| `nova_continuous_v3.py` | 3.0 | 24/7 continuous hunting |
| `nova_agentic_deploy.py` | 1.0 | Sandboxed payload evaluation |

---

## 7. Configuration

All settings live in `nova_config.json`. Copy to `~/nova_workspace/nova_config.json` to override defaults.

```json
{
  "llm": {
    "model":          "auto",          // "auto" uses model router
    "fallback_model": "llama3.2",
    "timeout":        120,
    "url":            "http://localhost:11434"
  },

  "recon": {
    "subdomain_tools": ["subfinder", "amass", "crt.sh"],
    "max_subdomains":  500,
    "max_urls":        10000,
    "threads":         10
  },

  "attack": {
    "enabled_chains": [
      "sqli", "xss", "ssrf", "cors", "jwt",
      "prototype_pollution", "race_condition"
    ],
    "severity_threshold": "low",
    "max_payloads_per_param": 50
  },

  "evolution": {
    "enabled":     true,
    "require_tests": true,
    "backup_before": true
  }
}
```

**Environment variable overrides:**

```bash
NOVA_LLM_URL=http://localhost:11434   # Ollama base URL
NOVA_LLM_MODEL=deepseek-r1:14b       # Force specific model (skip routing)
NOVA_LLM_TIMEOUT=120                  # LLM request timeout seconds
NOVA_MAX_STEPS=40                     # Max agentic loop steps
```

---

## 8. Compared to Frontier Agents

| Capability | Claude Mythos | OpenAI Daybreak | Nova v3.0 |
|---|---|---|---|
| **Cost per run** | $25–$125 / MTok | ~$100–200/mo | **$0** |
| **Tool use** | ✅ Free tool calls | ✅ Free tool calls | ✅ Free tool calls |
| **Browser** | ✅ Real Chromium | ✅ Real browser | ✅ Playwright Chromium |
| **Shell access** | ✅ Full Linux | ✅ Full Linux | ✅ Full Linux |
| **LLM drives loop** | ✅ | ✅ | ✅ ReAct loop |
| **Model quality** | Opus-class | GPT-4o class | Best Ollama available |
| **Security-specialized model** | ❌ General LLM | ❌ General LLM | ✅ xploiter/the-xploiter |
| **Chain-of-thought** | ✅ | ✅ | ✅ DeepSeek-R1 |
| **Prior hunt knowledge** | ❌ | ❌ | ✅ RAG from 100+ hunts |
| **Scope enforcement** | Manual | ✅ Built-in | ✅ H1 scope sync |
| **Persistent memory** | ❌ (session only) | ❌ | ✅ NovaBrain |
| **Self-improvement** | ❌ | ❌ | ✅ |
| **Privacy** | ❌ Sends code to cloud | ❌ Sends code to cloud | ✅ 100% local |
| **24/7 hunting** | ❌ | Limited | ✅ Continuous mode |

---

## 9. HackerOne Integration

```bash
# Configure H1 credentials
cat > ~/.nova/scope_config.json << 'EOF'
{
  "h1_username": "your_h1_handle",
  "h1_api_token": "your_h1_api_token"
}
EOF

# Sync scope for all your programs
python3 nova_scope_manager.py --sync

# Hunt within scope
python3 nova_agent_core.py \
  --target https://target.h1.program.com \
  --objective "Find high-severity vulnerabilities within HackerOne scope. Respect all out-of-scope rules."
```

Nova's `nova_scope_manager.py` enforces HackerOne program scopes at every step — she will not test out-of-scope assets.

Past H1 recon already completed and stored:

```
konghq.com — 50+ subdomains mapped
verily.com — 60+ subdomains mapped
notion.so  — 4 subdomains mapped
api.target.com — 1 endpoint mapped
```

---

## 10. Extending Nova

### Add a New Attack Module

1. Create `nova_myattack.py` with a class that takes `base_url` and returns a list of findings
2. Import it in `nova_core.py` and add a phase
3. Add it to the swarm in `nova_swarm_parallel.py` as an Agent subclass

### Add a New Tool (Agentic Mode)

1. Add a schema entry to `TOOL_SCHEMAS` in `nova_tool_kit.py`
2. Add the executor function
3. Register it in the `execute_tool()` dispatcher

### Train on New Findings

```bash
# After a successful hunt, rebuild the RAG with new findings
python3 nova_rag_builder.py . --force-rebuild
```

### Teach Nova a New Bypass

```python
from nova_memory_system import NovaBrain
brain = NovaBrain()
brain.record_waf_bypass("cloudflare", payload="<ScRiPt>alert(1)</ScRiPt>")
brain.record_technique_result("sqli_unicode_bypass", success=True)
```

---

## File Tree (Key Files)

```
Nova-arsenal/
├── nova_agent_core.py           ← START HERE for agentic mode
├── nova_core.py                 ← START HERE for pipeline mode
├── launch_swarm.py              ← START HERE for swarm mode
├── nova_setup.sh                ← One-command installation
├── nova_config.json             ← Main configuration
│
├── Intelligence/
│   ├── nova_model_router.py     ← Task → best Ollama model
│   ├── nova_reasoning_core.py   ← Unified LLM backbone
│   ├── nova_llm_bridge.py       ← NL mission planner
│   ├── nova_rag_builder.py      ← Past-hunt knowledge base
│   ├── nova_chain_of_thought.py ← Hypothesis→Probe→Conclude
│   ├── nova_hypothesis_engine.py← Bayesian testing
│   └── nova_adaptive_brain.py   ← Context-aware strategy
│
├── Agentic/
│   ├── nova_agent_core.py       ← ReAct loop (LLM drives hunt)
│   └── nova_tool_kit.py         ← bash/browser/http/file tools
│
├── Attack Modules/
│   ├── nova_exploit_synthesizer.py  ← SQLi, XSS, SSRF, LFI
│   ├── nova_jwt_forge.py            ← JWT attacks
│   ├── nova_race_engine.py          ← Race conditions
│   ├── nova_proto_polluter.py       ← Prototype pollution
│   ├── nova_deserialize_dropper.py  ← Deserialization
│   ├── nova_session_hijacker.py     ← Session attacks
│   └── nova_url_smuggling.py        ← HTTP smuggling
│
├── Recon/
│   ├── nova_wild_hunt.py        ← Real-world recon
│   ├── nova_scope_manager.py    ← HackerOne scope sync
│   └── nova_github_scanner.py   ← Secret scanning
│
├── Code Analysis/
│   ├── nova_code_reasoner_v2.py ← Source vulnerability analysis
│   ├── nova_source_auditor.py   ← Static analysis
│   └── nova_dataflow_engine.py  ← Taint tracing
│
├── Memory/
│   ├── nova_memory_system.py    ← NovaBrain persistence
│   ├── nova_feedback_cortex.py  ← Self-learning validation
│   ├── nova_brain_memory.json   ← Technique/payload scores
│   └── nova_exploit_memory.json ← What worked where
│
└── Output/
    ├── nova_report.py           ← HTML/MD/JSON reports
    ├── nova_daybreak.py         ← 3-stage assessment engine
    └── nova_continuous_v3.py    ← 24/7 hunting loop
```

---

<div align="center">

**Nova is a research and educational tool.**  
Only hunt targets you have explicit written permission to test.  
Always respect HackerOne / Bugcrowd program scope.

*Built for the solo researcher who can't afford $125/MTok frontier agents.*

</div>
