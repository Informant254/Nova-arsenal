<div align="center">

```
███╗   ██╗ ██████╗ ██╗   ██╗  █████╗
████╗  ██║██╔═══██╗██║   ██║ ██╔══██╗
██╔██╗ ██║██║   ██║██║   ██║ ███████║
██║╚██╗██║██║   ██║╚██╗ ██╔╝ ██╔══██║
██║ ╚████║╚██████╔╝ ╚████╔╝  ██║  ██║
╚═╝  ╚═══╝ ╚═════╝   ╚═══╝   ╚═╝  ╚═╝
         A R S E N A L  v3.5
```

**Fully Autonomous AI-Powered Bug Bounty & Security Research System**

*Tell Nova what you want in plain English. She plans, probes, verifies, and reports — fully autonomously.*

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![Ollama](https://img.shields.io/badge/LLM-Ollama%20Local-green)](https://ollama.com)
[![Cost](https://img.shields.io/badge/LLM%20Cost-%240%2Frun-brightgreen)](#)
[![Gap](https://img.shields.io/badge/Frontier%20Gap-Closed-red)](#8-capability-parity-with-frontier-agents)

</div>

---

## Table of Contents

1. [What Nova Is](#1-what-nova-is)
2. [Architecture Overview](#2-architecture-overview)
3. [Installation](#3-installation)
4. [Talking to Nova in Plain English](#4-talking-to-nova-in-plain-english)
5. [Gap-Closing Capabilities](#5-gap-closing-capabilities)
   - [Pre-Hunt Strategic Planning](#51-pre-hunt-strategic-planning--nova_plannerpy)
   - [Visual Screenshot Analysis](#52-visual-screenshot-analysis--nova_visionpy)
   - [Triple-Verify Engine](#53-triple-verify-engine--nova_verify_enginepy)
   - [CVE/PoC Web Research](#54-cvepoc-web-research--nova_web_researcherpy)
   - [Context Window Compression](#55-context-window-compression--nova_context_managerpy)
   - [20-Tool Agent Kit](#56-20-tool-agent-kit--nova_tool_kitpy-v20)
6. [Other Core Capabilities](#6-other-core-capabilities)
7. [Module Reference](#7-module-reference)
8. [Capability Parity with Frontier Agents](#8-capability-parity-with-frontier-agents)
9. [Configuration](#9-configuration)
10. [HackerOne Integration](#10-hackerone-integration)

---

## 1. What Nova Is

Nova is a **fully autonomous, locally-run AI security researcher**. Talk to her in plain English. She decides what to do and does it — no confirmation prompts, no menus, no configuration.

```
You:  "Hunt hackerone.com for SQL injection and SSRF"
Nova: parses → plans 8 phases → visual recon → researches CVEs →
      hunts with LLM-driven ReAct loop → triple-verifies every finding →
      scores CVSS 3.1 → writes HackerOne-ready report
```

Everything runs **100% locally**. Zero cloud cost. Zero API keys for LLM.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NOVA ARSENAL v3.5                               │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │             NATURAL LANGUAGE ENTRY POINT  (nova.py)               │  │
│  │   "Hunt X"  "Improve yourself"  "Assess Y"  "Swarm Z"             │  │
│  │   LLM intent parser → keyword fallback → dispatch                 │  │
│  └─────────────────────────────┬─────────────────────────────────────┘  │
│                                 │                                        │
│   ┌────────────────┐   ┌────────▼───────────┐   ┌─────────────────┐   │
│   │ nova_          │   │ nova_agent_core v2  │   │ launch_swarm    │   │
│   │ continuous_v3  │   │                     │   │ (10 parallel)   │   │
│   │ (24/7 + self-  │   │ PRE-HUNT            │   └─────────────────┘   │
│   │  improvement)  │   │  ├─ plan_hunt ✦     │                         │
│   └────────────────┘   │  ├─ visual_analyze✦ │                         │
│                         │  └─ research_cve ✦ │                         │
│                         │                     │                         │
│                         │ REACT LOOP          │                         │
│                         │  20 tools available │                         │
│                         │  reflect every 5    │                         │
│                         │  verify findings ✦  │                         │
│                         │  context compress ✦ │                         │
│                         └────────────────────-┘                         │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │              GAP-CLOSING MODULES (v3.5 NEW)                        │ │
│  │  nova_planner        — structured multi-phase planning  [Code]    │ │
│  │  nova_vision         — screenshot + LLM visual analysis [Mythos]  │ │
│  │  nova_verify_engine  — triple-confirm + CVSS + H1 pack  [Daybreak]│ │
│  │  nova_web_researcher — NVD/GitHub/OSV CVE + PoC lookup  [All 3]   │ │
│  │  nova_context_manager— rolling compression, 200+ steps  [Code]    │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │              SELF-IMPROVEMENT LAYER                                │ │
│  │  nova_self_improvement   nova_repo_intelligence                    │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### What Happens Before the First Tool Call

Unlike older Nova versions that jumped straight into the ReAct loop, Nova v2 runs three pre-hunt setup steps (the Claude Code pattern):

```
TARGET + OBJECTIVE
      │
      ▼  (1) nova_planner  — generate 8-phase attack plan
      │     phases: recon → passive → auth → inject → access → chain → verify → report
      │
      ▼  (2) nova_vision   — screenshot the target
      │     LLM vision model identifies: forms, auth state, admin links, attack vectors
      │
      ▼  (3) nova_web_researcher — HTTP probe → detect tech stack → NVD/GitHub CVE lookup
      │     result injected into context: "Express 4.17 has CVE-2024-XXXX (CVSS 9.8)"
      │
      ▼  ReAct loop starts WITH full situational awareness
```

---

## 3. Installation

```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
chmod +x nova_setup.sh && ./nova_setup.sh
```

Manual model pull (priority order):

```bash
ollama pull xploiter/the-xploiter  # security-specialized
ollama pull deepseek-r1:14b        # chain-of-thought
ollama pull devstral-small         # code + patches
ollama pull qwen3:8b               # NL parsing + intent
ollama pull llava                  # vision analysis (Mythos gap)
```

Python dependencies:

```bash
pip install requests playwright
python3 -m playwright install chromium
```

---

## 4. Talking to Nova in Plain English

```bash
# Start here — just say what you want
python3 nova.py "Hunt hackerone.com for SQL injection and SSRF vulnerabilities"
python3 nova.py "Run a full swarm on localhost:3000 — maximum power"
python3 nova.py "Assess notion.so using the Daybreak pipeline"
python3 nova.py "Recon target.com — subdomains, ports, tech stack"
python3 nova.py "Improve yourself using my recent hunt results"
python3 nova.py "24/7 continuous hunting across all bug bounty targets"
python3 nova.py "Code review the source for injection sinks"
python3 nova.py          # interactive prompt with examples
```

Nova's NL parser: local Ollama (zero-temp JSON extraction, ~1s) → keyword fallback if offline.
Every dispatch logged to `~/nova_workspace/nova_dispatch_log.json`.

---

## 5. Gap-Closing Capabilities

### 5.1 Pre-Hunt Strategic Planning — `nova_planner.py`

**Closes the Claude Code planning gap.**

Claude Code ALWAYS generates a structured plan before touching any file. Nova now does too.

```bash
# Standalone
python3 nova_planner.py http://localhost:3000 "Find all critical vulnerabilities"

# Automatic: runs before every hunt when nova_agent_core starts
NOVA_AUTO_PLAN=true python3 nova.py "Hunt target.com"
```

What it produces:

```
HUNT PLAN  (target: http://localhost:3000)
OBJECTIVE: Find all critical vulnerabilities
PROGRESS:  8/8 phases complete — 3 findings

PHASES:
  ⬜ [recon]   Reconnaissance            (priority 1)
               Goal: Map full attack surface
               Success: ≥5 endpoints discovered, tech stack identified
  ⬜ [passive] Passive Analysis          (priority 2)
               Goal: Source, JS, headers for secrets
               Depends on: recon
  ⬜ [auth]    Authentication Attack     (priority 2)
               Goal: Login, JWT, session, registration
  ⬜ [inject]  Injection Attacks         (priority 3)
               Goal: SQLi, XSS, SSTI, SSRF on all params
  ⬜ [access]  Access Control            (priority 3)
               Goal: IDOR, privilege escalation, traversal
               Depends on: auth
  ⬜ [chain]   Vulnerability Chaining    (priority 4)
               Goal: Chain confirmed findings
               Depends on: inject, access
  ⬜ [verify]  Verification              (priority 5)
               Goal: Triple-confirm every finding
  ⬜ [report]  Report Generation         (priority 6)

NEXT READY: Reconnaissance, Passive Analysis
```

The plan is:
- Generated by local Ollama (JSON schema enforced) with keyword fallback
- Injected into the agent's context window as a persistent heading
- Updated as phases complete — agent always knows where it is
- Saved to `~/nova_workspace/nova_plan_<id>.json` — resumable across sessions

**Agent tool:** `plan_hunt` — the LLM can call this itself mid-hunt

---

### 5.2 Visual Screenshot Analysis — `nova_vision.py`

**Closes the Claude Mythos computer-vision gap.**

Mythos sees screenshots and reasons about UI visually. Now Nova does too.

```bash
# Standalone
python3 nova_vision.py http://localhost:3000

# Automatic: visual recon runs before every hunt
NOVA_AUTO_VISUAL=true python3 nova.py "Hunt localhost:3000"

# Agent tool during hunt
{"action": "visual_analyze", "args": {"url": "http://target/admin"}}
```

What it finds that source code misses:

```json
{
  "forms": [
    {"purpose": "admin login", "fields": ["username", "password", "remember_me"], "action": "/admin/login"},
    {"purpose": "file upload", "fields": ["file", "description"], "action": "/api/upload"}
  ],
  "auth_state": "unauthenticated",
  "admin_links": ["/admin", "/admin/users", "/admin/config"],
  "upload_forms": ["/api/upload"],
  "attack_vectors": [
    {"type": "auth_bypass",    "target": "/admin/login",  "reasoning": "Login form visible, try SQLi and default creds"},
    {"type": "file_upload",    "target": "/api/upload",   "reasoning": "File upload with no visible type restriction"},
    {"type": "idor",           "target": "/admin/users",  "reasoning": "User list visible — enumerate and access others"}
  ],
  "summary": "Admin panel accessible at /admin. File upload form with no apparent type check. Auth is a login form."
}
```

**Vision models** (auto-selected in preference order):
`llava:34b` → `llava:13b` → `llava:7b` → `llava-phi3` → `moondream` → `bakllava`

**Graceful degradation:** If no vision model is installed, returns screenshot path + install instructions. Hunt continues — visual recon is additive, not blocking.

Install a vision model:
```bash
ollama pull llava        # recommended (7B, ~4GB)
ollama pull moondream    # fast, lightweight (1.8B, ~1.7GB)
```

---

### 5.3 Triple-Verify Engine — `nova_verify_engine.py`

**Closes the OpenAI Daybreak Stage-2 gap.**

Daybreak never reports a finding until it has been independently confirmed 3 times. Nova now does the same.

```bash
# Standalone
python3 nova_verify_engine.py sqli http://localhost:3000/rest/products/search q

# Via agent tool
{"action": "verify_finding", "args": {"vuln_type": "sqli", "endpoint": "http://target/search", "param": "q"}}
```

What happens:

```
  ✅ Proof 1/3: /search?q=' OR 1=1-- → status 200  (returns user data)
  ✅ Proof 2/3: /search?q=' OR 'a'='a → status 200  (returns user data)
  ✅ Proof 3/3: /search?q=1 UNION SELECT 1,2,3-- → status 200  (column layout)
  🔥 CONFIRMED (3/3) — CVSS 9.8 (CRITICAL) — CWE-89
```

Outputs:
- **Confirmation score**: N/3 independent proofs
- **CVSS 3.1 auto-score**: full base vector from vulnerability type
- **CWE mapping**: automatic
- **HackerOne-ready report**: title, severity, steps to reproduce, impact, evidence JSON

Supported types: `sqli`, `xss`, `ssrf`, `path_traversal`, `idor`, `auth_bypass`, `jwt_none`, `rce`, `race_condition`, `xxe`, `cors`, `open_redirect`, `prototype_pollution`, `deserialization`

When a finding is confirmed 2/3 or 3/3, it's automatically **pinned to the context window** and never compressed away.

---

### 5.4 CVE/PoC Web Research — `nova_web_researcher.py`

**Closes the live web-research gap (all three frontier agents have this).**

```bash
# Standalone
python3 nova_web_researcher.py "expressjs SQL injection"
python3 nova_web_researcher.py "log4j JNDI RCE"

# Via agent tool
{"action": "research_cve", "args": {"query": "Django 4.2 SQL injection"}}
```

Data sources (all public, no API keys needed):

| Source | What it returns |
|---|---|
| **NIST NVD** | CVE IDs, CVSS scores, severity, descriptions, references |
| **GitHub API** | PoC repositories sorted by stars |
| **OSV.dev** | Advisory database for 12 ecosystems (PyPI, npm, Maven, RubyGems, Go...) |

Example output for `"expressjs SQL injection"`:
```
🔍 expressjs: 8 CVEs, 5 PoC repos
CVEs: CVE-2024-1234 (9.8 CRITICAL), CVE-2023-5678 (7.5 HIGH)...
PoCs: expressjs-sqli-demo (⭐ 234), express-injection-poc (⭐ 89)...
```

All results cached for 12 hours at `~/nova_workspace/research_cache/`.
Pre-hunt CVE research: automatically runs on detected tech stack before the loop starts.

---

### 5.5 Context Window Compression — `nova_context_manager.py`

**Closes the long-context gap vs Claude Code (200K tokens).**

Old Nova: `HISTORY_LIMIT` → hard truncation → critical findings lost after step 30.
New Nova: rolling compression with 3 permanent sections.

```
┌─────────────────────────────────────────────────────────┐
│                   CONTEXT WINDOW                         │
│                                                          │
│  ── SYSTEM PROMPT ─────────────────────────────────────  │
│                                                          │
│  ── PINNED FINDINGS (never compressed) ────────────────  │
│     🔥 [CRITICAL] sqli at /search?q= — CVSS 9.8 (3/3)  │
│     🔥 [HIGH]     idor at /api/user/  — CVSS 7.5 (2/3)  │
│                                                          │
│  ── CURRENT HUNT PLAN ─────────────────────────────────  │
│     ✅ recon complete  ✅ passive complete               │
│     🔵 inject running  ⬜ verify pending                 │
│                                                          │
│  ── COMPRESSED HISTORY (steps 1–40) ───────────────────  │
│     • Found X-Powered-By: Express 4.17                  │
│     • Admin panel at /admin requires login              │
│     • /api/products vulnerable to SQLi (unverified)     │
│                                                          │
│  ── VERBATIM WINDOW (last 12 exchanges) ───────────────  │
│     [step 41] thought: ... action: verify_finding       │
│     [step 42] TOOL 'verify_finding' → SUCCESS           │
│     ...                                                  │
└─────────────────────────────────────────────────────────┘
```

Result: Nova can run **200+ step hunts** without losing confirmed findings or plan state.

Config:
```bash
NOVA_CTX_WINDOW=12   # verbatim last N exchanges
NOVA_CTX_SUMMARY=3000  # compressed summary max chars
```

---

### 5.6 20-Tool Agent Kit — `nova_tool_kit.py` v2.0

Nova now has 20 tools — matching the breadth of frontier agent tool sets.

| Tool | Category | Description |
|---|---|---|
| `bash_exec` | Shell | Any command — nmap, sqlmap, nuclei, curl |
| `http_request` | Network | Full HTTP with headers, auth, body, cookies |
| `browser_open` | Browser | Headless Chromium — handles JS SPAs |
| `browser_source` | Browser | Full rendered HTML after JS execution |
| `browser_click` | Browser | Click CSS-selector elements |
| `browser_fill` | Browser | Fill + submit forms |
| `browser_eval` | Browser | Execute JavaScript — read cookies, localStorage |
| `file_read` | File | Read any file — source, configs, findings |
| `file_write` | File | Write findings, exploits, reports |
| `grep_code` | Analysis | Search codebase for patterns, sinks, secrets |
| `install_tool` | System | On-demand pip/apt/go install |
| `self_review` | Memory | Read recent run reports, identify failures |
| `self_remember` | Memory | Persist lesson to long-term memory |
| `query_repo_index` | Memory | Look up Nova's own codebase symbols |
| **`visual_analyze`** | **Vision** | **Screenshot + LLM analysis [Mythos]** |
| **`research_cve`** | **Intel** | **NVD/GitHub/OSV CVE + PoC lookup [Daybreak]** |
| **`verify_finding`** | **Verify** | **Triple-confirm + CVSS + H1 report [Daybreak]** |
| **`plan_hunt`** | **Planning** | **Multi-phase strategic plan [Claude Code]** |
| **`parallel_probe`** | **Speed** | **Fire N HTTP probes simultaneously [All 3]** |
| `mission_complete` | Control | Signal hunt complete with findings summary |

**New: `parallel_probe`** — instead of 10 sequential `http_request` calls to test parameters, fire all 10 simultaneously:

```json
{
  "action": "parallel_probe",
  "args": {
    "probes": [
      {"url": "/search?q=' OR 1=1--"},
      {"url": "/search?q=<script>alert(1)</script>"},
      {"url": "/search?q=../../etc/passwd"},
      {"url": "/api/user/1"},
      {"url": "/api/user/2"}
    ],
    "timeout": 8
  }
}
```

All 5 fire simultaneously. Results returned together. **5-10x faster than sequential probing.**

Permission profiles unchanged: `full` | `read_only` | `no_network`

---

## 6. Other Core Capabilities

### Natural Language Interface (`nova.py`)

```bash
python3 nova.py "Hunt hackerone.com for SQL injection"  # hunt
python3 nova.py "Full swarm on localhost:3000"           # swarm
python3 nova.py "Assess notion.so — Daybreak pipeline"   # assess
python3 nova.py "Improve yourself"                       # self-improvement
python3 nova.py "24/7 continuous hunting"                # continuous
python3 nova.py "Recon target.com subdomains"            # recon
python3 nova.py "Code review for injection sinks"        # code_review
python3 nova.py                                          # interactive
```

### Self-Improvement (`nova_self_improvement.py` + `nova_repo_intelligence.py`)

Nova reads her own run history and proposes code improvements using local Ollama. In continuous mode, this runs automatically every 5 cycles.

```bash
python3 nova.py "Improve yourself"
```

### Continuous 24/7 Mode (`nova_continuous_v3.py`)

Real taint-flow analysis (source → sink, no sanitizer = real bug) across 9 major OSS targets. Self-improvement runs every `SELF_IMPROVE_EVERY` cycles (default: 5).

### Swarm Mode (`launch_swarm.py`)

10 specialized agents in parallel sharing a concurrent knowledge graph.

### Daybreak 3-Stage Assessment (`nova_daybreak.py`)

AI threat prioritization → scoped sandbox validation → HackerOne evidence package.

---

## 7. Module Reference

| Module | Version | What it does |
|---|---|---|
| **`nova.py`** | **1.0** | Natural language entry point |
| **`nova_agent_core.py`** | **2.0** | ReAct loop + pre-hunt plan/visual/CVE |
| **`nova_planner.py`** | **1.0** | Pre-hunt strategic planning |
| **`nova_vision.py`** | **1.0** | Screenshot + LLM visual analysis |
| **`nova_verify_engine.py`** | **1.0** | Triple-confirm + CVSS 3.1 + H1 report |
| **`nova_web_researcher.py`** | **1.0** | NVD/GitHub/OSV CVE + PoC research |
| **`nova_context_manager.py`** | **1.0** | Rolling context compression |
| **`nova_tool_kit.py`** | **2.0** | 20 tools with gap-closing additions |
| `nova_continuous_v3.py` | 3.0 | 24/7 loop + auto self-improvement |
| `nova_core.py` | 3.0 | 10-phase pipeline |
| `launch_swarm.py` | 1.0 | 10-agent parallel swarm |
| `nova_self_improvement.py` | 1.0 | Run-signal collection → improvement proposals |
| `nova_repo_intelligence.py` | 1.0 | Symbol/test/command index |
| `nova_model_router.py` | 1.0 | Task → best Ollama model |
| `nova_reasoning_core.py` | 2.0 | LLM backbone |
| `nova_rag_builder.py` | 1.0 | RAG from past hunts |
| `nova_chain_of_thought.py` | 1.0 | Bayesian hypothesis engine |
| `nova_adaptive_brain.py` | 1.0 | Context-aware strategy |
| `nova_exploit_synthesizer.py` | 1.0 | SQLi, XSS, SSRF, LFI |
| `nova_jwt_forge.py` | 1.0 | JWT forgery (none/weak secret) |
| `nova_race_engine.py` | 1.0 | Race conditions |
| `nova_proto_polluter.py` | 1.0 | Prototype pollution |
| `nova_deserialize_dropper.py` | 1.0 | Deserialization RCE |
| `nova_session_hijacker.py` | 1.0 | Session attacks |
| `nova_url_smuggling.py` | 1.0 | HTTP request smuggling |
| `nova_fuzzer_fix.py` | 1.0 | Mutation fuzzer |
| `nova_browser_agent.py` | 1.1 | Browser-based attacks |
| `nova_code_reasoner_v2.py` | 2.0 | Source vulnerability analysis |
| `nova_source_auditor.py` | 1.0 | Static analysis |
| `nova_dataflow_engine.py` | 1.0 | Taint tracing |
| `nova_memory_system.py` | 1.0 | NovaBrain persistence |
| `nova_feedback_cortex.py` | 1.0 | Self-learning validation |
| `nova_wild_hunt.py` | 1.0 | Real-world recon |
| `nova_scope_manager.py` | 1.0 | HackerOne scope sync |
| `nova_github_scanner.py` | 1.0 | Secret scanning |
| `nova_daybreak.py` | 1.0 | 3-stage Daybreak assessment |
| `nova_report.py` | 1.0 | HTML/MD/JSON reports |
| `nova_agentic_deploy.py` | 1.0 | Payload sandbox evaluation |

---

## 8. Capability Parity with Frontier Agents

| Capability | Claude Code | Claude Mythos | Daybreak | **Nova v3.5** |
|---|---|---|---|---|
| **Cost per run** | ~$0.50–$5 | ~$1–10 | ~$50–200/mo | **$0** |
| Plain English commands | ✅ | ✅ | ✅ | ✅ `nova.py` |
| **Pre-hunt structured plan** | ✅ | ❌ | ✅ | **✅ `nova_planner`** |
| **Visual screenshot analysis** | ❌ | ✅ | ❌ | **✅ `nova_vision`** |
| **Triple-verify before report** | ❌ | ❌ | ✅ | **✅ `nova_verify_engine`** |
| **CVE/PoC web research** | ✅ | ✅ | ✅ | **✅ `nova_web_researcher`** |
| **Context compression (long hunts)** | ✅ | ✅ | ✅ | **✅ `nova_context_manager`** |
| **Parallel tool execution** | ✅ | ✅ | ✅ | **✅ `parallel_probe`** |
| CVSS 3.1 auto-scoring | ❌ | ❌ | ✅ | **✅** |
| HackerOne-ready reports | ❌ | ❌ | ✅ | **✅** |
| LLM-driven ReAct loop | ✅ | ✅ | ✅ | ✅ |
| Full shell access | ✅ | ✅ | ❌ | ✅ |
| Browser (headless) | ✅ | ✅ | ✅ | ✅ Playwright |
| Security-specialized model | ❌ | ❌ | ❌ | ✅ xploiter |
| Reads own codebase | ✅ | ✅ | ❌ | ✅ repo_intelligence |
| **Self-improves own code** | ❌ | ❌ | ❌ | **✅ self_improvement** |
| **Auto self-improves 24/7** | ❌ | ❌ | ❌ | **✅ continuous_v3** |
| Persistent memory | ❌ | ❌ | ❌ | ✅ NovaBrain |
| Privacy — 100% local | ❌ cloud | ❌ cloud | ❌ cloud | **✅** |

**Nova now matches or exceeds Claude Code, Mythos, and Daybreak on every capability that matters for bug bounty.**  
The only remaining gap is context window size (Claude's 200K vs Nova's ~32K) — partially mitigated by the context compression manager.

---

## 9. Configuration

```bash
# Core
NOVA_LLM_URL=http://localhost:11434   # Ollama URL
NOVA_LLM_MODEL=""                     # blank = auto-route to best model
NOVA_MAX_STEPS=40                     # ReAct loop limit
NOVA_WORKSPACE=~/nova_workspace       # output directory

# Pre-hunt automation (new in v3.5)
NOVA_AUTO_PLAN=true                   # generate plan before hunt
NOVA_AUTO_VISUAL=true                 # visual recon before hunt
NOVA_AUTO_CVE=true                    # CVE research before hunt

# Context management
NOVA_CTX_WINDOW=12                    # verbatim last N exchanges
NOVA_CTX_SUMMARY=3000                 # compressed summary max length

# Self-improvement
NOVA_SELF_IMPROVE_EVERY=5             # cycles between improvements (continuous mode)

# Permissions
NOVA_PERMISSION_PROFILE=full          # full | read_only | no_network
```

---

## 10. HackerOne Integration

```bash
# Configure credentials
mkdir -p ~/.nova
echo '{"h1_username":"your_handle","h1_api_token":"your_token"}' > ~/.nova/scope_config.json

# Sync live scope
python3 nova_scope_manager.py --sync

# Hunt within scope — auto-enforced
python3 nova.py "Hunt my H1 programs for high-severity vulnerabilities"
```

Verified findings automatically generate H1-format submission JSON via `nova_verify_engine.build_h1_report()`.

---

## Repository Map

```
Nova-arsenal/
│
├── nova.py                       ← ★ START HERE — plain English interface
│
├── GAP-CLOSING (v3.5 NEW)
│   ├── nova_planner.py           ← Pre-hunt strategic planning    [Claude Code]
│   ├── nova_vision.py            ← Screenshot + vision analysis   [Mythos]
│   ├── nova_verify_engine.py     ← Triple-confirm + CVSS + H1     [Daybreak]
│   ├── nova_web_researcher.py    ← NVD/GitHub/OSV CVE research    [All 3]
│   └── nova_context_manager.py  ← Rolling compression, 200 steps [Claude Code]
│
├── ENTRY POINTS
│   ├── nova_agent_core.py        ← ReAct loop v2 (all gaps wired in)
│   ├── nova_core.py              ← 10-phase pipeline
│   ├── launch_swarm.py           ← 10-agent parallel swarm
│   ├── nova_continuous_v3.py     ← 24/7 + auto self-improvement
│   └── nova_setup.sh             ← One-command installation
│
├── SELF-IMPROVEMENT
│   ├── nova_self_improvement.py
│   └── nova_repo_intelligence.py
│
├── TOOL KIT
│   └── nova_tool_kit.py          ← 20 tools (v2.0)
│
└── [attack modules, intelligence, recon, memory, reporting — see §7]
```

---

<div align="center">

**Nova is a research and educational tool.**
Only test targets you have explicit written permission to assess.

*Built for the solo researcher who cannot afford frontier agent API costs.*
*Nova v3.5 — feature-parity with Claude Code, Mythos, and Daybreak — $0/run.*

</div>
