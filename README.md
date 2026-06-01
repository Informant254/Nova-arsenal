# 🦅 Nova Arsenal v4.1

<div align="center">

```
 ███╗   ██╗ ██████╗ ██╗   ██╗  █████╗
 ████╗  ██║██╔═══██╗██║   ██║ ██╔══██╗
 ██╔██╗ ██║██║   ██║██║   ██║ ███████║
 ██║╚██╗██║██║   ██║╚██╗ ██╔╝ ██╔══██║
 ██║ ╚████║╚██████╔╝ ╚████╔╝  ██║  ██║
 ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝   ╚═╝  ╚═╝   ARSENAL  v4.1
```

**Fully autonomous AI security research agent**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-green)](https://ollama.com)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o-black?logo=openai)](https://openai.com)
[![Anthropic](https://img.shields.io/badge/Anthropic-Claude--Sonnet-orange)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

*As powerful as OpenAI Agents SDK + Anthropic Claude Agent SDK — running 100% locally*

</div>

---

## What Nova Does

Nova is a production-grade autonomous security research agent built on top of OWASP Juice Shop. It:

- Accepts a single plain-English command and executes a complete bug bounty hunt end-to-end
- Runs **100+ specialist modules** covering every phase of the security research lifecycle
- Supports **OpenAI, Anthropic, Gemini, and Ollama** — auto-fallback chain, zero single-provider lock-in
- Orchestrates **multi-agent pipelines** (ReconAgent → AttackAgent → ReportAgent) with full handoffs, guardrails, typed context, and span-based tracing on every single run
- Fires **lifecycle hooks** at every event (PreRun, PostRun, PreTool, PostTool, OnFinding, OnError, OnHandoff) — the same architecture as Anthropic Claude Agent SDK
- Maintains **persistent sessions** across restarts — Nova remembers every finding, every cost, every conversation
- **Validates exploits** in a sandboxed environment before reporting
- Writes HackerOne-ready reports, executive summaries, Sigma detection rules, and code-level patches automatically
- Runs 24/7 on GitHub Actions at zero cost

---

## System Architecture

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        🦅  NOVA ARSENAL  v4.1                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   ┌─────────────────────────────────────────────────────────────────────┐    ║
║   │                     ENTRY POINT                                     │    ║
║   │                                                                     │    ║
║   │  nova_cli.py ──────────► nova.py ──────────► dispatch()            │    ║
║   │  (structured CLI)       (NLP intent parser)   (27+ modes)          │    ║
║   └────────────────────────────────┬────────────────────────────────────┘    ║
║                                    │                                          ║
║   ┌────────────────────────────────▼────────────────────────────────────┐    ║
║   │                   ⚡  PROVIDER LAYER  (v4.1 NEW)                    │    ║
║   │                                                                     │    ║
║   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │    ║
║   │  │nova_llm_router│  │  nova_hooks  │  │ nova_context │              │    ║
║   │  │              │  │              │  │              │              │    ║
║   │  │ OpenAI       │  │ PreRun       │  │ RunContext   │              │    ║
║   │  │ Anthropic    │  │ PostRun      │  │ Scope check  │              │    ║
║   │  │ Gemini       │  │ PreTool      │  │ Audit trail  │              │    ║
║   │  │ Ollama       │  │ PostTool     │  │ Child ctxs   │              │    ║
║   │  │ Auto-fallback│  │ OnFinding    │  │              │              │    ║
║   │  │ Circuit break│  │ OnError      │  │              │              │    ║
║   │  │ Cost tracking│  │ OnHandoff    │  │              │              │    ║
║   │  └──────────────┘  └──────────────┘  └──────────────┘              │    ║
║   │                                                                     │    ║
║   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │    ║
║   │  │nova_sessions │  │  nova_retry  │  │nova_observ.. │              │    ║
║   │  │              │  │              │  │              │              │    ║
║   │  │ Persist msgs │  │ Exp. backoff │  │ Span trees   │              │    ║
║   │  │ Dedup finds  │  │ Per-tool CB  │  │ Token/cost   │              │    ║
║   │  │ Cost acctng  │  │ Budget limit │  │ HTML report  │              │    ║
║   │  │ Resume runs  │  │              │  │ OTLP export  │              │    ║
║   │  └──────────────┘  └──────────────┘  └──────────────┘              │    ║
║   │                                                                     │    ║
║   │  ┌──────────────┐  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─   │    ║
║   │  │ nova_skills  │    All 7 modules wired automatically into         │    ║
║   │  │              │    nova.py and nova_orchestrator.py on every run  │    ║
║   │  │ 20+ prompt   │                                                   │    ║
║   │  │ templates    │  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─   │    ║
║   │  └──────────────┘                                                   │    ║
║   └─────────────────────────────────────────────────────────────────────┘    ║
║                                    │                                          ║
║   ┌────────────────────────────────▼────────────────────────────────────┐    ║
║   │                   🧠  AGENT LAYER                                   │    ║
║   │                                                                     │    ║
║   │  nova_orchestrator.py v2.0   ── ReconAgent                         │    ║
║   │  (all 7 modules wired)           │  AttackAgent                    │    ║
║   │                                  └─ ReportAgent                    │    ║
║   │                                                                     │    ║
║   │  nova_agent_core.py   ── ReAct loop (plan→act→observe→repeat)     │    ║
║   │  nova_swarm_v3.py     ── 10+ parallel agents                       │    ║
║   │  nova_daybreak.py     ── Scope-aware AI assessment                 │    ║
║   │  nova_triage.py       ── AI-powered findings ranker                │    ║
║   │  nova_mcp_client.py   ── Model Context Protocol                    │    ║
║   └─────────────────────────────────────────────────────────────────────┘    ║
║                                    │                                          ║
║   ┌────────────────────────────────▼────────────────────────────────────┐    ║
║   │              🔬  SCANNING LAYER  (27 modes)                         │    ║
║   │                                                                     │    ║
║   │  ┌─── PASSIVE ────────────────────────────────────────────────┐    │    ║
║   │  │ nova_recon.py          Subdomain + endpoint discovery       │    │    ║
║   │  │ nova_source_auditor.py SAST: secrets, hardcoded creds       │    │    ║
║   │  │ nova_git_scanner.py    Git history secret extraction        │    │    ║
║   │  │ nova_sca_scanner.py    npm/pip/cargo CVE matching           │    │    ║
║   │  │ nova_supply_chain_scorer.py  Typosquatting, maintainer risk  │    │    ║
║   │  │ nova_cicd_scanner.py   GitHub Actions / Jenkins audit       │    │    ║
║   │  │ nova_container_scanner.py  Docker/K8s audit                 │    │    ║
║   │  │ nova_github_scanner.py Public repo secret detection         │    │    ║
║   │  └────────────────────────────────────────────────────────────┘    │    ║
║   │                                                                     │    ║
║   │  ┌─── ACTIVE ─────────────────────────────────────────────────┐    │    ║
║   │  │ nova_fuzzer.py         SQLi, XSS, param fuzzing             │    │    ║
║   │  │ nova_idor_scanner.py   IDOR / BOLA horizontal escalation    │    │    ║
║   │  │ nova_graphql_tester.py Introspection + injection            │    │    ║
║   │  │ nova_csrf_tester.py    SameSite + origin validation         │    │    ║
║   │  │ nova_business_logic.py Neg prices, coupon stacking, races   │    │    ║
║   │  │ nova_jwt_forge.py      alg:none, key confusion, claim tamper│    │    ║
║   │  │ nova_race_engine.py    Concurrent request race conditions    │    │    ║
║   │  │ nova_proto_polluter.py __proto__ / constructor pollution     │    │    ║
║   │  │ nova_url_smuggling.py  HTTP request smuggling               │    │    ║
║   │  │ nova_session_hijacker.py  Session fixation / hijacking      │    │    ║
║   │  │ nova_llm_injection.py  Prompt injection against AI features │    │    ║
║   │  │ nova_sandbox_validator.py  Exploit POC confirmation          │    │    ║
║   │  └────────────────────────────────────────────────────────────┘    │    ║
║   └─────────────────────────────────────────────────────────────────────┘    ║
║                                    │                                          ║
║   ┌────────────────────────────────▼────────────────────────────────────┐    ║
║   │              📊  OUTPUT LAYER                                       │    ║
║   │                                                                     │    ║
║   │  nova_threat_model.py     ── STRIDE threat model generation         │    ║
║   │  nova_zero_day_correlator.py ─ Live NVD/OSV CVE correlation         │    ║
║   │  nova_patch_generator.py  ── AI-generated code fixes + tests        │    ║
║   │  nova_detection_engineer.py ─ Sigma/KQL/Suricata rules              │    ║
║   │  nova_audit_reporter.py   ── Executive + compliance reports         │    ║
║   │  nova_vuln_tracker.py     ── SQLite vulnerability database           │    ║
║   │  nova_report.py           ── HackerOne-ready report writer          │    ║
║   └─────────────────────────────────────────────────────────────────────┘    ║
║                                    │                                          ║
║   ┌────────────────────────────────▼────────────────────────────────────┐    ║
║   │              🧬  LEARNING LAYER                                     │    ║
║   │                                                                     │    ║
║   │  nova_memory_system.py   ── Persistent hunt memory (NovaBrain)      │    ║
║   │  nova_adaptive_brain.py  ── Pattern learning from past hunts        │    ║
║   │  nova_evolution.py       ── Safe self-modification engine           │    ║
║   │  nova_continuous.py      ── 24/7 autonomous hunt loop              │    ║
║   └─────────────────────────────────────────────────────────────────────┘    ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

## Data Flow — What Happens on Every Run

```
python3 nova.py "Hunt https://target.com"
         │
         ▼
  ┌──────────────────┐
  │ _parse_intent()  │  LLM + keyword match → mode="hunt", target="https://target.com"
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  _init_provider_layer()                                              │
  │                                                                      │
  │  LLMRouter      ← picks best provider: OpenAI→Anthropic→Gemini→Ollama│
  │  HookBus        ← wires PreRun/PostRun/PreTool/PostTool/OnFinding   │
  │  RunContext      ← typed shared state with scope enforcement         │
  │  Session         ← creates/resumes ~/nova_workspace/sessions/<id>   │
  │  Tracer          ← span tree for every operation                    │
  └────────┬─────────────────────────────────────────────────────────────┘
           │
           ▼  fire("PreRun")
  ┌──────────────────────────────────────────────────────────────────────┐
  │  dispatch()  — 12 phases, all sharing the same context/session/bus  │
  │                                                                      │
  │  Phase 1: SAST + SCA + Git + CI/CD + Container                     │
  │  Phase 2: Threat Modeling                                           │
  │  Phase 3: Passive Recon                                             │
  │  Phase 4: Active Vuln Testing (IDOR, GraphQL, CSRF, BL, JWT, SQLi) │
  │  Phase 5: CVE Correlation                                           │
  │  Phase 6: Exploit Validation                                        │
  │  Phase 7: Multi-Agent Orchestration                                 │
  │  Phase 8: Daybreak AI Assessment                                    │
  │  Phase 9: Full-Stack Active Probe                                   │
  │  Phase 10: Patch + Detection + Report Generation                    │
  │  Phase 11: AI Triage + H1 Prioritisation                           │
  │  Phase 12: Vuln Tracker Dashboard                                   │
  └────────┬─────────────────────────────────────────────────────────────┘
           │
           ▼  fire("PostRun")
  ┌──────────────────────────────────────────────────────────────────────┐
  │  _emit_findings()  →  HookBus · RunContext · Session · VulnTracker  │
  │  _TRACER.save()    →  ~/nova_workspace/nova_trace_<ts>.json + .html │
  │  _STORE.save()     →  ~/nova_workspace/sessions/<id>.json           │
  └──────────────────────────────────────────────────────────────────────┘
           │
           ▼
  ┌──────────────────┐
  │   Terminal       │  🔴 CRITICAL/HIGH findings → exit code 1 (CI/CD integration)
  │   Summary        │  📊 Count · Cost · Session ID · File path
  └──────────────────┘
```

---

## Multi-Agent Orchestrator Flow

```
nova_orchestrator.py v2.0 — build_security_network("https://target.com")
│
├── LLMRouter     auto-selects: OpenAI → Anthropic → Gemini → Ollama
├── HookBus       PreRun fires; Telegram alert wired if NOVA_TELEGRAM_TOKEN set
├── RunContext     scope enforcement on every tool call; findings deduplicated
├── Session        persisted to disk after every handoff
├── Tracer         span tree: Run → Agent → Tool/LLM spans → HTML flame graph
└── ResilientCaller  wraps every tool: 3-attempt retry + per-tool circuit breaker
         │
         ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  ReconAgent  (max 15 steps)                                  │
  │  Tools: http_probe · shell(subfinder, httpx, gau, katana)   │
  │  Goal: discover subdomains, endpoints, JS files, tech stack  │
  └──────────────────────┬───────────────────────────────────────┘
                         │  handoff → state + recon data
                         ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  AttackAgent  (max 25 steps)                                 │
  │  Tools: http_probe · shell(nuclei, ffuf) · python_eval      │
  │  Goal: IDOR · SQLi · XSS · SSRF · auth bypass · BL flaws   │
  │  Output schema: [{type, severity, endpoint, evidence, cvss}] │
  └──────────────────────┬───────────────────────────────────────┘
                         │  handoff → findings JSON
                         ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  ReportAgent  (max 10 steps)                                 │
  │  Tools: python_eval · read_file                             │
  │  Goal: executive summary · risk score · H1 readiness        │
  └──────────────────────────────────────────────────────────────┘
```

---

## Installation

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 20.04 / macOS 12 | Kali Linux 2024 / Ubuntu 22.04 |
| Python | 3.10 | 3.12 |
| RAM | 8 GB | 16 GB+ |
| Storage | 20 GB | 50 GB+ |
| CPU | 4 cores | 8+ cores |
| GPU | None (CPU inference) | NVIDIA 8 GB VRAM |

---

### Step 1 — Clone

```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
```

---

### Step 2 — Run Setup

```bash
chmod +x nova_setup.sh
./nova_setup.sh
```

**What it installs:**

| Category | Tools |
|----------|-------|
| Python runtime | venv at `~/nova_workspace/.venv`, all pip deps |
| Local LLM | Ollama + `qwen3:8b` (primary), `llama3.2` (fallback), `nomic-embed-text` (RAG) |
| Recon tools | `subfinder`, `httpx`, `gau`, `katana`, `amass`, `assetfinder` |
| Attack tools | `nuclei`, `ffuf`, `sqlmap`, `arjun`, `wafw00f` |
| Browsers | Playwright Chromium + Selenium |
| Analysis | `semgrep`, `bandit`, `safety`, `pip-audit`, `detect-secrets` |
| Workspace | `~/nova_workspace/` with reports, sessions, traces, wordlists |

**Flags:**

```bash
./nova_setup.sh --minimal       # Python deps only — no security tools, no models
./nova_setup.sh --models-only   # Pull Ollama models only
./nova_setup.sh --tools-only    # Install security tools only
```

---

### Step 3 — Activate Virtual Environment

```bash
source ~/nova_workspace/.venv/bin/activate
```

To auto-activate in every terminal:

```bash
echo 'source ~/nova_workspace/.venv/bin/activate' >> ~/.bashrc
source ~/.bashrc
```

---

### Step 4 — Configure LLM Providers

Nova uses a priority chain: **OpenAI → Anthropic → Gemini → Ollama**  
The first available provider wins. Ollama is always the final fallback (free, local, zero data leakage).

#### Option A — Local Only (Zero Cost, Zero Data Leakage)

```bash
# Verify Ollama is running and model is available
curl http://localhost:11434/api/tags
ollama pull qwen3:8b          # primary model
ollama pull llama3.2          # fallback model

# Test
python3 nova_llm_router.py "Hello — which providers are available?"
```

#### Option B — OpenAI (GPT-4o, o3)

```bash
export OPENAI_API_KEY="sk-..."
export NOVA_OPENAI_MODEL="gpt-4o"          # or: gpt-4o-mini  o3
```

#### Option C — Anthropic (Claude Sonnet 4 / Opus 4)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export NOVA_ANTHROPIC_MODEL="claude-sonnet-4-5"   # or: claude-opus-4-5  claude-haiku-3-5
```

#### Option D — Google Gemini

```bash
export GEMINI_API_KEY="AIza..."
export NOVA_GEMINI_MODEL="gemini-2.0-flash"        # or: gemini-2.5-pro
```

#### Recommended — All Providers (Best Performance + Failover)

```bash
cat >> ~/.bashrc << 'EOF'
# Nova Arsenal — LLM Providers
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="AIza..."
EOF
source ~/.bashrc

# Test the router
python3 nova_llm_router.py "What providers are available?"
python3 nova_llm_router.py --provider anthropic "Summarise OWASP Top 10 in 3 lines"
python3 nova_llm_router.py --stream "Explain SSRF in one paragraph"
```

---

### Step 5 — Configure Notifications (Optional)

#### Telegram (Real-Time CRITICAL/HIGH Alerts)

```bash
# 1. Talk to @BotFather on Telegram → /newbot → copy the token
# 2. Send a message to your bot, then visit:
#    https://api.telegram.org/bot<TOKEN>/getUpdates  → find chat.id
export NOVA_TELEGRAM_TOKEN="1234567890:ABCdef..."
export NOVA_TELEGRAM_CHAT_ID="987654321"
```

Nova automatically sends alerts for CRITICAL/HIGH findings and errors.

#### Discord

```bash
# Server Settings → Integrations → Webhooks → New Webhook → Copy URL
export NOVA_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
```

#### Slack

```bash
# api.slack.com → Incoming Webhooks → Activate → Copy URL
export NOVA_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
```

---

### Step 6 — Edit Configuration (Optional)

```bash
cp nova_config.json ~/nova_workspace/nova_config.json
nano ~/nova_workspace/nova_config.json
```

Key settings:

```jsonc
{
  "llm": {
    "model": "auto",           // "auto" = use best available provider
    "fallback_model": "llama3.2",
    "timeout": 120
  },
  "recon": {
    "max_subdomains": 500,
    "max_urls": 10000,
    "threads": 10
  },
  "attack": {
    "severity_threshold": "low",        // report everything low+
    "max_payloads_per_param": 50,
    "respect_robots": false
  },
  "notifications": {
    "min_severity": "high"              // only alert on high+
  }
}
```

---

### Step 7 — Verify Installation

```bash
python3 nova_cli.py status
```

Expected output:
```
✅  nova_llm_router         ✅  nova_hooks
✅  nova_context            ✅  nova_sessions
✅  nova_retry              ✅  nova_observability
✅  nova_skills             ✅  nova_orchestrator
✅  nova_triage             ✅  nova_daybreak
✅  nova_agent_core         ✅  nova_swarm_v3
✅  nova_recon              ✅  nova_fuzzer
✅  [... 35 modules total]

🔀  LLM Providers: openai, anthropic, ollama
📁  Workspace: ~/nova_workspace/
📂  Sessions: 0 saved

═══════════════════════════════════════════════
  35 modules ready, 0 missing
```

---

### Step 8 — Optional: Add `nova` to PATH

```bash
chmod +x nova_cli.py
sudo ln -sf "$(pwd)/nova_cli.py" /usr/local/bin/nova
nova status   # works from anywhere
```

Or with an alias:

```bash
echo "alias nova='python3 $(pwd)/nova_cli.py'" >> ~/.bashrc
source ~/.bashrc
```

---

## Usage

### Plain-English via nova.py (Simplest)

```bash
python3 nova.py "Hunt https://target.com for all bugs"
python3 nova.py "Orchestrate multi-agent recon+attack on https://target.com"
python3 nova.py "Full stack pipeline on ./juice-shop"
python3 nova.py "Daybreak AI assessment on https://target.com"
python3 nova.py "Triage my findings and rank them for H1"
python3 nova.py "SAST scan of ./src"
python3 nova.py "Check dependency security for ./package.json"
python3 nova.py "Scan git history for leaked secrets"
python3 nova.py "Build a STRIDE threat model for ./my-app"
python3 nova.py "Test GraphQL at http://localhost:4000"
python3 nova.py "Health check"

# Resume a previous session
python3 nova.py "Continue hunting https://target.com" --session abc12345
```

### Structured CLI via nova_cli.py

```bash
# Bug bounty hunt
nova hunt   https://target.com
nova hunt   https://target.com --provider openai --session abc123

# Full-stack (all 27 modules)
nova full   https://target.com
nova full   ./juice-shop

# Multi-agent orchestrator
nova orch   https://target.com

# Passive recon
nova recon  https://target.com

# Specific scan modes
nova scan   sqli       https://target.com
nova scan   idor       https://target.com
nova scan   xss        https://target.com
nova scan   csrf       https://target.com
nova scan   jwt        https://target.com
nova scan   graphql    https://target.com
nova scan   race       https://target.com
nova scan   ssrf       https://target.com
nova scan   container  ./

# Static analysis
nova sast   ./src
nova sca    ./

# Triage + reporting
nova triage
nova report

# Provider management
nova providers
nova providers --test

# Session management
nova session list
nova session list --target target.com
nova session resume abc12345
nova session export abc12345 --output ~/report.json
nova session delete abc12345

# System status
nova status
```

---

## Dispatch Modes Reference

| Command / Mode | What Runs | Phases |
|---|---|---|
| `full_stack` | Every module in sequence | 1–12 |
| `orchestrate` | ReconAgent → AttackAgent → ReportAgent | 7 |
| `daybreak` | NovaDaybreak + NovaScopeManager | 8 |
| `hunt` | NovaAgentCore ReAct loop | 4, 7 |
| `swarm` | 10+ parallel agents | 7 |
| `triage` | NovaTriage AI prioritiser | 11 |
| `recon` | NovaRecon passive discovery | 3 |
| `fuzz` | NovaFuzzer dir + param fuzzing | 4 |
| `sqli` | NovaFuzzer SQLi suite | 4 |
| `xss` | NovaFuzzer XSS suite | 4 |
| `idor` | NovaIDORScanner BOLA/horizontal | 4 |
| `graphql` | NovaGraphQLTester introspection+injection | 4 |
| `csrf` | NovaCsrfTester SameSite analysis | 4 |
| `jwt` | NovaJWTForge alg:none/key confusion | 4 |
| `race` | NovaRaceEngine concurrent requests | 4 |
| `ssrf` | NovaFuzzer SSRF chain | 4 |
| `business_logic` | NovaBusinessLogicTester | 4 |
| `llm_injection` | NovaLLMInjectionTester | 4 |
| `proto_pollution` | NovaProtoPolluter | 4 |
| `sast` | NovaSourceAuditor + FilePrioritizer | 1 |
| `sca` | NovaSCAScanner + SupplyChainScorer | 1 |
| `supply_chain` | NovaSupplyChainScorer typosquat/maintainer | 1 |
| `git_scan` | NovaGitScanner history extraction | 1 |
| `cicd` | NovaCICDScanner GitHub Actions/Jenkins | 1 |
| `container` | NovaContainerScanner Docker/K8s | 1 |
| `threat_model` | NovaThreatModel STRIDE generation | 2 |
| `zero_day` | NovaZeroDayCorrelator live CVE | 5 |
| `sandbox` | NovaSandboxValidator exploit confirm | 6 |
| `patch` | NovaPatchGenerator code fixes | 10 |
| `detect` | NovaDetectionEngineer Sigma/KQL | 10 |
| `audit_report` | NovaAuditReporter executive/compliance | 10 |
| `vuln_track` | NovaVulnTracker SQLite dashboard | 12 |
| `bootstrap` | Health check all modules | — |
| `continuous` | 24/7 hunt loop | all |

---

## Provider Layer — Module Reference

### nova_llm_router.py — Multi-Provider LLM

```python
from nova_llm_router import get_router, Provider

router = get_router()
print(router.available_providers())   # ['openai', 'anthropic', 'ollama']

# Auto-select best provider
resp = router.chat("Analyse this JWT: eyJhbGci...")
print(f"[{resp.provider}/{resp.model}] {resp.latency_ms:.0f}ms  ${resp.cost_usd:.5f}")
print(resp.content)

# Force specific provider
resp = router.chat("...", provider=Provider.ANTHROPIC)

# Streaming
for token in router.stream("Summarise these findings: ..."):
    print(token, end="", flush=True)

# Structured output (JSON schema enforced across all providers)
schema = {
    "type": "object",
    "properties": {
        "severity": {"type": "string", "enum": ["CRITICAL","HIGH","MEDIUM","LOW"]},
        "cvss":     {"type": "number"},
        "summary":  {"type": "string"}
    }
}
result = router.chat_structured("Score this SQLi finding", schema=schema)
# → {"severity": "HIGH", "cvss": 8.2, "summary": "..."}
```

---

### nova_hooks.py — Lifecycle Hooks

```python
from nova_hooks import get_bus, attach_logging_hooks, attach_telegram_hooks

bus = get_bus()
attach_logging_hooks(bus)                            # → nova_events.jsonl
attach_telegram_hooks(bus, token, chat_id)           # CRITICAL/HIGH alerts to Telegram

# Register custom hooks
@bus.on("OnFinding")
def save_to_jira(ctx):
    f = ctx["finding"]
    if f.get("severity") == "CRITICAL":
        jira.create_issue(f)

@bus.on("PreTool", priority=0)
def enforce_scope(ctx):
    url = ctx.get("args", {}).get("url", "")
    if "out-of-scope.com" in url:
        ctx["_hook_event"].cancelled = True          # blocks the tool call

# Fire manually
bus.fire("PreRun", {"agent": "ReconAgent", "target": "example.com"})
bus.fire_finding({"type": "XSS", "severity": "HIGH", "endpoint": "/search"})
```

**All hook events:**

| Event | Fires when |
|-------|-----------|
| `PreRun` | Before any agent run starts |
| `PostRun` | After the run completes |
| `PreTool` | Before a tool is called — can cancel the call |
| `PostTool` | After a tool returns |
| `OnFinding` | When any module emits a security finding |
| `OnError` | When any agent or tool raises an exception |
| `OnHandoff` | When one agent hands off to another |
| `OnHandoffDone` | After the receiving agent completes |
| `OnGuardrailBlock` | When a guardrail cancels an action |
| `OnStream` | Each streaming token from the LLM |
| `OnMemoryWrite` | When nova_memory_system writes |
| `OnPhaseStart` / `OnPhaseEnd` | Around each dispatch phase |

---

### nova_context.py — Typed Context Variables

```python
from nova_context import RunContext

ctx = RunContext(
    target="https://example.com",
    scope=["example.com", "*.example.com"],
    max_steps=40)

# Typed access
ctx.set("phase", "attack")
ctx.append("subdomains", "api.example.com", dedupe=True)
ctx.add_finding({"type": "SQLi", "severity": "HIGH", "endpoint": "/api/search"})

# Scope enforcement
print(ctx.in_scope("https://api.example.com/users"))  # True
print(ctx.in_scope("https://evil.com"))               # False

# Per-agent child context
recon_ctx  = ctx.child("ReconAgent")
attack_ctx = ctx.child("AttackAgent")
ctx.sync_from_child(recon_ctx)    # merge findings back to parent

# Persist & restore
ctx.save()                        # ~/nova_workspace/context_<session>.json
ctx2 = RunContext.load(path)
print(ctx.summary())
```

---

### nova_sessions.py — Persistent Sessions

```python
from nova_sessions import SessionStore

store   = SessionStore()                              # ~/nova_workspace/sessions/
session = store.create(target="https://example.com", mission="full_stack")

# Conversation history survives restarts
session.add_message("user",      "Hunt example.com for IDOR")
session.add_message("assistant", "Starting IDOR scan...")

# Deduplicated cross-run findings
session.add_finding({"type": "SQLi", "severity": "HIGH", "endpoint": "/api"})
session.add_finding({"type": "SQLi", "severity": "HIGH", "endpoint": "/api"})  # deduped

# Working memory
session.remember("admin_token", "Bearer abc123")
token = session.recall("admin_token")

# Cost accounting
run = session.start_run("full_stack")
# ... run modules ...
session.end_run(run, findings_count=5, cost_usd=0.04, token_total=12000)
store.save(session)

# Resume
session = store.load(session.session_id)
print(session.all_findings(min_severity="HIGH"))
print(f"Total cost: ${session.total_cost_usd:.5f}")
```

---

### nova_observability.py — Execution Tracing

```python
from nova_observability import Tracer

tracer = Tracer(run_id="hunt_20260601", verbose=True)

with tracer.span("ReconAgent", kind="agent") as recon:
    recon.set("target", "example.com")

    with tracer.tool_span("subfinder", args={"domain": "example.com"}, parent=recon) as t:
        # ... run subfinder ...
        t.set("result_count", 42)

    with tracer.llm_span("gpt-4o", "openai", parent=recon) as llm:
        llm.tokens_in  = 800
        llm.tokens_out = 300
        llm.cost_usd   = 0.005

tracer.print_tree()         # coloured span tree in terminal
tracer.save()               # ~/nova_workspace/trace_hunt_20260601.json
tracer.export_html()        # ~/nova_workspace/trace_hunt_20260601.html
print(tracer.summary())
```

---

### nova_retry.py — Retry + Circuit Breaker

```python
from nova_retry import retry, CircuitBreaker, ResilientCaller

# Decorator usage
@retry(max_attempts=5, base_delay=1.0, max_delay=30.0, jitter=True)
def call_nuclei(target):
    ...

# Circuit breaker — per-service
cb = CircuitBreaker("nuclei", threshold=3, reset_after=60)
if cb.is_open():
    print("nuclei circuit breaker open — skipping")
else:
    result = call_nuclei(target)
    cb.record_success()

# Combined: retry + circuit breaker (used in nova_orchestrator for all tools)
caller = ResilientCaller("subfinder", cb_threshold=3, cb_reset=60.0)
result = caller.call(subfinder_fn, domain="example.com")
```

---

### nova_skills.py — Reusable Prompt Templates

```python
from nova_skills import SkillLibrary

lib = SkillLibrary()
print(lib.categories())                          # ['attack', 'recon', 'analysis', 'report']
print(lib.list_skills(category="attack"))        # 7 attack skills

# Render a skill → get system + user prompts
prompts = lib.render("sqli_analysis",
    target="example.com",
    endpoint="/api/search",
    param="q",
    method="GET",
    request_sample="GET /api/search?q=test HTTP/1.1\nHost: example.com")

# Feed to the LLM router
from nova_llm_router import get_router
resp = get_router().chat(prompts["user"], system=prompts["system"])
payloads = json.loads(resp.content)

# Register custom skill
from nova_skills import Skill
lib.register(Skill(
    name="my_oauth_attack",
    category="attack",
    description="Test OAuth 2.0 flows for common misconfigurations",
    system="You are an OAuth security specialist...",
    template="Target: {target}\nOAuth endpoint: {auth_url}\nTest for: {tests}",
    params=["target", "auth_url", "tests"],
    tags=["attack", "oauth", "auth"]))
```

**Built-in skills:**

| Skill | Category | Tests for |
|-------|----------|-----------|
| `subdomain_analysis` | recon | High-value attack surface ranking |
| `js_secret_analysis` | recon | Leaked keys, endpoints in JS |
| `sqli_analysis` | attack | 10 targeted SQLi payloads |
| `idor_analysis` | attack | Ownership check gaps, BOLA |
| `xss_analysis` | attack | Context-aware XSS payloads |
| `jwt_attack` | attack | alg:none, key confusion, claim tamper |
| `ssrf_analysis` | attack | Cloud metadata, internal network |
| `business_logic_analysis` | attack | Payment, workflow, race flaws |
| `sast_triage` | analysis | False-positive triage, exploitability |
| `threat_model_stride` | analysis | STRIDE full threat model |
| `patch_generation` | analysis | Root-cause + fix + test |
| `h1_report` | report | HackerOne submission |
| `executive_summary` | report | Business risk, non-technical |

---

## Cloud Deployment: GitHub Actions (24/7 Free)

```yaml
# .github/workflows/nova.yml
name: Nova Continuous Hunt
on:
  schedule:
    - cron: '0 */6 * * *'   # every 6 hours
  workflow_dispatch:
    inputs:
      target:
        description: 'Target URL'
        required: true
jobs:
  hunt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: ./nova_setup.sh --minimal
      - run: python3 nova.py "Full stack hunt on ${{ github.event.inputs.target }}"
        env:
          OPENAI_API_KEY:          ${{ secrets.OPENAI_API_KEY }}
          ANTHROPIC_API_KEY:       ${{ secrets.ANTHROPIC_API_KEY }}
          NOVA_TELEGRAM_TOKEN:     ${{ secrets.NOVA_TELEGRAM_TOKEN }}
          NOVA_TELEGRAM_CHAT_ID:   ${{ secrets.NOVA_TELEGRAM_CHAT_ID }}
          NOVA_TARGET:             ${{ github.event.inputs.target }}
```

Or use the cloud helper:

```bash
python3 nova_cloud.py hunt https://target.com
python3 nova_cloud.py watch <run-id>
python3 nova_cloud.py results
```

---

## Workspace Structure

```
~/nova_workspace/
├── sessions/              ← Persistent sessions (JSON, one per target run)
│   └── abc12345.json
├── reports/               ← Generated reports (MD, HTML, JSON)
├── logs/                  ← nova_events.jsonl (all hook events)
├── memory/                ← NovaBrain persistent memory
├── wordlists/             ← Attack wordlists
├── screenshots/           ← Browser screenshots from Playwright
├── bin/                   ← Installed security tool binaries
├── nova_trace_<ts>.json   ← Execution span trace (JSON)
├── nova_trace_<ts>.html   ← Execution flame graph (HTML, open in browser)
├── nova_<mode>_<ts>.json  ← Raw findings per run
├── nova_triage_report.json ← AI-ranked findings
├── nova_audit_report.json  ← Executive report
├── nova_patches.json       ← AI-generated code fixes
├── nova_detection_rules.json ← Sigma / KQL rules
└── nova_tracker_dashboard.md ← Markdown vuln dashboard
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | OpenAI API key |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `GEMINI_API_KEY` | — | Google Gemini API key |
| `NOVA_LLM_URL` | `http://localhost:11434` | Ollama server URL |
| `NOVA_LLM_MODEL` | `qwen3:8b` | Ollama model name |
| `NOVA_OPENAI_MODEL` | `gpt-4o` | OpenAI model |
| `NOVA_ANTHROPIC_MODEL` | `claude-sonnet-4-5` | Anthropic model |
| `NOVA_GEMINI_MODEL` | `gemini-2.0-flash` | Gemini model |
| `NOVA_WORKSPACE` | `~/nova_workspace` | All output goes here |
| `NOVA_MAX_STEPS` | `40` | Max ReAct loop steps |
| `NOVA_TARGET` | `http://localhost:3000` | Default target |
| `NOVA_TELEGRAM_TOKEN` | — | Telegram bot token |
| `NOVA_TELEGRAM_CHAT_ID` | — | Telegram chat ID |
| `NOVA_DISCORD_WEBHOOK` | — | Discord webhook URL |
| `NOVA_SLACK_WEBHOOK` | — | Slack webhook URL |

---

## Troubleshooting

### Ollama not found / model not found

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start server
ollama serve &

# Pull models
ollama pull qwen3:8b
ollama pull llama3.2

# Verify
curl http://localhost:11434/api/tags
```

### "All LLM providers failed"

```bash
# Check Ollama is up
curl http://localhost:11434/api/tags

# Verify API keys are set
echo "OpenAI:    ${OPENAI_API_KEY:0:8}..."
echo "Anthropic: ${ANTHROPIC_API_KEY:0:8}..."

# Run router diagnostic
python3 nova_llm_router.py "test"
```

### Import errors / missing modules

```bash
source ~/nova_workspace/.venv/bin/activate
pip install -r requirements.txt

# Or re-run setup
./nova_setup.sh --minimal
```

### Playwright browser not found

```bash
playwright install chromium
playwright install-deps chromium
```

### Circuit breaker open for a tool

Circuit breakers auto-reset after 60 seconds. To clear immediately, restart nova.

```bash
python3 nova_cli.py status   # check current state
```

### Session not found

```bash
python3 nova_cli.py session list   # show all saved sessions
```

### Exit code 1 in CI

This is expected — Nova returns exit code 1 when it finds CRITICAL or HIGH severity bugs. Use it in your CI pipeline:

```bash
python3 nova.py "Hunt https://staging.example.com" || echo "VULNERABILITIES FOUND"
```

---

## Feature Comparison

| Feature | Nova Arsenal v4.1 | OpenAI Agents SDK | Anthropic Agent SDK |
|---|---|---|---|
| Multi-agent orchestration | ✅ | ✅ | ✅ |
| Agent handoffs | ✅ | ✅ | ✅ |
| Input / output guardrails | ✅ | ✅ | ✅ |
| Lifecycle hooks | ✅ 12 events | Partial | ✅ 4 events |
| Typed context variables | ✅ | ✅ | — |
| Structured outputs | ✅ All 4 providers | ✅ OpenAI only | ✅ Claude only |
| Streaming | ✅ All 4 providers | ✅ | ✅ |
| Span-based tracing + HTML | ✅ | ✅ | Partial |
| Persistent sessions | ✅ | ✅ | — |
| Reusable skills/templates | ✅ 13 built-in | — | ✅ |
| Multi-provider LLM | ✅ 4 providers | Partial | ❌ Claude only |
| Per-tool circuit breaker | ✅ | ❌ | ❌ |
| Retry with budget limit | ✅ | Partial | Partial |
| Cost per span | ✅ | Partial | ❌ |
| Local / offline mode | ✅ Ollama | ❌ | ❌ |
| Security domain built-in | ✅ 100+ modules | ❌ | ❌ |
| GitHub Actions 24/7 | ✅ | Partial | — |
| Zero cost option | ✅ Ollama | ❌ | ❌ |
| HackerOne integration | ✅ | — | — |
| SAST / SCA built-in | ✅ | ❌ | ❌ |
| Exploit validation | ✅ | ❌ | ❌ |
| Detection rule generation | ✅ Sigma/KQL | ❌ | ❌ |

---

## License

MIT — see [`LICENSE`](LICENSE) for details.

**Bug bounty responsibly.** Only test systems you have written permission to test.  
HackerOne safe-harbor applies when targeting programs that explicitly grant it.
