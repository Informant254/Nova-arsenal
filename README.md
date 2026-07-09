# Nova-Arsenal

[![CI](https://github.com/Informant254/Nova-arsenal/actions/workflows/ci.yml/badge.svg)](https://github.com/Informant254/Nova-arsenal/actions/workflows/ci.yml)
[![Security](https://github.com/Informant254/Nova-arsenal/actions/workflows/security.yml/badge.svg)](https://github.com/Informant254/Nova-arsenal/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Kubernetes](https://img.shields.io/badge/kubernetes-ready-326CE5?logo=kubernetes&logoColor=white)](k8s/)

**Autonomous security research platform with a real conversational chat UI**

Nova is two things at once:

1. **A chat assistant** — talk to it like ChatGPT/Claude/Grok (streaming web UI + VS Code + API).
2. **A security agent stack** — recon, swarm, tools, and zero-day *candidate* research for **authorized** work only.

### How powerful is it (honest)

| Layer | Strength | Limit |
|-------|----------|--------|
| **Conversation** | Multi-turn chat with history, streaming, your LLM (ChatGPT OAuth / API keys / **local Ollama**) | Quality = whichever model you connect |
| **Security knowledge** | Broad Kali/tooling/concepts; offline tool cards when no LLM | Not a substitute for an expert human |
| **Automation** | Swarm phases, tool selection, integrations (Nmap/Burp/MSF/SQLmap APIs) | Needs tools installed + scope/authorization |
| **Zero-day pipeline** | Fast ranking, variants, fuzz *plans*, crash triage | **Candidates in seconds**, not guaranteed 0-days |
| **Subscriptions** | ChatGPT/Codex OAuth, API keys, Ollama | Claude Pro OAuth is not a clean third-party path |

> ⚠️ **Ethical use only** — only test systems you have written permission to assess.

### Chat like a normal AI

```bash
# 1) Give Nova a brain (pick one)
nova-agent login --provider openai --oauth    # ChatGPT subscription
# or
nova-agent login --provider ollama            # free local

# 2) Start API + open the chat UI
python -m nova_arsenal.api
# → http://localhost:8000   (Chat tab — stream replies)
```

Also: VS Code **Nova: Open Chat**, or `POST /api/chat/stream` / `POST /api/chat/send`.

---

## Features

- **300+ Security Modules** – Massive Kali Linux knowledge base across 35 categories, including new Cloud, AD, Mobile, and IoT/SCADA suites.
- **V2.0 Multi-Agent Swarm** – Phased orchestration: **Recon → Zero-Day Researcher → Web/Exploit/Validator**, with weighted consensus. Researcher automatically runs `ZeroDayHunter` on recon output.
- **Self-Evolution Loop** – Nova now analyzes her own trajectories in real-time, detecting failures, breaking infinite loops, and self-authoring new skills autonomously.
- **Fugu-Style LLM Orchestration** – Dynamic routing across 10 providers (Anthropic, OpenAI, Gemini, DeepSeek, Qwen, OpenRouter, Ollama, HuggingFace, Opencode) with automatic fallback
- **Native Tool Integrations** – Programmatic control of Metasploit (msfrpcd REST), Burp Suite (REST API + GraphQL), SQLmap (API mode), and Nmap (XML parsing)
- **Skills Marketplace** – Installable platform connectors; Nova can also self-author new skills after novel tasks, pending human review before they go live
- **Platform Connectors** – HackerOne, Bugcrowd, HackTheBox, TryHackMe; Nova reasons across all connected platforms to recommend which target is worth her time
- **Persistent Memory** – Per-user SQLite memory: task log, target history, findings, preferences – the "what were we working on?" answer at the start of every session
- **Self-Training RL Pipeline** – GRPO-based training on Nova's own pentest trajectories; Muon optimizer; cross-stage knowledge distillation
- **Tool-Selection Intelligence** – Rule engine maps discovered services to optimal tools automatically (Port 445 → Metasploit SMB modules, web app → Burp + nuclei, etc.)
- **Cross-Tool Result Correlation** – Findings from Nmap + Burp + Metasploit + SQLmap are correlated; multi-source confirmed vulnerabilities get boosted confidence scores
- **Fix Verification** – 1-click retest to confirm a vulnerability was actually remediated
- **Incremental Testing** – Only retests what changed between versions
- **CTF Solver Mode** – Automatic challenge classification and solve pipelines (web, crypto, stego, pwn, OSINT, forensics, reversing)
- **MCP Server Export** – Nova exposes her tools via JSON-RPC so Cursor, Claude, and any MCP-compatible agent can use her as a plugin
- **VS Code Extension** – 6 commands, webview chat panel, streaming responses, one-click run
- **Web Dashboard** – Dark-themed Next.js UI with real-time agent chat, target management, findings review, and skills approval queue
- **E2E Encryption** – RSA-4096 + AES-256-GCM for agent communications
- **🔄 Production Resilience** – Async timeouts, circuit breakers, retry budgets, and resource limits prevent agent hangs and cascading failures
- **⚡ Zero-Day Candidate Pipeline** – Seconds-scale attack-surface ranking, CVE variant/patch-gap analysis, static bug-class scan, **live fuzz worker** (ffuf / AFL++ / honggfuzz / radamsa / HTTP mutator when installed), crash triage, and novelty scoring. Outputs ranked *research candidates* (not auto-confirmed 0-days). Authorization-gated for live execution.

📖 **[See the full feature reference →](docs/FEATURES.md)** — deep-dive config snippets and internals for every module above.

---

## Zero-Day Research Stack (v1.3)

### What is wired

| Layer | Module | Status |
|-------|--------|--------|
| Surface ranking | `nova_arsenal.zeroday.surface` | ✅ |
| Variant / patch-gap | `nova_arsenal.zeroday.variant` | ✅ |
| Static sinks | `nova_arsenal.zeroday.static_scanner` | ✅ |
| Fuzz campaign planner | `nova_arsenal.zeroday.fuzz_orchestrator` | ✅ |
| **Live fuzz worker** | `nova_arsenal.zeroday.fuzz_worker` | ✅ detects + runs installed engines |
| Crash triage | `nova_arsenal.zeroday.crash_triage` | ✅ |
| Novelty filter | `nova_arsenal.zeroday.novelty` | ✅ |
| Unified hunter | `nova_arsenal.zeroday.pipeline` | ✅ |
| Recon → services bridge | `nova_arsenal.zeroday.recon_bridge` | ✅ |
| **Swarm Researcher** | `nova_arsenal.swarm` phase `researcher_zeroday` | ✅ after recon |
| CLI | `--zeroday`, `--swarm`, `--live-fuzz` | ✅ |
| MCP tool | `zeroday_hunt`, `swarm_scan` | ✅ |
| Tool schema | `zeroday_hunt` in `NOVA_SECURITY_TOOLS` | ✅ |
| Tool selector | web/SMB → recommend zeroday_hunt | ✅ |
| Package export | `from nova_arsenal import ZeroDayHunter, LiveFuzzWorker, ...` | ✅ |

### CLI

```bash
# 1) Candidate pipeline (plan + rank). Live engines only with --live-fuzz --authorized
nova-agent --target lab.example.local --zeroday --authorized --auth-ref ENG-42 \
  --services-json '{"https":{"ports":[443],"version":"nginx/1.25","paths":["/upload","/api"]}}'

# 2) Same + live fuzz (ffuf/AFL++/http_mutator when installed on PATH)
nova-agent --target lab.example.local --zeroday --authorized --auth-ref ENG-42 --live-fuzz

# 3) Full swarm: recon → zeroday researcher → web/exploit/validator
nova-agent --target lab.example.local --swarm --authorized --auth-ref ENG-42
nova-agent --target lab.example.local --swarm --authorized --auth-ref ENG-42 --live-fuzz
```

### Python API

```python
from nova_arsenal import (
    ZeroDayHunter, ZeroDayHuntConfig, LiveFuzzWorker,
    SwarmOrchestrator, findings_to_services,
)

# Standalone hunt
result = await ZeroDayHunter().hunt(
    target="lab.example.local",
    services={"https": {"ports": [443], "paths": ["/upload"], "params": ["file"]}},
    config=ZeroDayHuntConfig(
        authorized=True,
        authorization_ref="ENG-42",
        execute_fuzz=True,      # live worker
        dry_run_fuzz=False,     # actually run available engines
        live_fuzz=True,
        fuzz_job_timeout=60,
    ),
)

# Swarm with automatic researcher phase after recon
swarm = SwarmOrchestrator(
    target="lab.example.local",
    enable_zeroday=True,
    zeroday_authorized=True,
    zeroday_auth_ref="ENG-42",
    execute_live_fuzz=True,
    dry_run_fuzz=False,
)
swarm_result = await swarm.run_swarm()
print(swarm_result.summary)
print(swarm_result.zeroday_hunt["candidate_count"])
```

### Live fuzz worker

`LiveFuzzWorker` probes the host for:

- **ffuf** — content discovery / path surface expansion  
- **afl-fuzz** (AFL++) — coverage-guided binary fuzz (needs `binary_path` + corpus)  
- **honggfuzz** / **radamsa** — when installed  
- **http_mutator** — built-in Nova HTTP edge-case mutator (always available with Python)  

Missing tools are **skipped** (not fatal). Crashes under `./fuzz_out` are collected and fed into crash triage.

```python
from nova_arsenal.zeroday import FuzzOrchestrator, LiveFuzzWorker, AttackSurfaceMapper

surface = AttackSurfaceMapper().map("lab.local", services={"http": [80]})
campaign = FuzzOrchestrator().plan("lab.local", surface.endpoints)
worker = LiveFuzzWorker(authorized=True, authorization_ref="ENG-42", output_dir="./fuzz_out")
print(worker.detect_engines())
live = await worker.run(campaign, dry_run=False, job_timeout=45)
```

### Swarm phase flow

```
┌─────────┐    services/findings     ┌──────────────────────┐
│  RECON  │ ───────────────────────► │ RESEARCHER           │
│ (+OSINT)│                          │  ZeroDayHunter       │
└─────────┘                          │  + LiveFuzzWorker    │
                                     └──────────┬───────────┘
                                                │ candidates
                     ┌──────────────────────────┼──────────────┐
                     ▼                          ▼              ▼
                  ┌─────┐                  ┌─────────┐   ┌───────────┐
                  │ WEB │                  │ EXPLOIT │   │ VALIDATOR │
                  └─────┘                  └─────────┘   └───────────┘
                                    │
                                    ▼
                              consensus merge
```

> **Reality check:** orchestration and prioritization run in milliseconds–seconds. Live fuzz runtime is capped (`fuzz_job_timeout`) so the agent stays responsive; deep AFL++ campaigns should be run longer in dedicated lab jobs. Confirmed zero-days still need human validation and responsible disclosure.

---

## Resilience & Production Hardening

Nova-Arsenal v1.1+ includes enterprise-grade resilience patterns:

### Async Timeout Guards
- All async operations protected with configurable timeouts
- Prevents hung LLM calls or tool invocations from blocking the agent loop
- Default: 120s per step, 600s total execution

```python
from nova_arsenal.resilient_agent_core import ResilientNovaAgent, ResilientAgentConfig

config = ResilientAgentConfig(
    step_timeout=120.0,        # Timeout per action
    total_timeout=600.0,       # 10-minute maximum execution
    max_concurrent_tasks=5,    # Prevent task explosion
    max_tool_calls_per_step=10, # Rate limit tool usage
)

agent = ResilientNovaAgent(
    target="example.com",
    config=config,
)
```

### Circuit Breaker
- Stops cascading failures if external services (LLM, Metasploit, Burp) fail repeatedly
- Automatic recovery with exponential backoff
- Rejects requests immediately when circuit is OPEN

### Retry Logic
- Exponential backoff for transient errors
- Configurable retry budget (default: 3 retries)
- Jitter to prevent thundering herd

### Resource Limits
- Concurrent task limits (prevents task explosion)
- Tool call budgets (rate limiting)
- Execution time caps (prevents infinite loops)
- Bounded error logs (prevents memory leaks)

### Graceful Degradation
- Partial results returned on timeout
- Error tracking for debugging
- Resource usage telemetry in summaries

---

## Installation

### Prerequisites

| Requirement | Minimum version |
|-------------|----------------|
| Python | 3.10+ |
| Docker + Docker Compose | 24.x+ |
| Node.js (web dashboard only) | 20+ |
| Git | 2.x+ |

### Option 1 – Docker (Recommended)

The fastest path. Spins up the API, web dashboard, Ollama (local LLM), and a Kali sandbox container in one command.

```bash
# 1. Clone
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

# 2. Configure environment
cp config/.env.example .env
# Edit .env – set your LLM provider keys, JWT secret, and any platform API tokens

# 3. Start all services
docker compose up -d

# 4. Check everything is running
docker compose ps

# 5. Open the dashboard
open http://localhost:3000

# 6. Default admin credentials (change immediately)
# Username: admin
# Password: set in .env as NOVA_ADMIN_PASSWORD
```

To run Nova from the CLI inside Docker:

```bash
docker compose exec agent nova-agent --target scanme.nmap.org
```

### Option 2 – Local Development

Use this if you want to edit Nova's code or run the RL training pipeline locally.

```bash
# 1. Clone
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux/macOS
# venv\Scripts\activate           # Windows

# 3. Install the Python package
pip install -e ".[dev]"

# 4. Install web dashboard dependencies
cd clients/web && npm install && cd ../..

# 5. Copy and edit environment config
cp config/.env.example .env

# 6. Run database migrations
alembic upgrade head

# 7. Start Ollama (local LLM – no API key needed)
ollama pull qwen3:1.7b            # smallest, good for 4GB RAM
# ollama pull deepseek-r1         # better reasoning, needs 8GB+ RAM

# 8. Start Nova's API
export LLM_PROVIDER=ollama
export LLM_MODEL=qwen3:1.7b
python -m nova_arsenal.api

# 9. In a separate terminal, start the web dashboard
cd clients/web && npm run dev

# Dashboard: http://localhost:3000
# API docs:  http://localhost:8000/docs
```

### Option 3 – Kali Linux / NetHunter

Tested on both desktop Kali and Kali NetHunter (Android). The Kali container gives Nova access to the full Kali toolset natively.

```bash
# Clone and install inside a venv (Kali blocks system-wide pip installs)
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
python3 -m venv venv
source venv/bin/activate
pip install -e "."

# Pull a small model
ollama pull qwen3:1.7b

# Start Nova
export LLM_PROVIDER=ollama
export LLM_MODEL=qwen3:1.7b
python -m nova_arsenal.api
```

### Option 4 – GitHub Codespaces

Zero local setup. Works in a browser.

1. Go to `github.com/Informant254/Nova-arsenal`
2. Click **Code → Codespaces → Create codespace on main**
3. In the terminal:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e "."
# Use OpenRouter for free model access in Codespaces (no local Ollama needed)
export LLM_PROVIDER=openrouter
export LLM_MODEL=qwen/qwen3-1.7b:free
export OPENROUTER_API_KEY=your_key_here
python -m nova_arsenal.api
```

---

## Configuration

### Use your AI accounts (like Codex / Claude Code) — not only API keys

Nova supports **two** ways to power the agent:

1. **Account / session login** (preferred if you already use Claude Code, Codex, ChatGPT Plus, etc.)
2. **Classic API keys** in `.env`

```bash
# A) ChatGPT Plus/Pro subscription via Codex OAuth (browser)
nova-agent login --provider openai --oauth
# Headless / SSH:
nova-agent login --provider openai --oauth --device-code

# B) Local LLM — Ollama (no cloud account, fully offline)
ollama pull llama3.2
nova-agent login --provider ollama
# or: nova-agent login --provider ollama --url http://127.0.0.1:11434 --model llama3.2

# C) Import sessions from tools already signed in on this machine
nova-agent login --import-existing

# D) Claude Code token / Google OAuth / API keys still work
nova-agent login --provider anthropic --token "$CLAUDE_CODE_OAUTH_TOKEN"
nova-agent login --provider gemini --oauth

nova-agent accounts          # accounts + local LLM discovery
nova-agent llm-status        # full wiring status
```

Tokens are stored in `~/.nova/accounts.json` (mode `0600`) and picked up automatically by the LLM router.

**VS Code:** command palette → `Nova: Sign In (AI Account)` · `Nova: Import Claude Code / Codex Sessions` · `Nova: Show AI Accounts / LLM Status`

### Classic API keys (BYOK) still work

```bash
cp config/.env.example .env
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GOOGLE_API_KEY=...
export OPENROUTER_API_KEY=sk-or-...
export LLM_PROVIDER=openai
export LLM_MODEL=gpt-4o
python -m nova_arsenal.api
curl -s http://localhost:8000/api/llm/status | jq .
```

| Provider | Account login | API key env |
|----------|---------------|-------------|
| OpenAI / Codex | `login --provider openai` / import Codex | `OPENAI_API_KEY` |
| Anthropic / Claude Code | `login --provider anthropic` / `CLAUDE_CODE_OAUTH_TOKEN` | `ANTHROPIC_API_KEY` |
| Gemini | `login --provider gemini --oauth` | `GOOGLE_API_KEY` |
| OpenRouter | token login | `OPENROUTER_API_KEY` |
| Ollama | n/a (local) | none |

API: `GET /api/llm/status` · `GET /api/llm/accounts` · `POST /api/llm/accounts/login` · `POST /api/llm/accounts/import` · `POST /api/llm/reload`

### VS Code extension

```bash
cd clients/vscode && npm install && npm run compile
# VS Code: Extensions → … → Install from Location → clients/vscode
```

Commands: Open Chat (`Ctrl+Alt+N`), Sign In, Import sessions, Quick Scan, Nmap, OSINT, CTF, Configure API URL.  
Chat uses `POST /api/chat/send` through the extension host (auth headers applied).

### LLM Providers (YAML)

Optional advanced config in `settings.yaml` (env keys still win when YAML leaves `api_key` empty):

```yaml
# config/settings.yaml
llm:
  primary:
    provider: "openai"          # or ollama / anthropic / openrouter / ...
    model: "gpt-4o"
    api_key: "${OPENAI_API_KEY}"
  fallbacks:
    - provider: "anthropic"
      model: "claude-sonnet-4-20250514"
      api_key: "${ANTHROPIC_API_KEY}"
    - provider: "openrouter"
      model: "openrouter/auto"
      api_key: "${OPENROUTER_API_KEY}"
    - provider: "ollama"          # free local fallback
      model: "qwen3:1.7b"
```

### Platform Connectors (Skills Marketplace)

Connect Nova to bug bounty and CTF platforms so she can reason about what's worth working on.

```bash
# Via the API (after Nova is running)
curl -X POST http://localhost:8000/api/skills/hackerone-connector/credentials \
  -H "Authorization: Bearer YOUR_JWT" \
  -H "Content-Type: application/json" \
  -d '{"credentials": {"api_username": "your_h1_username", "api_token": "your_h1_token"}}'

curl -X POST http://localhost:8000/api/skills/hackthebox-connector/credentials \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{"credentials": {"app_token": "your_htb_token"}}'

curl -X POST http://localhost:8000/api/skills/bugcrowd-connector/credentials \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{"credentials": {"api_token": "your_bugcrowd_token"}}'

# Then ask Nova what's worth working on
curl http://localhost:8000/api/targets/recommend \
  -H "Authorization: Bearer YOUR_JWT"
```

### Memory

Nova remembers what you were working on between sessions. Check your recap:

```bash
curl http://localhost:8000/api/memory/recap?days=7 \
  -H "Authorization: Bearer YOUR_JWT"
```

---

## Testing

Nova-Arsenal includes comprehensive test coverage (80%+) for unit, integration, and stress scenarios:

```bash
# Run all tests with coverage
make test

# Run unit tests only
make test-unit

# Run integration tests
make test-integration

# Run quality gates (lint + test)
make quality

# Tests cover:
# - Agent state management and step tracking
# - Async timeouts and circuit breaker patterns
# - Retry logic with exponential backoff
# - Resource limit enforcement
# - Swarm coordination under stress
# - Error accumulation and recovery
```

---

## Architecture

```
─────────────────────────────────────────────────────────────
│                        Nova-Arsenal                       │
─────────────────────────────────────────────────────────────
│                                                           │
│  ───────────────────────────────────────────────────     │
│  │   Web    │    │  Agent Core  │    │   LLM Router  │    │
│  │Dashboard │────│  + Swarm     │────│ (10 providers, │    │
│  │(Next.js) │    │Coordinator  │    │multi + fallback)   │
│  ────────────    ──────┬──────────    ─────────────────    │
│                        │                                  │
│             ──────────┼──────────────                    │
│             ▼          ▼          ▼                       │
│        ──────────  ──────────  ──────────                │
│        │  Kali   │ │  Tool  │ │Platform │               │
│        │ Sandbox │ │ Intel  │ │Connectors              │
│        │(Docker) │ │(Burp/  │ │(H1/BC/  │               │
│        │         │ │ MSF)   │ │ HTB/THM)                │
│        ──────────  ──────────  ──────────                │
│                                                           │
│        ──────────────────────────────────────             │
│        │  Skills Marketplace                  │          │
│        │  skills/ (installed) + pending_skills│          │
│        │  (self-authored, awaiting review)    │          │
│        ──────────────────────────────────────             │
│                                                           │
│        ──────────────────────────────────────             │
│        │  Session Memory (SQLite, per-user)  │          │
│        │  task_log | target_history | findings          │
│        │  preferences | recap                 │          │
│        ──────────────────────────────────────             │
│                                                           │
│        ═══════════════════════════════════════            │
│        ║  Resilience Layer (NEW)                ║         │
│        ║  • Async Timeouts (prevent hangs)     ║         │
│        ║  • Circuit Breaker (fail gracefully)  ║         │
│        ║  • Retry Logic (exponential backoff)  ║         │
│        ║  • Resource Limits (prevent explosion)║         │
│        ═══════════════════════════════════════            │
│                                                           │
─────────────────────────────────────────────────────────────
```

---

## Key API Endpoints

Once Nova is running, full interactive docs are at `http://localhost:8000/docs`.

| Endpoint | Description |
|----------|-------------|
| `POST /api/auth/login` | Get a JWT token |
| `GET /api/targets/recommend` | Nova's ranked target recommendation across all connected platforms |
| `GET /api/targets` | All available targets from connected platform connectors |
| `GET /api/skills` | List installed skills and their credential status |
| `POST /api/skills/{name}/credentials` | Connect a platform (HackerOne, HTB, etc.) |
| `GET /api/memory/recap?days=7` | "What were we working on?" – task + target + findings summary |
| `GET /api/memory/targets` | Full target history for the authenticated user |
| `GET /api/skills/pending` | Self-authored skills awaiting human review |
| `POST /api/skills/pending/{name}/approve` | Approve a self-authored skill (analyst+ role) |
| `POST /api/agent/run` | Run Nova's autonomous agent loop against a target |
| `GET /api/findings` | All findings for the authenticated user |

---

## Building a Skill

Anyone can add a new platform connector or tool without touching Nova's core. See [skills/SKILL_AUTHORING_GUIDE.md](skills/SKILL_AUTHORING_GUIDE.md) for the full guide.

Quick version – create `skills/my-connector/skill.json`:

```json
{
  "name": "my-connector",
  "version": "1.0.0",
  "author": "your-github-handle",
  "description": "What this skill does",
  "type": "platform_connector",
  "entry": "connector.py",
  "entry_class": "MyConnector",
  "requires_credentials": ["api_token"],
  "tags": ["bug-bounty"],
  "nova_min_version": "1.0.0"
}
```

Then implement `connector.py` extending `PlatformConnector` from `nova_arsenal/skills/platform_connector.py`. Open a PR – that's it.

---

## Documentation

- [Getting Started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [API Reference](docs/api-reference.md)
- [Deployment](docs/deployment.md)
- [Skill Authoring Guide](skills/SKILL_AUTHORING_GUIDE.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

---

## Security & Responsible Use

Nova-Arsenal is a professional security research tool. You are solely responsible for ensuring you have proper authorization before running any scans or tests. Unauthorized use against systems you do not own or have permission to test is illegal.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The fastest way to contribute is building a new skill connector – see the skill authoring guide above.

---

## License

Apache-2.0 – See [LICENSE](LICENSE) for details.
