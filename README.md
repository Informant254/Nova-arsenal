<div align="center">

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗      █████╗ ██████╗ ███████╗███████╗║
║   ████╗  ██║██╔═══██╗██║   ██║██╔══██╗    ██╔══██╗██╔══██╗██╔════╝██╔════╝║
║   ██╔██╗ ██║██║   ██║██║   ██║███████║    ███████║██████╔╝███████╗█████╗  ║
║   ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║    ██╔══██║██╔══██╗╚════██║██╔══╝  ║
║   ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║    ██║  ██║██║  ██║███████║███████╗║
║   ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝║
║                                                                              ║
║              🦅  Autonomous Security Research Platform  v4.2               ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Node.js 22+](https://img.shields.io/badge/Node.js-22+-green.svg)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Android-lightgrey.svg)]()

</div>

---

## What is Nova Arsenal?

Nova Arsenal is a **fully autonomous, multi-agent security research platform**. It combines a sophisticated Python agentic engine with an OWASP Juice Shop web server for hands-on security training, bug-bounty automation, penetration testing, and continuous vulnerability research.

Nova uses LLM reasoning (local via Ollama, or cloud via OpenAI / Anthropic / Gemini) to plan, execute, and learn from security assessments — no manual intervention required.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          NOVA ARSENAL v4.2                                  │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        ENTRY POINTS                                 │   │
│  │                                                                     │   │
│  │   nova.py (CLI)          nova_core.py         nova_orchestrator.py  │   │
│  │   "Hunt target.com"      (11-phase mission)   (multi-agent runner)  │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│  ┌──────────────────────────────▼──────────────────────────────────────┐   │
│  │                      PROVIDER LAYER                                 │   │
│  │                                                                     │   │
│  │   nova_llm_router.py          nova_model_router.py                  │   │
│  │   ┌───────────┐  ┌──────────┐ ┌──────────┐ ┌────────────────────┐  │   │
│  │   │  Ollama   │  │ OpenAI   │ │Anthropic │ │  Google Gemini     │  │   │
│  │   │ (local)   │  │ GPT-4o   │ │ Claude   │ │  gemini-2.0-flash  │  │   │
│  │   └───────────┘  └──────────┘ └──────────┘ └────────────────────┘  │   │
│  │         ↑ auto-fallback chain (primary → secondary → Ollama)        │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│  ┌──────────────────────────────▼──────────────────────────────────────┐   │
│  │                   INTELLIGENCE LAYER                                │   │
│  │                                                                     │   │
│  │   nova_reasoning_core.py      nova_knowledge_rag.py                 │   │
│  │   nova_codebase_mapper.py     nova_payload_engine.py                │   │
│  │   nova_chain_of_thought.py    nova_rag_builder.py                   │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│  ┌──────────────────────────────▼──────────────────────────────────────┐   │
│  │                   AGENT NETWORK                                     │   │
│  │                                                                     │   │
│  │  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐               │   │
│  │  │ ReconAgent  │──▶│ AttackAgent │──▶│ ReportAgent │               │   │
│  │  └─────────────┘   └─────────────┘   └─────────────┘               │   │
│  │                                                                     │   │
│  │  nova_hooks.py (HookBus)     nova_context.py (RunContext)           │   │
│  │  nova_sessions.py            nova_observability.py (Tracer)         │   │
│  │  nova_tool_kit.py            nova_retry.py (ResilientCaller)        │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│  ┌──────────────────────────────▼──────────────────────────────────────┐   │
│  │               SECURITY TESTING MODULES (13 phases)                 │   │
│  │                                                                     │   │
│  │  Phase 0: Codebase Mapper    │  Phase 7: Prototype Pollution        │   │
│  │  Phase 1: SAST / SCA         │  Phase 8: Deserialization            │   │
│  │  Phase 2: Exploit Synthesis  │  Phase 9: Learning (RAG feedback)    │   │
│  │  Phase 3: Fuzzing            │  Phase 10: Post-Hunt Learning        │   │
│  │  Phase 4: Session Hijacking  │  Phase 11: Triage & Prioritisation  │   │
│  │  Phase 5: Race Conditions    │  Phase 12: Vuln Tracker Dashboard    │   │
│  │  Phase 6: JWT Attacks        │                                      │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│  ┌──────────────────────────────▼──────────────────────────────────────┐   │
│  │                  WEB SERVER (OWASP Juice Shop)                      │   │
│  │                                                                     │   │
│  │   app.ts / server.ts (Express 4)                                    │   │
│  │   frontend/              models/            routes/ (60+ handlers)  │   │
│  │   SQLite + Sequelize     swagger.yml         Socket.io              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │             PERSISTENCE & OUTPUT                                    │   │
│  │                                                                     │   │
│  │  ~/nova_workspace/                                                  │   │
│  │    ├── nova_rag_db.jsonl        (RAG knowledge base)                │   │
│  │    ├── nova_sessions/           (persistent sessions)               │   │
│  │    ├── nova_vuln_tracker.db     (SQLite vuln tracker)               │   │
│  │    ├── reports/                 (HTML, Markdown, JSON reports)      │   │
│  │    ├── screenshots/             (browser evidence)                  │   │
│  │    └── logs/                    (structured run logs)               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
User Query (plain English)
       │
       ▼
  nova.py _parse_intent()
  ─── detects: mode + target ──────────────────────────────────┐
       │                                                        │
       ▼                                                        ▼
  _init_provider_layer()                              _run_phase0_mapper()
  • LLMRouter (auto-detects API keys)                 • Scans codebase
  • HookBus (lifecycle events)                        • Discovers endpoints
  • RunContext (shared state)                         • Detects frameworks
  • SessionStore (persistence)                        • Flags risky deps
  • Tracer (observability)                            • Builds CodebaseMap
       │                                                        │
       └───────────────────────────┬────────────────────────────┘
                                   ▼
                           dispatch(intent)
                    ┌──────────────────────────┐
                    │  13 Phase Pipeline       │
                    │  (mode-gated execution)  │
                    └──────────────┬───────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │  _emit_findings()            │
                    │  ├─ HookBus.fire_finding()   │
                    │  ├─ RunContext.add_finding()  │
                    │  ├─ Session.add_finding()     │
                    │  └─ NovaVulnTracker.ingest()  │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │  Final Report + Save         │
                    │  • JSON findings file        │
                    │  • Triage ranking            │
                    │  • Trace HTML export         │
                    └─────────────────────────────┘
```

---

## Requirements

### System

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Linux / macOS / Android (Termux) | Ubuntu 22.04 / Kali |
| Python | 3.10 | 3.12 |
| Node.js | 22 | 24 |
| RAM | 4 GB | 16 GB |
| Disk | 5 GB | 20 GB |
| GPU | — | 8 GB VRAM (for local LLMs) |

### LLM Providers (at least one required)

| Provider | Setup | Cost |
|----------|-------|------|
| **Ollama** (recommended) | `curl -fsSL https://ollama.com/install.sh \| sh` | Free |
| OpenAI | Set `OPENAI_API_KEY` | Pay-per-token |
| Anthropic | Set `ANTHROPIC_API_KEY` | Pay-per-token |
| Google Gemini | Set `GEMINI_API_KEY` | Free tier available |

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
```

### 2. Run the Setup Script (Recommended)

The setup script installs all dependencies and configures your workspace in one step:

```bash
bash nova_setup.sh
```

For a minimal install (Python + Ollama only, no system tools):

```bash
bash nova_setup.sh --minimal
```

To pull/update Ollama models only:

```bash
bash nova_setup.sh --models-only
```

### 3. Manual Installation

#### 3a. Python Environment

```bash
# Create a virtual environment
python3 -m venv ~/nova_workspace/.venv
source ~/nova_workspace/.venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browsers (for browser-based modules)
playwright install chromium
```

#### 3b. Node.js Server (OWASP Juice Shop)

```bash
# Install Node.js dependencies + build frontend
npm install

# The postinstall script builds the frontend automatically.
# If it fails, build manually:
cd frontend && npm install && npm run build && cd ..
npx tsc
```

#### 3c. Ollama (Local LLM — Recommended)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start the Ollama server
ollama serve &

# Pull the recommended model (fast, 8B params)
ollama pull qwen3:8b

# Optional: pull a larger model for better reasoning
ollama pull qwen3:30b
ollama pull deepseek-r1:14b
```

### 4. Configure Environment Variables

```bash
# Copy the example config
cp .env.example .env

# Edit with your values
nano .env
```

Key variables:

```bash
# LLM (pick at least one — Ollama is default and free)
OPENAI_API_KEY=sk-...          # optional
ANTHROPIC_API_KEY=sk-ant-...   # optional
GEMINI_API_KEY=AIza...         # optional

# Nova runtime
NOVA_TARGET=http://localhost:3000     # default scan target
NOVA_WORKSPACE=~/nova_workspace       # output directory
NOVA_LLM_MODEL=qwen3:8b              # Ollama model
NOVA_PERMISSION_PROFILE=scoped        # read_only | scoped | full

# Notifications (optional)
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
DISCORD_WEBHOOK_URL=...
```

### 5. Verify Installation

```bash
# Health check — verifies all Nova modules
python3 nova.py "bootstrap"

# Or run the bootstrap module directly
python3 nova_bootstrap.py
```

Expected output:
```
  ✅ Python 3.12.x
  ✅ Ollama running — 2 models available
  ✅ nova_source_auditor       (v2.0) NovaSourceAuditor
  ✅ nova_vuln_tracker         (v4.0) NovaVulnTracker
  ...
  🦅 Nova Arsenal ready.
```

---

## Quick Start

### Start the Juice Shop Target Server

```bash
# Start the Node.js server (port 3000)
npm start

# Or in development mode with hot-reload
npm run serve:dev
```

Open [http://localhost:3000](http://localhost:3000) to confirm it's running.

### Run Nova Against It

```bash
# Full vulnerability hunt (all 13 phases)
python3 nova.py "Hunt http://localhost:3000 for all vulnerabilities"

# Just map the codebase
python3 nova.py "Map the codebase at ."

# SAST only
python3 nova.py "SAST code audit of ."

# Full-stack pipeline (static + dynamic)
python3 nova.py "Full stack pipeline on http://localhost:3000"

# Build a threat model
python3 nova.py "Build STRIDE threat model for ."

# Show vulnerability dashboard
python3 nova.py "Show vulnerability tracker dashboard"

# Health check
python3 nova.py "bootstrap"
```

### Resume a Session

```bash
# Nova creates a session ID for each run — look for it in output
python3 nova.py "Continue hunt on http://localhost:3000" --session abc12345
```

---

## Modes Reference

| Mode | Command Example | What It Does |
|------|----------------|--------------|
| `hunt` | `"Hunt http://target.com"` | Full web app pentest (active) |
| `full_stack` | `"Full stack pipeline on ./src"` | Static + dynamic combined |
| `sast` | `"SAST code audit of ./src"` | Static analysis only |
| `sca` | `"Dependency scan of ."` | CVE-affected packages |
| `map` | `"Map the codebase at ."` | Codebase intelligence map |
| `recon` | `"Recon http://target.com"` | Passive recon + enumeration |
| `git_scan` | `"Scan git history for secrets"` | Leaked secrets in commits |
| `cicd` | `"Audit CI/CD pipelines"` | GitHub Actions / Jenkins |
| `container` | `"Docker security scan"` | Dockerfile + K8s misconfig |
| `threat_model` | `"STRIDE threat model for ."` | STRIDE threat modeling |
| `patch` | `"Generate patches for findings"` | Auto-remediation suggestions |
| `vuln_track` | `"Show vulnerability dashboard"` | Tracker dashboard |
| `continuous` | `"Continuously monitor target"` | Scheduled monitoring loop |
| `swarm` | `"Swarm parallel scan"` | Multi-agent parallel scan |
| `bootstrap` | `"bootstrap"` | Health check all modules |

---

## Module Reference

### Core Entry Points

| File | Purpose |
|------|---------|
| `nova.py` | Main CLI — plain-English task dispatcher |
| `nova_core.py` | 11-phase sequential mission runner |
| `nova_orchestrator.py` | Multi-agent network (ReAct loop) |
| `nova_bootstrap.py` | Health check and module verification |

### Provider Layer

| File | Purpose |
|------|---------|
| `nova_llm_router.py` | Multi-provider LLM (Ollama/OpenAI/Anthropic/Gemini) |
| `nova_model_router.py` | Task-based model selection (security/reasoning/coding) |
| `nova_llm_bridge.py` | Legacy LLM interface with RAG injection |

### Intelligence Layer

| File | Purpose |
|------|---------|
| `nova_codebase_mapper.py` | Static codebase analysis + attack surface mapping |
| `nova_reasoning_core.py` | Chain-of-thought reasoning wrapper |
| `nova_knowledge_rag.py` | Retrieval-augmented generation knowledge base |
| `nova_payload_engine.py` | Polymorphic payload generator (SQLi, XSS, SSRF…) |
| `nova_rag_builder.py` | RAG document builder and indexer |
| `nova_payload_engine.py` | WAF-bypass payload mutations |

### Infrastructure

| File | Purpose |
|------|---------|
| `nova_hooks.py` | Lifecycle hook bus (PreRun, PostRun, OnFinding…) |
| `nova_context.py` | Typed shared context for agent networks |
| `nova_sessions.py` | Persistent session management |
| `nova_observability.py` | Distributed tracing + span export |
| `nova_tool_kit.py` | Governed tool execution (scope, rate-limit, audit) |
| `nova_retry.py` | Exponential backoff + circuit breaker |
| `nova_memory_system.py` | Persistent cross-run memory |
| `nova_evolver.py` | Self-improvement engine (dry-run by default) |

### Security Testing Modules

| File | Vulnerability Class |
|------|-------------------|
| `nova_exploit_synthesizer.py` | SQLi, auth bypass |
| `nova_fuzzer_fix.py` | Input fuzzing (SQLi, XSS) |
| `nova_session_hijacker.py` | Session fixation / theft |
| `nova_race_engine.py` | Race conditions, rate-limit bypass |
| `nova_jwt_forge.py` | JWT algorithm confusion, none attack |
| `nova_proto_polluter.py` | Prototype pollution |
| `nova_deserialize_dropper.py` | Deserialization RCE |
| `nova_source_auditor.py` | Multi-language SAST |
| `nova_sca_scanner.py` | Dependency CVE scanning |
| `nova_git_scanner.py` | Git history secret scanning |
| `nova_cicd_scanner.py` | CI/CD pipeline security |
| `nova_container_scanner.py` | Docker/Kubernetes security |
| `nova_idor_scanner.py` | IDOR / broken access control |
| `nova_csrf_tester.py` | CSRF vulnerability testing |
| `nova_graphql_tester.py` | GraphQL security |
| `nova_supply_chain_scorer.py` | Supply chain risk scoring |
| `nova_threat_model.py` | STRIDE threat modeling |
| `nova_vuln_tracker.py` | SQLite vulnerability dashboard |
| `nova_triage.py` | LLM-ranked finding prioritisation |
| `nova_patch_generator.py` | Auto-remediation code patches |
| `nova_detection_engineer.py` | Sigma / SIEM rule generation |

---

## Output Files

All outputs are written to `~/nova_workspace/` by default:

```
~/nova_workspace/
├── nova_<mode>_<timestamp>.json     # Raw findings
├── nova_triage_report.json          # Ranked findings
├── nova_unified_mission_report.json # Full mission summary
├── nova_threat_model.json           # Threat model
├── nova_tracker_dashboard.md        # Vuln tracker markdown
├── nova_trace_<timestamp>.json      # Agent trace (JSON)
├── nova_trace_<timestamp>.html      # Agent trace (visual)
├── nova_rag_db.jsonl                # RAG knowledge base
├── reports/                         # Generated HTML/PDF reports
├── screenshots/                     # Browser evidence
├── sessions/                        # Persistent session files
└── logs/                            # Structured logs
```

---

## Development

### Running Tests

```bash
# Node.js / Juice Shop tests
npm test                    # all (frontend + server + API)
npm run test:server         # server unit tests only
npm run test:api            # API integration tests
npm run test:frontend       # Angular frontend tests

# Python module health check
python3 nova_bootstrap.py
```

### Linting

```bash
# TypeScript
npm run lint

# Python
pip install flake8 && flake8 nova_*.py --max-line-length=120
```

### Building

```bash
# Build Node.js server (TypeScript → JavaScript)
npm run build

# Build frontend only
npm run build:frontend
```

---

## Security & Ethics

> **Nova Arsenal is designed for authorised security research only.**

- Only scan targets you own or have explicit written permission to test
- The `NOVA_PERMISSION_PROFILE=scoped` default limits network access to `NOVA_TARGET`
- Setting `NOVA_ALLOW_EVOLUTION=true` enables self-modification — **never use in production**
- All active scanning modules require network access — set `read_only` profile for CI/CD pipelines
- Review `SECURITY.md` for responsible disclosure guidelines

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Ollama not running` | Run `ollama serve` or `systemctl start ollama` |
| `Module not found: nova_xxx` | Run `python3 nova_bootstrap.py` to diagnose |
| `npm install fails` | Ensure Node.js 22+ — check `node --version` |
| `Playwright browser missing` | Run `playwright install chromium` |
| `All LLM providers failed` | Check `.env` API keys and Ollama connectivity |
| `Permission denied on workspace` | Run `mkdir -p ~/nova_workspace && chmod 755 ~/nova_workspace` |
| Port 3000 already in use | `lsof -ti:3000 \| xargs kill -9` |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. All security-related PRs are reviewed within 72 hours.

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

**🦅 Nova Arsenal — Autonomous security research, one prompt away.**

</div>
