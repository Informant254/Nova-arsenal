# Nova-Arsenal

[![CI](https://github.com/Informant254/Nova-arsenal/actions/workflows/ci.yml/badge.svg)](https://github.com/Informant254/Nova-arsenal/actions/workflows/ci.yml)
[![Security](https://github.com/Informant254/Nova-arsenal/actions/workflows/security.yml/badge.svg)](https://github.com/Informant254/Nova-arsenal/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Kubernetes](https://img.shields.io/badge/kubernetes-ready-326CE5?logo=kubernetes&logoColor=white)](k8s/)

**Autonomous Security Research Platform**

Nova-Arsenal is an autonomous security agent platform with 240+ modules covering reconnaissance, exploitation, analysis, and reporting. Features a multi-agent swarm architecture, self-training RL pipeline, native Burp Suite + Metasploit RPC integration, a skills marketplace with platform connectors for HackerOne, Bugcrowd, HackTheBox, and TryHackMe, and persistent per-user memory so you never lose track of what you were working on.

> ⚠️ **Ethical Use Only** — Nova-Arsenal is built for authorized security research and bug bounty engagements. Only run against targets you have explicit written permission to test. See [SECURITY.md](SECURITY.md) for responsible disclosure policy.

---

## Features

- **240+ Security Modules** — Kali Linux knowledge base across 25 categories (recon, exploitation, cloud, AD, wireless, mobile, web, OSINT, etc.)
- **Multi-Agent Swarm** — Parallel Scout, Exploiter, Validator, and Reporter agents with weighted consensus findings
- **Fugu-Style LLM Orchestration** — Dynamic routing across 10 providers (Anthropic, OpenAI, Gemini, DeepSeek, Qwen, OpenRouter, Ollama, HuggingFace, Opencode) with automatic fallback
- **Native Tool Integrations** — Programmatic control of Metasploit (msfrpcd REST), Burp Suite (REST API + GraphQL), SQLmap (API mode), and Nmap (XML parsing)
- **Skills Marketplace** — Installable platform connectors; Nova can also self-author new skills after novel tasks, pending human review before they go live
- **Platform Connectors** — HackerOne, Bugcrowd, HackTheBox, TryHackMe; Nova reasons across all connected platforms to recommend which target is worth her time
- **Persistent Memory** — Per-user SQLite memory: task log, target history, findings, preferences — the "what were we working on?" answer at the start of every session
- **Self-Training RL Pipeline** — GRPO-based training on Nova's own pentest trajectories; Muon optimizer; cross-stage knowledge distillation
- **Tool-Selection Intelligence** — Rule engine maps discovered services to optimal tools automatically (Port 445 → Metasploit SMB modules, web app → Burp + nuclei, etc.)
- **Cross-Tool Result Correlation** — Findings from Nmap + Burp + Metasploit + SQLmap are correlated; multi-source confirmed vulnerabilities get boosted confidence scores
- **Fix Verification** — 1-click retest to confirm a vulnerability was actually remediated
- **Incremental Testing** — Only retests what changed between versions
- **CTF Solver Mode** — Automatic challenge classification and solve pipelines (web, crypto, stego, pwn, OSINT, forensics, reversing)
- **MCP Server Export** — Nova exposes her tools via JSON-RPC so Cursor, Claude, and any MCP-compatible agent can use her as a plugin
- **VS Code Extension** — 6 commands, webview chat panel, streaming responses, one-click run
- **Web Dashboard** — Dark-themed Next.js UI with real-time agent chat, target management, findings review, and skills approval queue
- **E2E Encryption** — RSA-4096 + AES-256-GCM for agent communications

---

## Installation

### Prerequisites

| Requirement | Minimum version |
|-------------|----------------|
| Python | 3.10+ |
| Docker + Docker Compose | 24.x+ |
| Node.js (web dashboard only) | 20+ |
| Git | 2.x+ |

### Option 1 — Docker (Recommended)

The fastest path. Spins up the API, web dashboard, Ollama (local LLM), and a Kali sandbox container in one command.

```bash
# 1. Clone
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

# 2. Configure environment
cp config/.env.example .env
# Edit .env — set your LLM provider keys, JWT secret, and any platform API tokens

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

### Option 2 — Local Development

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

# 7. Start Ollama (local LLM — no API key needed)
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

### Option 3 — Kali Linux / NetHunter

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

### Option 4 — GitHub Codespaces

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

All configuration lives in `.env` (copied from `config/.env.example`).

### LLM Providers

Nova supports 10 LLM providers with automatic fallback. Configure as many or as few as you want — she'll use whatever's available.

```yaml
# config/settings.yaml
llm:
  primary:
    provider: "ollama"          # free, local, no key needed
    model: "qwen3:1.7b"        # or deepseek-r1, llama3, etc.
  fallbacks:
    - provider: "openrouter"    # one key, 200+ models
      model: "qwen/qwen3-1.7b:free"
    - provider: "anthropic"
      model: "claude-sonnet-4-20250514"
    - provider: "openai"
      model: "gpt-4o"
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

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────
│                        Nova-Arsenal                             │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────────────────────────────────
│  │   Web    │    │  Agent Core  │    │   LLM Router       │    │
│  │Dashboard │───▶│  + Swarm     │───▶│ (10 providers,     │    │
│  │ (Next.js)│    │  Coordinator │    │  multi + fallback) │    │
│  └──────────────    └─────┬───────────    └───────────────────────    │
│                         │                                       │
│              ┌──────────┼──────────┐                           │
│              ▼          ▼          ▼                           │
│         ┌─────────┐ ┌───────┐ ┌──────────┐                    │
│         │  Kali   │ │  Tool │ │ Platform │                    │
│         │ Sandbox │ │ Intel │ │ Connectors│                   │
│         │(Docker) │ │(Burp/ │ │(H1/BC/   │                   │
│         │         │ │ MSF)  │ │ HTB/THM) │                   │
│         └─────────┘ └───────┘ └──────────┘                    │
│                                                                 │
│         ┌─────────────────────────────────────┐            │
│         │  Skills Marketplace                      │            │
│         │  skills/ (installed) + pending_skills/   │            │
│         │  (self-authored, awaiting review)         │            │
│         └─────────────────────────────────────┘            │
│                                                                 │
│         ┌─────────────────────────────────────┐            │
│         │  Session Memory (SQLite, per-user)       │            │
│         │  task_log | target_history | findings    │            │
│         │  preferences | recap                     │            │
│         └─────────────────────────────────────┘            │
└──────────────────────────────────────────────────────────────────────────────────
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
| `GET /api/memory/recap?days=7` | "What were we working on?" — task + target + findings summary |
| `GET /api/memory/targets` | Full target history for the authenticated user |
| `GET /api/skills/pending` | Self-authored skills awaiting human review |
| `POST /api/skills/pending/{name}/approve` | Approve a self-authored skill (analyst+ role) |
| `POST /api/agent/run` | Run Nova's autonomous agent loop against a target |
| `GET /api/findings` | All findings for the authenticated user |

---

## Building a Skill

Anyone can add a new platform connector or tool without touching Nova's core. See [skills/SKILL_AUTHORING_GUIDE.md](skills/SKILL_AUTHORING_GUIDE.md) for the full guide.

Quick version — create `skills/my-connector/skill.json`:

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

Then implement `connector.py` extending `PlatformConnector` from `nova_arsenal/skills/platform_connector.py`. Open a PR — that's it.

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

Nova-Arsenal is a professional security research tool. You are solely responsible for ensuring you have proper authorization before running any scans or tests. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The fastest way to contribute is building a new skill connector — see the skill authoring guide above.

---

## License

Apache-2.0 — See [LICENSE](LICENSE) for details.
