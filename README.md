# Nova-Arsenal

[![CI](https://github.com/Informant254/Nova-arsenal/actions/workflows/ci.yml/badge.svg)](https://github.com/Informant254/Nova-arsenal/actions/workflows/ci.yml)
[![Security](https://github.com/Informant254/Nova-arsenal/actions/workflows/security.yml/badge.svg)](https://github.com/Informant254/Nova-arsenal/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Kubernetes](https://img.shields.io/badge/kubernetes-ready-326CE5?logo=kubernetes&logoColor=white)](k8s/)

**Autonomous Security Research Platform**

Nova-Arsenal is an autonomous security agent platform with 70+ modules covering reconnaissance, exploitation, and analysis. Features a full-featured web dashboard, multi-LLM support, and Docker-based deployment.

> ⚠️ **Ethical Use Only** — Nova-Arsenal is built for authorized security research and bug bounty engagements. Only run against targets you have explicit written permission to test. See [SECURITY.md](SECURITY.md) for responsible disclosure policy.

---

## Features

- **240+ Security Tools & Modules** — Comprehensive Kali Linux knowledge base split into Core & Extended modules across 25 categories (mobile, cloud, active directory, container, wireless, password cracking, reverse engineering, web exploitation, etc.)
- **Fugu-Style LLM Orchestration** — Dynamic task classification, routing, and automatic fallback across 8 LLM providers (Anthropic, OpenAI, Gemini, DeepSeek, Qwen, OpenRouter, HuggingFace, Ollama)
- **Conversational Chat Assistant (Nova)** — Real-time SSE streaming interface to converse with Nova, lookup tool information, or run security tasks autonomously
- **Interactive Web Dashboard** — Dark-themed chat interface with streaming display, instant tool suggestions, session history, and capability templates
- **Docker-Isolated Execution** — Secure command validation and scope guards to prevent unauthorized system modification or escape
- **SQLite/Postgres Storage** — Multi-user authentication, persistent session history, database-backed logging, and structured reporting

## Quick Start

### Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

# Copy environment variables
cp config/.env.example .env

# Start all services
docker compose up -d

# Access the dashboard
open http://localhost:3000
```

### Local Development

```bash
# Install Python package
pip install -e ".[dev]"

# Install web client
cd clients/web && npm install && cd ../..

# Start services
docker compose up -d llm sandbox

# Run the agent (use scanme.nmap.org for authorized demo testing)
nova-agent --target scanme.nmap.org

# Start the web UI
cd clients/web && npm run dev
```

### Conversational Chat Interface (No Docker Required)

```bash
# Install FastAPI dependencies
pip install fastapi uvicorn

# Start the conversational API server
python -m nova_arsenal.api

# Access the interactive dashboard
open http://localhost:8000
```

The web dashboard provides:
- **Real-time streaming responses** from Nova
- **Intent classification** (security task, tool info, conversation, code, question)
- **Direct tool lookup** from 240+ Kali tools
- **Session persistence** with history
- **Quick-start capability cards** for common tasks

## Testing Against Targets

Run autonomous penetration tests against authorized targets:

```bash
# Run a comprehensive test
python test_nova.py localhost "Full audit of exposed services" 20

# Test with specific target
python test_nova.py 192.168.1.100 "Identify vulnerabilities" 15

# Quick scan mode
python test_nova.py example.com "Web app security test" 10
```

The test script demonstrates:
- Autonomous agent loop execution
- Tool selection based on task requirements
- Security constraints and scope enforcement
- Real-time findings detection
- Report generation

**Note**: Only test against systems you own or have explicit written authorization to test.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Nova-Arsenal                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │   Web    │    │   Agent  │    │   LLM    │              │
│  │Dashboard │───▶│   Core   │───▶│ Provider │              │
│  │ (Next.js)│    │  (Python)│    │ (Multi)  │              │
│  └──────────┘    └────┬─────┘    └──────────┘              │
│                       │                                     │
│                       ▼                                     │
│                ┌──────────┐                                 │
│                │  Sandbox │                                 │
│                │  (Kali)  │                                 │
│                └──────────┘                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Conversational Chat Flow

Nova uses Fugu-style orchestration to intelligently route tasks:

```
User Message → Intent Classification → Route Decision
    │
    ├─→ CONVERSATION → General LLM → Friendly response
    ├─→ TOOL_INFO → Tool Lookup → Kali docs (230 tools)
    ├─→ QUESTION → Security Knowledge → Expert answers
    ├─→ CODE_REQUEST → Code Gen → Exploit generation
    └─→ SECURITY_TASK → AgentRunner → Full autonomic loop
                             │
                             ├─→ Planning → Recon → Scan → Exploit
                             └─→ Analysis → Findings → Report
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [API Reference](docs/api-reference.md)
- [Deployment](docs/deployment.md)

## Configuration

See [config/settings.example.yaml](config/settings.example.yaml) for all available options.

### LLM Providers

```yaml
llm:
  primary:
    provider: "ollama"
    model: "deepseek-r1"
  fallbacks:
    - provider: "openai"
      model: "gpt-4o"
    - provider: "anthropic"
      model: "claude-sonnet-4-20250514"
```

## Security & Responsible Use

Nova-Arsenal is a professional security research tool. You are solely responsible for ensuring you have proper authorization before running any scans or tests. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

See [SECURITY.md](SECURITY.md) for vulnerability reporting policy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

Apache-2.0 — See [LICENSE](LICENSE) for details.
