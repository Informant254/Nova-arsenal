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

- **70+ Security Modules** — Recon, attack, analysis, and reporting
- **Multi-LLM Support** — Ollama (local), OpenAI, Anthropic, Gemini
- **Web Dashboard** — Real-time monitoring and management
- **Docker Deployment** — Containerized, isolated execution
- **Multi-User Auth** — Role-based access control
- **SQLite Storage** — Persistent findings and agent state
- **Kubernetes Ready** — Production deployment manifests

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
