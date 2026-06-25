# Nova-Arsenal Architecture

This document describes the high-level architecture of Nova-Arsenal.

## System Overview

Nova-Arsenal is an autonomous security research platform composed of several microservices working together to perform security assessments.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Nova-Arsenal                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │    Web      │    │    Agent    │    │    LLM      │         │
│  │  Dashboard  │───▶│    Core     │───▶│  Provider   │         │
│  │  (Next.js)  │    │  (FastAPI)  │    │  (Multi)    │         │
│  └─────────────┘    └──────┬──────┘    └─────────────┘         │
│                            │                                    │
│                            ▼                                    │
│                     ┌─────────────┐                             │
│                     │   Sandbox   │                             │
│                     │   (Kali)    │                             │
│                     └─────────────┘                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Agent Core (`nova_arsenal/`)

The Python package containing all core logic:

- **LLM Router**: Multi-provider routing with fallback
- **Tool Kit**: Governed tool execution with scope enforcement
- **Skills Library**: Reusable prompt templates
- **Database Layer**: SQLite storage for findings and agents
- **Auth System**: JWT-based authentication

### 2. Web Dashboard (`clients/web/`)

Next.js application providing:

- Real-time agent monitoring
- Finding management
- User administration
- Scope configuration

### 3. Sandbox (`containers/Dockerfile.kali`)

Kali Linux container with security tools:

- Reconnaissance tools (nmap, subfinder, etc.)
- Web exploitation tools (sqlmap, nuclei, etc.)
- Network tools (hydra, impacket, etc.)

### 4. LLM Provider (`config/litellm.yaml`)

LiteLLM gateway for:

- Local inference (Ollama)
- Cloud APIs (OpenAI, Anthropic, Gemini)
- Automatic failover

## Data Flow

1. **User** creates agent via Web UI
2. **Agent Core** receives request, starts execution
3. **LLM Router** selects best provider, generates actions
4. **Tool Kit** executes actions in sandbox
5. **Database** stores findings
6. **WebSocket** streams updates to Web UI

## Security Model

### Network Isolation

- **Agent Network**: Management plane (agent, web, llm)
- **Sandbox Network**: Isolated offensive plane (sandbox only)

### Container Security

- Capability dropping (`cap_drop: ALL`)
- No new privileges
- Memory and CPU limits
- Health checks

### Authentication

- JWT tokens (15-minute expiry)
- Refresh tokens (7-day expiry)
- Role-based access control

## Deployment Options

### Docker Compose (Development)

```bash
docker compose up -d
```

### Docker Compose (Production)

```bash
docker compose -f docker-compose.prod.yml up -d
```

### Kubernetes

```bash
kubectl apply -f k8s/
```

## Scaling

### Horizontal Scaling

- Web dashboard: Multiple replicas behind load balancer
- LLM provider: Use LiteLLM proxy for request distribution

### Vertical Scaling

- Agent: Increase memory/CPU limits
- Sandbox: Increase memory for intensive scans
- LLM: Use GPU-enabled nodes for inference
