# Getting Started

This guide will help you get Nova-Arsenal up and running.

## Prerequisites

- Python 3.10+
- Docker and Docker Compose
- Node.js 18+ (for web development)

## Quick Start (Docker)

### 1. Clone the Repository

```bash
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
```

### 2. Configure Environment

```bash
cp config/.env.example .env
# Edit .env with your API keys (optional for Ollama)
```

### 3. Start Services

```bash
docker compose up -d
```

### 4. Access the Dashboard

Open http://localhost:3000 in your browser.

### 5. Create an Account

1. Click "Register"
2. Enter your email and password
3. Login with your credentials

## Local Development

### 1. Install Python Package

```bash
pip install -e ".[dev]"
```

### 2. Install Web Client

```bash
cd clients/web
npm install
cd ../..
```

### 3. Start Infrastructure Services

```bash
docker compose up -d llm sandbox
```

### 4. Run the Agent (CLI)

```bash
nova-agent --target example.com
```

### 5. Start Web Development Server

```bash
cd clients/web
npm run dev
```

## Configuration

### LLM Providers

#### Ollama (Local - Free)

No API key required. Ollama runs locally.

```yaml
llm:
  primary:
    provider: "ollama"
    model: "deepseek-r1"
```

#### OpenAI

```yaml
llm:
  primary:
    provider: "openai"
    model: "gpt-4o"
    api_key: "${OPENAI_API_KEY}"
```

#### Anthropic

```yaml
llm:
  primary:
    provider: "anthropic"
    model: "claude-sonnet-4-20250514"
    api_key: "${ANTHROPIC_API_KEY}"
```

### Target Scope

Define which targets are in scope:

```yaml
scope:
  targets:
    - "example.com"
    - "*.example.com"
```

## Usage Examples

### Basic Scan

```bash
nova-agent --target example.com
```

### Custom Objective

```bash
nova-agent --target example.com --objective "Find SQL injection vulnerabilities"
```

### Multiple Scope Targets

```bash
nova-agent --target example.com --scope example.com api.example.com
```

### Using Docker

```bash
docker compose run --rm agent --target example.com
```

## Web Dashboard

### Features

- **Agent Management**: Create, monitor, and control agents
- **Findings View**: Review discovered vulnerabilities
- **Scope Management**: Define target scope
- **User Management**: Admin user administration

### Real-time Updates

The dashboard receives real-time updates via WebSocket:

- Agent progress
- Tool executions
- Finding discoveries
- Log messages

## Troubleshooting

### Agent Won't Start

Check logs:

```bash
docker compose logs agent
```

### LLM Connection Issues

Verify Ollama is running:

```bash
curl http://localhost:11434/api/tags
```

### Database Errors

Reset database:

```bash
docker compose down -v
docker compose up -d
```

## Next Steps

- [Configuration](configuration.md) - Advanced configuration options
- [API Reference](api-reference.md) - REST API documentation
- [Deployment](deployment.md) - Production deployment guide
