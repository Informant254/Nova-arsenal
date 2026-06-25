# ADR-0006: Container Architecture

## Status

Accepted

## Context

Nova-Arsenal requires containerization for:
- Reproducible deployments
- Isolation of security tools
- Easy scaling
- Production readiness

## Decision

We will use **Docker Compose** with multiple containers:

### Container Design

| Container | Base | Purpose |
|-----------|------|---------|
| agent | python:3.13-slim | Agent core runtime |
| sandbox | kalilinux/kali-rolling | Security tools |
| web | node:20-alpine | Next.js dashboard |
| llm | ollama/ollama | Local LLM inference |

### Network Isolation

- **agent-net**: Management plane (agent, web, llm)
- **sandbox-net**: Isolated offensive plane (sandbox only)

### Security Hardening

- Capability dropping (`cap_drop: ALL`)
- No new privileges
- Memory and CPU limits
- Health checks

## Consequences

### Positive

- Reproducible environments
- Isolated security tools
- Easy scaling
- Production-ready

### Negative

- Increased resource usage
- Docker dependency
- Network complexity

## Implementation

See `docker-compose.yml` and `containers/` for implementation details.
