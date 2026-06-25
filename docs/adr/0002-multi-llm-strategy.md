# ADR-0002: Multi-LLM Strategy

## Status

Accepted

## Context

Nova-Arsenal needs to support multiple LLM providers for flexibility, cost optimization, and reliability. Users may prefer different providers based on:
- Cost (Ollama is free, cloud APIs cost money)
- Performance (different models for different tasks)
- Availability (fallback when one provider is down)

## Decision

We will implement a multi-provider LLM system with:

1. **Provider Interface**: Abstract base class for all providers
2. **Router**: Automatic provider selection and fallback
3. **Configuration**: YAML-based provider configuration
4. **Fallback Chain**: Automatic failover on provider failure

### Supported Providers

| Provider | Use Case | Cost |
|----------|----------|------|
| Ollama | Local inference | Free |
| OpenAI | High-quality output | Pay-per-token |
| Anthropic | Long context | Pay-per-token |
| Gemini | Fast inference | Pay-per-token |

### Routing Strategy

```yaml
routing:
  strategy: "cost-optimized"
  fallback_threshold: 3
  max_retries: 3
```

## Consequences

### Positive

- Users can choose their preferred provider
- Automatic fallback increases reliability
- Cost optimization for budget-conscious users
- Local inference option for privacy

### Negative

- Increased complexity in provider management
- Need to maintain multiple provider implementations
- Potential inconsistencies between providers

## Implementation

See `nova_arsenal/llm/` for implementation details.
