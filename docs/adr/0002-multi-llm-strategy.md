# ADR-0002: Multi-LLM Strategy

## Status

Accepted, revised September 2026.

## Context

Nova-Arsenal supports multiple LLM providers for reliability, privacy, cost control,
and local inference. Model catalogs, pricing, context windows, and published latency
change too quickly to be reliable routing constants inside application code.

The previous router embedded exact vendor model names, token prices, context sizes,
and guessed latency values. That created two correctness problems:

1. routing metadata could report a different model from the one actually configured;
2. routing quality degraded as vendor catalogs changed.

## Decision

Nova uses a provider interface plus runtime-aware routing.

1. **Actual configured model wins.** Routing decisions always report the model on the
   registered provider instance.
2. **Stable capabilities only.** Static profiles describe broad task strengths,
   local-vs-cloud status, and tool support. They do not contain model catalogs,
   prices, context-window sizes, or assumed latency.
3. **Runtime telemetry.** Successful and failed calls update per-provider reliability
   and observed latency. Later routing decisions can use those measurements.
4. **Preferences are bounded.**
   - `balanced` combines task fit, reliability, observed latency, and a small local bonus;
   - `quality` emphasizes task fit and observed reliability;
   - `speed` uses observed latency when available;
   - `cost` only gives a structural advantage to local inference, because cloud pricing
     varies by model and account and must not be guessed.
5. **Fallback remains automatic.** Up to three alternate registered providers are
   retained in the routing decision.
6. **Provider defaults stay overridable.** `LLM_PROVIDER`, `LLM_MODEL`, and
   provider-specific model environment variables always take precedence over defaults.
7. **OpenAI API mode.** Official OpenAI endpoints use the Responses API; generic
   OpenAI-compatible local endpoints continue to use Chat Completions by default.

## Consequences

### Positive

- routing reflects the model that will actually receive the request;
- no stale in-code price or latency tables;
- local inference remains a first-class privacy/cost option;
- provider reliability can improve routing over time;
- vendor model upgrades mostly become configuration changes rather than router rewrites.

### Negative

- cold-start routing has less model-specific detail;
- runtime telemetry is process-local and is not yet persisted;
- “quality” is approximated by capability fit and reliability, not subjective benchmark rankings.

## Follow-up

Persist routing telemetry and add optional administrator-defined provider weights if
production deployments need deterministic organization-specific routing policy.
