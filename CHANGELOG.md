# Changelog

All notable changes to Nova-Arsenal will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No unreleased changes yet.

---

## [2.0.0] - 2026-10-01

### Added
- **Concurrent work sessions + sub-agents** — `SessionManager` runs recon/web/osint/researcher/exploit/validator/reporter **in parallel** under one session; API `/api/work-sessions`, CLI `nova-agent session`, consensus aggregation, event stream, disk persistence
- **Natural multi-turn chat** — conversation-first system prompts, full history, fixed SSE streaming via LLMRouter (not broken `active_providers`), offline fallback that still talks; web UI welcome copy for “chat like ChatGPT”
- **ChatGPT / Codex subscription OAuth** — `nova-agent login --provider openai --oauth` (PKCE browser) and `--device-code` for headless; token refresh; preferred primary when signed in
- **Local LLM first-class** — Ollama auto-discovery, `nova-agent login --provider ollama`, LM Studio/OpenAI-compatible local servers; `GET /api/llm/local`
- **Account-style AI login (Codex / Claude Code)** — `nova-agent login`, import local Claude/Codex sessions, `CLAUDE_CODE_OAUTH_TOKEN`, Google OAuth for Gemini; tokens in `~/.nova/accounts.json`; API `/api/llm/accounts/*`
- **VS Code extension fixed** — compiles to `out/`, correct chat endpoint, Sign In / Import sessions / Ollama commands, host-mediated API calls, Output channel
- **BYOK (bring-your-own-key) LLM wiring** — auto-detect OpenAI/Anthropic/Gemini/OpenRouter/DeepSeek/Qwen/HF keys from `.env`; honor `LLM_PROVIDER` + `LLM_MODEL`; `GET /api/llm/status` + `POST /api/llm/reload`; Settings UI shows live key status (no secrets leaked)
- **Zero-Day Candidate Pipeline (`nova_arsenal.zeroday`)** — high-speed research stack:
  - Parallel attack-surface ranking (`AttackSurfaceMapper`)
  - CVE variant / patch-gap analysis (`VariantAnalyzer`)
  - Static bug-class heuristics (`StaticBugScanner`)
  - Multi-engine fuzz campaign orchestration (`FuzzOrchestrator`)
  - **Live fuzz worker** (`LiveFuzzWorker`) — detects/runs ffuf, AFL++, honggfuzz, radamsa, HTTP mutator
  - Crash triage & dedup (`CrashTriageEngine`)
  - Novelty scoring vs known CVE fingerprints (`NoveltyScorer`)
  - Recon→services bridge (`findings_to_services`)
  - Unified hunter (`ZeroDayHunter`) with authorization gate
- **Swarm phase wiring:** recon → `researcher_zeroday` (auto ZeroDayHunter) → web/exploit/validator
- CLI: `--zeroday`, `--swarm`, `--live-fuzz`, `--authorized`, `--auth-ref`
- MCP: `zeroday_hunt`; `swarm_scan` returns phases + zeroday candidate count
- Tool schema + tool-selector rules for zeroday research
- Unit tests: `tests/unit/test_zeroday.py`, `tests/unit/test_swarm_zeroday.py`

### Notes
- Pipeline optimizes *seconds-scale prioritization and planning*. Live fuzz uses short
  job timeouts by default. It does **not** guarantee confirmed zero-day discovery;
  candidates require human validation and responsible disclosure. Authorized testing only.

### Previous
- Initial release of Nova-Arsenal platform
- 70+ security modules (recon, attack, analysis, reporting)
- Multi-LLM support (Ollama, OpenAI, Anthropic, Gemini)
- Web dashboard with real-time monitoring
- Docker-based deployment
- Multi-user authentication with JWT
- SQLite database for findings storage
- Kubernetes deployment manifests
- GitHub Actions CI/CD pipeline
- Security scanning (CodeQL, Trivy, TruffleHog)

### Changed
- N/A (initial release)

### Deprecated
- N/A (initial release)

### Removed
- N/A (initial release)

### Fixed
- N/A (initial release)

### Security
- Privileged MCP and shared LLM-management APIs require analyst/admin authentication
- Nmap MCP execution uses validated argument-vector subprocesses instead of shell interpolation
- Credentialed CORS rejects wildcard origins and production Compose requires explicit secrets/origins
- Authentication uses PyJWT + Argon2 with transparent legacy bcrypt migration
- Internal provider/MCP exceptions are logged server-side and redacted from client responses
- CI enforces Ruff formatting/linting, BasedPyright, Python 3.10–3.13 tests, web/VS Code builds, and Docker builds
- Security CI runs dependency audit, Trivy secret scanning, and CodeQL
- Capability dropping in all containers
- Network isolation for sandbox
- Secret redaction in logs
- Tool governance and rate limiting

---

## Pre-2.0 development history

### Added
- Core agent system with autonomous reasoning
- Skills library with prompt templates
- Governed tool kit with scope enforcement
- Multi-agent swarm architecture
- Web UI dashboard
- REST API with FastAPI
- WebSocket real-time updates
- Docker deployment
- Kubernetes manifests
- CI/CD pipeline
- Comprehensive documentation

---

## Versioning

We use [SemVer](https://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/Informant254/Nova-arsenal/tags).

## Release Process

See [`docs/RELEASING.md`](docs/RELEASING.md). The tag must exactly match the package version
(for example, package `2.0.0` requires tag `v2.0.0`). The release workflow validates the
tag/version pair and full Python quality gate before publishing to PyPI, GHCR, Docker Hub,
and GitHub Releases.
