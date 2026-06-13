# 🦅 Nova Arsenal — Feature Capability Matrix

This document maps **every user-facing feature** to its entry point, requirements, and output.

---

## Core Capabilities by Role

### 🔰 Beginner (Non-Technical, Hands-Off)

| Feature | Command | Setup | Time | Output |
|---------|---------|-------|------|--------|
| **One-command hunt** | `nova hunt http://target.com` | None | 5-30m | JSON findings + HTML report |
| **Full pipeline** | `nova full ./my-app` | None | 15-45m | Map + SAST + SCA + report |
| **Codebase map only** | `nova map ./my-app` | None | 2-15s | `_CMAP.json` (tech stack) |
| **View latest report** | `nova report` | 1 hunt completed | 1s | Open in browser |
| **Health check** | `nova status` | None | 5s | Module status |

### 👨‍💻 Intermediate (Security Professional)

| Feature | Command | Setup | Time | Output |
|---------|---------|-------|------|--------|
| **Specific scanner** | `nova scan sqli http://target.com` | None | 5-15m | Verified SQLi findings |
| **Multi-agent orchestration** | `nova orch http://target.com` | LLM provider set | 30-60m | Recon → Attack → Report |
| **Real-time monitoring** | `nova-watch ./my-app --staged` | Pre-commit hook (optional) | Continuous | Blocks commit if HIGH found |
| **Session management** | `nova session list`, `resume <id>` | Completed hunts | 1s | Resume interrupted scans |
| **Custom reporting** | `nova report --template executive` | 1 hunt completed | 5s | C-suite summary |
| **Notification alerts** | Set `TELEGRAM_BOT_TOKEN` | Telegram bot setup | Real-time | Alerts on Telegram |

### 🔒 Advanced (Red Team / Researchers)

| Feature | Command | Setup | Time | Output |
|---------|---------|-------|------|--------|
| **Threat modeling** | `python3 nova_threat_model.py ./my-app` | None | 5-10s | STRIDE threats + vectors |
| **Patch generation** | `nova generate-patch <id>` | LLM provider | 10-30s | `patch.diff` (reviewable) |
| **Detection rules** | `nova generate-detection <id>` | LLM provider | 5-10s | `sigma_rules.yml` |
| **Cloud hunting** | `nova-cloud hunt http://target.com` | GitHub + API key | 30-60m | Full report on GitHub |
| **Self-evolution** | `python3 nova_evolution.py --goal "..."` | `NOVA_ALLOW_EVOLUTION=true` | 5-15m | Improved code + tests |
| **Custom agent loop** | `python3 nova_orchestrator.py --mode custom` | Custom prompts | Variable | Custom output |
| **RAG knowledge** | `python3 nova_rag_builder.py` | Past hunt reports | 2-5m | Searchable knowledge base |

---

## Feature Inventory (35+ Modules)

### 🎯 Entry Points (What Users Actually Run)

#### Command-Line Interface (Structured)
```bash
nova hunt <url>              # Single-target hunt
nova full <path>             # Local full pipeline
nova map <path>              # Codebase intelligence only
nova orch <url>              # Multi-agent orchestration
nova recon <url>             # Passive recon only
nova sast <path>             # Static analysis only
nova sca <path>              # Dependency scan only
nova triage                   # Re-prioritize findings

# Specific scanners
nova scan sqli|xss|idor|ssrf|jwt|csrf|race|graphql <url>

# Management
nova status                  # Health check
nova providers --test        # LLM provider check
nova session list|resume|export
nova report [--format html|json|md]
nova eval --quick|--live|--full
```

#### Python Direct Invocation
```bash
python3 nova.py "<intent>"                    # Natural language mode
python3 nova_cli.py <structured commands>    # Structured CLI
python3 nova_orchestrator.py --mode <mode>   # Multi-agent
python3 nova_threat_model.py <path>          # Threat modeling
python3 nova_diff_watcher.py <path>          # Real-time watch
python3 nova_eval.py --quick                 # Benchmarking
python3 nova_evolution.py --goal "..."       # Self-improve
python3 nova_rag_builder.py <path>           # Knowledge base
```

#### Cloud/GitHub Actions
```bash
nova-cloud hunt <url>                        # Cloud hunt
nova-cloud results <job-id>                  # Get results
nova-cloud brain                             # See learning
nova-watch ./app --on-commit                 # Pre-commit hook
```

---

## Scanning Modules (What Each Does)

### Phase 0 — Codebase Mapping (Always First)

| Module | CLI | Time | Detects |
|--------|-----|------|----------|
| `nova_codebase_mapper.py` | `nova map` | 2-15s | 30+ languages, 25+ frameworks, all routes, auth mechanisms, secrets, CVE deps, attack surface |

### Phase 1 — Static Analysis

| Module | CLI | Time | Detects |
|--------|-----|------|----------|
| `nova_source_auditor.py` | `nova sast` | 10-60s | Code injection, crypto misuse, logic flaws (Python, JS/TS, Go, Java, PHP) |
| `nova_sca_scanner.py` | `nova sca` | 5-30s | CVE-affected dependencies, version mismatches |
| `nova_git_scanner.py` | `nova scan secrets` | 5-20s | Leaked API keys, DB credentials, private keys |
| `nova_cicd_scanner.py` | `nova scan ci-cd` | 5-10s | GitHub Actions, GitLab CI misconfigs |
| `nova_container_scanner.py` | `nova scan container` | 2-5s | Dockerfile vulnerabilities, base image CVEs |

### Phase 2 — Active Scanning

| Module | CLI | Time | Detects |
|--------|-----|------|----------|
| `nova_fuzzer.py` | `nova scan sqli` / `nova scan xss` | 5-15m | SQL injection, XSS via fuzzing |
| `nova_idor_scanner.py` | `nova scan idor` | 5-10m | Insecure direct object references |
| `nova_graphql_tester.py` | `nova scan graphql` | 5-10m | GraphQL introspection, batching, IDOR |
| `nova_csrf_tester.py` | `nova scan csrf` | 2-5m | CSRF token validation bypass |
| `nova_jwt_forge.py` | `nova scan jwt` | 5-10m | JWT alg:none, key confusion, expiry bypass |
| `nova_business_logic.py` | `nova scan business-logic` | 10-15m | Price manipulation, race conditions |
| `nova_race_engine.py` | `nova scan race` | 15-30m | Time-of-check-time-of-use bugs |
| `nova_llm_injection.py` | `nova scan llm-injection` | 5-10m | Prompt injection attacks |

### Phase 3 — Intelligence & Verification

| Module | CLI | Time | Output |
|--------|-----|------|--------|
| `nova_ast_intel.py` | Auto-invoked | 5s | Route→sink dataflow, taint analysis |
| `nova_verify_engine.py` | Auto-invoked | 10-30s | Triple-confirms findings (control + attack + replay) |
| `nova_browser_session.py` | Auto-invoked | 5-30s | Executes XSS, captures HAR, screenshots |
| `nova_triage.py` | `nova triage` | 5s | Scores findings by H1 standards (CVSS) |
| `nova_zero_day_correlator.py` | Auto-invoked | 5s | Correlates with live CVE feeds (NVD/OSV) |

### Phase 4 — Output Generation

| Module | CLI | Time | Output |
|--------|-----|------|--------|
| `nova_patch_generator.py` | `nova generate-patch <id>` | 10-30s | `patch.diff` (code-level fix) |
| `nova_detection_engineer.py` | `nova generate-detection <id>` | 5-10s | `sigma_rules.yml` (SIEM rules) |
| `nova_audit_reporter.py` | `nova report` | 5s | HTML/JSON/MD/CSV reports |
| `nova_vuln_tracker.py` | `nova vuln-db` | 1s | Query local SQLite database |

---

## Provider Layer (Infrastructure)

These run **automatically** behind the scenes; users don't invoke directly:

| Module | Purpose | Configured Via |
|--------|---------|----------------|
| `nova_llm_router.py` | Routes tasks to best LLM provider | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `NOVA_LLM_URL` |
| `nova_hooks.py` | Event lifecycle (PreRun, PostRun, OnFinding, etc.) | `.env` (implicit) |
| `nova_context.py` | Shared state across phases | Auto-initialized |
| `nova_sessions.py` | Persists scan progress | `~/nova_workspace/sessions/` |
| `nova_observability.py` | Tracing + flame graphs | `DEBUG=true` |
| `nova_retry.py` | Resilient retries + circuit breaker | Auto-configured |
| `nova_skills.py` | Skill templates + system prompts | `nova_skills.py` (edit for custom prompts) |
| `nova_tool_kit.py` | Tool governance + audit log | `NOVA_PERMISSION_PROFILE` |

---

## Orchestration Modes

### Single-Command Natural Language

```bash
python3 nova.py "Hunt http://localhost:3000 for SQL injection"
# → Intent parser → Phase 0 → dispatch to relevant modules
```

**Supported intents:**
- "Hunt <url> for <vulnerability-type>"
- "Map <path>"
- "Full pipeline on <path|url>"
- "SAST on <path>"
- "SCA on <path>"
- "Build threat model for <path>"
- "Orchestrate attack on <url>"

### Structured CLI

```bash
nova hunt http://target.com --provider anthropic --max-time 30m
# → Calls nova_cli.py → dispatches
```

### Multi-Agent Orchestration

```bash
python3 nova_orchestrator.py --mode full http://target.com
# Sequence:
#   1. ReconAgent: Discovers endpoints, tech stack, attack surface
#   2. AttackAgent: Plans exploits, crafts payloads, verifies
#   3. ReportAgent: Writes findings, generates patches
```

---

## Configuration Matrix

### How to Set Features

| Feature | Method 1 | Method 2 | Default |
|---------|----------|----------|----------|
| **LLM Provider** | `OPENAI_API_KEY=...` | Export in shell | Ollama (localhost:11434) |
| **LLM Model** | `NOVA_LLM_MODEL=qwen3:8b` | Edit `.env` | qwen3:8b |
| **Permission** | `NOVA_PERMISSION_PROFILE=full` | `.env` | scoped |
| **Target** | `nova hunt http://...` | `NOVA_TARGET=...` | Arg required |
| **Max steps** | `NOVA_MAX_STEPS=100` | `.env` | 40 |
| **Notifications** | `TELEGRAM_BOT_TOKEN=...` | `.env` | Silent (no notifications) |
| **Workspace** | `NOVA_WORKSPACE=~/my-workspace` | `.env` | `~/nova_workspace` |
| **Evolution** | `NOVA_ALLOW_EVOLUTION=true` | `.env` | false |
| **Debug** | `DEBUG=true python3 nova.py ...` | `.env` | false |

---

## Troubleshooting: "I want to do X, how?"

| User Goal | Command(s) |
|-----------|----------|
| **Scan a web app for all vulns** | `nova full http://target.com` or `nova hunt http://target.com` |
| **Map a codebase (no scanning)** | `nova map ./my-app` |
| **Find hardcoded secrets** | `nova scan secrets ./my-app` |
| **Find dependency vulns** | `nova sca ./my-app` |
| **Generate security patches** | `nova generate-patch <finding-id>` (requires finding from hunt) |
| **Generate SIEM detection rules** | `nova generate-detection <finding-id>` |
| **Hunt 24/7 on cloud** | `nova-cloud hunt http://target.com` (+ GitHub Actions) |
| **Stop me from committing secrets** | `nova-watch ./my-app --staged` (in pre-commit hook) |
| **Resume interrupted scan** | `nova session list` then `nova session resume <id>` |
| **See what Nova learned** | `nova-cloud brain` or query `~/nova_workspace/nova_brain.json` |
| **Improve Nova's code** | `python3 nova_evolution.py --goal "Better IDOR detection"` |
| **Test Nova's accuracy** | `nova_eval.py --quick` |
| **Send alerts to Slack** | Set `SLACK_WEBHOOK_URL=...` in `.env` |

---

## Performance Expectations

| Task | Time | Typical Output Size |
|------|------|--------------------|
| Codebase map (1000 files) | 2-15s | 50KB JSON |
| SAST scan | 10-60s | 100KB-1MB |
| SCA scan | 5-30s | 50KB-500KB |
| Secret scan (git history) | 5-20s | 10KB-100KB |
| Single vulnerability scan (SQLi, XSS, IDOR) | 5-15m | 10KB-100KB |
| Full active scan (all scanners) | 1-2h | 1-10MB |
| Multi-agent orchestration | 30-60m | 5-50MB |
| Evaluation suite (20 missions) | 5-30m | 1MB |
| Threat modeling | 5-10s | 20KB |
| Patch generation | 10-30s | 5KB |

---

## What Gets Saved Where

```
~/nova_workspace/
├── reports/              # HTML, JSON, MD, CSV reports
├── sessions/             # Scan state (resumable)
├── logs/
│   ├── nova.log         # Main activity log
│   ├── nova_tool_audit.jsonl  # Tool call audit trail
│   └── *.log
├── screenshots/         # Browser screenshots from Playwright
├── har/                 # HAR files (network recordings)
├── nova_brain.json      # Knowledge base (for RAG)
├── nova_vulnerabilities.db  # SQLite vuln database
└── .venv/              # Python virtual environment
```

---

## What's Next?

- **New user?** Start with [INSTALLATION_COMPLETE.md](INSTALLATION_COMPLETE.md)
- **Want examples?** See [SOLUTIONS.md](SOLUTIONS.md) and [REFERENCES.md](REFERENCES.md)
- **Contributing?** Read [AGENTS.md](AGENTS.md) for AI assistant guidelines
- **Detailed docs?** Check [README.md](README.md) architecture section

---

**Last Updated:** June 2026  
**Version:** Nova Arsenal v4.2
