# 🦅 Nova Arsenal v4.2

> **The most capable open-source autonomous security research agent.**
> Reads your entire codebase in seconds, maps every language and framework strategically, connects all 35+ modules together, and hunts vulnerabilities with the intelligence of a senior penetration tester.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     nova_cli.py  /  nova.py                     │
│              Natural-language entry point (intent parser)       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
         ┌──────────────────▼──────────────────┐
         │         PHASE 0 — ALWAYS FIRST       │
         │       nova_codebase_mapper.py         │
         │  128 threads · 30+ langs · 25+ fwks  │
         │  route extract · secret scan · CVEs  │
         │  AI attack-surface prioritisation    │
         └──────────────────┬──────────────────┘
                            │  CodebaseMap → _CMAP (global)
         ┌──────────────────▼──────────────────┐
         │          PROVIDER LAYER              │
         │  LLMRouter  HookBus  RunContext      │
         │  Sessions   Tracer   Retry  Skills   │
         └──┬──────┬───────┬──────┬────────────┘
            │      │       │      │
    ┌───────▼──┐ ┌─▼───┐ ┌▼────┐ ┌▼──────────────────────────┐
    │  STATIC  │ │RECON│ │CTVE │ │  MULTI-AGENT ORCHESTRATOR  │
    │  SAST    │ │Sub- │ │PROBES│ │  nova_orchestrator.py v3   │
    │  SCA     │ │finder│ │IDOR │ │  ┌──────────┐             │
    │  Git scan│ │httpx │ │SQLi │ │  │ReconAgent│ ←map seeded │
    │  CI/CD   │ │gau   │ │XSS  │ │  └────┬─────┘             │
    │  Container│ └─────┘ │SSRF │ │       │ handoff           │
    │  IaC     │         │JWT  │ │  ┌────▼──────┐             │
    └──────────┘         │CSRF │ │  │AttackAgent│ ←map brief  │
                         │RACE │ │  └────┬──────┘             │
                         └─────┘ │       │ handoff           │
                                 │  ┌────▼──────┐             │
                                 │  │ReportAgent│             │
                                 │  └───────────┘             │
                                 └───────────────────────────-┘
                            │
         ┌──────────────────▼──────────────────┐
         │         INTELLIGENCE LAYER           │
         │  nova_ast_intel.py  — route→sink     │
         │  nova_verify_engine — triple confirm  │
         │  nova_triage        — H1 scoring     │
         │  nova_zero_day_correlator — live CVEs │
         │  nova_browser_session — Playwright    │
         └──────────────────┬──────────────────┘
                            │
         ┌──────────────────▼──────────────────┐
         │          OUTPUT LAYER                │
         │  nova_patch_generator               │
         │  nova_detection_engineer            │
         │  nova_audit_reporter                │
         │  nova_vuln_tracker  (SQLite)         │
         └──────────────────┬──────────────────┘
                            │
         ┌──────────────────▼──────────────────┐
         │       CONTINUOUS IMPROVEMENT         │
         │  nova_diff_watcher   real-time watch │
         │  nova_eval.py        20 benchmarks   │
         └─────────────────────────────────────┘
```

---

## Quick Start

```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
pip install -r requirements.txt

# Check all modules load
python3 nova.py "Health check of all modules"

# Map a codebase (Phase 0 standalone)
python3 nova_codebase_mapper.py ./juice-shop --brief

# Hunt for bugs (Phase 0 runs automatically before scanning)
python3 nova.py "Hunt http://localhost:3000 for vulnerabilities"

# Full pipeline (map + SAST + SCA + active scans + report)
python3 nova.py "Full stack pipeline on ./juice-shop"

# Multi-agent orchestration
python3 nova.py "Orchestrate attack on http://localhost:3000"

# Real-time file watcher
python3 nova_diff_watcher.py ./my-app

# Run evaluation suite
python3 nova_eval.py --quick
```

---

## The Codebase Mapper (Phase 0)

Every single Nova run starts with `nova_codebase_mapper.py`. Before any probe touches the network, Nova reads the **entire codebase** and builds a strategic intelligence map:

| What it detects | How |
|---|---|
| **30+ languages** | Extension map + shebang + content signatures |
| **25+ frameworks** | Manifest file parsing (package.json, requirements.txt, go.mod, Cargo.toml, pom.xml, Gemfile, mix.exs, composer.json, *.csproj) |
| **All routes/endpoints** | Regex extraction for Express, Flask, FastAPI, Django, Spring, Rails, Laravel, Gin, Echo, Phoenix, Next.js, ASP.NET |
| **Auth mechanisms** | JWT, OAuth2, Sessions, API Keys, SAML, LDAP, Bcrypt, CSRF, TOTP, Passport.js, Firebase Auth |
| **Databases** | PostgreSQL, MySQL, SQLite, MongoDB, Redis, Elasticsearch, DynamoDB, Firestore, Prisma, TypeORM, Sequelize, SQLAlchemy, Drizzle, GORM |
| **Secrets** | AWS keys, GitHub tokens, Stripe keys, OpenAI/Anthropic keys, JWT secrets, private keys, hardcoded passwords, DB connection strings |
| **CVE-affected deps** | 18 known-risky packages mapped to CVEs and safe versions |
| **Attack surface** | Every endpoint scored and prioritised by attack potential |
| **AI analysis** | LLM-generated "what's the #1 bug in this specific stack" brief |

**Performance:** 10,000 files < 2s · 100,000 files < 15s (128 parallel threads)

The map is then:
- Injected into every active scanner as pre-discovered endpoint seeds
- Injected into every agent's system prompt as a strategic attack brief
- Used to seed the threat model with real entry points
- Used to prioritise SAST on high-value files first

---

## All Modules

### Core Runtime
| Module | Role |
|---|---|
| `nova.py` | Natural-language entry point, Phase 0 runner, 30-mode dispatcher |
| `nova_cli.py` | Structured CLI (`nova hunt`, `nova sast`, `nova orch`, etc.) |
| `nova_codebase_mapper.py` | Hyper-fast codebase intelligence (Phase 0) |
| `nova_orchestrator.py` | Multi-agent runner (ReconAgent → AttackAgent → ReportAgent) |

### Provider Layer (7 modules)
| Module | Role |
|---|---|
| `nova_llm_router.py` | OpenAI → Anthropic → Gemini → Ollama with cost tracking |
| `nova_hooks.py` | Lifecycle event bus (PreRun/PostRun/OnFinding/PreTool/PostTool) |
| `nova_context.py` | Typed shared RunContext across all phases |
| `nova_sessions.py` | Persistent session store (SQLite) |
| `nova_observability.py` | Distributed tracer, spans, HTML flame graph |
| `nova_retry.py` | Resilient caller with exponential backoff + circuit breaker |
| `nova_skills.py` | Skill library with templated system prompts |

### Intelligence Layer
| Module | Role |
|---|---|
| `nova_ast_intel.py` | AST/tree-sitter code analysis, route→sink tracing, taint dataflow |
| `nova_browser_session.py` | Persistent Playwright session, HAR capture, XSS execution verification |
| `nova_tool_kit.py` | Hardened governed tools: scope check, rate limit, audit log, redaction |
| `nova_verify_engine.py` | Triple-confirmation verification (control + attack + replay) |
| `nova_triage.py` | AI-powered H1-ready finding prioritisation |
| `nova_zero_day_correlator.py` | Live CVE correlation via NVD/OSV APIs |
| `nova_diff_watcher.py` | Real-time file change monitor → targeted incremental scans |
| `nova_eval.py` | 20-mission deterministic evaluation harness |

### Scanning Modules
| Module | Role |
|---|---|
| `nova_source_auditor.py` | SAST — Python, JS/TS, Go, Java, PHP |
| `nova_sca_scanner.py` | SCA — dependency CVE detection |
| `nova_supply_chain_scorer.py` | Package risk scoring, typosquatting detection |
| `nova_git_scanner.py` | Git history secret scanning |
| `nova_cicd_scanner.py` | CI/CD pipeline misconfiguration |
| `nova_container_scanner.py` | Dockerfile / Kubernetes security |
| `nova_idor_scanner.py` | IDOR / BOLA testing |
| `nova_graphql_tester.py` | GraphQL introspection, batching, IDOR |
| `nova_csrf_tester.py` | CSRF token analysis |
| `nova_business_logic.py` | Business logic flaw testing |
| `nova_jwt_forge.py` | JWT alg:none, key confusion, expiry bypass |
| `nova_fuzzer.py` | SQLi, XSS, SSRF fuzzing |
| `nova_llm_injection.py` | Prompt injection testing |
| `nova_threat_model.py` | STRIDE threat model generation |

### Output Modules
| Module | Role |
|---|---|
| `nova_patch_generator.py` | AI-generated code-level patches |
| `nova_detection_engineer.py` | Sigma / SIEM detection rules |
| `nova_audit_reporter.py` | Executive report + CVSS scoring |
| `nova_vuln_tracker.py` | SQLite vulnerability database with trend analysis |

---

## CLI Reference

```bash
# Core modes
nova hunt   <url>   [--provider openai|anthropic|ollama]
nova full   <path>  # Full pipeline: map + SAST + SCA + active + report
nova map    <path>  # Codebase map only
nova orch   <url>   # Multi-agent orchestration
nova recon  <url>   # Passive recon only
nova sast   <path>  # Static analysis
nova sca    <path>  # Dependency scan
nova triage         # Re-triage loaded findings

# Specific scanners
nova scan sqli   <url>
nova scan xss    <url>
nova scan idor   <url>
nova scan ssrf   <url>
nova scan jwt    <url>
nova scan csrf   <url>
nova scan race   <url>
nova scan graphql <url>

# Utilities
nova status                    # Health check all 35 modules
nova providers --test          # Test all LLM providers
nova session list
nova session resume <id>
nova session export <id>
nova report                    # Generate latest audit report
nova eval --quick              # Run evaluation benchmark

# Diff watcher (run in background during development)
nova-watch ./my-app            # Alias for nova_diff_watcher.py
nova-watch ./my-app --on-commit # Scan last commit (CI/CD)
nova-watch ./my-app --staged    # Scan staged files (pre-commit hook)
```

---

## Data Flow

```
                          Query: "Hunt http://target.com"
                                        │
                               1. _parse_intent()
                               2. _init_provider_layer()
                                        │
                    ┌───────────────────▼───────────────────┐
                    │        Phase 0: Codebase Mapper        │
                    │  • Enumerate all files (os.walk)       │
                    │  • Read in parallel (128 threads)      │
                    │  • Detect languages + frameworks       │
                    │  • Extract all routes                  │
                    │  • Detect secrets + risky deps         │
                    │  • Score attack surface                │
                    │  • AI strategic analysis               │
                    │  → _CMAP (global CodebaseMap)          │
                    └───────────────────┬───────────────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │   Seed map findings into _CTX          │
                    │   • Secrets → HIGH findings            │
                    │   • CVE deps → HIGH findings           │
                    │   • Endpoints → _CTX.endpoints[]       │
                    └───────────────────┬───────────────────┘
                                        │
                         dispatch(intent) → Phase 1–12
                                        │
               ┌────────────┬───────────┼──────────────┐
               │            │           │              │
          STATIC       ACTIVE        AGENTS        OUTPUT
          SAST+SCA   scanners     Orchestrator    Triage+
          Git scan   seeded with  map brief in   Report+
          IaC scan   map_endpoints agent prompts  Patches
               │            │           │              │
               └────────────┴───────────┴──────────────┘
                                        │
                              _emit_findings()
                                        │
                    ┌───────────────────▼───────────────────┐
                    │  HookBus.fire_finding()                │
                    │  RunContext.add_finding()              │
                    │  Session.add_finding()                 │
                    │  VulnTracker.ingest()                  │
                    └───────────────────────────────────────┘
```

---

## Gaps Addressed (v4.2)

### GAP 1 — Integration Reliability ✅
- `nova.py` is the single blessed runtime spine: `nova.py → provider layer → context/session/tracer → tool executor → agent → findings`
- `NovaAgentCore` alias resolves to `NovaAgent` automatically — silent failures fixed
- Every dispatch mode calls `_emit_findings()` which fans out to all 4 sinks atomically

### GAP 2 — Tool Governance ✅
`nova_tool_kit.py` now provides:
- **Permission profiles**: `read_only | scoped | full` (default: `scoped`)
- **Shell allow-list**: Only 30 approved commands; `rm -rf /`, `curl|bash`, `DROP TABLE`, etc. are blocked unconditionally
- **Scope enforcement**: Every HTTP tool checks the target against declared scope
- **Full audit log**: Every call logged to `nova_tool_audit.jsonl` with args (redacted) + result + elapsed
- **Secret redaction**: 14 patterns stripped before any log entry
- **Rate limiter**: Per-tool call budget prevents runaway agent loops
- **Path safety**: `read_file` / `grep_code` block sensitive system paths

### GAP 3 — Verification Quality ✅
`nova_verify_engine.py` now requires:
- Control request (baseline) + attack request + replay request = triple confirmation
- IDOR tests require user-A / user-B auth context
- SSRF supports OAST/collaborator callback URLs
- XSS verification via `nova_browser_session.py` — console log execution, not just text reflection

### GAP 4 — Persistent Browser State ✅
`nova_browser_session.py`:
- One Playwright context per session
- Login state persisted (cookies + localStorage saved to file)
- HAR capture for every request/response
- Screenshot on every major action
- Console log capture → XSS execution verification
- Visual diffs between page states
- Auth bypass detection (no login redirect = bypass)

### GAP 5 — Code Intelligence ✅
`nova_ast_intel.py`:
- tree-sitter parsing for JS/TS/Python when available
- stdlib `ast` module fallback for Python (zero extra deps)
- Route → handler → sink tracing
- Taint dataflow: `req.body.query` → SQL concatenation → HIGH finding
- Call graph construction
- Test coverage map (which tests cover which source files)

### GAP 6 — Evaluation Harness ✅
`nova_eval.py` — 20 deterministic benchmark missions:

| ID | Mission | Quick |
|---|---|---|
| map_01 | Map Express routes from fixture | ✓ |
| sca_01 | Detect CVE in jsonwebtoken | ✓ |
| secret_01 | Find hardcoded AWS key | ✓ |
| map_02 | Identify 8+ languages in polyglot repo | ✓ |
| map_03 | Detect 6+ frameworks from manifests | ✓ |
| map_04 | Attack surface admin/payment ranked first | ✓ |
| diff_01 | DiffWatcher detects new secret | ✓ |
| infra_01 | Juice Shop reachability check | ✓ |
| idor_01 | Juice Shop IDOR on /rest/user | live |
| jwt_01 | Juice Shop JWT alg:none | live |
| sast_01 | SAST finds hardcoded creds in Python | ✓ |
| sca_02 | SCA detects PyYAML RCE | ✓ |
| diff_02 | DiffWatcher detects insecure Terraform | ✓ |
| diff_03 | DiffWatcher triggers SCA on manifest change | ✓ |
| perf_01 | Map 1000 files in < 10s | - |
| infra_02 | All 7 provider modules import | ✓ |
| orch_01 | Orchestrator builds 3-agent network | ✓ |
| map_05 | attack_brief() contains required sections | ✓ |
| core_01 | Intent classification (10 queries) | ✓ |
| e2e_01 | End-to-end on local test server | live |

Run: `python3 nova_eval.py --quick` (no live targets needed)

### GAP 7 — Repo Hygiene ✅
- `.gitignore` now excludes all generated outputs (reports, HAR, screenshots, eval fixtures, sessions, traces)
- All runtime artifacts go to `~/nova_workspace` — never committed
- Source, tests, configs, docs, and fixtures only in the repo

---

## Environment Variables

```bash
# LLM provider (fallback chain: OpenAI → Anthropic → Gemini → Ollama)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=AIza...
NOVA_LLM_URL=http://localhost:11434    # Ollama
NOVA_LLM_MODEL=qwen3:8b               # Ollama model

# Nova runtime
NOVA_TARGET=http://localhost:3000      # Default target
NOVA_WORKSPACE=~/nova_workspace        # Output directory (never committed)
NOVA_MAX_STEPS=40                      # Max agent steps per run
NOVA_PERMISSION_PROFILE=scoped         # read_only | scoped | full

# Notifications
NOVA_TELEGRAM_TOKEN=...
NOVA_TELEGRAM_CHAT_ID=...

# Eval targets
EVAL_JUICE_SHOP=http://localhost:3000
EVAL_DVWA=http://localhost:4280
EVAL_WEBGOAT=http://localhost:8080/WebGoat
```

---

## Pre-commit Hook (Diff Watcher)

```bash
# .git/hooks/pre-commit
#!/bin/bash
python3 /path/to/nova_diff_watcher.py . --staged
exit $?
```

Automatically scans staged files for secrets, CVE deps, and IaC misconfigs before every commit.

---

## CI/CD Integration

```yaml
# .github/workflows/nova.yml
name: Nova Security Scan
on: [push, pull_request]
jobs:
  nova-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Nova
        run: pip install -r requirements.txt
      - name: Run eval benchmark
        run: python3 nova_eval.py --quick
      - name: Scan changed files
        run: python3 nova_diff_watcher.py . --git-diff HEAD~1
      - name: Full SAST + SCA
        run: python3 nova.py "SAST and SCA scan of ."
```

---

## Where Things Live

```
Nova-arsenal/
├── nova.py                    # Main entry point v4.2
├── nova_cli.py                # Structured CLI
├── nova_codebase_mapper.py    # Phase 0 codebase intelligence
├── nova_orchestrator.py       # Multi-agent orchestrator v3.0
├── nova_diff_watcher.py       # Real-time change watcher
├── nova_eval.py               # 20-mission evaluation harness
├── nova_ast_intel.py          # AST/tree-sitter code intelligence
├── nova_browser_session.py    # Persistent Playwright session
├── nova_tool_kit.py           # Hardened governed tools
│
├── nova_llm_router.py         # Provider layer: LLM router
├── nova_hooks.py              # Provider layer: hook bus
├── nova_context.py            # Provider layer: typed context
├── nova_sessions.py           # Provider layer: session store
├── nova_observability.py      # Provider layer: tracer
├── nova_retry.py              # Provider layer: retry + circuit breaker
├── nova_skills.py             # Provider layer: skill library
│
├── nova_source_auditor.py     # SAST
├── nova_sca_scanner.py        # SCA
├── nova_verify_engine.py      # Triple-confirmation verification
├── nova_triage.py             # H1-ready prioritisation
├── nova_threat_model.py       # STRIDE threat modeling
├── nova_zero_day_correlator.py# Live CVE correlation
├── nova_patch_generator.py    # AI patch generation
├── nova_detection_engineer.py # Detection rule generation
├── nova_audit_reporter.py     # Executive reporting
├── nova_vuln_tracker.py       # Vulnerability database
│
├── requirements.txt
├── .gitignore                 # Excludes all generated outputs
└── README.md
```

All runtime outputs → `~/nova_workspace/` (never committed to the repo).

---

## Architecture Decisions

1. **Phase 0 is mandatory** — The codebase mapper runs before every scan. It costs 1-15s and saves 10x that in wasted probes against irrelevant endpoints.

2. **Single blessed emission path** — `_emit_findings()` in `nova.py` fans out to HookBus + RunContext + Session + VulnTracker atomically. No module writes findings directly; everything goes through this function.

3. **Tool governance is non-negotiable** — `nova_tool_kit.py` wraps every callable. `NOVA_PERMISSION_PROFILE=full` must be set explicitly to unlock destructive tools. The audit log is append-only.

4. **Map-aware is better than blind** — Rather than crawling the live app to discover endpoints, Nova reads the source code to discover them in milliseconds. Active probes confirm what the map already predicts.

5. **Evaluation harness drives quality** — `nova_eval.py` must be run after every significant change. Regressions on quick missions (no live targets) block merges.
