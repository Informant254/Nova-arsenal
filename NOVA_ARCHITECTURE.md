# Nova Arsenal — System Architecture

> v4.2 + Truth Engine v1.0 | Zero False Positive Bug Bounty Framework

---

## High-Level Flow

```
╔══════════════════════════════════════════════════════════════════════════╗
║                      USER / CI PIPELINE                                  ║
║  python3 nova.py "Hunt https://target.com for all bugs"                  ║
╚══════════════════════╦═══════════════════════════════════════════════════╝
                        │
                        ▼
╔══════════════════════════════════════════════════════════════════════════╗
║                    nova.py  ─  ORCHESTRATOR                              ║
║                                                                          ║
║  ┌────────────────┐   ┌──────────────────┐   ┌──────────────────────┐   ║
║  │ Intent Parser  │──▶│ _parse_intent()  │──▶│ mode + target        │   ║
║  │ (NLP + LLM)    │   │ 40+ keyword maps │   │ e.g. hunt/xss/sast   │   ║
║  └────────────────┘   └──────────────────┘   └──────────────────────┘   ║
╚══════════════════════╦═══════════════════════════════════════════════════╝
                        │
                        ▼
╔══════════════════════════════════════════════════════════════════════════╗
║                  PROVIDER LAYER  (_init_provider_layer)                  ║
║                                                                          ║
║  ┌─────────────────┐  ┌──────────────┐  ┌────────────────────────────┐  ║
║  │  nova_llm_router│  │  nova_hooks  │  │  nova_sessions             │  ║
║  │  OpenAI         │  │  Hook Bus    │  │  Session Store             │  ║
║  │  Anthropic      │  │  (lifecycle  │  │  (persists findings        │  ║
║  │  Gemini         │  │   events)    │  │   across restarts)         │  ║
║  │  Ollama         │  └──────────────┘  └────────────────────────────┘  ║
║  └────────┬────────┘                                                     ║
║           │          ┌──────────────┐  ┌────────────────────────────┐   ║
║           │          │nova_memory_  │  │  nova_observability        │   ║
║           │          │system        │  │  Tracer                    │   ║
║           │          │(cross-session│  └────────────────────────────┘   ║
║           │          │ memory)      │                                    ║
║           │          └──────────────┘  ┌────────────────────────────┐   ║
║           │                            │  nova_truth_engine  ◀ NEW  │   ║
║           └───────────────────────────▶│  NovaTruthEngine           │   ║
║                                        │  (receives _ROUTER for LLM │   ║
║                                        │   false-positive analysis) │   ║
║                                        └────────────────────────────┘   ║
╚══════════════════════╦═══════════════════════════════════════════════════╝
                        │
                        ▼
╔══════════════════════════════════════════════════════════════════════════╗
║              PHASE 0 — CODEBASE MAPPER  (nova_codebase_mapper)           ║
║                                                                          ║
║  Only runs when target is a local directory OR NOVA_SOURCE_DIR is set.  ║
║  Remote URL targets skip Phase 0 entirely.                               ║
║                                                                          ║
║  Produces CodebaseMap:                                                   ║
║    • languages / frameworks / databases                                  ║
║    • endpoints[], auth_patterns[], data_models[]                         ║
║    • secret_findings[] (injected as HIGH findings)                       ║
║    • risky_deps[] (CVE-flagged packages)                                 ║
║    • attack_brief() → plain-English AI attack plan                      ║
║                                                                          ║
║  All subsequent phases read _CMAP for smarter targeting.                 ║
╚══════════════════════╦═══════════════════════════════════════════════════╝
                        │
                        ▼
╔══════════════════════════════════════════════════════════════════════════╗
║                  SCAN PHASES 1 – 13  (dispatch)                         ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  Phase 1 — RECON           nova_recon.py                                 ║
║             Subdomain enum, DNS brute-force, cert.sh, wayback           ║
║                                                                          ║
║  Phase 2 — AUTH            nova_auth_scanner.py                          ║
║             Auth bypass, default creds, broken session mgmt             ║
║                                                                          ║
║  Phase 3 — WEB SCANNERS    (parallel)                                   ║
║   ├─ IDOR          nova_idor_scanner.py                                  ║
║   ├─ XSS           nova_xss_injection_analysis.json (payloads)          ║
║   ├─ CSRF          nova_csrf_tester.py  ←── (fixed: endpoint probe)     ║
║   ├─ SSRF          via nova_attack_chain.py                             ║
║   ├─ SQL Injection via nova_payload_engine.py                           ║
║   ├─ JWT           nova_jwt_forge.py                                     ║
║   ├─ GraphQL       nova_graphql_tester.py                                ║
║   ├─ LFI/Path      via nova_payload_engine.py                           ║
║   └─ SSTI          via nova_payload_engine.py                           ║
║                                                                          ║
║  Phase 4 — SAST            nova_source_auditor.py                        ║
║             Map-aware: scans high-value files first                     ║
║                                                                          ║
║  Phase 5 — SCA             nova_sca_scanner.py  ←── (fixed: sentinel)   ║
║             CVE-affected deps, nova_supply_chain_scorer.py              ║
║                                                                          ║
║  Phase 6 — GIT + SECRETS   nova_git_scanner.py, nova_github_scanner.py  ║
║             Leaked keys, commit history, truffleHog patterns            ║
║                                                                          ║
║  Phase 7 — CI/CD           nova_cicd_scanner.py  ←── (fixed: sentinel)  ║
║             Pipeline injection, exposed tokens, workflow misconfig      ║
║                                                                          ║
║  Phase 8 — CONTAINERS      nova_container_scanner.py                     ║
║             Dockerfile vulns, privileged pods, image CVEs               ║
║                                                                          ║
║  Phase 9 — BUSINESS LOGIC  nova_business_logic.py  ←── (fixed: probe)   ║
║             Price manipulation, coupon abuse, workflow bypass           ║
║                                                                          ║
║  Phase 10— THREAT MODEL    nova_threat_model.py                          ║
║             STRIDE analysis seeded with mapper entry points             ║
║                                                                          ║
║  Phase 11— LLM INJECTION   nova_llm_injection.py                         ║
║             Prompt injection, jailbreak, AI system prompt leaks         ║
║                                                                          ║
║  Phase 12— PROTO POLLUTION nova_proto_polluter.py                        ║
║             JavaScript prototype chain attacks                          ║
║                                                                          ║
║  Phase 13— RACE CONDITIONS nova_race_engine.py                           ║
║             Concurrent requests, TOCTOU, balance manipulation           ║
║                                                                          ║
║  ──────────────────────────────────────────────────────────────────────  ║
║  All findings → _emit_findings() → Hook Bus + Context + Session + DB    ║
╚══════════════════════╦═══════════════════════════════════════════════════╝
                        │  raw findings (may contain false positives)
                        ▼
╔══════════════════════════════════════════════════════════════════════════╗
║            TRUTH ENGINE GATE  (nova_truth_engine.py)  ◀ NEW             ║
║                                                                          ║
║  NovaTruthEngine.filter_real_findings(findings)                         ║
║                                                                          ║
║  For EACH finding, runs up to 7 verification methods:                   ║
║                                                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐    ║
║  │  Step 1 │ False Positive Pattern Check  (auto-reject if >85%)  │    ║
║  │  Step 2 │ Type-Specific Verification    (SQLi/XSS/IDOR/etc.)   │    ║
║  │  Step 3 │ Reproduction Check            (steps+payload+evidence)│    ║
║  │  Step 4 │ Differential Analysis         (vuln vs safe response) │    ║
║  │  Step 5 │ LLM Analysis                  (via _ROUTER if avail.) │    ║
║  │  Step 6 │ Weighted Confidence Score     (0–100%)                │    ║
║  │  Step 7 │ Verdict: CONFIRMED / FALSE_POSITIVE / INCONCLUSIVE    │    ║
║  └─────────────────────────────────────────────────────────────────┘    ║
║                                                                          ║
║  Default threshold: 85% confidence + ≥2 verification methods passing   ║
║  Override: NOVA_TRUTH_THRESHOLD=0.75  (env var)                         ║
║  Bypass:   NOVA_TRUTH_DISABLED=1      (debug only)                      ║
║                                                                          ║
║  Output: only confirmed REAL findings pass through                       ║
╚══════════════════════╦═══════════════════════════════════════════════════╝
                        │  verified findings only
                        ▼
╔══════════════════════════════════════════════════════════════════════════╗
║                  OUTPUT LAYER                                            ║
║                                                                          ║
║  ┌──────────────────────┐   ┌────────────────────┐   ┌───────────────┐  ║
║  │  nova_report.py      │   │ nova_weapon_forge  │   │ nova_notific- │  ║
║  │  HTML + Markdown     │   │ Exploit generator  │   │ ations.py     │  ║
║  │  + JSON reports      │   │ CVE lookup + code  │   │ Telegram/     │  ║
║  │  CVSS auto-scored    │   │ WAF bypass layer   │   │ webhook       │  ║
║  └──────────────────────┘   └────────────────────┘   └───────────────┘  ║
║                                                                          ║
║  ┌──────────────────────┐   ┌────────────────────┐                       ║
║  │  nova_vuln_tracker   │   │ nova_findings_db   │                       ║
║  │  Regression tracking │   │ SQLite persistence │                       ║
║  └──────────────────────┘   └────────────────────┘                       ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## Module Dependency Map

```
nova.py (orchestrator)
  ├── PROVIDER LAYER (loaded once, shared by all phases)
  │     ├── nova_llm_router.py        LLM abstraction
  │     ├── nova_hooks.py             Hook bus (PreRun/PostRun/FindingAdded)
  │     ├── nova_context.py           Typed RunContext
  │     ├── nova_sessions.py          Session persistence
  │     ├── nova_observability.py     Tracer / spans
  │     ├── nova_retry.py             Retry + circuit breaker
  │     ├── nova_skills.py            Skill library
  │     ├── nova_memory_system.py     Cross-session brain
  │     ├── nova_notifications.py     Alert dispatching
  │     ├── nova_error_handler.py     Structured error recovery
  │     ├── nova_findings_db.py       Findings SQLite store
  │     ├── nova_context_engine.py    Enriched context assembly
  │     ├── nova_rag_builder.py       RAG index for codebase
  │     ├── nova_weapon_forge.py      Exploit writer
  │     ├── nova_auto_exploit_loop.py Autonomous exploit pipeline
  │     └── nova_truth_engine.py  ◀── NEW (false positive filter)
  │
  ├── PHASE 0
  │     └── nova_codebase_mapper.py   Source code intelligence
  │
  ├── SCAN PHASES (each receives _ROUTER, _CMAP, _CTX)
  │     ├── nova_recon.py
  │     ├── nova_auth_scanner.py
  │     ├── nova_idor_scanner.py
  │     ├── nova_csrf_tester.py
  │     ├── nova_sca_scanner.py
  │     ├── nova_cicd_scanner.py
  │     ├── nova_business_logic.py
  │     ├── nova_git_scanner.py
  │     ├── nova_github_scanner.py
  │     ├── nova_container_scanner.py
  │     ├── nova_threat_model.py
  │     ├── nova_source_auditor.py
  │     ├── nova_graphql_tester.py
  │     ├── nova_llm_injection.py
  │     ├── nova_proto_polluter.py
  │     ├── nova_race_engine.py
  │     ├── nova_jwt_forge.py
  │     ├── nova_payload_engine.py
  │     ├── nova_attack_chain.py
  │     └── nova_chain_verifier.py    (pre-Truth Engine: chain validation)
  │
  └── OUTPUT (after Truth Engine gate)
        ├── nova_report.py
        ├── nova_weapon_forge.py      (exploit generation for confirmed findings)
        ├── nova_vuln_tracker.py
        └── nova_findings_db.py
```

---

## Truth Engine Verification Weight Table

| Method               | Weight | Triggers on                              |
|----------------------|--------|------------------------------------------|
| Proof of Concept     | 30%    | RCE, LFI, path traversal, cmd injection |
| Time-Based           | 20%    | Blind SQLi, blind command injection      |
| Reproduction         | 20%    | All finding types                        |
| Out-of-Band          | 25%    | XXE, SSRF, blind vulnerabilities         |
| Differential         | 15%    | SQLi, XSS, open redirect                |
| Behavioral           | 15%    | XSS context, CSRF state-change check    |
| LLM Analysis         | 10%    | All (when `_ROUTER` available)           |
| Pattern Analysis     | 10%    | All (false positive pre-filter)          |

**Verdict thresholds:**
- `≥ 85% + ≥2 methods` → CONFIRMED (reported)
- `< 40%` → FALSE POSITIVE (dropped silently)
- `40–84%` → INCONCLUSIVE (logged, not reported)

---

## Environment Variables

| Variable                  | Default          | Description                                      |
|---------------------------|------------------|--------------------------------------------------|
| `NOVA_LLM_URL`            | localhost:11434  | Ollama base URL                                  |
| `NOVA_LLM_MODEL`          | qwen3:8b         | Ollama model name                                |
| `NOVA_TARGET`             | http://localhost:3000 | Default scan target                         |
| `NOVA_SOURCE_DIR`         | (unset)          | Path to cloned target source for Phase 0        |
| `NOVA_TRUTH_THRESHOLD`    | 0.85             | Truth Engine confidence cutoff (0.0–1.0)        |
| `NOVA_TRUTH_DISABLED`     | (unset)          | Set to `1` to bypass Truth Engine (debug only)  |
| `NOVA_TELEGRAM_TOKEN`     | (unset)          | Telegram bot token for real-time alerts         |
| `NOVA_TELEGRAM_CHAT_ID`   | (unset)          | Telegram chat ID for alerts                     |
| `NOVA_WORKSPACE`          | ~/nova_workspace | Output directory for reports/findings           |
| `NOVA_MAX_STEPS`          | 40               | Max agentic steps per run                       |
| `OPENAI_API_KEY`          | (unset)          | OpenAI GPT-4 (primary LLM)                      |
| `ANTHROPIC_API_KEY`       | (unset)          | Anthropic Claude (fallback LLM)                 |
| `GEMINI_API_KEY`          | (unset)          | Google Gemini (fallback LLM)                    |
