# Nova Arsenal — Complete Repository Architecture

> **Nova Arsenal v4.2** — Autonomous AI security research framework built in Python.  
> Natural language in → vulnerabilities, exploits, reports out. No manual steps.

---

## Table of Contents

1. [How Nova Works (30-second summary)](#how-nova-works)
2. [Repo Structure Overview](#repo-structure-overview)
3. [Entry Points](#entry-points)
4. [Provider Layer — Shared Infrastructure](#provider-layer--shared-infrastructure)
5. [Phase 0 — Codebase Intelligence](#phase-0--codebase-intelligence)
6. [Phase 1 — Reconnaissance](#phase-1--reconnaissance)
7. [Phase 2 — Vulnerability Discovery](#phase-2--vulnerability-discovery)
8. [Phase 3 — Exploitation Engines](#phase-3--exploitation-engines)
9. [Phase 4 — Reasoning & Intelligence](#phase-4--reasoning--intelligence)
10. [Phase 5 — Orchestration & Swarms](#phase-5--orchestration--swarms)
11. [Specialised Hunters](#specialised-hunters)
12. [Kali Linux Knowledge Base](#kali-linux-knowledge-base)
13. [Reporting & Triage](#reporting--triage)
14. [Self-Improvement System](#self-improvement-system)
15. [Installation & Setup](#installation--setup)
16. [Runtime Data & Results](#runtime-data--results)
17. [Target Bank](#target-bank)
18. [God-Mode / Phase Scripts (Historical)](#god-mode--phase-scripts-historical)
19. [OWASP Juice Shop (Embedded Test Target)](#owasp-juice-shop-embedded-test-target)
20. [Data Flow Diagram](#data-flow-diagram)
21. [Module Dependency Map](#module-dependency-map)
22. [Complete File Index](#complete-file-index)

---

## How Nova Works

```
User types: "Hunt https://target.com for all vulnerabilities"
                              │
                    nova.py  (intent parser)
                              │
              ┌───────────────┴───────────────┐
              │         Provider Layer         │
              │  LLM · Hooks · Context ·       │
              │  Sessions · Tracer · Retry     │
              └───────────────┬───────────────┘
                              │
              Phase 0 ────── Codebase Mapper
              (maps all source code, finds routes, secrets, deps)
                              │
              Phase 1 ────── Recon Engine
              (subdomains, live hosts, JS analysis, Wayback, certs)
                              │
              Phase 2 ────── Vuln Discovery
              (SAST, IDOR, SQLi, XSS, SSRF, JWT, GraphQL, CSRF...)
                              │
              Phase 3 ────── Exploitation
              (Synthesizer → Sandbox Validator → Live Verify)
                              │
              Post-Run ─────  Auto-Exploit Loop  [NEW]
              (Critical/High → Weapon Forge → confirm → Telegram)
                              │
              Phase 4 ────── Triage + Report
              (CVSS scoring, H1-ready writeup, patch generation)
                              │
              Output ──────── ~/nova_workspace/
              (JSON findings, HTML report, Markdown, SQLite DB)
```

---

## Repo Structure Overview

```
Nova-arsenal/
│
├── ── ENTRY POINTS ──────────────────────────────────────────────────────────
│   nova.py                          Main entry point (natural language → dispatch)
│   nova_bootstrap.py                Health check — loads all 77 modules
│   nova_cli.py                      Interactive REPL shell
│   nova_config.json                 Runtime configuration file
│   nova_welcome.py                  Welcome screen / onboarding
│
├── ── PROVIDER LAYER (shared across all modules) ───────────────────────────
│   nova_llm_router.py               Multi-LLM router (Ollama→OpenAI→Anthropic→Gemini)
│   nova_llm_bridge.py               Alternate LLM HTTP bridge
│   nova_model_router.py             Low-level model selector
│   nova_language_model.py           LLM abstraction base
│   nova_hooks.py                    Lifecycle event bus (PreRun/PostRun/OnFinding...)
│   nova_context.py                  Typed shared state (flows through all agents)
│   nova_context_engine.py           Context computation engine
│   nova_context_enricher.py         Auto-enriches context with target metadata
│   nova_context_manager.py          Context lifecycle + scoped sub-contexts
│   nova_sessions.py                 Persistent sessions (conversation + findings)
│   nova_session_manager.py          Session CRUD, search, expiry
│   nova_observability.py            OpenTelemetry-compatible execution tracer
│   nova_retry.py                    Exponential backoff + circuit breaker
│   nova_skills.py                   Reusable prompt template library
│   nova_memory_system.py            NovaBrain — cross-session persistent intelligence
│   nova_memory.py                   Extended memory utilities
│   nova_notifications.py            Telegram / webhook / email alerts
│   nova_error_handler.py            Centralised error handling + recovery
│   nova_findings_db.py              SQLite findings database
│   nova_vuln_tracker.py             Vulnerability lifecycle tracker (open→verified→fixed)
│   nova_output_parser.py            Structured output parser for all agent responses
│   nova_result_parser.py            Result normalisation + deduplication
│   nova_config_manager.py           Runtime config read/write/validate
│   nova_performance_optimizer.py    Parallelism + resource tuning
│   nova_tool_dependency_manager.py  External tool (nmap/ffuf/nuclei) install + verify
│   nova_audit_logger.py             Append-only audit log for every action
│   nova_mcp_client.py               MCP (Model Context Protocol) client
│
├── ── PHASE 0 — CODEBASE INTELLIGENCE ──────────────────────────────────────
│   nova_codebase_mapper.py          59 KB — parallel scanner: 30+ langs, routes, secrets
│   nova_ast_intel.py                AST-level code analysis (function calls, sinks, sources)
│   nova_code_comprehension.py       Deep code understanding + attack surface annotation
│   nova_code_reasoner.py            LLM-powered code reasoning (v1)
│   nova_code_reasoner_v2.py         LLM-powered code reasoning (v2 — chain of thought)
│   nova_deep_semantic.py            Semantic analysis: data flow, taint, business logic
│   nova_dataflow_engine.py          Inter-procedure data flow tracking
│   nova_source_auditor.py           White-box source code security audit
│   nova_file_prioritizer.py         Risk-scores files by attack surface potential
│   nova_rag_builder.py              RAG (retrieval-augmented generation) index builder
│   nova_knowledge_rag.py            CVE + findings knowledge base query layer
│   nova_repo_intelligence.py        Git-aware repo structure + commit history analysis
│   nova_diff_watcher.py             Watches for code changes, rescans diffs in real-time
│
├── ── PHASE 1 — RECONNAISSANCE ─────────────────────────────────────────────
│   nova_recon.py                    10-phase recon: subdomains, Wayback, JS, DNS, S3...
│   nova_scope_manager.py            Scope definition, wildcard matching, exclusions
│   nova_github_scanner.py           GitHub secret / exposure scanner
│   nova_git_scanner.py              Local git history: secrets, deleted files, commits
│   nova_sca_scanner.py              Dependency CVE scanner (SCA — all package ecosystems)
│   nova_ecosystem_auditor.py        Full ecosystem risk audit (npm/pip/gem/cargo/maven)
│   nova_cicd_scanner.py             CI/CD pipeline security audit (GH Actions, Jenkins...)
│   nova_container_scanner.py        Docker image + Kubernetes manifest security audit
│   nova_supply_chain_scorer.py      Supply chain risk scoring (typosquat, malicious deps)
│   nova_zero_day_correlator.py      Real-time CVE correlation against target tech stack
│   nova_pypi_hunter.py              PyPI package security research + malware detection
│   nova_pypi_strike.py              Targeted PyPI attack simulation
│   nova_cve_package.py              CVE-to-package mapping and exploitability scoring
│
├── ── PHASE 2 — VULNERABILITY DISCOVERY ───────────────────────────────────
│   nova_exploit_synthesizer.py      444-line active exploit engine — 8 vuln types, 80+ payloads
│   nova_fuzzer.py                   Smart fuzzer (param/header/body/path fuzzing)
│   nova_fuzzer_fix.py               Fuzzer with crash-safe error handling
│   nova_csrf_tester.py              CSRF token presence, SameSite, origin checks
│   nova_idor_scanner.py             IDOR / BOLA horizontal + vertical access control
│   nova_graphql_tester.py           GraphQL: introspection, batching, IDOR, injection
│   nova_jwt_forge.py                JWT: none-alg, RS256→HS256, weak secret, kid injection
│   nova_llm_injection.py            LLM prompt injection + jailbreak testing
│   nova_business_logic.py           Business logic flaws: price manipulation, race, replay
│   nova_race_engine.py              Race condition engine (concurrent request storm)
│   nova_session_hijacker.py         Session fixation, token prediction, cookie theft
│   nova_proto_polluter.py           JavaScript prototype pollution fuzzer
│   nova_deserialize_dropper.py      Deserialization gadget chain tester (Python/Java/PHP)
│   nova_url_smuggling.py            HTTP request smuggling (CL.TE / TE.CL / TE.TE)
│   nova_payload_engine.py           Polymorphic payload generator (encodes/mutates payloads)
│   nova_auth_scanner.py             Auth endpoint scanner (weak passwords, bypass, enum)
│   nova_challenge_hunter.py         CTF + HackTheBox challenge solver
│   nova_challenge_sniper.py         Single-challenge precision solver
│   nova_view_grepper.py             Template/view file grep for reflected sinks
│   nova_vuln_synthesis.py           Synthesises multiple signals into a unified finding
│
├── ── PHASE 3 — EXPLOITATION ENGINES ──────────────────────────────────────
│   nova_weapon_forge.py      ⚔️ NEW  CVE→code exploit writer (6 templates, WAF bypass, LLM gen)
│   nova_auto_exploit_loop.py 🔴 NEW  Autonomous Critical/High exploit pipeline
│   nova_sandbox_validator.py         Isolated exploit validation before reporting
│   nova_live_verify.py               Confirms finding is live + exploitable in production
│   nova_live_exploit.py              Full live exploitation engine with evidence capture
│   nova_verify_exploit.py            Exploit verification helper
│   nova_verify_engine.py             Triple-verification engine (static + dynamic + live)
│   nova_attack.py                    Multi-stage attack execution engine
│   nova_attack_chain.py              43 KB — full MITRE ATT&CK kill chain implementation
│   nova_unified_attack.py            Unified attack surface + single-entry exploit runner
│   nova_deep_strike.py               Deep targeted attack against specific vuln class
│   nova_deep_strike_openssl.py       OpenSSL-targeted deep strike module
│   nova_breach_study.py              Post-breach reconstruction and study
│
├── ── PHASE 4 — REASONING & INTELLIGENCE ───────────────────────────────────
│   nova_chain_of_thought.py          ReAct (Reason+Act) loop — core agent brain
│   nova_chain_reasoner.py            Full chain reasoning with tool calling (29 KB)
│   nova_reasoning_core.py            Core reasoning primitives + decision engine
│   nova_hypothesis_engine.py         Generates and tests attack hypotheses autonomously
│   nova_planner.py                   Multi-step mission planner with dependency resolution
│   nova_adaptive_brain.py            Adaptive strategy — adjusts attack plan mid-hunt
│   nova_feedback_cortex.py           Feedback loop — learns from failed attempts
│   nova_prompt_engineer.py           Prompt construction + optimisation for all agents
│   nova_chain_deduplicator.py        Deduplicates chains of findings across agents
│   nova_chain_verifier.py            Cross-validates chains of reasoning
│   nova_eval.py                      49 KB — comprehensive agent benchmark + evaluation
│
├── ── PHASE 5 — ORCHESTRATION & SWARMS ─────────────────────────────────────
│   nova_orchestrator.py              47 KB — master orchestrator: coordinates all agents
│   nova_pipeline.py                  Linear pipeline runner with stage gating
│   nova_agent_core.py                Base agent class — tools, memory, handoffs, lifecycle
│   nova_execution_controller.py      Execution budget + kill-switch + resource limits
│   nova_swarm.py                     10-agent parallel swarm orchestrator
│   nova_swarm_v2.py                  Swarm v2 — weighted agent selection
│   nova_swarm_v3.py                  Swarm v3 — adaptive routing based on findings
│   nova_swarm_parallel.py            True parallel swarm (thread-pool + result merge)
│   nova_multi_target_orchestrator.py Multi-target scan orchestrator (batch domains)
│   nova_daybreak.py                  45 KB — Daybreak AI: full security assessment suite
│   nova_nextgen_agentic.py           Next-gen agentic architecture (handoff + tools v2)
│   nova_continuous.py                24/7 continuous scanning loop
│   nova_continuous_v2.py             Continuous v2 — smarter change detection
│   nova_continuous_v3.py             Continuous v3 — multi-target persistent loop
│   nova_control_panel.py             Runtime control panel (pause/resume/reprioritise)
│   nova_diff_watcher.py              File-system diff watcher → triggers rescans
│   nova_conversational_agent.py      Conversational mode — ask Nova questions mid-hunt
│   nova_unlimited.py                 Uncapped full-power run (removes all step limits)
│   nova_full_clear.py                Full-clear mode — exhaustive 100% coverage scan
│   nova_features.py                  Feature flags + A/B testing for agent strategies
│   nova_core.py                      27 KB — core agent runtime primitives
│   nova_toolbox.py                   Utility toolbox (HTTP, file, subprocess helpers)
│   nova_tool_kit.py                  32 KB — full tool kit: all external CLI wrappers
│   nova_termux_client.py             Termux (Android) remote client
│
├── ── SPECIALISED HUNTERS ───────────────────────────────────────────────────
│   nova_wild_hunt.py                 Autonomous live bug bounty hunting on real programs
│   nova_ibb_hunter.py                Intigriti bug bounty hunter (scope-aware)
│   nova_active_ibb.py                Active Intigriti submission pipeline
│   nova_0din_hunter.py               0Din security platform targeted hunter
│   nova_deploy_0din.py               0Din finding deployment + submission
│   nova_agentic_deploy.py            Agentic deployment of findings to bug bounty platforms
│   nova_ai_titan_hunter.py           AI/ML model security hunter
│   nova_titan_capabilities.py        AI system attack capability mapping
│   nova_binary_hunter.py             Binary / compiled app reverse engineering + hunting
│   nova_portswigger_academy.py       PortSwigger Web Security Academy lab solver
│   nova_web_researcher.py            Web-based research + OSINT gathering
│   nova_chrome_hunter.py             Chrome DevTools Protocol-based hunting
│   nova_browser_session.py           25 KB — full browser session automation
│   nova_browser_agent.py             Browser-based attack agent
│   nova_browser_v1.py / v2 / v3      Browser automation iterations
│   nova_live_hunt.py                 Live real-time hunt against active targets
│   nova_vision.py                    Screenshot + visual analysis of target UIs
│   nova_sharpen.py                   Precision sharpening of existing findings
│   nova_scope_runner.sh              Bash scope runner for multi-domain campaigns
│
├── ── KALI LINUX KNOWLEDGE BASE ─────────────────────────────────────────────
│   nova_kali_agent.py                Kali Linux tool orchestrator (22 KB)
│   nova_kali_knowledge_base.py       Master KB — 70 KB of Kali tool knowledge
│   nova_kali_knowledge.py            Structured Kali knowledge query layer
│   nova_kali_kb_web_application.py   Web app attack techniques (48 KB)
│   nova_kali_kb_exploitation.py      Exploitation techniques + Metasploit (36 KB)
│   nova_kali_kb_post_exploitation.py Post-exploitation: persistence, pivoting (45 KB)
│   nova_kali_kb_scanning.py          Nmap, masscan, Shodan scanning knowledge (44 KB)
│   nova_kali_kb_forensics.py         Digital forensics + log analysis (44 KB)
│   nova_kali_kb_password_attacks.py  Password attacks: hashcat, john, rainbow (37 KB)
│   nova_kali_kb_sniffing.py          Network sniffing + MITM (Wireshark, tcpdump) (35 KB)
│   nova_kali_kb_crypto_stego.py      Cryptography + steganography tools (37 KB)
│   nova_kali_kb_social_engineering.py Social engineering techniques (22 KB)
│   nova_kali_kb_reporting.py         Pentest reporting best practices (24 KB)
│
├── ── REPORTING & TRIAGE ────────────────────────────────────────────────────
│   nova_report.py                    HTML + Markdown report generator (24 KB)
│   nova_triage.py                    H1-ready triage: CVSS, severity, priority scoring
│   nova_audit_reporter.py            Enterprise audit report (executive + technical)
│   nova_patch_generator.py           Auto-generates code patches for found vulns
│   nova_threat_model.py              STRIDE threat model generation
│   nova_detection_engineer.py        SIEM rule + detection signature generation
│   nova_approval_workflow.py         Human-in-the-loop approval before submission
│
├── ── SELF-IMPROVEMENT SYSTEM ───────────────────────────────────────────────
│   nova_evolver.py                   LLM-driven self-patching (backup + forbidden files)
│   nova_self_improvement.py          Strategy improvement from past hunt results
│   nova_adaptive_brain.py            Real-time strategy adaptation mid-hunt
│
├── ── INSTALLATION & SETUP ──────────────────────────────────────────────────
│   nova_install.sh                   Full automated installer (10 KB)
│   nova_setup.sh                     Basic setup script
│   nova_setup_enhanced.sh            Enhanced setup with tool verification (14 KB)
│   nova_codespaces_deploy.sh         GitHub Codespaces one-click deploy
│   requirements.txt                  All Python dependencies
│   install.sh                        Minimal bootstrap entry
│
├── ── RUNTIME DATA — SCAN RESULTS ──────────────────────────────────────────
│   nova_brain_memory.json            Persistent NovaBrain state
│   nova_memory.json                  Working memory snapshot
│   nova_exploit_memory.json          All exploit attempts + outcomes (25 KB)
│   nova_credentials.json             Discovered credentials from scans
│   nova_signatures.json              Attack signature library
│   nova_config_analysis.json         Config vulnerability findings
│   nova_leaked_paths.json            Discovered leaked paths/endpoints
│   nova_real_findings.json           Verified real-world findings
│   nova_verified_findings.json       Triple-verified finding set
│   nova_smart_audit_juice-shop.json  Full smart audit of Juice Shop (38 KB)
│   nova_ibb_report.json              Intigriti bug bounty report (10 KB)
│   nova_live_exploit_report.json     Live exploitation evidence (13 KB)
│   nova_jwt_forge_report.json        JWT forge attack results
│   nova_race_report.json             Race condition findings
│   nova_proto_pollution_report.json  Prototype pollution results
│   nova_deserialize_report.json      Deserialization attack results
│   nova_session_hijack_report.json   Session hijack findings
│   nova_0din_deployment_report.json  0Din platform deployment report (17 KB)
│   nova_breach_study_*.json          Full breach reconstruction study (1.3 MB)
│   nova_titan_scan_*.json            AI titan scan results (33 KB)
│   nova_ecosystem_audit_*.json       Ecosystem audit snapshots (28 KB × 5)
│   nova_parallel_swarm_report.json   Parallel swarm run results
│   nova_autonomous_hunt_report.json  Autonomous hunt summary
│   nova_challenge_analysis.json      CTF challenge analysis (24 KB)
│
├── ── SUBMISSION EVIDENCE ───────────────────────────────────────────────────
│   nova_0din_submission/             0Din platform submission package
│   │   ├── manifest.json            Submission manifest
│   │   ├── nova_0din_deployment_report.json
│   │   ├── nova_live_exploit_report.json
│   │   └── evidence/exploit_0-5.json   6 exploit evidence files
│   nova_nextgen_submission/          Next-gen agentic submission package
│   │   ├── manifest.json
│   │   └── evidence/finding_1-6_evidence.json
│   nova_agentic_evidence/            Agentic deployment evidence
│       └── exploit_0-5.json
│
├── ── TARGET BANK ───────────────────────────────────────────────────────────
│   targets.txt                       Full target list (bug bounty programs)
│   targets_priority.txt              Priority tier-1 targets
│   targets_verily.txt                Verily.com target subdomain list
│   nova_h1_hunt_*.json               HackerOne hunt results — 100+ target files
│                                     (konghq.com, verily.com, notion.so...)
│
├── ── SECURITY POLICY ───────────────────────────────────────────────────────
│   .well-known/security.txt          Responsible disclosure contact
│   .well-known/csaf/index.txt        CSAF security advisory index
│   swagger.yml                       API documentation (Swagger/OpenAPI)
│
├── ── HISTORICAL / GOD-MODE PHASE SCRIPTS ──────────────────────────────────
│   (Development-history scripts used to build and debug Nova iteratively)
│   nova_god_phase2.py → phase7.py    Phase-by-phase god-mode build iterations
│   nova_god_mythos_black.py          Mythos Black agent prototype
│   nova_god_ultimate.py              Ultimate god-mode prototype
│   nova_god_redteam.py               Red team god-mode variant
│   clean_and_phase1.sh               Phase 1 environment prep
│   auto_phase4_escalation.sh         Phase 4 privilege escalation automation
│   auto_phase5_godmode.sh            Phase 5 god-mode activation
│   phase2_fix.sh / phase3_escalation.sh  Phase patch scripts
│   stop_loop_and_phase2.sh           Loop control utility
│   godmode_final_fix.sh              Final god-mode environment fix
│   ultimate_godmode_install_fix.sh   Install-level god-mode fix (5 KB)
│
├── ── MISC UTILITIES ────────────────────────────────────────────────────────
│   nova_trace_isolator.py            Trace isolation helper
│   nova_explainer.py                 Stub — finding explanation helper
│   nova_training_academy.py          Stub — planned training module
│   nova_vscode_extension_generator.py  Stub — VS Code extension generator
│   nova_mythos_browser_research.py   Mythos browser research helper
│   nova_termux_client.py             Termux remote client
│   nova_harvest_subdomains.sh        Subdomain harvest bash wrapper
│   nova_send_mission.sh              Mission dispatch helper
│   nova_scope_runner.sh              Scope campaign runner
│   output.txt / result.txt           Misc scan output
│   ssrf_results.txt                  Raw SSRF probe results
│   verify_output.txt                 Verification run output
│   nova_llm_mission_report.txt       LLM mission narrative
│   nova_jenkins_crash_submission.txt Jenkins crash finding submission
│   verify_ssrf_direct.py             Direct SSRF verification script
│
└── ── OWASP JUICE SHOP (Embedded Test Target) ──────────────────────────────
    (Full OWASP Juice Shop application used as Nova's default test target)
    server.ts                          Express app server (38 KB)
    frontend/                          Angular frontend (400+ components)
    routes/                            All API route handlers
    models/                            Sequelize database models
    lib/                               Shared utilities + challenge helpers
    data/                              Seed data, CVEs, static content
    test/                              API tests (Cypress E2E + unit specs)
    ftp/                               Intentionally exposed FTP files (CTF artifacts)
    views/                             Pug/Handlebars templates
    swagger.yml                        Juice Shop API spec
```

---

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        nova.py  (entry point)                           │
│   parse intent → _init_provider_layer() → _run_phase0_mapper()         │
│   → dispatch() → post-run hooks → return findings                      │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
   nova_llm_router         nova_hooks             nova_context
   (LLM provider)          (event bus)            (typed state)
        │                      │                      │
        └──────────────────────┴──────────────────────┘
                               │
                    nova_observability
                    (execution tracer)
                               │
              ┌────────────────┴─────────────────────┐
              │            nova_sessions              │
              │     (persists everything to disk)     │
              └────────────────┬─────────────────────┘
                               │
     ┌─────────────────────────┼─────────────────────────┐
     │                         │                         │
Phase 0               Phase 1–2                   Phase 3–4
nova_codebase_mapper  nova_recon                  nova_exploit_synthesizer
nova_ast_intel        nova_fuzzer                 nova_weapon_forge  ⚔️NEW
nova_dataflow_engine  nova_idor_scanner           nova_auto_exploit_loop 🔴NEW
nova_rag_builder      nova_csrf_tester            nova_sandbox_validator
                      nova_jwt_forge              nova_live_verify
                      nova_graphql_tester         nova_chain_of_thought
                      nova_race_engine            nova_reasoning_core
                      nova_sca_scanner
                           │
              ┌────────────┴────────────┐
              │                         │
       nova_findings_db           nova_memory_system
       (SQLite store)             (NovaBrain — cross-session)
              │                         │
              └────────────┬────────────┘
                           │
                    nova_triage.py
                    nova_report.py
                    nova_patch_generator
                    nova_audit_reporter
                           │
                    ~/nova_workspace/
                    ├── nova_<mode>_<ts>.json
                    ├── nova_report_<mode>.html
                    ├── nova_report_<mode>.md
                    ├── nova_auto_exploit_<ts>.json  ← NEW
                    ├── exploits/exploit_*.py        ← NEW
                    ├── nova_brain.json
                    └── nova_findings.db
```

---

## Module Dependency Map

```
nova.py
  ├── nova_llm_router         ← ALL modules depend on this
  ├── nova_hooks              ← ALL modules fire events here
  ├── nova_context            ← shared state carrier
  ├── nova_sessions           ← conversation + finding persistence
  ├── nova_observability      ← span/trace for every operation
  ├── nova_retry              ← wraps all network calls
  ├── nova_skills             ← prompt templates for all agents
  ├── nova_memory_system      ← NovaBrain (read at start, write at end)
  ├── nova_memory             ← extended memory
  ├── nova_error_handler      ← catches all unhandled exceptions
  ├── nova_findings_db        ← persists every finding
  ├── nova_context_engine     ← enriches context between phases
  ├── nova_rag_builder        ← loads CVE/findings RAG index
  ├── nova_codebase_mapper    ← Phase 0 (always runs first)
  ├── nova_weapon_forge       ← ⚔️  loaded at startup, forges on Critical
  ├── nova_auto_exploit_loop  ← 🔴 fires post-run on Critical/High
  │
  ├── [Hunt phase]
  │   ├── nova_recon
  │   ├── nova_exploit_synthesizer
  │   ├── nova_fuzzer
  │   ├── nova_idor_scanner
  │   ├── nova_csrf_tester
  │   ├── nova_jwt_forge
  │   ├── nova_graphql_tester
  │   ├── nova_business_logic
  │   ├── nova_race_engine
  │   ├── nova_session_hijacker
  │   └── nova_payload_engine
  │
  ├── [Validate phase]
  │   ├── nova_sandbox_validator
  │   ├── nova_live_verify
  │   ├── nova_verify_engine
  │   └── nova_chain_verifier
  │
  ├── [Reasoning phase]
  │   ├── nova_chain_of_thought  (ReAct loop)
  │   ├── nova_chain_reasoner
  │   ├── nova_reasoning_core
  │   ├── nova_hypothesis_engine
  │   └── nova_planner
  │
  └── [Report phase]
      ├── nova_triage
      ├── nova_report
      ├── nova_patch_generator
      └── nova_audit_reporter
```

---

## Complete File Index

### Engine Python Files (191 files)

| File | Size | Role |
|------|------|------|
| `nova.py` | 83 KB | **Main entry point** — NL intent parser, 56 dispatch modes, provider init, Phase 0 |
| `nova_bootstrap.py` | 19 KB | **Health check** — loads all 77 modules, prints capability summary |
| `nova_cli.py` | 22 KB | **Interactive REPL** — tab completion, spinner, severity bar chart, session browser |
| `nova_core.py` | 27 KB | Core agent runtime primitives |
| `nova_config.json` | 2 KB | Runtime configuration |
| `nova_welcome.py` | 4.7 KB | Welcome / onboarding screen |
| `nova_llm_router.py` | 23 KB | Multi-LLM router: Ollama → OpenAI → Anthropic → Gemini auto-fallback |
| `nova_llm_bridge.py` | 26 KB | Alternate LLM HTTP bridge |
| `nova_model_router.py` | 11 KB | Low-level model selection |
| `nova_language_model.py` | 11 KB | LLM abstraction base class |
| `nova_hooks.py` | 13 KB | Lifecycle event bus — 10 hook points |
| `nova_context.py` | 12 KB | Typed shared state with audit trail |
| `nova_context_engine.py` | 5 KB | Context computation engine |
| `nova_context_enricher.py` | 15 KB | Auto-enriches context with target metadata |
| `nova_context_manager.py` | 13 KB | Context lifecycle + scoped sub-contexts |
| `nova_sessions.py` | 13 KB | Persistent sessions — conversation + findings |
| `nova_session_manager.py` | 20 KB | Session CRUD, search, resume, expiry |
| `nova_observability.py` | 14 KB | OpenTelemetry-compatible span/trace |
| `nova_retry.py` | 11 KB | Exponential backoff + circuit breaker |
| `nova_skills.py` | 21 KB | 40+ prompt template skills |
| `nova_memory_system.py` | 19 KB | **NovaBrain** — cross-session persistent intelligence |
| `nova_memory.py` | 25 KB | Extended memory (target, tech, payload memory) |
| `nova_notifications.py` | 14 KB | Telegram / webhook / email real-time alerts |
| `nova_error_handler.py` | 18 KB | Centralised error handling + recovery |
| `nova_findings_db.py` | 20 KB | SQLite findings store |
| `nova_vuln_tracker.py` | 12 KB | Vulnerability lifecycle: open → verified → fixed |
| `nova_output_parser.py` | 28 KB | Structured output parser for all agents |
| `nova_result_parser.py` | 34 KB | Result normalisation + deduplication |
| `nova_config_manager.py` | 17 KB | Runtime config read/write/validate |
| `nova_performance_optimizer.py` | 26 KB | Thread pool + resource tuning |
| `nova_tool_dependency_manager.py` | 31 KB | External tool installer + verifier |
| `nova_audit_logger.py` | 16 KB | Append-only audit log |
| `nova_mcp_client.py` | 17 KB | MCP (Model Context Protocol) client |
| `nova_codebase_mapper.py` | 59 KB | **Phase 0** — 30+ languages, routes, secrets, deps |
| `nova_ast_intel.py` | 24 KB | AST-level code analysis |
| `nova_code_comprehension.py` | 12 KB | Deep code understanding |
| `nova_code_reasoner.py` | 15 KB | LLM code reasoning v1 |
| `nova_code_reasoner_v2.py` | 19 KB | LLM code reasoning v2 (chain of thought) |
| `nova_deep_semantic.py` | 11 KB | Semantic data flow + taint analysis |
| `nova_dataflow_engine.py` | 10 KB | Inter-procedure data flow |
| `nova_source_auditor.py` | 17 KB | White-box source code audit |
| `nova_file_prioritizer.py` | 7 KB | Attack surface risk scoring |
| `nova_rag_builder.py` | 24 KB | RAG index builder |
| `nova_knowledge_rag.py` | 5 KB | CVE + findings knowledge retrieval |
| `nova_repo_intelligence.py` | 9 KB | Git-aware repo + commit analysis |
| `nova_diff_watcher.py` | 27 KB | Real-time file diff watcher |
| `nova_recon.py` | 18 KB | **10-phase recon**: subdomains, Wayback, JS, DNS, S3, certs |
| `nova_scope_manager.py` | 33 KB | Scope + exclusion management |
| `nova_github_scanner.py` | 10 KB | GitHub secret/exposure scanner |
| `nova_git_scanner.py` | 10 KB | Local git history scanner |
| `nova_sca_scanner.py` | 10 KB | SCA dependency CVE scanner |
| `nova_ecosystem_auditor.py` | 12 KB | Full ecosystem risk audit |
| `nova_cicd_scanner.py` | 7 KB | CI/CD pipeline audit |
| `nova_container_scanner.py` | 8 KB | Docker + Kubernetes audit |
| `nova_supply_chain_scorer.py` | 8 KB | Supply chain risk scoring |
| `nova_zero_day_correlator.py` | 10 KB | Real-time CVE correlation |
| `nova_pypi_hunter.py` | 7 KB | PyPI malware + security research |
| `nova_pypi_strike.py` | 4 KB | PyPI targeted attack sim |
| `nova_cve_package.py` | 5 KB | CVE-to-package exploitability mapping |
| `nova_exploit_synthesizer.py` | 18 KB | Active exploit engine — 8 vuln types, 80+ payloads |
| `nova_weapon_forge.py` | **27 KB** | ⚔️ **NEW** — CVE→exploit writer, LLM gen, WAF bypass |
| `nova_auto_exploit_loop.py` | **14 KB** | 🔴 **NEW** — Autonomous Critical/High pipeline |
| `nova_sandbox_validator.py` | 9 KB | Isolated exploit validation |
| `nova_live_verify.py` | 2.8 KB | Live production confirmation |
| `nova_live_exploit.py` | 13 KB | Full live exploitation with evidence |
| `nova_verify_exploit.py` | 2.9 KB | Exploit verification helper |
| `nova_verify_engine.py` | 14 KB | Triple-verification engine |
| `nova_attack.py` | 21 KB | Multi-stage attack engine |
| `nova_attack_chain.py` | 43 KB | Full MITRE ATT&CK kill chain |
| `nova_unified_attack.py` | 11 KB | Unified attack surface runner |
| `nova_deep_strike.py` | 11 KB | Deep targeted strike |
| `nova_deep_strike_openssl.py` | 15 KB | OpenSSL-targeted deep strike |
| `nova_breach_study.py` | 8 KB | Post-breach reconstruction |
| `nova_fuzzer.py` | 15 KB | Smart multi-vector fuzzer |
| `nova_fuzzer_fix.py` | 9 KB | Crash-safe fuzzer |
| `nova_csrf_tester.py` | 10 KB | CSRF vulnerability tester |
| `nova_idor_scanner.py` | 10 KB | IDOR / BOLA scanner |
| `nova_graphql_tester.py` | 7 KB | GraphQL security tester |
| `nova_jwt_forge.py` | 12 KB | JWT attack engine |
| `nova_llm_injection.py` | 9 KB | LLM prompt injection tester |
| `nova_business_logic.py` | 8 KB | Business logic flaw tester |
| `nova_race_engine.py` | 19 KB | Race condition engine |
| `nova_session_hijacker.py` | 13 KB | Session attack module |
| `nova_proto_polluter.py` | 19 KB | Prototype pollution fuzzer |
| `nova_deserialize_dropper.py` | 10 KB | Deserialization gadget tester |
| `nova_url_smuggling.py` | 6 KB | HTTP request smuggling |
| `nova_payload_engine.py` | 7 KB | Polymorphic payload generator |
| `nova_auth_scanner.py` | 3 KB | Auth endpoint scanner |
| `nova_challenge_hunter.py` | 15 KB | CTF challenge solver |
| `nova_challenge_sniper.py` | 7 KB | Single-challenge solver |
| `nova_chain_of_thought.py` | 19 KB | **ReAct loop** — core agent brain |
| `nova_chain_reasoner.py` | 29 KB | Full chain reasoning + tool calling |
| `nova_reasoning_core.py` | 16 KB | Core reasoning primitives |
| `nova_hypothesis_engine.py` | 13 KB | Attack hypothesis generator |
| `nova_planner.py` | 16 KB | Multi-step mission planner |
| `nova_adaptive_brain.py` | 16 KB | Adaptive mid-hunt strategy |
| `nova_feedback_cortex.py` | 16 KB | Learning from failed attempts |
| `nova_prompt_engineer.py` | 15 KB | Prompt construction + optimisation |
| `nova_chain_deduplicator.py` | 16 KB | Finding chain deduplication |
| `nova_chain_verifier.py` | 13 KB | Cross-validation of reasoning chains |
| `nova_eval.py` | 49 KB | Comprehensive agent benchmark |
| `nova_orchestrator.py` | 47 KB | **Master orchestrator** |
| `nova_pipeline.py` | 23 KB | Linear pipeline runner |
| `nova_agent_core.py` | 23 KB | Base agent class |
| `nova_execution_controller.py` | 13 KB | Budget + kill-switch |
| `nova_swarm.py` | 22 KB | 10-agent parallel swarm |
| `nova_swarm_v2.py` | 13 KB | Swarm v2 (weighted) |
| `nova_swarm_v3.py` | 15 KB | Swarm v3 (adaptive) |
| `nova_swarm_parallel.py` | 16 KB | True parallel swarm |
| `nova_multi_target_orchestrator.py` | 30 KB | Multi-target batch orchestrator |
| `nova_daybreak.py` | 45 KB | **Daybreak AI** — full security assessment |
| `nova_nextgen_agentic.py` | 13 KB | Next-gen agentic architecture |
| `nova_continuous.py` | 10 KB | 24/7 continuous loop |
| `nova_continuous_v2.py` | 13 KB | Continuous v2 (change detection) |
| `nova_continuous_v3.py` | 18 KB | Continuous v3 (multi-target) |
| `nova_wild_hunt.py` | 16 KB | Live bug bounty autonomous hunter |
| `nova_ibb_hunter.py` | 10 KB | Intigriti bug bounty hunter |
| `nova_active_ibb.py` | 11 KB | Active Intigriti pipeline |
| `nova_0din_hunter.py` | 8 KB | 0Din platform hunter |
| `nova_deploy_0din.py` | 9 KB | 0Din submission pipeline |
| `nova_agentic_deploy.py` | 12 KB | Agentic platform submission |
| `nova_ai_titan_hunter.py` | 10 KB | AI/ML model security hunter |
| `nova_titan_capabilities.py` | 14 KB | AI attack capability mapper |
| `nova_binary_hunter.py` | 13 KB | Binary / RE hunter |
| `nova_portswigger_academy.py` | 12 KB | PortSwigger lab solver |
| `nova_web_researcher.py` | 14 KB | Web OSINT researcher |
| `nova_chrome_hunter.py` | 9 KB | Chrome DevTools hunter |
| `nova_browser_session.py` | 25 KB | Full browser session automation |
| `nova_browser_agent.py` | 6 KB | Browser attack agent |
| `nova_live_hunt.py` | 12 KB | Real-time live hunter |
| `nova_vision.py` | 10 KB | Screenshot + visual UI analysis |
| `nova_sharpen.py` | 14 KB | Finding precision sharpener |
| `nova_kali_agent.py` | 22 KB | Kali tool orchestrator |
| `nova_kali_knowledge_base.py` | 70 KB | **Master Kali KB** |
| `nova_kali_knowledge.py` | 19 KB | Kali knowledge query |
| `nova_kali_kb_web_application.py` | 48 KB | Web attack techniques |
| `nova_kali_kb_exploitation.py` | 36 KB | Exploitation + Metasploit |
| `nova_kali_kb_post_exploitation.py` | 45 KB | Post-exploitation |
| `nova_kali_kb_scanning.py` | 44 KB | Scanning knowledge |
| `nova_kali_kb_forensics.py` | 44 KB | Digital forensics |
| `nova_kali_kb_password_attacks.py` | 37 KB | Password attacks |
| `nova_kali_kb_sniffing.py` | 35 KB | Network sniffing |
| `nova_kali_kb_crypto_stego.py` | 37 KB | Crypto + steganography |
| `nova_kali_kb_social_engineering.py` | 22 KB | Social engineering |
| `nova_kali_kb_reporting.py` | 24 KB | Pentest reporting |
| `nova_report.py` | 24 KB | HTML + Markdown report generator |
| `nova_triage.py` | 23 KB | H1-ready triage + CVSS scoring |
| `nova_audit_reporter.py` | 13 KB | Enterprise audit reports |
| `nova_patch_generator.py` | 12 KB | Auto-patch generation |
| `nova_threat_model.py` | 12 KB | STRIDE threat model |
| `nova_detection_engineer.py` | 9 KB | SIEM rule generation |
| `nova_approval_workflow.py` | 14 KB | Human-in-the-loop approval |
| `nova_evolver.py` | 6 KB | LLM-driven self-patching |
| `nova_self_improvement.py` | 7 KB | Strategy improvement engine |

---

## Key Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `NOVA_LLM_URL` | `http://localhost:11434` | Ollama / OpenAI-compatible endpoint |
| `NOVA_LLM_MODEL` | `qwen3:8b` | LLM model to use |
| `NOVA_TARGET` | `http://localhost:3000` | Default scan target |
| `NOVA_WORKSPACE` | `~/nova_workspace` | Output directory |
| `NOVA_MAX_STEPS` | `40` | ReAct loop step limit |
| `NOVA_AUTO_EXPLOIT` | `0` | `1` = enable auto-exploit loop |
| `NOVA_EXPLOIT_DRY` | `1` | `0` = fire live exploits |
| `NOVA_SCOPE` | _(all)_ | `*.example.com,api.example.com` |
| `NOVA_EXCLUDED` | _(none)_ | Excluded domains |
| `NOVA_TELEGRAM_TOKEN` | _(none)_ | Telegram bot token |
| `NOVA_TELEGRAM_CHAT_ID` | _(none)_ | Telegram chat ID |
| `OPENAI_API_KEY` | _(none)_ | OpenAI key (optional) |
| `ANTHROPIC_API_KEY` | _(none)_ | Anthropic key (optional) |
| `GEMINI_API_KEY` | _(none)_ | Gemini key (optional) |

---

*Generated by Nova Arsenal v4.2 — commit df34db43*
