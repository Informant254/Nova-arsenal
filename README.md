# Nova Arsenal v4.2

> **AI-powered security framework** — static analysis, active testing, agentic hunt loops, CVE correlation, threat modelling, auto-patching, and multi-agent swarms. One natural-language command runs them all.

```
 ███╗   ██╗ ██████╗ ██╗   ██╗  █████╗
 ████╗  ██║██╔═══██╗██║   ██║ ██╔══██╗
 ██╔██╗ ██║██║   ██║██║   ██║ ███████║
 ██║╚██╗██║██║   ██║╚██╗ ██╔╝ ██╔══██║
 ██║ ╚████║╚██████╔╝ ╚████╔╝  ██║  ██║
 ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝   ╚═╝  ╚═╝  ARSENAL v4.2
```

---

## Table of Contents

1. [Architecture & Complete Repo Tree](#architecture--complete-repo-tree)
   - [How Nova Works](#how-nova-works)
   - [Repo Structure Overview](#repo-structure-overview)
   - [Provider Layer](#provider-layer--shared-infrastructure)
   - [Phase 0 — Codebase Intelligence](#phase-0--codebase-intelligence)
   - [Phase 1 — Reconnaissance](#phase-1--reconnaissance)
   - [Phase 2 — Vulnerability Discovery](#phase-2--vulnerability-discovery)
   - [Phase 3 — Exploitation Engines](#phase-3--exploitation-engines)
   - [Phase 4 — Reasoning & Intelligence](#phase-4--reasoning--intelligence)
   - [Phase 5 — Orchestration & Swarms](#phase-5--orchestration--swarms)
   - [Specialised Hunters](#specialised-hunters)
   - [Kali Linux Knowledge Base](#kali-linux-knowledge-base)
   - [Reporting & Triage](#reporting--triage)
   - [Self-Improvement System](#self-improvement-system)
   - [Data Flow Diagram](#data-flow-diagram)
   - [Module Dependency Map](#module-dependency-map)
   - [Complete File Index](#complete-file-index)
2. [Installation](#installation)
   - [Linux — Debian / Ubuntu / Kali](#linux--debian--ubuntu--kali)
   - [Linux — Arch / Manjaro](#linux--arch--manjaro)
   - [macOS](#macos)
   - [Windows — WSL 2](#windows--wsl-2)
   - [Android — Termux](#android--termux)
   - [Docker](#docker)
3. [Quick Start](#quick-start)
4. [Interactive CLI](#interactive-cli)
5. [Modes Reference](#modes-reference)
6. [Module Reference](#module-reference)
7. [Data Flow](#data-flow)
8. [Configuration](#configuration)
9. [Output Files](#output-files)
10. [Troubleshooting](#troubleshooting)
11. [Contributing](#contributing)
12. [Legal](#legal)

---

## Architecture & Complete Repo Tree

> **Every module, every file, every data flow — explained.**  
> This section is the single source of truth for Nova's structure.
> Paste it into ChatGPT, Claude, or Gemini for full architectural awareness.

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

---

## Installation

### Requirements (all platforms)

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.10 | 3.11 or 3.12 |
| RAM | 4 GB | 8 GB+ (16 GB for local LLM) |
| Disk | 2 GB | 10 GB+ (for Ollama models) |
| LLM | Any cloud API key OR Ollama | Ollama + qwen3:8b |

---

### Linux — Debian / Ubuntu / Kali

**Tested on:** Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Kali Linux 2024.x, Debian 12

```bash
# ── 1. System packages ────────────────────────────────────────────────────────
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv \
    git curl wget build-essential \
    nmap sqlmap nikto gobuster ffuf \
    chromium-browser chromium-chromedriver \
    docker.io docker-compose

# ── 2. Clone the repository ───────────────────────────────────────────────────
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

# ── 3. Python dependencies ────────────────────────────────────────────────────
pip3 install -r requirements.txt

# If Ubuntu 23+ shows "externally-managed-environment" error, use a venv:
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# ── 4. Install Ollama (free local LLM — no API key needed) ────────────────────
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &                    # start in background
ollama pull qwen3:8b              # ~5 GB download
# Alternatives: llama3.1:8b  |  mistral:7b  |  deepseek-r1:8b

# ── 5. (Optional) Cloud LLM keys ──────────────────────────────────────────────
# Set any one — Nova auto-detects and uses the best available
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="AIza..."

# Persist across reboots (add to ~/.bashrc or ~/.zshrc):
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.bashrc && source ~/.bashrc

# ── 6. Health check ───────────────────────────────────────────────────────────
python3 nova_bootstrap.py

# ── 7. First scan ─────────────────────────────────────────────────────────────
python3 nova.py "Hunt http://localhost:3000 for all vulnerabilities"

# Or use the interactive CLI (recommended):
python3 nova_cli.py
```

**Optional external tools** (expand active scan coverage):

```bash
# Nuclei — fast template-based vulnerability scanner
wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
unzip -q nuclei_linux_amd64.zip && sudo mv nuclei /usr/local/bin/
nuclei -update-templates

# Subfinder — passive subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx — fast HTTP probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Trivy — container & SCA scanning
sudo apt install -y trivy

# Verify all tools are detected
python3 nova_bootstrap.py
```

---

### Linux — Arch / Manjaro

```bash
# ── 1. System packages ────────────────────────────────────────────────────────
sudo pacman -Syu --noconfirm \
    python python-pip git curl wget \
    nmap sqlmap nikto gobuster docker docker-compose

# AUR tools (requires yay or paru)
yay -S nuclei ffuf subfinder trivy

# ── 2. Clone & install ────────────────────────────────────────────────────────
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# ── 3. Ollama ─────────────────────────────────────────────────────────────────
curl -fsSL https://ollama.com/install.sh | sh
systemctl --user enable --now ollama
ollama pull qwen3:8b

# ── 4. Run ────────────────────────────────────────────────────────────────────
python nova_bootstrap.py
python nova_cli.py
```

---

### macOS

**Tested on:** macOS 13 Ventura, macOS 14 Sonoma — Intel and Apple Silicon (M1/M2/M3)

```bash
# ── 1. Homebrew ───────────────────────────────────────────────────────────────
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# ── 2. Dependencies ───────────────────────────────────────────────────────────
brew install python@3.11 git curl wget nmap sqlmap gobuster ffuf

# ── 3. Clone ──────────────────────────────────────────────────────────────────
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

# ── 4. Virtual environment (recommended on macOS) ─────────────────────────────
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# ── 5. Ollama — native Apple Neural Engine support on M-series ────────────────
brew install ollama && brew services start ollama
ollama pull qwen3:8b
# M1/M2/M3: 2–4× faster inference than Intel via Metal GPU

# ── 6. Run ────────────────────────────────────────────────────────────────────
python3 nova_bootstrap.py
python3 nova_cli.py
```

> **SSL errors on macOS:** run `/Applications/Python 3.11/Install Certificates.command`
> or `pip install --upgrade certifi`.

> **Apple Silicon:** Ollama runs natively with Metal acceleration. A 8B model fits
> in unified memory with no swapping on 16 GB M-series Macs.

---

### Windows — WSL 2

Nova runs on Windows via **WSL 2** with Ubuntu 22.04. Native Windows is not supported.

```powershell
# Step 1 — PowerShell (as Administrator): enable WSL 2
wsl --install -d Ubuntu-22.04
# Restart when prompted, then open Ubuntu from the Start menu
```

```bash
# All remaining steps run inside the Ubuntu WSL terminal

# 2. System packages
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv git curl wget nmap sqlmap

# 3. Clone
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
pip3 install -r requirements.txt

# 4. Ollama inside WSL
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull qwen3:8b

# 5. Run
python3 nova_bootstrap.py
python3 nova_cli.py
```

**Alternative — Ollama for Windows (native), reached from WSL:**

```bash
# Install Ollama from https://ollama.com/download/windows (Windows side)
# Then from WSL, point Nova at the Windows host:
WIN_IP=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
export NOVA_LLM_URL="http://${WIN_IP}:11434"
python3 nova.py "hunt http://localhost:3000"
```

---

### Android — Termux

> Install Termux from **[F-Droid](https://f-droid.org/packages/com.termux/)** only.
> The Play Store version is outdated and breaks pip.

```bash
# ── 1. Core packages ──────────────────────────────────────────────────────────
pkg update && pkg upgrade -y
pkg install -y python git curl wget nmap openssh

# ── 2. Build dependencies (Termux has no pre-built wheels for some packages) ──
pkg install -y python-cryptography libxml2 libxslt

# ── 3. Python packages ────────────────────────────────────────────────────────
pip install requests beautifulsoup4 aiohttp pydantic rich
pip install openai anthropic                    # cloud LLM clients

# ── 4. Clone ──────────────────────────────────────────────────────────────────
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
pip install -r requirements.txt --ignore-requires-python 2>/dev/null || true

# ── 5. Cloud API key (Ollama does not run on Android ARM) ─────────────────────
export OPENAI_API_KEY="sk-..."         # recommended for Android
# Or: export ANTHROPIC_API_KEY="sk-ant-..."
# Persist: echo 'export OPENAI_API_KEY="sk-..."' >> ~/.bashrc

# ── 6. Grant storage access ───────────────────────────────────────────────────
termux-setup-storage

# ── 7. Run ────────────────────────────────────────────────────────────────────
python nova_bootstrap.py --quick
python nova.py "SAST audit of ./myapp"
python nova_cli.py
```

> **Android notes:**
> - Active network scans (nmap SYN, sqlmap) require root
> - Static analysis modes (sast, sca, git_scan, threat_model) work without root
> - Use `--quick` flag to skip slow bootstrap smoke tests on slow devices

---

### Docker

```bash
# ── Build ─────────────────────────────────────────────────────────────────────
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
docker build -t nova-arsenal .

# ── Interactive CLI ───────────────────────────────────────────────────────────
docker run -it --rm \
  -e OPENAI_API_KEY="sk-..." \
  -e NOVA_TARGET="http://host.docker.internal:3000" \
  -v "$HOME/nova_workspace:/root/nova_workspace" \
  nova-arsenal python3 nova_cli.py

# ── One-shot scan ─────────────────────────────────────────────────────────────
docker run --rm \
  -e OPENAI_API_KEY="sk-..." \
  nova-arsenal \
  python3 nova.py "Hunt http://target.com for all vulnerabilities"

# ── SAST on a local codebase ──────────────────────────────────────────────────
docker run --rm \
  -e OPENAI_API_KEY="sk-..." \
  -v "/path/to/myapp:/scan/myapp:ro" \
  -v "$HOME/nova_workspace:/root/nova_workspace" \
  nova-arsenal \
  python3 nova.py "Full stack scan on /scan/myapp"
```

---

## Quick Start

```bash
# Verify all 77 modules load
python3 nova_bootstrap.py

# Natural language — any phrasing works:
python3 nova.py "Hunt http://localhost:3000 for all vulnerabilities"
python3 nova.py "SAST code audit of ./src"
python3 nova.py "Map the codebase at ./juice-shop"
python3 nova.py "Full stack scan on ./myapp"
python3 nova.py "Generate threat model for ./myapp"
python3 nova.py "Scan git history for leaked secrets in ./repo"
python3 nova.py "Triage findings and show top H1-ready bugs"
python3 nova.py "Kali agent pentest http://localhost:3000"
python3 nova.py "Wild hunt http://bugbounty.target.com"
python3 nova.py "Multi-target scan t1.com,t2.com,t3.com"

# Resume a previous session
python3 nova.py "Hunt http://target.com" --session abc12345

# ⚔️  Weapon Forge — write exploit code directly
python3 nova.py "Forge exploit for CVE-2024-1234 on http://target.com"
python3 nova.py "Generate exploit code for SQL injection on http://target.com"
python3 nova.py "Write exploit for XSS vulnerability on http://target.com"

# Or invoke the Weapon Forge module directly:
python3 nova_weapon_forge.py cve CVE-2024-1234 http://target.com
python3 nova_weapon_forge.py desc "SQL injection in login form" http://target.com
python3 nova_weapon_forge.py type xss http://target.com

# 🔴 Auto-Exploit Loop — autonomous PoC on Critical/High findings:
NOVA_AUTO_EXPLOIT=1 python3 nova.py "Hunt http://target.com"
NOVA_AUTO_EXPLOIT=1 NOVA_EXPLOIT_DRY=0 python3 nova.py "Full stack on http://target.com"

# Interactive shell (recommended)
python3 nova_cli.py
```

---

## Interactive CLI

`nova_cli.py` is a full interactive REPL with:

| Feature | Details |
|---------|---------|
| **Tab completion** | All 54 mode names, commands, `http://`, `https://`, `./` |
| **Spinner + timer** | Animated progress + elapsed seconds during every scan |
| **Severity chart** | Critical / High / Medium / Low / Info bar chart after each run |
| **Top-5 findings** | Immediately shown with file / endpoint context |
| **Session browser** | List, inspect, and resume past sessions interactively |
| **History** | Persisted to `~/.nova_history` across restarts |
| **Inline flags** | `--target`, `--session`, `--no-map` inside any query |
| **Prompt shortcuts** | `set target <url>`, `set session <id>` |
| **One-shot** | `python3 nova_cli.py "hunt http://target.com"` |

```
$ python3 nova_cli.py

  nova(localhost:3000) › hunt http://target.com
  nova(localhost:3000) › modes
  nova(localhost:3000) › set target https://myapp.com
  nova(myapp.com) › full_stack
  nova(myapp.com) › triage
  nova(myapp.com) › sessions
  nova(myapp.com) › status
  nova(myapp.com) › help
```

Inline flags inside queries:
```
nova(myapp.com) › hunt http://target.com --session abc123
nova(myapp.com) › sast ./src --target ./backend
nova(myapp.com) › full_stack --no-map
```

---

## Modes Reference

| # | Mode | Description | Target |
|---|------|-------------|--------|
| 1 | `hunt` 🦅 | Full agentic ReAct hunt loop — best all-around | URL |
| 2 | `full_stack` 💥 | All phases combined — maximum coverage | URL / path |
| 3 | `sast` 🔬 | Multi-language static analysis | path |
| 4 | `dataflow` 🌊 | Taint / data-flow analysis | path |
| 5 | `sca` 📦 | Dependency CVE scan | path |
| 6 | `supply_chain` ⛓ | Supply-chain risk scoring | path |
| 7 | `git_scan` 📜 | Git history — leaked secrets | path |
| 8 | `cicd` ⚙️ | CI/CD pipeline security audit | path |
| 9 | `container` 🐳 | Docker / Kubernetes security | path |
| 10 | `ecosystem` 🌱 | Full package-ecosystem audit | path |
| 11 | `pypi` 🐍 | Malicious PyPI package hunter | package name |
| 12 | `recon` 🔭 | Passive recon — subdomains, DNS | domain |
| 13 | `map` 🗺 | Deep codebase map | path |
| 14 | `github_scan` 🐙 | GitHub code & secret scanner | org/repo |
| 15 | `auth` 🔐 | Authenticated scanner — auth bypass | URL |
| 16 | `idor` 🚪 | IDOR / broken-access-control | URL |
| 17 | `sqli` 💉 | SQL injection (sqlmap + AI) | URL |
| 18 | `xss` 📝 | Cross-site scripting | URL |
| 19 | `ssrf` 🔄 | Server-Side Request Forgery | URL |
| 20 | `csrf` 🎭 | CSRF vulnerability testing | URL |
| 21 | `graphql` 🕸 | GraphQL introspection & injection | URL |
| 22 | `jwt` 🎫 | JWT algorithm confusion & forgery | URL |
| 23 | `proto_pollution` ☣️ | Prototype pollution | URL |
| 24 | `race` 🏁 | Race conditions & TOCTOU | URL |
| 25 | `business_logic` 🧮 | Business-logic bypass | URL |
| 26 | `llm_injection` 🤖 | LLM / prompt-injection testing | URL |
| 27 | `fuzz` 🌀 | Directory & endpoint fuzzing | URL |
| 28 | `browser` 🌐 | Headless-browser visual scanner | URL |
| 29 | `daybreak` 🌅 | AI-powered Daybreak full assessment | URL |
| 30 | `threat_model` 🗡 | STRIDE threat-model generation | path |
| 31 | `zero_day` 💀 | Live CVE / zero-day correlation | URL / CVE |
| 32 | `patch` 🩹 | Auto patch-generation from findings | path |
| 33 | `detect` 🚨 | SIEM / Sigma detection-rule generation | findings |
| 34 | `orchestrate` 🎯 | Multi-agent orchestration pipeline | URL |
| 35 | `swarm` 🐝 | Parallel swarm (v2 + v3 + parallel) | URL |
| 36 | `multi_target` 🎪 | Bulk multi-target parallel scan | t1,t2,t3 |
| 37 | `pipeline` 🚀 | Full staged scan pipeline | URL |
| 38 | `nextgen` ⚡ | Next-gen autonomous agent | URL |
| 39 | `wild_hunt` 🏴 | Open bug-bounty wild hunt | URL |
| 40 | `ibb` 🎖 | Internet Bug Bounty (IBB) hunter | URL |
| 41 | `0din` 👁 | 0DIN zero-day hunter | URL |
| 42 | `attack` ⚔️ | Unified chained attack | URL |
| 43 | `kali` 🐉 | Kali agent — plan → approve → execute | URL |
| 44 | `triage` 🩺 | AI triage — rank findings by H1 priority | findings |
| 45 | `audit_report` 📋 | Enterprise compliance audit report | findings |
| 46 | `report` 📄 | HTML + Markdown report | findings |
| 47 | `vuln_track` 📊 | Vulnerability tracker dashboard (SQLite) | db |
| 48 | `sandbox` 🧪 | Exploit sandbox validation | findings |
| 49 | `portswigger` 🎓 | PortSwigger Web Security Academy | topic |
| 50 | `continuous` 🔁 | 24/7 continuous monitoring loop | URL |
| 51 | `bootstrap` ❤️ | Health check — verify all modules | — |

---

## Module Reference

Nova contains **160+ Python modules** across these layers:

### Provider Layer (always loaded at startup)

| Module | Class | Purpose |
|--------|-------|---------|
| `nova_llm_router` | `get_router()` | Cascading LLM: OpenAI → Anthropic → Gemini → Ollama |
| `nova_hooks` | `get_bus()` | Lifecycle event bus (PreRun, PostRun, FindingEmit, Telegram) |
| `nova_context` | `RunContext` | Typed run context shared across all modules |
| `nova_sessions` | `SessionStore` | Session persistence, resume, and history |
| `nova_observability` | `Tracer` | Execution spans → interactive HTML flame graph |
| `nova_retry` | `RetryPolicy` | Exponential back-off + circuit breaker |
| `nova_skills` | `SkillLibrary` | Reusable skill library for agent loops |
| `nova_codebase_mapper` | `NovaCodebaseMapper` | Full strategic codebase map (Phase 0) |
| `nova_memory_system` | `NovaBrain` | Cross-session persistent memory |
| `nova_notifications` | `NovaNotifications` | Telegram / email real-time alerts |
| `nova_error_handler` | `NovaErrorHandler` | Structured error classification |
| `nova_findings_db` | `NovaFindingsDB` | Persistent SQLite findings database |
| `nova_context_engine` | `NovaContextEngine` | Dynamic context management |
| `nova_context_enricher` | `ContextEnricher` | Application context enrichment |
| `nova_rag_builder` | `get_rag()` | RAG knowledge retrieval |
| `nova_llm_bridge` | `NovaLLMBridge` | HTTP-based alternate LLM client |
| `nova_output_parser` | `NovaOutputParser` | Parse nmap / nikto / sqlmap raw output |
| `nova_result_parser` | `FindingsDatabase` | Normalise findings across scanners |
| `nova_memory` | `TargetMemory` | Target / finding / session memory stores |

### Static Analysis

| Module | Class | Purpose |
|--------|-------|---------|
| `nova_source_auditor` | `NovaSourceAuditor` | Multi-language SAST (Python/JS/Go/PHP/Ruby/Java/C) |
| `nova_dataflow_engine` | `NovaDataFlowEngine` | Taint analysis / source-sink tracking |
| `nova_sca_scanner` | `NovaSCAScanner` | CVE scan via OSV.dev + NVD |
| `nova_supply_chain_scorer` | `NovaSupplyChainScorer` | Supply-chain risk scoring |
| `nova_git_scanner` | `NovaGitScanner` | Git history secret & credential scan |
| `nova_cicd_scanner` | `NovaCICDScanner` | CI/CD pipeline misconfiguration |
| `nova_container_scanner` | `NovaContainerScanner` | Docker / Kubernetes security |
| `nova_ecosystem_auditor` | `NovaEcosystemAuditor` | Full package-ecosystem audit |
| `nova_file_prioritizer` | `NovaFilePrioritizer` | Risk-rank source files (1–5 score) |
| `nova_github_scanner` | `NovaGitHubScanner` | GitHub code & secret scanner |

### Active Testing

| Module | Class | Purpose |
|--------|-------|---------|
| `nova_agent_core` | `NovaAgentCore` | ReAct hunt loop (plan → tool → observe → repeat) |
| `nova_auth_scanner` | `NovaAuthenticatedScanner` | Auth bypass & session testing |
| `nova_idor_scanner` | `NovaIDORScanner` | IDOR / BOLA / horizontal privilege escalation |
| `nova_graphql_tester` | `NovaGraphQLTester` | GraphQL introspection, injection, BOLA |
| `nova_csrf_tester` | `NovaCsrfTester` | CSRF — SameSite, Referer, origin |
| `nova_business_logic` | `NovaBusinessLogicTester` | Price manipulation, coupon stacking, workflow bypass |
| `nova_jwt_forge` | — | JWT algorithm confusion (none, RS256→HS256) |
| `nova_proto_polluter` | — | Prototype pollution test harness |
| `nova_race_engine` | — | Race condition & TOCTOU engine |
| `nova_fuzzer` | — | Smart directory & endpoint fuzzer |
| `nova_llm_injection` | `NovaLLMInjectionTester` | LLM / prompt-injection test suite |
| `nova_sandbox_validator` | `NovaSandboxValidator` | Safe PoC-level exploit sandbox |
| `nova_live_verify` | `LiveVerificationEngine` | Verify findings live before reporting |
| `nova_live_exploit` | `NovaLiveExploit` | Live exploitation (authorised targets only) |
| `nova_browser_agent` | `NovaBrowserAgent` | Headless-browser scanner |
| `nova_url_smuggling` | — | HTTP request smuggling (CL.TE, TE.CL, TE.TE) |
| `nova_deserialize_dropper` | — | Deserialization vulnerability testing |
| `nova_exploit_synthesizer` | — | AI-powered exploit synthesis |
| `nova_session_hijacker` | — | Session-fixation & hijacking tests |

### Intelligence

| Module | Class | Purpose |
|--------|-------|---------|
| `nova_hypothesis_engine` | `HypothesisEngine` | Hypothesis-driven attack generation |
| `nova_chain_of_thought` | `NovaChainOfThought` | Chain-of-thought reasoning |
| `nova_vuln_synthesis` | `NovaVulnSynthesis` | Cross-finding synthesis into attack chains |
| `nova_threat_model` | `NovaThreatModel` | STRIDE threat model from source / spec |
| `nova_zero_day_correlator` | `NovaZeroDayCorrelator` | Live CVE feed correlation |
| `nova_knowledge_rag` | — | RAG knowledge base (findings + CVEs) |
| `nova_payload_engine` | — | Polymorphic payload generator (SQLi/XSS/SSRF/SSTI/XXE) |
| `nova_evolver` | — | Self-improvement engine (LLM-driven patch proposals) |
| `nova_adaptive_brain` | — | Adaptive reasoning brain |
| `nova_feedback_cortex` | — | Feedback loop for self-improvement |
| `nova_reasoning_core` | — | Core reasoning engine |

### Orchestration

| Module | Class | Purpose |
|--------|-------|---------|
| `nova_orchestrator` | `Agent` | Master orchestrator |
| `nova_swarm_v3` | — | 10-agent parallel swarm (v3) |
| `nova_swarm_v2` | `NovaSwarmV2` | Parallel swarm (v2) |
| `nova_swarm_parallel` | — | Concurrent recon/exploit/auth/code agents |
| `nova_multi_target_orchestrator` | `TargetQueue` | Bulk multi-target orchestration |
| `nova_pipeline` | `NovaPipeline` | Staged scan pipeline |
| `nova_nextgen_agentic` | `NovaNextGenAgentic` | Next-gen autonomous agent |
| `nova_daybreak` | — | Daybreak AI assessment pipeline |
| `nova_continuous` | — | 24/7 continuous monitoring |
| `nova_planner` | `NovaPlanner` | Pre-hunt strategic planner |

### Kali & Knowledge Base

| Module | Class | Purpose |
|--------|-------|---------|
| `nova_kali_agent` | `NovaKaliAgent` | Kali agent (plan → approve → execute) |
| `nova_kali_knowledge_base` | `KaliKnowledgeBase` | Master Kali tool knowledge base |
| `nova_kali_kb_crypto_stego` | — | Crypto & steganography techniques |
| `nova_kali_kb_exploitation` | — | Exploitation techniques & payloads |
| `nova_kali_kb_forensics` | — | Digital forensics procedures |
| `nova_kali_kb_password_attacks` | — | Password attack techniques |
| `nova_kali_kb_post_exploitation` | — | Post-exploitation playbooks |
| `nova_kali_kb_reporting` | — | Pentest reporting templates |
| `nova_kali_kb_scanning` | — | Scanning & enumeration techniques |
| `nova_kali_kb_sniffing` | — | Sniffing & spoofing techniques |
| `nova_kali_kb_social_engineering` | — | Social engineering playbooks |
| `nova_kali_kb_web_application` | — | Web application attack techniques |

### Reporting

| Module | Class | Purpose |
|--------|-------|---------|
| `nova_report` | — | HTML + Markdown report with CVSS scores |
| `nova_audit_reporter` | `NovaAuditReporter` | Enterprise compliance (PCI-DSS, SOC 2, ISO 27001) |
| `nova_detection_engineer` | `NovaDetectionEngineer` | SIEM / Sigma rule generation |
| `nova_patch_generator` | `NovaPatchGenerator` | AI-powered code patch generation |
| `nova_vuln_tracker` | `NovaVulnTracker` | SQLite vulnerability tracker with trends |
| `nova_explainer` | — | AI-powered finding explainer |

---

## Data Flow

```
User query / CLI input
        │
        ▼
┌──────────────────────────────────────────────┐
│  Intent Parser                               │
│  LLM classifies natural language             │
│  ──► mode name + target extracted            │
└────────────────────┬─────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│  Provider Layer Init  (once per process)     │
│  ROUTER   LLM cascade (OpenAI/Claude/…)      │
│  BUS      event bus (hooks + Telegram)       │
│  SESSION  load or create SQLite session      │
│  TRACER   start execution span tree          │
│  BRAIN    load cross-session memory          │
│  FDB      open findings database             │
│  RAG      load knowledge index               │
└────────────────────┬─────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│  Phase 0 — Codebase Mapper                   │
│  Scans source tree ──► CodebaseMap           │
│    ● languages / frameworks / deps           │
│    ● all routes & endpoints from code        │
│    ● auth patterns / DB connections          │
│    ● pre-detected secrets                    │
│    ● CVE-affected dependencies               │
│    ● AI attack-priority order                │
│  Map injected into every downstream phase    │
└────────────────────┬─────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│  Dispatch (54 modes)                         │
│  Each phase: _load("nova_xxx","ClassName")   │
│  Findings ──► _emit_findings() fans out:     │
│    ● Hook bus    (fire_finding event)         │
│    ● Typed ctx   (add_finding)               │
│    ● Session     (add_finding)               │
│    ● VulnTracker (ingest_findings)           │
│    ● Findings DB (persist to SQLite)         │
└────────────────────┬─────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│  Post-Run                                    │
│    ● Tracer saved → HTML flame graph         │
│    ● Session saved → SQLite                  │
│    ● HTML + Markdown reports generated       │
│    ● All findings → JSON workspace file      │
│    ● Brain stores session memory             │
│    ● PostRun hook fires (Telegram alert)     │
│    ● Severity bar chart printed to terminal  │
└────────────────────┬─────────────────────────┘
                     │
                     ▼
              ~/nova_workspace/
```

---

## Configuration

All configuration is via **environment variables** — no config file required.

### LLM Provider

```bash
# Cloud — set any one or more (Nova auto-selects the best available)
export OPENAI_API_KEY="sk-..."            # GPT-4o / GPT-4-turbo
export ANTHROPIC_API_KEY="sk-ant-..."    # Claude 3.5 Sonnet
export GEMINI_API_KEY="AIza..."          # Gemini 1.5 Pro / 2.0 Flash

# Local — free, fully private (requires Ollama)
export NOVA_LLM_URL="http://localhost:11434"
export NOVA_LLM_MODEL="qwen3:8b"         # or: llama3.1:8b  mistral:7b  deepseek-r1:8b
```

Router cascade order: `OpenAI → Anthropic → Gemini → Ollama → keyword-fallback`

### Target & Workspace

```bash
export NOVA_TARGET="http://localhost:3000"    # default scan target
export NOVA_WORKSPACE="~/nova_workspace"      # output directory (created automatically)
export NOVA_MAX_STEPS="40"                    # max ReAct loop steps per run
```

### Notifications (optional)

```bash
# Real-time Critical/High findings pushed to Telegram
export NOVA_TELEGRAM_TOKEN="123456:ABC-DEF..."
export NOVA_TELEGRAM_CHAT_ID="-1001234567890"
```

### Scope (bug bounty)

```bash
export NOVA_SCOPE="*.example.com,api.example.com"
export NOVA_EXCLUDED="admin.example.com"
```

### ⚔️ Weapon Forge & Auto-Exploit Loop

```bash
# Enable autonomous exploit loop (off by default — safety first)
export NOVA_AUTO_EXPLOIT=1           # 1 = enable, 0 = disable (default)
export NOVA_EXPLOIT_DRY=1            # 1 = dry-run only — forge code, do NOT fire (default)
                                     # 0 = LIVE — exploits will fire against the target
                                     #     Only use on targets you own or have written permission for

# Weapon Forge output directory (auto-created)
# Exploits are saved to: $NOVA_WORKSPACE/exploits/exploit_<id>_<timestamp>.py
```

> **Safety note:** `NOVA_AUTO_EXPLOIT=1` only generates & validates PoC code.
> Set `NOVA_EXPLOIT_DRY=0` only when running on targets you own or have explicit written
> authorization to test. Nova will never execute live exploits without both flags set.

---

## Output Files

All outputs in `~/nova_workspace/` (or `$NOVA_WORKSPACE`):

| File | Contents |
|------|----------|
| `nova_<mode>_<timestamp>.json` | Structured findings — every run |
| `nova_report_<mode>.html` | HTML report with CVSS scores & remediation |
| `nova_report_<mode>.md` | Markdown report (great for GitHub issues) |
| `nova_triage_report.json` | H1-ranked triage output |
| `nova_trace_<ts>.html` | Interactive HTML execution flame graph |
| `nova_threat_model.json` | STRIDE threat model |
| `nova_sca_report.json` | SCA dependency CVE report |
| `nova_git_report.json` | Git history secret scan |
| `nova_cicd_report.json` | CI/CD pipeline audit |
| `nova_container_report.json` | Docker / K8s audit |
| `nova_supply_chain_report.json` | Supply-chain risk report |
| `nova_codebase_map_latest.json` | Full codebase map (Phase 0) |
| `nova_vulns.db` | SQLite vulnerability tracker |
| `nova_findings.db` | Persistent findings database |
| `nova_tracker_dashboard.md` | Vuln tracker Markdown dashboard |
| `nova_bootstrap_status.json` | Last health-check result |
| `nova_auto_exploit_<ts>.json` | Auto-exploit confirmed findings report |
| `exploits/exploit_<id>_<ts>.py` | Weapon Forge — runnable exploit code |
| `exploits/forge_manifest.json` | Manifest of all forged exploits (rolling, last 100) |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: No module named 'nova_xxx'` | Run from repo root: `cd Nova-arsenal && python3 nova.py "..."` |
| Ollama not responding | `ollama serve &` then `curl http://localhost:11434/api/tags` |
| No findings returned | Verify target: `curl -I http://localhost:3000` then try `recon` mode first |
| Permission denied (nmap) | `sudo python3 nova.py "..."` or `export NOVA_NMAP_FLAGS="-sT"` |
| SQLite locked | `rm -f ~/nova_workspace/*.db-wal ~/nova_workspace/*.db-shm` |
| OpenAI 429 rate limit | `unset OPENAI_API_KEY` — Nova falls back to Anthropic/Gemini/Ollama |
| macOS SSL error | `/Applications/Python 3.11/Install Certificates.command` |
| Windows WSL can't reach host | `export NOVA_LLM_URL="http://$(grep nameserver /etc/resolv.conf \| awk '{print $2}'):11434"` |
| Termux pip wheel fails | `pkg install python-cryptography && pip install --no-binary :all: requests` |
| Ubuntu "externally-managed" | `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt` |

---

## Contributing

1. Fork → feature branch: `git checkout -b feature/nova-my-module`
2. Follow the module pattern: main class + optional `get_xxx()` factory
3. Add to `nova_bootstrap.py` MODULES dict with class name and description
4. Wire into `nova.py` dispatch with `_load("nova_your_module", "YourClass")`
5. Submit a pull request

### Module Template

```python
#!/usr/bin/env python3
"""nova_my_module.py — one-line description"""
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class MyNovaModule:
    def __init__(self, target: str = "", **kwargs):
        self.target   = target
        self.findings: List[Dict[str, Any]] = []

    def run(self) -> List[Dict[str, Any]]:
        """Return list of finding dicts."""
        self.findings.append({
            "type":        "MyVulnType",
            "severity":    "HIGH",          # CRITICAL/HIGH/MEDIUM/LOW/INFO
            "description": "Issue description",
            "endpoint":    self.target,
            "file":        "",
            "remediation": "How to fix it",
            "source":      "nova_my_module",
        })
        return self.findings


def get_my_module(target: str = "") -> MyNovaModule:
    return MyNovaModule(target)
```

---

## Legal

**Nova Arsenal is a security research tool.**
Use it only on systems you own or have **explicit written permission** to test.

- Unauthorised scanning is illegal under CFAA (US), Computer Misuse Act (UK), and equivalent laws worldwide
- The `kali` agent requires your explicit approval before executing any command
- The `live_exploit` module is for authorised targets only
- The authors accept no responsibility for misuse

**Bug bounty:** always verify the target is in-scope before running active tests.

---

*Nova Arsenal v4.2 · github.com/Informant254/Nova-arsenal*
