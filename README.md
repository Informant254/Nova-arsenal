# ð¦ Nova Arsenal v4.2

> **The most capable open-source autonomous security research agent.**
> 
> Reads your entire codebase in seconds, maps every language and framework strategically, connects all 35+ modules together, and hunts vulnerabilities with the intelligence of a senior penetration tester.

**Status:** â Production-Ready | ð¦ 35+ Modules | ð¤ Multi-Agent LLM | ð Cloud-Native


## Nova Autonomous Agent Runtime

Nova Arsenal now ships as an **autonomous coding and security agent runtime**. The
security modules remain available, but the core agent loop has been upgraded to
support repository mapping, governed tool execution, autonomous patch planning,
validated diff application, test execution, retry-on-failure, and auditable run
reports.

### What changed in this release

- `nova code` runs a conservative autonomous coding loop: map the repository,
  generate a plan, request a minimal patch from the configured model, validate it
  with `git apply --check`, apply only safe diffs, run tests, and retry once.
- `nova_tool_kit.py` exposes a real tool registry (`execute_tool`,
  `tools_summary_for_prompt`, and `TOOL_SCHEMAS`) so ReAct agents can call tools
  through one governed interface.
- Scope enforcement is strict by default. If a scope is declared, network tools
  block out-of-scope hosts unless `NOVA_STRICT_SCOPE=false` is set deliberately.
- `nova_features.py --check` now verifies core imports and exported attributes,
  not only whether files exist.
- `nova_evolution.py` provides a safe self-improvement entrypoint. It is blocked
  unless `NOVA_ALLOW_EVOLUTION=true` is set, then routes improvements through the
  same validated coding-agent loop.

### Architecture diagram

```mermaid
flowchart TD
    U[User intent / CLI / natural language] --> R[Intent parser + CLI router]
    R --> M[Phase 0 codebase mapper]
    M --> C[Context packer + repository brief]
    C --> A{Agent mode}

    A -->|nova code| CA[Autonomous coding agent]
    A -->|hunt / full / scan| SA[Security orchestration pipeline]
    A -->|evolution| EV[Safe self-improvement gate]

    CA --> P[Plan]
    P --> L[LLM router]
    L --> D[Minimal unified diff]
    D --> G[git apply --check]
    G -->|valid| AP[Apply patch]
    G -->|invalid| NP[Reject patch]
    AP --> T[Test runner]
    T -->|fail| RR[One repair retry]
    T -->|pass or no tests| REP[Audit report]
    RR --> L
    NP --> REP

    SA --> SAST[SAST / SCA / secrets / CI/CD / container]
    SA --> ACT[Active scanners: IDOR / GraphQL / CSRF / JWT / SQLi / SSRF]
    SA --> TRI[Triage + patch + detection + report]

    EV -->|NOVA_ALLOW_EVOLUTION=true| CA
    EV -->|default| BLOCK[Blocked]

    subgraph Governance
      TK[Governed tool registry]
      SG[Strict scope guard]
      AL[Redacted audit log]
      RL[Rate limiter]
    end

    CA --> TK
    SA --> TK
    TK --> SG
    TK --> AL
    TK --> RL
```

### Installation manual

#### 1. Clone

```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
```

#### 2. Create an isolated Python environment

```bash
python3 -m venv ~/nova_workspace/.venv
source ~/nova_workspace/.venv/bin/activate
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

The full requirements file installs security, browser, binary-analysis,
cloud-security, and OSINT tooling. For a lean coding-agent environment, install
at minimum:

```bash
pip install requests aiohttp beautifulsoup4 lxml colorama rich tabulate pyyaml python-dotenv ollama
```

#### 3. Install and start a local model provider

Nova works with API providers, but the default open-source path is Ollama:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve
ollama pull qwen3:8b
```

Optional provider keys can be configured when you want stronger remote models:

```bash
export OPENAI_API_KEY="..."
export ANTHROPIC_API_KEY="..."
export GEMINI_API_KEY="..."
```

#### 4. Configure Nova runtime policy

```bash
export NOVA_WORKSPACE=~/nova_workspace
export NOVA_LLM_URL=http://localhost:11434
export NOVA_LLM_MODEL=qwen3:8b
export NOVA_PERMISSION_PROFILE=scoped
export NOVA_STRICT_SCOPE=true
```

For autonomous coding verification, pass an explicit test command whenever
possible:

```bash
export NOVA_CODE_TEST_COMMAND="python3 -m pytest"
```

#### 5. Verify installation

```bash
python3 nova_features.py --check
python3 -m py_compile nova.py nova_cli.py nova_code_agent.py nova_tool_kit.py nova_agent_core.py
```

#### 6. Run Nova as an autonomous coding agent

Inspection-only mode:

```bash
python3 nova_code_agent.py "Inspect the repository and create a plan" --repo . --no-edit
```

Autonomous coding mode with verification:

```bash
python3 nova_cli.py code "Fix the failing tests" --repo . --test-command "python3 -m pytest"
```

Natural-language mode:

```bash
python3 nova.py "Use the autonomous coding agent to fix failing tests in ."
```

#### 7. Run Nova as a security agent

```bash
python3 nova.py "Map the codebase at ."
python3 nova.py "SAST code audit of ."
python3 nova.py "Hunt http://localhost:3000 for vulnerabilities"
```

#### 8. Safe self-improvement

Self-improvement is blocked by default. To allow Nova to improve itself, require
an explicit local opt-in and a verification command:

```bash
export NOVA_ALLOW_EVOLUTION=true
python3 nova_evolution.py --goal "Improve import smoke tests" --repo . --test-command "python3 nova_features.py --check"
```

### Industrial-grade operating principles

1. **Never apply unvalidated patches.** Nova only applies generated diffs after
   `git apply --check` succeeds.
2. **Always run a verification command.** Use `--test-command` or
   `NOVA_CODE_TEST_COMMAND` for every coding task.
3. **Keep scope strict.** Leave `NOVA_STRICT_SCOPE=true` unless you are running a
   controlled lab.
4. **Review audit reports.** Nova writes reports to `NOVA_WORKSPACE` for every
   coding-agent run.
5. **Treat local models as runtime components.** Better open models improve Nova;
   the runtime is model-agnostic and can also route to OpenAI, Anthropic,
   Gemini, or OpenAI-compatible endpoints.

---

---

## ð Table of Contents

1. [ð Quick Start](#-quick-start)
2. [ð Installation (Detailed)](#-installation-detailed)
3. [ðï¸ Architecture](#ï¸-architecture)
4. [ð¯ Capabilities](#-capabilities)
5. [ð All Modules](#-all-modules)
6. [ð§ Configuration](#-configuration)
7. [ð Next Steps](#-next-steps)

---

## ð Quick Start

### 1ï¸â£ Clone and Install (2 minutes)

```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal

# Option A: Automated setup (recommended)
bash nova_setup_enhanced.sh

# Option B: Manual setup
pip install -r requirements.txt
ollama serve  # In another terminal
```

### 2ï¸â£ Verify Installation (30 seconds)

```bash
# Check all 35+ modules are working
python3 nova_features.py --check

# View all available capabilities
python3 nova_features.py
```

### 3ï¸â£ Run Your First Hunt (5-30 minutes)

```bash
# Hunt localhost for vulnerabilities
python3 nova.py "Hunt http://localhost:3000 for vulnerabilities"

# Or use structured CLI
nova hunt http://localhost:3000

# View report
nova report
```

---

## ð Installation (Detailed)

### Step 1: Prerequisites

â **Python 3.10+**
```bash
python3 --version  # Should be 3.10 or higher
```

â **Git**
```bash
git --version
```

â **Ollama** (for local LLM, completely free)
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Step 2: Clone Repository

```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
```

### Step 3: Install Python Dependencies

**Option A: Use enhanced setup script (Recommended)**
```bash
bash nova_setup_enhanced.sh
# This will:
# â Create virtual environment
# â Install all 100+ Python packages
# â Install Ollama + models
# â Install Playwright browser
# â Create .env configuration
# â Verify all modules
```

**Option B: Manual setup**
```bash
# Create virtual environment
python3 -m venv ~/nova_workspace/.venv
source ~/nova_workspace/.venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser
python3 -m playwright install chromium
```

### Step 4: Configure Environment

```bash
# Copy example configuration
cp .env.example .env

# Edit .env with your preferences
nano .env  # or use your favorite editor
```

**Key Configuration Options:**

| Option | Default | Purpose |
|--------|---------|----------|
| `NOVA_LLM_URL` | `http://localhost:11434` | Local Ollama (free) |
| `NOVA_LLM_MODEL` | `qwen3:8b` | Fast model for queries |
| `NOVA_PERMISSION_PROFILE` | `scoped` | `read_only` \| `scoped` \| `full` |
| `NOVA_WORKSPACE` | `~/nova_workspace` | Where reports are saved |
| `OPENAI_API_KEY` | (empty) | Optional: OpenAI API key |
| `TELEGRAM_BOT_TOKEN` | (empty) | Optional: Telegram alerts |

### Step 5: Start Ollama (if using local LLM)

```bash
# In a separate terminal:
ollama serve

# In another terminal, pull a model:
ollama pull qwen3:8b
```

### Step 6: Verify Installation

```bash
# Check all modules are working
python3 nova_features.py --check

# Output should show: "All modules verified!"
```

---

## ðï¸ Architecture

### System Architecture Diagram

```
âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
â                         ð¦ NOVA ARSENAL v4.2                                â
â                    Autonomous Security Research Agent                        â
âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

                              USER INTENT
                                  â
                  âââââââââââââââââ¼ââââââââââââââââ
                  â   Intent Parser & CLI Router   â
                  â  (nova.py / nova_cli.py)      â
                  â  "Hunt target.com"            â
                  â  "Full pipeline on ./app"     â
                  â  "Orchestrate attack"         â
                  âââââââââââââââââ¬ââââââââââââââââ
                                  â
      âââââââââââââââââââââââââââââ¼ââââââââââââââââââââââââââââ
      â           PHASE 0: CODEBASE MAPPER                    â
      â  (nova_codebase_mapper.py)                            â
      âââââââââââââââââââââââââââââââââââââââââââââââââââââââ¤
      â  30+ Languages  â 25+ Frameworks  â All Endpoints    â
      â  Secrets        â CVE Deps        â Attack Surface   â
      âââââââââââââââââââââââââââââ¬ââââââââââââââââââââââââââââ
                                  â
                    CodebaseMap (_CMAP) â Distributed to all phases
                                  â
      âââââââââââââââââââââââââââââ¼ââââââââââââââââââââââââââââ
      â          PROVIDER LAYER (Infrastructure)              â
      âââââââââââââââââââââââââââââââââââââââââââââââââââââââ¤
      â  â¢ nova_llm_router.py      (OpenAIâAnthropicâOllama) â
      â  â¢ nova_context.py         (Shared RunContext)       â
      â  â¢ nova_sessions.py        (Scan State Persistence)  â
      â  â¢ nova_tool_kit.py        (Governed Tools + Audit)   â
      â  â¢ nova_hooks.py           (Event Lifecycle)         â
      â  â¢ nova_skills.py          (System Prompts)          â
      âââââââââââââââââââââââââââââ¬ââââââââââââââââââââââââââââ
                                  â
  âââââââââââââââââââââââââââââââââ¼ââââââââââââââââââââââââââââââââ
  â                               â                               â
  â¼                               â¼                               â¼
ââââââââââââââââââââ     ââââââââââââââââââââ     ââââââââââââââââââââ
â PHASE 1: STATIC  â     â PHASE 2: ACTIVE  â     â PHASE 3: AGENTS  â
â ANALYSIS         â     â SCANNING         â     â & ORCHESTRATION  â
ââââââââââââââââââââ¤     ââââââââââââââââââââ¤     ââââââââââââââââââââ¤
â SAST             â     â SQLi Testing     â     â ReconAgent       â
â SCA              â     â XSS Fuzzing      â     â â discovers      â
â Git Secret Scan  â     â IDOR Testing     â     â AttackAgent      â
â CI/CD Scan       â     â JWT Forge        â     â â chains         â
â Container Scan   â     â CSRF Testing     â     â ReportAgent      â
â IaC Scan         â     â GraphQL Tests    â     â â generates      â
â Supply Chain     â     â Race Conditions  â     â Patches & Rules  â
ââââââââââ¬ââââââââââ     ââââââââââ¬ââââââââââ     ââââââââââ¬ââââââââââ
         â                        â                        â
         ââââââââââââââââââââââââââ¼âââââââââââââââââââââââââ
                                  â
      âââââââââââââââââââââââââââââ¼ââââââââââââââââââââââââââââ
      â     PHASE 4: INTELLIGENCE & VERIFICATION              â
      âââââââââââââââââââââââââââââââââââââââââââââââââââââââ¤
      â  â¢ nova_ast_intel.py       (Dataflow Analysis)       â
      â  â¢ nova_verify_engine.py   (Triple-Confirm)         â
      â  â¢ nova_browser_session.py (XSS Execution Check)    â
      â  â¢ nova_triage.py          (H1 Scoring)             â
      â  â¢ nova_zero_day_correlator.py (CVE Correlation)    â
      âââââââââââââââââââââââââââââ¬ââââââââââââââââââââââââââââ
                                  â
      âââââââââââââââââââââââââââââ¼ââââââââââââââââââââââââââââ
      â        PHASE 5: OUTPUT GENERATION                    â
      âââââââââââââââââââââââââââââââââââââââââââââââââââââââ¤
      â  â¢ nova_patch_generator.py (AI Code Fixes)          â
      â  â¢ nova_detection_engineer.py (Sigma Rules)         â
      â  â¢ nova_audit_reporter.py (Reports: HTML/JSON/MD)   â
      â  â¢ nova_vuln_tracker.py (SQLite Database)           â
      âââââââââââââââââââââââââââââ¬ââââââââââââââââââââââââââââ
                                  â
      âââââââââââââââââââââââââââââ¼ââââââââââââââââââââââââââââ
      â        CONTINUOUS IMPROVEMENT                        â
      âââââââââââââââââââââââââââââââââââââââââââââââââââââââ¤
      â  â¢ nova_diff_watcher.py    (Real-time Monitoring)   â
      â  â¢ nova_eval.py            (20 Benchmarks)          â
      â  â¢ nova_evolution.py       (Self-Improvement)       â
      â  â¢ nova_rag_builder.py     (Knowledge Learning)     â
      âââââââââââââââââââââââââââââââââââââââââââââââââââââââ

                              OUTPUTS
                    âââââââââââââââ¬ââââââââââââââ
                    â¼             â¼             â¼
            HTML Report      JSON Findings   Sigma Rules
            Executive Brief   CVSS Scores    Patches
```

### Data Flow Diagram

```
âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
â  Query: "Hunt http://target.com for vulnerabilities"           â
ââââââââââââââââââââ¬âââââââââââââââââââââââââââââââââââââââââââââââ
                   â
        ââââââââââââ¼âââââââââââ
        â  Parse Intent       â
        â  Initialize Context â
        ââââââââââââ¬âââââââââââ
                   â
        ââââââââââââ¼âââââââââââââââââââââââââââââââââââ
        â  PHASE 0: CODEBASE MAPPER                   â
        â  â¢ Enumerate all files (128 threads)       â
        â  â¢ Detect 30+ languages                    â
        â  â¢ Extract routes (25+ frameworks)         â
        â  â¢ Scan for secrets & CVE deps             â
        â  â¢ AI: "Top 3 bugs in this stack"          â
        â  â _CMAP (global map)                      â
        ââââââââââââ¬âââââââââââââââââââââââââââââââââââ
                   â
        ââââââââââââ¼âââââââââââââââââââââââââââââââââââ
        â  Seed Findings into Context                â
        â  â¢ Secrets â HIGH                          â
        â  â¢ CVE deps â HIGH                         â
        â  â¢ Endpoints â active scanners             â
        â  â¢ Brief â agent system prompts            â
        ââââââââââââ¬âââââââââââââââââââââââââââââââââââ
                   â
        ââââââââââââ¼âââââââââââââââââââââââââââââââââââ
        â  Dispatch to Phases (1-5)                  â
        â  â¢ Run in parallel or sequence             â
        â  â¢ Each uses _CMAP for optimization        â
        ââââââââââââ¬âââââââââââââââââââââââââââââââââââ
                   â
        ââââââââââââ¼âââââââââââââââââââââââââââââââââââ
        â  Emit Findings (Atomic)                    â
        â  â¢ HookBus.fire_finding()                  â
        â  â¢ RunContext.add_finding()                â
        â  â¢ Session.add_finding()                   â
        â  â¢ VulnTracker.ingest()                    â
        ââââââââââââ¬âââââââââââââââââââââââââââââââââââ
                   â
        ââââââââââââ¼âââââââââââââââââââââââââââââââââââ
        â  Generate Output Reports                   â
        â  â¢ HTML dashboard                          â
        â  â¢ JSON for parsing                        â
        â  â¢ Markdown for HackerOne                  â
        â  â¢ Sigma rules for SOC                     â
        ââââââââââââ¬âââââââââââââââââââââââââââââââââââ
                   â
        ââââââââââââ¼âââââââââââââââââââââââââââââââââââ
        â  Save to Workspace                         â
        â  ~/nova_workspace/                         â
        â  âââ reports/                              â
        â  âââ findings/                             â
        â  âââ sessions/                             â
        â  âââ logs/                                 â
        âââââââââââââââââââââââââââââââââââââââââââââ
```

### Multi-Agent Orchestration Flow

```
âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
â MULTI-AGENT ORCHESTRATION: nova_orchestrator.py                â
âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

    PHASE 1: RECONNAISSANCE AGENT
    ââââââââââââââââââââââââââââââââââââ
    â "Discover all endpoints & tech"  â
    â                                  â
    â Input:  CodebaseMap              â
    â Task:   â¢ Probe endpoints        â
    â         â¢ Identify frameworks    â
    â         â¢ Map auth mechanisms    â
    â         â¢ Find CDNs/WAFs         â
    â                                  â
    â Output: AttackBrief + Endpoints  â
    ââââââââââââââââââââ¬ââââââââââââââââ
                       â Handoff
                       â¼
    PHASE 2: ATTACK AGENT
    ââââââââââââââââââââââââââââââââââââ
    â "Chain exploits & verify"        â
    â                                  â
    â Input:  AttackBrief + Endpoints  â
    â Task:   â¢ Craft payloads         â
    â         â¢ Execute attacks       â
    â         â¢ Verify findings       â
    â         â¢ Chain vulns (SSRFâRCE)â
    â                                  â
    â Output: Verified Findings        â
    ââââââââââââââââââââ¬ââââââââââââââââ
                       â Handoff
                       â¼
    PHASE 3: REPORT AGENT
    ââââââââââââââââââââââââââââââââââââ
    â "Generate fixes & detection"     â
    â                                  â
    â Input:  Verified Findings        â
    â Task:   â¢ Score by CVSS          â
    â         â¢ Generate patches      â
    â         â¢ Create detection rulesâ
    â         â¢ Write executive brief â
    â                                  â
    â Output: Final Report             â
    ââââââââââââââââââââââââââââââââââââ
```

---

## ð¯ Capabilities

### By User Role

#### ð° Beginner (Any skill level)
- â One-command vulnerability hunt: `nova hunt http://target.com`
- â Full pipeline: `nova full ./my-app`
- â Codebase mapping: `nova map ./my-app`
- â View reports: `nova report`
- â Health check: `nova status`

#### ð¨âð» Intermediate (Security Pro)
- â Specific scanners: `nova scan sqli`, `nova scan xss`, etc.
- â Multi-agent orchestration: `nova orch http://target.com`
- â Real-time monitoring: `nova-watch ./my-app --staged`
- â Session management: `nova session list`, `resume <id>`
- â Telegram alerts: Set `TELEGRAM_BOT_TOKEN`
- â Custom reporting: `nova report --template executive`

#### ð Advanced (Red Team)
- â Threat modeling: `python3 nova_threat_model.py ./my-app`
- â Patch generation: `nova generate-patch <finding-id>`
- â Detection rules: `nova generate-detection <finding-id>`
- â Cloud hunting: `nova-cloud hunt http://target.com`
- â Self-evolution: `python3 nova_evolution.py --goal "..."`
- â Custom RAG: `python3 nova_rag_builder.py`

### Scanning Coverage

```
â SQL Injection       - Fuzzing + Blind SQLi detection
â XSS (Reflected)     - DOM + Reflected + Stored
â XSS (DOM)           - JavaScript execution verification
â IDOR / BOLA         - Multi-user context testing
â SSRF                - Blind + Callback-based detection
â JWT                 - alg:none, key confusion, expiry bypass
â CSRF                - Token validation bypass
â GraphQL             - Introspection, batching, IDOR
â Business Logic      - Price manipulation, race conditions
â Race Conditions     - Concurrency testing
â LLM Injection       - Prompt injection attacks
â Secrets             - API keys, DB credentials, tokens
â CVE Dependencies    - Known-risky packages
â CI/CD Misconfiguration
â IaC (Terraform)     - Security group misconfigs
â Container Security  - Dockerfile + Kubernetes
```

---

## ð All Modules

See [CAPABILITIES.md](CAPABILITIES.md) for complete feature matrix.

### Core Runtime (4 modules)
| Module | Role |
|--------|------|
| `nova.py` | Natural-language entry point |
| `nova_cli.py` | Structured CLI commands |
| `nova_codebase_mapper.py` | Phase 0: Codebase intelligence |
| `nova_orchestrator.py` | Multi-agent orchestration |

### Provider Layer (7 modules)
| Module | Role |
|--------|------|
| `nova_llm_router.py` | LLM provider routing |
| `nova_context.py` | Shared execution context |
| `nova_sessions.py` | Scan state persistence |
| `nova_tool_kit.py` | Governed tools + audit log |
| `nova_hooks.py` | Event lifecycle |
| `nova_skills.py` | System prompts |
| `nova_retry.py` | Resilient calling |

### Intelligence Layer (8 modules)
| Module | Role |
|--------|------|
| `nova_ast_intel.py` | Code dataflow analysis |
| `nova_verify_engine.py` | Triple-confirmation |
| `nova_browser_session.py` | Playwright browser |
| `nova_triage.py` | H1-ready prioritization |
| `nova_zero_day_correlator.py` | CVE correlation |
| `nova_diff_watcher.py` | Real-time monitoring |
| `nova_eval.py` | 20 benchmarks |
| `nova_threat_model.py` | STRIDE modeling |

### Active Scanning (14 modules)
SQLi, XSS, IDOR, SSRF, JWT, CSRF, Race Conditions, GraphQL, Business Logic, LLM Injection, Supply Chain, Git Secrets, CI/CD, Container

### Output Generation (4 modules)
| Module | Role |
|--------|------|
| `nova_patch_generator.py` | AI code patches |
| `nova_detection_engineer.py` | Sigma detection rules |
| `nova_audit_reporter.py` | Multi-format reports |
| `nova_vuln_tracker.py` | Vulnerability database |

**Total: 35+ Modules**

---

## ð§ Configuration

### Environment Variables

See [.env.example](.env.example) for all options.

**Quick Setup:**
```bash
cp .env.example .env

# For local development (free, no API keys):
NOVA_PERMISSION_PROFILE=scoped
NOVA_LLM_URL=http://localhost:11434
NOVA_LLM_MODEL=qwen3:8b

# For paid APIs (faster reasoning):
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# For notifications:
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
```

### Permission Profiles

```bash
# Safe for CI/CD (no network, no shell)
export NOVA_PERMISSION_PROFILE=read_only

# Default: scoped to NOVA_TARGET
export NOVA_PERMISSION_PROFILE=scoped

# All tools enabled (local only)
export NOVA_PERMISSION_PROFILE=full
```

---

## ð Next Steps

### For First-Time Users

1. **Read:** [INSTALLATION_COMPLETE.md](INSTALLATION_COMPLETE.md)
2. **Discover:** `python3 nova_features.py`
3. **Run:** `python3 nova.py "Hunt http://localhost:3000"`
4. **Verify:** `python3 nova_eval.py --quick`

### For Security Professionals

1. **See Capabilities:** [CAPABILITIES.md](CAPABILITIES.md)
2. **Configure Notifications:** Set `TELEGRAM_BOT_TOKEN` in `.env`
3. **Try Orchestration:** `nova orch http://target.com`
4. **Set Up Pre-commit:** `nova-watch ./my-app --staged`

### For Red Teamers

1. **Enable Cloud Hunting:** `nova-cloud hunt http://target.com`
2. **Generate Patches:** `nova generate-patch <finding-id>`
3. **Create Detection Rules:** `nova generate-detection <finding-id>`
4. **Enable Self-Evolution:** Set `NOVA_ALLOW_EVOLUTION=true`

---

## ð Documentation

- **[INSTALLATION_COMPLETE.md](INSTALLATION_COMPLETE.md)** â Full post-install guide
- **[CAPABILITIES.md](CAPABILITIES.md)** â Feature matrix by role
- **[SOLUTIONS.md](SOLUTIONS.md)** â Hacking guides and walkthroughs
- **[REFERENCES.md](REFERENCES.md)** â Research and talks
- **[.env.example](.env.example)** â Configuration template
- **[nova_features.py](nova_features.py)** â Feature discovery tool

---

## ðï¸ Architecture Principles

1. **Phase 0 is Mandatory** â Codebase mapper runs first, optimizes all downstream phases
2. **Single Emission Path** â All findings go through `_emit_findings()` atomically
3. **Tool Governance Required** â Every tool wrapped, audited, rate-limited
4. **Map-Aware Better Than Blind** â Read source code to discover, probe to verify
5. **Quality Driven by Benchmarks** â `nova_eval.py` gates all changes

---

## âï¸ CLI Quick Reference

### Core Commands
```bash
nova hunt <url>              # Single-target hunt
nova full <path>             # Local full pipeline
nova map <path>              # Codebase mapping only
nova orch <url>              # Multi-agent orchestration
nova sast <path>             # Static analysis
nova sca <path>              # Dependency scanning
```

### Specific Scanners
```bash
nova scan sqli <url>         # SQL injection
nova scan xss <url>          # Cross-site scripting
nova scan idor <url>         # Insecure direct object references
nova scan ssrf <url>         # Server-side request forgery
nova scan jwt <url>          # JWT vulnerabilities
nova scan csrf <url>         # Cross-site request forgery
nova scan race <url>         # Race conditions
nova scan graphql <url>      # GraphQL injection
```

### Management
```bash
nova status                  # Health check
nova providers --test        # Test LLM providers
nova session list            # View sessions
nova session resume <id>     # Resume hunt
nova report                  # Generate report
nova eval --quick            # Quick benchmarks
```

---

## ð Performance

| Task | Time | Output |
|------|------|--------|
| Codebase map (1,000 files) | 2-15s | 50KB JSON |
| SAST scan | 10-60s | 100KB-1MB |
| SCA scan | 5-30s | 50KB-500KB |
| SQL injection scan | 5-15m | 10KB-100KB |
| Full hunt | 30-60m | 5-50MB |
| Threat model | 5-10s | 20KB |

---

## ð¤ Contributing

See [AGENTS.md](AGENTS.md) for AI assistant guidelines and [CONTRIBUTING.md](CONTRIBUTING.md) for development practices.

---

## ð License

MIT License â See LICENSE file

---

## ð Acknowledgments

Built by the Nova Arsenal team with contributions from the security community.

---

**Version:** 4.2  
**Last Updated:** June 2026  
**Status:** â Production Ready
