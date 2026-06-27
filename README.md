# Nova-Arsenal

[![CI](https://github.com/Informant254/Nova-arsenal/actions/workflows/ci.yml/badge.svg)](https://github.com/Informant254/Nova-arsenal/actions/workflows/ci.yml)
[![Security](https://github.com/Informant254/Nova-arsenal/actions/workflows/security.yml/badge.svg)](https://github.com/Informant254/Nova-arsenal/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)

**Autonomous Security Research Platform**

Nova-Arsenal is an autonomous security agent platform with **native API integrations** for Metasploit, Burp Suite, Nmap, and SQLmap — a **tool-selection intelligence engine** that decides which tool to use when, and a **cross-tool correlation engine** that sees the full picture across all sources.

> ⚠️ **Ethical Use Only** — Nova-Arsenal is built for authorized security research and bug bounty engagements. Only run against targets you have explicit written permission to test. See [SECURITY.md](SECURITY.md) for responsible disclosure policy.

---

## Features

- **240+ Security Tools & Modules** — Comprehensive Kali Linux knowledge base split into Core & Extended modules across 25 categories (mobile, cloud, active directory, container, wireless, password cracking, reverse engineering, web exploitation, etc.)
- **Fugu-Style LLM Orchestration** — Dynamic task classification, routing, and automatic fallback across 9 LLM providers (Anthropic, OpenAI, Gemini, DeepSeek, Qwen, OpenRouter, HuggingFace, Ollama, **Opencode**)
- **Native API/RPC Integrations** — Programmatic control over Metasploit (msfrpcd REST), Burp Suite (REST API + GraphQL), SQLmap (API mode), with structured Nmap XML parsing
- **Tool-Selection Intelligence** — Rule engine that maps detected services to the optimal tool: Port 445 → Metasploit SMB modules, Web app → Burp scan + nuclei, Login form → SQLmap vs Hydra decision
- **Cross-Tool Result Correlation** — Correlates findings from Nmap + Burp + Metasploit + SQLmap + heuristics. Multi-source confirmed vulnerabilities get boosted severity and confidence scoring
- **Specialized Security Personas** — 10 phase-specific AI personas (Recon Specialist, Offensive Operator, Senior Analyst, etc.) that transform Nova's behavior per task phase
- **Live CVE & Exploit Research** — Automatic CVE lookup for every detected service version. Covers 7 service types + 10 known exploit patterns (EternalBlue, BlueKeep, Log4j, etc.)
- **Payload Generation Engine** — Reverse shells in 6 languages (Bash, Python, Perl, Ruby, PowerShell, Netcat), bind shells, webshells (PHP/ASPX), and download-exec stagers
- **Scheduled Scanning** — Cron-based scheduler for recurring scans. Full cron expression support with run history, pause/resume, and async execution loop
- **Compliance Mapping** — Maps every finding to PCI DSS v4.0, SOC 2, ISO 27001:2022, and NIST SP 800-53 control IDs
- **OSINT Chain Investigation** — 7-phase automated OSINT pipeline: domain discovery → subdomain enum → tech detection → email harvest → social discovery → breach search → correlation
- **Multi-Agent Swarm Architecture** — Parallel Recon, Web, Exploit, and OSINT agents with weighted voting for consensus findings
- **Agent IDE** — Web-based code editor (Monaco) with syntax highlighting, template library, and one-click run/copy
- **CTF Solver Mode** — Automatic CTF challenge solving with challenge type classification (web, crypto, stego, forensics, reversing, pwn, OSINT, recon), pattern-based flag extraction, and type-specific solve pipelines
- **MCP Server Export** — Model Context Protocol (MCP) server exposing Nova's tools (nmap, burp, sqlmap, osint, CVE, payload, compliance, CTF, swarm) for AI-agent interoperability via stdio JSON-RPC
- **VS Code Extension** — Full VS Code extension with 6 commands (chat, scan, nmap, payload, OSINT, CTF), webview panel with streaming chat, quick-action buttons, and configurable API connection
- **E2E Encryption** — End-to-end encryption using RSA-4096 key exchange + AES-256-GCM for agent communications. Key generation, rotation, secure envelope format with AAD support
- **Conversational Chat Assistant (Nova)** — Real-time SSE streaming interface to converse with Nova, lookup tool information, or run security tasks autonomously
- **Interactive Web Dashboard** — Dark-themed chat interface with tabbed Chat/IDE panels, streaming display, instant tool suggestions, session history, and capability templates
- **Docker-Isolated Execution** — Secure command validation and scope guards to prevent unauthorized system modification or escape
- **SQLite/Postgres Storage** — Multi-user authentication, persistent session history, database-backed logging, and structured reporting
- **Nex-N2-Pro Integration** — Native support for `nexus/nex-n2-pro` and `nexus/nex-n2-mini` (free on OpenRouter) with Nex-N2 XML tool format, Adaptive Thinking profiles, and samplling params tuned for agentic security tasks
- **Adaptive Thinking Engine** — Phase-aware reasoning depth control (ThinkingProfile: FORCE_ON/SEARCH/SWE) mapped to agent phases; injects **Coherent Thinking** blocks into priority prompt trees for concentrated reasoning where uncertainty is highest
- **GRPO Training Pipeline** — Self-hosted Group Relative Policy Optimization ported from NexRL: 256 async rollout workers, temperature=1.0, rollout_repeat_n=8, group-relative advantages, rule-based security rewards (exact match, F1, keyword, tool output quality), parquet data format
- **GLM-5.1 Asynchronous Agentic RL** — Fully decoupled inference/training engines with TITO Gateway (Token-in-Token-out), Direct Double-sided Importance Sampling, off-policy sample dropping by version gap, DP-aware routing, and a Multi-Task Rollout Orchestrator supporting 1k+ concurrent rollouts across SWE/Terminal/Search environments
- **Cross-Stage Distillation** — On-policy teacher-student distillation across multi-stage RL (Reasoning → Agentic → General) using teacher-logit gaps as advantages; group_size=1, batch_size=1024, staged curriculum
- **DeepSeek Sparse Attention (DSA) Compressor** — Content compression for long security tool outputs (nmap, burp, sqlmap) using compressed latent projection, deterministic top-k segment selection (k=2048), and HCA-style windowing
- **Muon Optimizer** — Newton-Schulz matrix orthogonalization for 2D weight matrices with automatic AdamW fallback for biases/norms/embeddings; drop-in `torch.optim.Optimizer` for fine-tuning
- **mHC Architecture Reference** — Manifold-Constrained Hyper-Connections (nhc=4, Sinkhorn-Knopp tmax=20) and Anticipatory Routing for MoE load balancing, extracted from DeepSeek V4 Pro
- **Safe Exploitation Engine** — Pentera-inspired controlled exploitation with guardrails (damage limits, blocked targets, stealth modes, rollback support, emergency stop). Every action validated, logged, and reversible before execution
- **Autonomous Attack Chaining** — NodeZero-inspired attack graph builder with BFS path discovery, prerequisite resolution, autonomous execution with timeout, credential harvesting per chain, and pivot detection
- **Multi-Agent Coordinator** — XBOW-inspired architecture: thousands of parallel agents (Scout, Exploiter, Validator, Chainer, Reporter) with semaphore-bounded concurrency, structured reasoning traces, and real-time global state view
- **Deterministic Validation Engine** — XBOW-inspired zero-false-positive validation: every finding must be proven exploitable via 9 validation methods (exploit confirmed, response analyzed, vuln exists, credential validated, privilege escalated, persistence verified, etc.)
- **Emergency Stop & Safety Controls** — Pentera-inspired safety controller with risk-level gating, target blocklists, approval workflows for high-risk operations, concurrent operation limits, and full audit trail
- **MITRE ATT&CK Mapping** — 30+ technique database with automatic behavior-to-technique mapping, kill chain construction, coverage analysis, and compliance reporting
- **Advanced Credential Harvesting** — NodeZero-inspired credential access: SAM dumps, Kerberoasting, AS-REP Roasting, DPAPI extraction, GPP passwords, unattended install files, memory dumps. LLM-powered risk analysis and password complexity assessment
- **Safe Ransomware Emulation** — Full ransomware kill chain simulation (reconnaissance → encryption → ransom note) without actual destruction. Hash-based encryption simulation, shadow copy enumeration, backup discovery
- **Fix Verification & Retesting** — NodeZero-inspired 1-click retesting: replay original exploit steps to confirm remediation, track fix confidence, detect regressions across verification history
- **Incremental Testing Engine** — XBOW-inspired delta-only testing: compare versions, detect changes, generate focused test plans covering only modified components. Impact scoring, technique inference, priority matrix
- **Real-time Finding Streaming** — XBOW-inspired live updates: stream findings, agent reasoning traces, chain progress, and status updates to connected clients via WebSocket/SSE with filtering and heartbeat

## Quick Start

### Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

# Copy environment variables
cp config/.env.example .env

# Start all services
docker compose up -d

# Access the dashboard
open http://localhost:3000
```

### Local Development

```bash
# Install Python package
pip install -e ".[dev]"

# Install web client
cd clients/web && npm install && cd ../..

# Start services
docker compose up -d llm sandbox

# Run the agent (use scanme.nmap.org for authorized demo testing)
nova-agent --target scanme.nmap.org

# Start the web UI
cd clients/web && npm run dev
```

### Conversational Chat Interface (No Docker Required)

```bash
# Install FastAPI dependencies
pip install fastapi uvicorn

# Start the conversational API server
python -m nova_arsenal.api

# Access the interactive dashboard
open http://localhost:8000
```

The web dashboard provides:
- **Real-time streaming responses** from Nova
- **Intent classification** (security task, tool info, conversation, code, question)
- **Direct tool lookup** from 240+ Kali tools
- **Session persistence** with history
- **Quick-start capability cards** for common tasks

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              Nova-Arsenal                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌──────────┐   ┌────────────┐   ┌──────────┐   ┌──────────────────────────┐  │
│  │   Web    │   │  Persona   │   │   LLM    │   │    Intelligence Layer     │  │
│  │Dashboard │   │  Manager   │   │ Provider │   │  ┌────────────────┐       │  │
│  │ Chat+IDE │──▶│(10 Phase   │──▶│ (Multi)  │   │  │Tool Selector   │       │  │
│  │ (static) │   │  Personas) │   └────┬─────┘   │  │Correlator      │       │  │
│  └──────────┘   └────────────┘        │         │  │CveResearch     │       │  │
│                                        │         │  │OsintChain      │       │  │
│                                        ▼         │  └────────────────┘       │  │
│                                 ┌──────────┐     │                           │  │
│                                 │  Agent   │     │  ┌────────────────┐       │  │
│                                 │  Core    │─────│  │PayloadGen      │       │  │
│                                 │ (Python) │     │  │Scheduler       │       │  │
│                                 └┬─────────┘     │  │SwarmOrch       │       │  │
│                                  │               │  │Compliance      │       │  │
│                                  ▼               │  └────────────────┘       │  │
│                           ┌──────────┐           └──────────────────────────┘  │
│                           │Integration│                                        │
│                           │  Clients  │                                        │
│                           │ ┌────────┐ │        ┌──────────────────────────┐  │
│                           │ │Metaspl│ │        │    Tool Integrations      │  │
│                           │ │oit RPC│ │        │  ┌────────────────────┐   │  │
│                           │ ├────────┤ │        │  │Nmap (CLI + XML)   │   │  │
│                           │ │Burp    │ │        │  │Burp (REST/GQL)    │   │  │
│                           │ │(REST/  │ │        │  │Metasploit (RPC)   │   │  │
│                           │ │GraphQL)│ │        │  │SQLmap (API)       │   │  │
│                           │ ├────────┤ │        │  │Nuclei, Hydra, ... │   │  │
│                           │ │SQLmap  │ │        │  └────────────────────┘   │  │
│                           │ │(API)   │ │        └──────────────────────────┘  │
│                           │ ├────────┤ │                                        │
│                           │ │Nmap    │ │        ┌──────────────────────────┐  │
│                           │ │(XML    │ │        │   Compliance & Reporting  │  │
│                           │ │Parser) │ │        │  ┌────────────────────┐   │  │
│                           │ └────────┘ │        │  │PCI DSS / SOC 2     │   │  │
│                           └───────────┘         │  │ISO 27001 / NIST    │   │  │
│                                                  │  └────────────────────┘   │  │
│                                                  └──────────────────────────┘  │
│                                                                                 │
│                                                    ┌────────────────────────┐  │
│                                                    │   Agent IDE (Monaco)   │  │
│                                                    │  6 Templates, 6 Langs  │  │
│                                                    └────────────────────────┘  │
│                                                                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
│  │  CTF Solver Mode  │  │  E2E Encryption  │  │   MCP Server Export      │  │
│  │  ┌──────────────┐ │  │  ┌─────────────┐ │  │  ┌────────────────────┐  │  │
│  │  │Web/Crypto   │ │  │  │RSA-4096    │ │  │  │9 Tools (nmap,     │  │  │
│  │  │Stego/OSINT  │ │  │  │AES-256-GCM │ │  │  │burp, sqlmap, ...) │  │  │
│  │  │PWN/Forensics│ │  │  │Key Rotation│ │  │  │4 Resources         │  │  │
│  │  │Flag Extract │ │  │  │AAD Support │ │  │  │JSON-RPC stdio      │  │  │
│  │  └──────────────┘ │  │  └─────────────┘ │  │  └────────────────────┘  │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────┘  │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  VS Code Extension (clients/vscode/)                                │   │
│  │  6 Commands · Webview Chat · Quick Actions · Configurable API       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Integrated Tool Flow

Nova orchestrates all tools through three layers:

```
Layer 1: Detection (What's running?)
  Nmap (CLI + XML parser) → Services, ports, versions, OS
  └─→ Detects: http, smb, ssh, mysql, etc.

Layer 2: Intelligence (Which tool to use?)
  ToolSelector (rule engine)
  ├─→ Port 445 (SMB) → Metasploit SMB modules + enum4linux + crackmapexec
  ├─→ Web app       → Burp scan + nuclei + nikto + dirsearch
  ├─→ SSH           → hydra brute force + nmap NSE scripts
  ├─→ Login form    → SQLmap (POST) vs Hydra (form brute)
  └─→ DB service    → SQLmap + hydra + nmap DB scripts

Layer 3: Correlation (What does it mean together?)
  Correlator (multi-source)
  ├─→ Nmap says outdated service
  ├─→ Metasploit says exploitable
  ├─→ Burp confirms weak headers
  └─→ = CRITICAL finding (confidence 1.0, 3 tools confirmed)
```

### Conversational Chat Flow

Nova uses Fugu-style orchestration to intelligently route tasks:

```
User Message → Intent Classification → Route Decision
    │
    ├─→ CONVERSATION → General LLM → Friendly response
    ├─→ TOOL_INFO → Tool Lookup → Kali docs (230 tools)
    ├─→ QUESTION → Security Knowledge → Expert answers
    ├─→ CODE_REQUEST → Code Gen → Exploit generation
    └─→ SECURITY_TASK → AgentRunner → Full autonomic loop
                             │
                             ├─→ Plan → Recon → Scan → Integrations → Exploit
                             └─→ Correlate → Report
```

## API/RPC Integrations

### Configuration

Available integrations are configured via the `integrations` dict when creating an `AgentRunner`:

```python
from nova_arsenal import AgentRunner

runner = AgentRunner(
    target="10.0.0.1",
    integrations={
        "metasploit": {
            "enabled": True,
            "host": "https://127.0.0.1:55553",
            "password": "your_msf_pass",
        },
        "burp": {
            "enabled": True,
            "url": "http://127.0.0.1:1337",
            "api_key": "your_burp_api_key",
        },
        "sqlmap": {
            "enabled": True,
            "url": "http://127.0.0.1:8775",
        },
    },
)
```

### Metasploit RPC (`integrations/msf_rpc.py`)

Communicates with `msfrpcd` (JSON-RPC over HTTP, default port 55553):

- **Login** — authenticate with msfrpcd, manage token
- **Execute modules** — run auxiliary, exploit, post modules with structured results
- **Session management** — list active Meterpreter sessions, get session IDs
- **Run module groups** — chain multiple modules against shared targets
- **Finding extraction** — auto-detect vulnerabilities from module output

```bash
# Start msfrpcd
msfrpcd -P your_password -S -a 127.0.0.1
```

### Burp Suite REST (`integrations/burp_api.py`)

Communicates with Burp's REST API (PortSwigger REST + GraphQL):

- **Start scans** — launch active scans against target URLs
- **Pull issues** — collect structured findings with severity, confidence, remediation
- **Manage scope** — configure include/exclude rules
- **Generate reports** — HTML/XML report generation
- **Auto-create findings** — Burp issues become Nova findings with full evidence

```bash
# Burp's REST API is available via Burp's REST Extension or PortSwigger Cloud
```

### Nmap XML Parser (`integrations/nmap_parser.py`)

Parses nmap `-oX` XML output into structured data:

- **Host discovery** — IP, hostname, MAC, OS detection, state
- **Port parsing** — port, protocol, service, version, product, CPE
- **NSE script extraction** — script ID and output from NSE runs
- **Finding extraction** — auto-classifies services (web, SMB, DB, SSH) and detects outdated versions

```bash
# Nova uses -oX for structured output
nmap -sV -sC -p- target -oX /workspace/nmap_full.xml
```

### SQLmap API (`integrations/sqlmap_api.py`)

Communicates with `sqlmapapi.py` (REST API, default port 8775):

- **Create tasks** — new scan tasks with URL, options (level, risk, technique)
- **Set options** — data, cookie, headers, method, threads, DBMS, etc.
- **Poll status** — progress tracking, status, completion detection
- **Parse findings** — injection points, techniques (boolean/error/time/union), DBMS info, payloads
- **Manage tasks** — list, stop, kill, flush tasks

```bash
# Start sqlmap API server
sqlmapapi.py -s -H 0.0.0.0 -p 8775
```

## Tool-Selection Intelligence (`intelligence/tool_selector.py`)

Nova's internal rule engine decides **which tool to use when** based on detected services and findings:

### Service Rules

| Detected Service | Tools Selected | Priority |
|-----------------|----------------|----------|
| HTTP/HTTPS | Burp scan, nuclei, nikto, whatweb, dirsearch, sqlmap | 10-6 |
| SMB (445) | Metasploit SMB modules, enum4linux, crackmapexec, nmap SMB vuln | 10-7 |
| SSH (22) | hydra brute force, nmap SSH NSE scripts, Metasploit SSH scan | 8-6 |
| MySQL/Postgres | SQLmap, nmap DB NSE scripts, Metasploit DB modules, hydra | 9-6 |
| RDP (3389) | nmap RDP NSE scripts (BlueKeep), crowbar brute force | 9-7 |
| DNS | dnsrecon, dnsenum | 8-7 |
| LDAP/Kerberos | nmap LDAP scripts, Metasploit Kerberos modules, kerbrute | 9-8 |
| FTP (21) | hydra brute force, nmap FTP NSE scripts | 8-7 |

### Finding Rules

| Finding Pattern | Tools Triggered |
|----------------|-----------------|
| SQL Injection | SQLmap, Metasploit SQLi auxiliary |
| XSS | dalfox, Burp Suite XSS scan |
| RCE | Metasploit exploit modules, Burp RCE scan |
| Default Credentials | hydra, crackmapexec |
| Info Disclosure | Burp info leak scan, nuclei exposure templates |

### Cross-Service Correlations

| Combination | Strategy |
|-------------|----------|
| Web + Database | SQLmap for DB injection + Burp for web-layer vulns |
| Outdated SMB | Immediate EternalBlue (MS17-010) check via Metasploit |
| Login Form | SQLmap for POST injection + Hydra for form brute force |

## Cross-Tool Result Correlation (`correlation/correlator.py`)

Nova reads output from **all tools** and correlates them to see the full picture:

### How It Works

```
Nmap:  Port 80 open (Apache 2.4.49 outdated)
Burp:  SQL Injection confirmed in /login
MSF:   auxiliary/scanner/http/sql_injection → vulnerable
Nuclei: CVE-2021-41773 detected
                            ↓
          Correlator matches 4 sources against rules
                            ↓
     CORRELATED CRITICAL: Web vuln (4 tools, confidence 1.0)
```

### Correlation Rules

| Rule | Min Sources | Severity | Sources |
|------|-------------|----------|---------|
| Web Critical Chain | 2 | critical | burp, nuclei, nikto, sqlmap, nmap, msf, findings |
| Web High Chain | 1 | high | burp, nuclei, nikto, whatweb, nmap, findings |
| SMB Critical Chain | 2 | critical | msf, nmap, enum4linux, crackmapexec, findings |
| SMB High Chain | 1 | high | msf, nmap, enum4linux, findings |
| Outdated Service | 2 | high | nmap, msf, whatweb, nuclei, findings |
| Credential Chain | 2 | critical | hydra, msf, crackmapexec, burp, nmap, findings |

### Confidence Scoring

- **1 source** → 0.3 confidence (possible, low certainty)
- **2 sources** → 0.6 confidence (probable, medium certainty)
- **3 sources** → 0.9 confidence (confirmed, high certainty)
- **4+ sources** → 1.0 confidence (verified, maximum certainty)

### Cross-Tool Insights

The correlator generates high-level insights like:
- "3 findings confirmed by multiple independent tools (high confidence)"
- "Burp Suite + Nmap both active: service enumeration + web-layer vuln scanning"
- "Metasploit integration active: exploit modules deployable for confirmed vulns"
- "2 CRITICAL severity findings require immediate attention"

## Specialized Security Personas (`persona_manager.py`)

Nova uses **10 phase-specific AI personas** that adapt the agent's behavior to each phase of the pentesting lifecycle:

| Phase | Persona | Focus |
|-------|---------|-------|
| Init | System Initializer | Validate target, load configs |
| Planning | Strategic Planner | Threat model, attack tree, objective scoping |
| Recon | Reconnaissance Specialist | OSINT gathering, DNS enumeration, passive recon |
| Scan | Scanning Specialist | Port scanning, service detection, fingerprinting |
| Exploit | Offensive Operator | Vulnerability exploitation, payload delivery |
| Post-Exploit | Post-Exploitation Operator | Privilege escalation, lateral movement, data exfiltration |
| Integration | Integration Commander | Multi-tool orchestration, API coordination |
| Correlation | Senior Analyst | Multi-source correlation, false positive elimination |
| Report | Executive Reporter | Risk scoring, remediation roadmaps, executive summary |
| Completed | Mission Debriefer | Session review, lessons learned |

Personas are injected directly into the LLM system prompt via `get_system_prompt_augmentation()`, transforming tone, tactics, and expertise per phase without changing the agent architecture.

```python
from nova_arsenal import PersonaManager

persona_mgr = PersonaManager()
augmentation = persona_mgr.get_system_prompt_augmentation("recon")
# Returns persona-specific instructions for recon phase
```

## Live CVE & Exploit Research (`intelligence/cve_research.py`)

Nova automatically researches CVEs and exploits for every detected service version:

**Offline Service→CVE Mappings** (7 service types):
| Service | CVE Patterns |
|---------|-------------|
| HTTP (Apache 2.4.49) | CVE-2021-41773, CVE-2021-42013 |
| SMB (Windows) | CVE-2017-0144 (EternalBlue), CVE-2019-0708 (BlueKeep) |
| SSH (OpenSSH) | CVE-2024-6387 (RegreSSHion) |
| MySQL | CVE-2012-2122, CVE-2016-6662 |
| PostgreSQL | CVE-2019-9193 |
| RDP | CVE-2019-0708 (BlueKeep) |
| Kerberos | CVE-2020-1472 (Zerologon) |

**Known Exploit Pattern Detection** (10 patterns):
- EternalBlue (MS17-010), BlueKeep, Log4j (CVE-2021-44228), Shellshock, Heartbleed, PrintNightmare, Zerologon, ProxyShell, ProxyLogon, RegreSSHion

**Risk Scoring**:
- Base CVSS score + exploit availability + exploit count factors → weighted risk score

Research fires asynchronously during service detection, producing structured `Finding` objects with CVE ID, description, severity, exploit source, and remediation.

```python
from nova_arsenal import CveResearch

researcher = CveResearch()
result = researcher.research_service("http", "Apache httpd 2.4.49")
print(result.cve_ids, result.risk_score, result.is_exploitable)
```

## Payload Generator (`payload_generator.py`)

Nova's payload engine produces ready-to-deploy payloads across 4 types and 6 languages:

**Payload Types**:
| Type | Description | Languages |
|------|-------------|-----------|
| Reverse Shell | Connects back to listener | Bash, Python, Perl, Ruby, PowerShell, Netcat |
| Bind Shell | Opens shell on target port | Bash, Python, Perl, Ruby, PowerShell, Netcat |
| Webshell | Web-accessible command execution | PHP, ASPX |
| Download Exec | Downloads & runs remote binary | Bash, Python, PowerShell |

```python
from nova_arsenal import PayloadGenerator

generator = PayloadGenerator()
payloads = generator.generate_chain("10.0.0.1", 4444)
# Returns dict of type→language→payload_template
for ptype, langs in payloads.items():
    for lang, template in langs.items():
        print(f"{ptype}/{lang}: {len(template)} chars")
```

Payloads are automatically generated during the exploitation phase and emitted as agent events for Metasploit module integration.

## Scheduled Scanning (`scheduler.py`)

Nova's cron-based scheduler runs autonomous scans on a recurring schedule:

**Features**:
- **Cron Expression Parsing** — 5-field format with `*`, `*/N`, `,`, `-` support
- **Async Tick Loop** — 30-second poll interval, runs due entries via callbacks
- **Pause/Resume** — Per-entry pause control
- **Run History** — `ScheduleRunResult` with start/end time, success, findings_count, error
- **Stats Dashboard** — Total runs, success rate, findings per schedule

```python
from nova_arsenal import NovaScheduler, ScheduleEntry, CronExpression

scheduler = NovaScheduler()

# Nightly scan at 2 AM
entry = ScheduleEntry(
    name="nightly-scan",
    cron="0 2 * * *",
    target="10.0.0.1",
    task_type="full_scan",
    objective="Comprehensive vulnerability scan",
)
scheduler.add_entry(entry)
scheduler.start(agent_runner.run)
```

## Compliance Mapping Engine (`compliance/mapper.py`)

Every Nova finding is automatically mapped to compliance frameworks:

**Supported Frameworks**:
| Framework | Description |
|-----------|-------------|
| PCI DSS v4.0 | Payment Card Industry Data Security Standard |
| SOC 2 | Service Organization Control 2 |
| ISO 27001:2022 | Information Security Management |
| NIST SP 800-53 Rev 5 | Security and Privacy Controls |

**Finding Type → Control Mappings** (11 types): SQL injection, XSS, RCE, LFI, info disclosure, default credentials, open ports, outdated software, weak SSL, insecure headers, authentication bypass.

**Fuzzy Matching** — Handles aliases like `sqli` → `sql_injection`, `rce` → `remote_code_execution`.

```python
from nova_arsenal import ComplianceMapper

mapper = ComplianceMapper()
result = mapper.map_finding("sql_injection", "SQL injection in /login.php")
print(result.frameworks_affected)  # {"PCI DSS v4.0", "ISO 27001:2022", "NIST SP 800-53"}
stats = mapper.get_summary_stats()
```

## OSINT Chain Investigation (`intelligence/osint_chain.py`)

Nova's 7-phase automated OSINT pipeline:

```
Phase 1: Domain Discovery     → whois, dig SOA
Phase 2: Subdomain Enumeration → subfinder, crtsh, dig
Phase 3: Technology Detection  → whatweb, nmap
Phase 4: Email Harvesting      → theHarvester
Phase 5: Social Discovery      → theHarvester (social)
Phase 6: Breach Search         → theHarvester (breach)
Phase 7: Correlation           → Synthesize all results
```

All commands run via asyncio subprocess with 15-second timeout. Phase failures are logged and skipped — not fatal.

```python
from nova_arsenal import OsintChain

chain = OsintChain()
result = await chain.investigate("example.com")
print(f"Subdomains: {len(result.subdomains)}")
print(f"Emails: {len(result.emails)}")
print(f"Technologies: {result.technologies}")
```

## Multi-Agent Swarm Architecture (`swarm.py`)

Nova's swarm orchestrator runs multiple specialized agents in parallel:

**Agent Roles**:
| Role | Weight | Focus |
|------|--------|-------|
| ReconAgent | 1.0 | Host discovery, port scanning, service enumeration |
| WebAgent | 1.0 | Web app analysis, directory brute force, tech detection |
| ExploitAgent | 1.2 | Vulnerability exploitation, payload delivery |
| OSINTAgent | 0.8 | Open-source intelligence gathering |

**Consensus Computation**:
- Findings deduplicated by lowercase title
- Confidence boosted for repeated findings across agents
- Multi-vote or critical/high severity findings only
- Weights applied: exploit (1.2) > recon/web (1.0) > osint (0.8)

```python
from nova_arsenal import SwarmOrchestrator

swarm = SwarmOrchestrator()
result = await swarm.run_swarm("10.0.0.1")
for finding in result.findings:
    print(f"[{finding.severity}] {finding.title} (votes: {finding.votes})")
```

## Agent IDE Web Interface

The web dashboard includes a full code editor integrated with Nova:

**Features**:
- **Monaco Editor** — Feature-rich code editor with syntax highlighting, line numbers, dark theme
- **Template Selector** — 6 pre-built templates: reverse shell, bind shell, port scanner, subdomain enum, webshell, keylogger
- **Language Selector** — Python, Bash, PHP, PowerShell, Ruby, Perl
- **One-Click Run** — Sends code to Nova's chat API for execution
- **Copy to Clipboard** — Quick copy of generated payloads
- **Clear Output** — Reset the execution log

Access via the IDE tab in the web dashboard at `http://localhost:8000`.

## CTF Solver Mode (`ctf_solver.py`)

Nova automatically solves Capture The Flag challenges with type-specific pipelines:

**Challenge Type Classification**:
| Type | Patterns | Pipeline |
|------|----------|----------|
| Web | SQL injection, XSS, admin, login, CSRF | curl + gobuster + cookie analysis |
| Crypto | RSA, AES, hash, base64, XOR | Decoding, brute force, frequency analysis |
| Stego | LSB, hidden, embedded, exif | strings, exiftool, zsteg, steghide, binwalk |
| OSINT/Recon | whois, dig, search, social | whois, dig, nslookup, GitHub API |
| PWN | buffer overflow, ROP, shellcode | Exploit generation pipeline |
| Misc | Everything else | Generic pattern matching |

**Flag Extraction**: 5 regex patterns detect `flag{...}`, `CTF{...}`, and free-form flags with confidence scoring.

```python
from nova_arsenal import CtfSolver, ChallengeType

solver = CtfSolver()
challenge = solver.add_challenge(
    name="SQL Injection Lab",
    challenge_type=ChallengeType.WEB,
    url="http://target:8080",
    points=100,
)
flag = await solver.solve_challenge(challenge)
print(f"Solved: {flag.flag}, Method: {flag.method}")
```

## MCP Server Export (`mcp/server.py`)

Nova exposes its full capability set as a Model Context Protocol (MCP) server, allowing any MCP-compatible AI agent to use Nova's tools:

**Exposed Tools** (9 total):
| Tool | Description |
|------|-------------|
| `nmap_scan` | Run Nmap scans against targets |
| `burp_scan` | Start Burp Suite scans |
| `sqlmap_scan` | Run SQLmap injection tests |
| `osint_investigate` | Multi-phase OSINT investigation |
| `cve_lookup` | CVE research for service versions |
| `payload_generate` | Generate reverse shells, webshells, etc. |
| `compliance_check` | Map findings to compliance frameworks |
| `ctf_solve` | Automatically solve CTF challenges |
| `swarm_scan` | Multi-agent swarm scanning |

**Exposed Resources** (4 total): `nova://findings`, `nova://agents`, `nova://compliance`, `nova://keys`

```bash
# Run the MCP server (stdio mode)
python -c "from nova_arsenal.mcp import run_server; import asyncio; asyncio.run(run_server())"

# Or use fallback JSON-RPC mode (no MCP package needed)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python -c "..." 
```

API endpoints also available: `GET /api/mcp/tools`, `GET /api/mcp/resources`, `POST /api/mcp/call`.

## VS Code Extension (`clients/vscode/`)

A full VS Code extension integrates Nova into the editor with 6 commands:

| Command | Action |
|---------|--------|
| `Nova: Open Chat` | Opens webview chat panel (Ctrl+Alt+N / Cmd+Alt+N) |
| `Nova: Quick Security Scan` | Prompt for target, run quick scan |
| `Nova: Run Nmap Scan` | Prompt for target/ports, run nmap |
| `Nova: Generate Payload` | Select type, LHOST, LPORT |
| `Nova: OSINT Investigation` | Prompt for domain, run OSINT chain |
| `Nova: CTF Solver` | Prompt for challenge name/type/URL |

**Features**:
- **Webview Chat Panel** — Full Nova chat interface with streaming responses
- **Quick-Action Buttons** — Nmap, Payload, OSINT, CTF, Swarm, Compliance
- **Configurable** — `nova-arsenal.apiUrl`, `nova-arsenal.apiKey`, `nova-arsenal.defaultTarget`
- **Status Indicator** — Shows API connection status (connected/offline/error)

```bash
# Build the extension
cd clients/vscode
npm install && npm run compile
# Install the .vsix or copy to ~/.vscode/extensions/
```

## E2E Encryption (`crypto/`)

End-to-end encryption for agent communications using hybrid RSA + AES-GCM:

**Architecture**:
```
Plaintext → AES-256-GCM (ephemeral key) → Ciphertext
AES key → RSA-4096 (recipient public key) → Encrypted key
Envelope = ciphertext + IV + encrypted key + fingerprint + metadata
```

**Components**:
- **KeyManager** — RSA keypair generation (2048/4096), AES key generation, key rotation, disk persistence
- **Cipher** — Hybrid encrypt/decrypt with AAD (Additional Authenticated Data), message dict support
- **SecureEnvelope** — Serializable envelope with ciphertext, IV, encrypted_key, key_fingerprint, algorithm, timestamps, sender/recipient IDs

```python
from nova_arsenal import KeyManager, Cipher, KeySize

km = KeyManager()
kp = km.generate_rsa_keypair(KeySize.RSA_4096)

cipher = Cipher(km)
envelope = cipher.encrypt("secret mission data", kp.public_key_pem)
plaintext = cipher.decrypt(envelope, kp.private_key_pem)
assert plaintext == "secret mission data"
```

API endpoints: `POST /api/crypto/keypair`, `POST /api/crypto/encrypt`, `POST /api/crypto/decrypt`.

## Training Pipeline (`training/`)

Nova's training pipeline implements three RL paradigms ported from state-of-the-art model post-training recipes:

### GRPO Trainer (`training/grpo_trainer.py`)

Ported from **NexRL** (Nex-N2-Pro's self-hosted GRPO recipe). Group Relative Policy Optimization for security agent fine-tuning:

```
1. Sample batch of prompts from parquet dataset
2. Generate N responses per prompt (rollout_repeat_n=8, temperature=1.0)
3. Score with rule-based rewards (exact match, F1, keyword coverage, security output quality)
4. Compute group-relative advantages: (reward - mean(group)) / std(group)
5. Optimize policy with PPO-style clipped surrogate + KL penalty
```

```python
from nova_arsenal.training import GRPOTrainer, GRPOConfig

trainer = GRPOTrainer(
    config=GRPOConfig(batch_size=32, rollout_repeat_n=8),
    llm_complete=my_llm_callable,
    reward_fn=my_reward_function,
)
summary = await trainer.train(num_steps=200)
```

### GLM Agentic RL Loop (`training/glm_agentic_rl.py`)

Ported from **GLM-5.1** (arXiv 2602.15763, Sections 3.3 & 4.1). Fully asynchronous RL for long-horizon agent tasks:

| Component | Purpose |
|-----------|---------|
| `TITOGateway` | Token-in-Token-out — preserves exact tokenization, avoids re-tokenization mismatches during RL |
| `DoubledSidedImportanceSampling` | r_t(θ)=exp(logπ_θ−logπ_rollout); double-sided clip [1−ϵ_ℓ, 1+ϵ_h]; masks outside interval |
| `OffPolicySampleDropper` | Drops stale trajectories (w'−w_0 > τ), filters env failures, pads/drops incomplete GRPO groups |
| `DPAwareRouter` | Consistent hashing for KV-cache locality across multi-turn rollouts; rebalancing over hash space |
| `MultiTaskRolloutOrchestrator` | Central orchestrator with per-task microservices (SWE/Terminal/Search), unified message-list format, 1k+ concurrent rollouts |
| `AsyncAgenticRLTrainer` | Decoupled inference/training engines, continuous rollout, threshold-based batch consumption, periodic weight sync |

```python
from nova_arsenal.training import (
    MultiTaskRolloutOrchestrator, AsyncAgenticRLTrainer,
    AgenticTaskType, SWEEnvironment,
)

orchestrator = MultiTaskRolloutOrchestrator()
orchestrator.register_service(
    task_type=AgenticTaskType.SWE,
    rollout_fn=my_swe_rollout,
    reward_fn=my_swe_reward,
)
trainer = AsyncAgenticRLTrainer(
    config=grpo_config,
    orchestrator=orchestrator,
    llm_complete=my_llm_callable,
)
stats = await trainer.train_loop(my_data_loader)
```

### Cross-Stage Distillation (`training/cross_stage_distillation.py`)

Ported from **GLM-5.1** (Section 3.5). Prevents catastrophic forgetting across sequential RL stages:

```
Advantage per token:  Â_{i,t} = sg[log(π_teacher(y) / π_train(y))]

- Teachers are frozen checkpoints from Reasoning RL, Agentic RL, General RL stages
- group_size=1 (advantage from teacher gap, not group statistics)
- batch_size=1024
- Training prompts sampled from each teacher's RL training set (mixed proportionally)
```

```python
from nova_arsenal.training import CrossStageDistillationTrainer, RLStage

trainer = CrossStageDistillationTrainer(
    config=cross_stage_config,
    opd_config=opd_config,
    student_llm_complete=student_llm,
    teacher_llm_complete=teacher_llm,
)
trainer.register_teacher(RLStage.REASONING, "nova-reasoning-v1", weight=1.0)
trainer.register_teacher(RLStage.AGENTIC, "nova-agentic-v1", weight=1.0)
results = await trainer.distill_with_staged_curriculum(
    reasoning_prompts=reasoning_data,
    agentic_prompts=agentic_data,
    general_prompts=general_data,
)
```

## Nex-N2-Pro Integration & Adaptive Thinking

Nova natively supports **Nex-N2-Pro** (397B/17A, 512 experts) and **Nex-N2-mini** (35B/3A) on OpenRouter (`nexus/nex-n2-pro`, `nexus/nex-n2-mini`). Both are **free** on OpenRouter.

### Adaptive Thinking

Maps Nova's agent phases to reasoning-depth profiles, concentrating computation where uncertainty is highest:

| Phase | Thinking Profile | Effect |
|-------|-----------------|--------|
| Planning | `FORCE_ON` | Forces `<think>` blocks for attack tree generation |
| Recon / Scanning | `SEARCH` | Concentrates reasoning on multi-source evidence |
| Exploitation / Post-Exploit | `SWE` | Focuses on code execution, tool sequencing |
| Correlation | `FORCE_ON` | Ensures thorough cross-source analysis |
| Default | `DEFAULT` | Model decides when to think |

```python
from nova_arsenal.prompt_builder import ThinkingProfile, adaptive_thinking_block

# Inject adaptive thinking block into prompt tree
thinking_node = adaptive_thinking_block(
    profile=ThinkingProfile.SWE,
    task="Exploit CVE-2024-XXXX with Metasploit",
)
```

### Nex-N2 XML Tool Format

```python
from nova_arsenal.tool_definitions import tools_to_nexn2_xml_format

xml_tools = tools_to_nexn2_xml_format(tools)
# Generates <tools>...</tools><tool_call><function=name><parameter=key>value</parameter></function></tool_call>
```

### Nex-N2 RL Data Format

```python
from nova_arsenal.data_generation import to_nexn2_rl_row, NEXN2_RL_DATA_FORMAT

row = to_nexn2_rl_row(prompt="Scan 10.0.0.1", ground_truth="open ports: 22,80,443")
# Writes parquet with prompt/ground_truth columns matching NexRL format
```

## Context Compression (`context/`)

Port of **DeepSeek Sparse Attention (DSA)** patterns for compressing long security tool outputs:

```python
from nova_arsenal.context import ContentCompressor

compressor = ContentCompressor()
compressed = compressor.compress(
    content=long_nmap_output,
    query_keywords=["cve", "open port", "vulnerable", "critical"],
)
# Selects top-k most relevant segments (k=2048) with HCA windowing
```

The compressor uses deterministic top-k selection (torch.topk for consistency) and keyword-weighted relevance scoring (CVE IDs, severity levels, port numbers, vulnerability names). Supports three strategies: `DSA` (pure sparse), `HCA` (window + coarse), `CSA` (compressed latent).

## Muon Optimizer (`optimizers/`)

Port of the **DeepSeek V4 Pro** Muon optimizer — Newton-Schulz matrix orthogonalization for 2D weight parameters, with automatic AdamW fallback for 1D/3D+ parameters:

```python
from nova_arsenal.optimizers import MuonAdamW

optimizer = MuonAdamW(
    model.parameters(),
    lr=1e-4,
    weight_decay=0.1,
    ns_iters=5,  # Newton-Schulz iterations
)
# Muon applied to all 2D weight matrices; AdamW applied to biases, norms, embeddings
```

## mHC Architecture Reference (`arch/`)

Reference implementation of **Manifold-Constrained Hyper-Connections** and **Anticipatory Routing** from DeepSeek V4 Pro:

```python
from nova_arsenal.arch import (
    ManifoldConstrainedHyperConnection,  # nhc=4, Sinkhorn-Knopp tmax=20
    AnticipatoryRouter,                   # Route conflict detection + knowledge transfer
    sinkhorn_knopp,                        # Doubly-stochastic normalization
)
mhc = ManifoldConstrainedHyperConnection(hidden_dim=4096, nhc=4)
output = mhc(hidden_states)
```

## Testing Against Targets

Run autonomous penetration tests against authorized targets:

```bash
# Run a comprehensive test
python test_nova.py localhost "Full audit of exposed services" 20

# Test with specific target
python test_nova.py 192.168.1.100 "Identify vulnerabilities" 15

# Quick scan mode
python test_nova.py example.com "Web app security test" 10
```

The test script demonstrates:
- Autonomous agent loop execution
- Tool selection based on task requirements
- Security constraints and scope enforcement
- Real-time findings detection
- **API integration triggers** (if configured)
- **Cross-tool correlation** and confidence scoring
- Report generation

**Note**: Only test against systems you own or have explicit written authorization to test.

## Documentation

- [Getting Started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [API Reference](docs/api-reference.md)
- [Deployment](docs/deployment.md)
- [Integrations](docs/integrations.md)

## Configuration

See [config/settings.example.yaml](config/settings.example.yaml) for all available options.

### LLM Providers

```yaml
llm:
  primary:
    provider: "openrouter"
    model: "nexus/nex-n2-pro"        # Free, best for agentic security tasks
  fallbacks:
    - provider: "openai"
      model: "gpt-4o"
    - provider: "anthropic"
      model: "claude-sonnet-4-20250514"
    - provider: "opencode"
      model: "opencode"
  # Nex-N2 adaptive thinking profiles (auto-mapped to agent phases)
  nexn2:
    enable_thinking: true
    thinking_profile: "auto"          # auto|force_on|force_off|search|swe|long_horizon
    system_prompt: "nova_agentic"     # Uses Coherent Thinking paradigm
  # Training (GRPO / agentic RL)
  training:
    backend: "openrouter"
    temperature: 1.0
    max_response_length: 8192
    num_rollout_workers: 256
```

### Authentication

Nova supports multiple authentication methods for the API server:

**Methods (checked in order)**:

| Method | Header/Env | Use Case |
|--------|-----------|----------|
| Subscription API Key | `X-API-Key` | Programmatic access with quota enforcement |
| PAT Token | `X-PAT` or `PAT_TOKEN` env | CLI/CI integrations |
| JWT Token | `Authorization: Bearer <jwt>` | Web dashboard sessions |
| OAuth (GitHub/Google) | Via `/api/auth/oauth/{provider}/login` | Social login with auto-provisioning |

**OAuth flow**: Users sign in via GitHub or Google → system auto-creates account + free subscription (100 API calls/day) → users generate API keys via `POST /api/auth/api-keys` → use `X-API-Key` header for API access with automatic daily quota enforcement.

```yaml
auth:
  jwt_secret: "${JWT_SECRET?must-be-set}"
  access_token_expire_minutes: 15
  refresh_token_expire_days: 7
  oauth:
    github_client_id: "${GITHUB_CLIENT_ID}"
    github_client_secret: "${GITHUB_CLIENT_SECRET}"
    github_redirect_uri: "http://localhost:8000/api/auth/oauth/github/callback"
    google_client_id: "${GOOGLE_CLIENT_ID}"
    google_client_secret: "${GOOGLE_CLIENT_SECRET}"
    default_tier: "free"        # free | pro | enterprise
    free_api_calls_per_day: 100
    pro_api_calls_per_day: 10000
    enterprise_api_calls_per_day: 100000
```

**API Endpoints**:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/auth/oauth/{provider}/login` | Redirect to OAuth provider |
| GET | `/api/auth/oauth/{provider}/callback` | OAuth callback (returns JWT) |
| GET | `/api/auth/oauth/accounts` | List linked social accounts |
| DELETE | `/api/auth/oauth/{provider}` | Unlink social account |
| GET | `/api/auth/subscription` | Current tier and usage |
| POST | `/api/auth/subscription/upgrade` | Change tier (pro/enterprise) |
| POST | `/api/auth/api-keys` | Generate new API key |
| GET | `/api/auth/api-keys` | List active API keys |
| DELETE | `/api/auth/api-keys/{key_id}` | Revoke API key |
| GET | `/api/auth/api-keys/usage` | Key statistics |

```python
# Example: Authenticate with subscription API key
import httpx

resp = httpx.post(
    "http://localhost:8000/api/auth/login",
    json={"email": "user@example.com", "password": "..."},
)
jwt = resp.json()["access_token"]

# Generate API key
key_resp = httpx.post(
    "http://localhost:8000/api/auth/api-keys",
    json={"name": "ci-key"},
    headers={"Authorization": f"Bearer {jwt}"},
)
api_key = key_resp.json()["full_key"]  # na_<64 hex chars>

# Use API key for any protected endpoint
scan = httpx.post(
    "http://localhost:8000/api/agents",
    params={"target": "scanme.nmap.org"},
    headers={"X-API-Key": api_key},
)
```

### API Integrations

```yaml
integrations:
  metasploit:
    enabled: true
    host: "https://127.0.0.1:55553"
    password: "${MSF_PASSWORD}"
  burp:
    enabled: true
    url: "http://127.0.0.1:1337"
    api_key: "${BURP_API_KEY}"
  sqlmap:
    enabled: true
    url: "http://127.0.0.1:8775"
```

## Security & Responsible Use

Nova-Arsenal is a professional security research tool. You are solely responsible for ensuring you have proper authorization before running any scans or tests. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

See [SECURITY.md](SECURITY.md) for vulnerability reporting policy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

Apache-2.0 — See [LICENSE](LICENSE) for details.
