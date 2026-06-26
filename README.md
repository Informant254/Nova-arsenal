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
- **Conversational Chat Assistant (Nova)** — Real-time SSE streaming interface to converse with Nova, lookup tool information, or run security tasks autonomously
- **Interactive Web Dashboard** — Dark-themed chat interface with streaming display, instant tool suggestions, session history, and capability templates
- **Docker-Isolated Execution** — Secure command validation and scope guards to prevent unauthorized system modification or escape
- **SQLite/Postgres Storage** — Multi-user authentication, persistent session history, database-backed logging, and structured reporting

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
┌──────────────────────────────────────────────────────────────────────┐
│                           Nova-Arsenal                               │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────────┐ │
│  │   Web    │   │   Agent  │   │   LLM    │   │  Integration API │ │
│  │Dashboard │──▶│   Core   │──▶│ Provider │   │  Clients:        │ │
│  │ (static) │   │ (Python) │   │ (Multi)  │   │  ┌─────────────┐ │ │
│  └──────────┘   └────┬─────┘   └──────────┘   │  │Metasploit   │ │ │
│                       │                        │  │(msfrpcd)    │ │ │
│                       ▼                        │  ├─────────────┤ │ │
│                ┌──────────┐                    │  │Burp Suite   │ │ │
│                │Intelligence│                  │  │(REST API)   │ │ │
│                │──────────│                    │  ├─────────────┤ │ │
│                │Tool Select│                   │  │SQLmap       │ │ │
│                │Correlator │                   │  │(API mode)   │ │ │
│                └─────┬────┘                    │  ├─────────────┤ │ │
│                      │                         │  │Nmap Parser  │ │ │
│                      ▼                         │  │(XML→struct) │ │ │
│                ┌──────────┐                    │  └─────────────┘ │ │
│                │  Sandbox │                    └──────────────────┘ │
│                │  (Kali)  │                                         │
│                └──────────┘                                         │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
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
    provider: "ollama"
    model: "deepseek-r1"
  fallbacks:
    - provider: "openai"
      model: "gpt-4o"
    - provider: "anthropic"
      model: "claude-sonnet-4-20250514"
    - provider: "opencode"
      model: "opencode"
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
