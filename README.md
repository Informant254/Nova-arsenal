<div align="center">

# Nova Arsenal

**AI-assisted security research workspace built around a Nova Python agent and a local OWASP Juice Shop lab.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Node](https://img.shields.io/badge/Node.js-22--25-339933?logo=node.js)](https://nodejs.org)
[![Ollama](https://img.shields.io/badge/LLM-Ollama-orange)](https://ollama.com)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](Dockerfile)
[![License](https://img.shields.io/github/license/Informant254/Nova-arsenal)](LICENSE)

</div>

---

## Overview

Nova Arsenal combines two related surfaces:

| Surface | Main entry points | Purpose |
|---|---|---|
| **Nova security agent** | `nova.py`, `nova_agent_core.py`, `nova_tool_kit.py`, `nova_install.sh` | Natural-language security research, code review, recon, vulnerability verification, reporting, and learning workflows. |
| **Local vulnerable lab app** | `app.ts`, `server.ts`, `frontend/`, `routes/`, `Dockerfile`, `package.json` | A Node/TypeScript OWASP Juice Shop style target that can be run locally and used as a legal test bed for Nova. |

The repository also contains many supporting Nova modules, prior run outputs, JSON reports, challenge data, CI workflows, and testing assets. Use the agent only against systems where you have explicit authorization.

---

## Architecture

```mermaid
flowchart TB
    User["Operator"] --> CLI["nova.py\nNatural-language dispatcher"]

    CLI --> Intent["Intent parser\nLLM first, keyword fallback"]
    Intent --> Dispatch["Dispatch table"]

    Dispatch --> Agent["nova_agent_core.py\nReAct hunt loop"]
    Dispatch --> Static["Static/code analysis modules"]
    Dispatch --> Active["Active web testing modules"]
    Dispatch --> Reports["Reporting and tracking modules"]

    Agent --> Planner["nova_planner.py\nPre-hunt plan"]
    Agent --> Context["nova_context_manager.py\nRolling context"]
    Agent --> Tools["nova_tool_kit.py / nova_toolbox.py\nHTTP, browser, recon, CVE, validation tools"]
    Agent --> Verify["nova_verify_engine.py\nEvidence checks"]

    Static --> SourceAudit["nova_source_auditor.py"]
    Static --> SCA["nova_sca_scanner.py"]
    Static --> GitScan["nova_git_scanner.py"]
    Static --> CICD["nova_cicd_scanner.py"]
    Static --> Container["nova_container_scanner.py"]

    Active --> Recon["nova_recon.py"]
    Active --> Attack["nova_attack.py / nova_unified_attack.py"]
    Active --> Browser["nova_vision.py / Playwright"]
    Active --> Specialist["IDOR, GraphQL, CSRF, JWT, race, LLM injection modules"]

    Reports --> Tracker["nova_vuln_tracker.py\nSQLite-backed findings history"]
    Reports --> AuditReport["nova_audit_reporter.py / nova_report.py\nHTML, Markdown, JSON reports"]
    Reports --> Workspace["~/nova_workspace\nlogs, memory, reports, screenshots"]

    subgraph Lab["Local lab application"]
        App["app.ts"] --> Server["server.ts"]
        Server --> Routes["routes/*.ts"]
        Server --> Data["data/ + models/"]
        Server --> Frontend["frontend/"]
        Docker["Dockerfile"] --> App
    end

    Tools --> Lab
    Browser --> Lab
```

---

## Runtime Flow

```mermaid
sequenceDiagram
    autonumber
    participant Operator
    participant Nova as nova.py
    participant LLM as Ollama
    participant Agent as NovaAgent
    participant Tools as Tool modules
    participant Target as Authorized target or local lab
    participant Store as Workspace/report store

    Operator->>Nova: python3 nova.py "Scan http://localhost:3000 for SQL injection"
    Nova->>LLM: Classify intent
    LLM-->>Nova: mode and task context
    Nova->>Agent: Dispatch selected workflow
    Agent->>Tools: Plan, recon, probe, validate
    Tools->>Target: Authorized requests and browser actions
    Target-->>Tools: Responses, screenshots, evidence
    Tools-->>Agent: Observations and findings
    Agent->>Store: Save findings, logs, memory, reports
    Store-->>Operator: JSON/Markdown/HTML output paths
```

---

## Repository Map

```mermaid
graph LR
    Root["Repository root"] --> NovaPy["Nova Python modules\nnova*.py"]
    Root --> WebApp["Node/TypeScript app\napp.ts, server.ts, routes/, models/, data/"]
    Root --> UI["Frontend\nfrontend/"]
    Root --> Tests["Tests\ntest/api, test/server, Cypress"]
    Root --> Config["Config\nconfig/, nova_config.json, tsconfig.json"]
    Root --> Automation["Automation\n.github/workflows, Dockerfile, scripts"]
    Root --> Reports["Generated outputs\nrun reports, findings JSON, screenshots"]
```

Important files:

| Path | Role |
|---|---|
| `nova.py` | Single-command Nova dispatcher. Parses intent and routes to specialist modules. |
| `nova_agent_core.py` | Autonomous ReAct-style loop with planning, context management, CVE research, visual recon, and verification hooks. |
| `nova_tool_kit.py`, `nova_toolbox.py` | Tool execution layer for HTTP probing, browser work, recon, research, validation, and file operations. |
| `nova_install.sh` | One-shot Nova environment installer. |
| `requirements.txt` | Python dependencies for Nova and optional security tooling. |
| `nova_config.json` | Default Nova workspace, LLM, recon, attack, reporting, and rate-limit settings. |
| `app.ts`, `server.ts` | Node/TypeScript lab application entry points. |
| `frontend/`, `routes/`, `models/`, `data/` | Web UI, API routes, persistence models, and challenge/lab data. |
| `package.json` | Node scripts for building, serving, testing, and packaging the lab app. |
| `Dockerfile` | Container build for the lab application. |

---

## Installation Decision Tree

```mermaid
flowchart TD
    Start["Choose what you want to run"] --> AgentOnly{"Run Nova agent?"}
    Start --> LabOnly{"Run local lab app?"}

    AgentOnly -->|Yes| PyReq["Install Python 3.10+"]
    PyReq --> Venv["Create virtual environment"]
    Venv --> Pip["pip install -r requirements.txt"]
    Pip --> Ollama["Install Ollama and pull model"]
    Ollama --> AgentReady["Run nova.py"]

    LabOnly -->|Yes| NodeReq["Install Node.js 22-25"]
    NodeReq --> NpmInstall["npm install"]
    NpmInstall --> Build["npm run build"]
    Build --> Serve["npm run serve or npm start"]
    Serve --> LabReady["Open http://localhost:3000"]

    LabOnly -->|Docker path| DockerBuild["docker build -t nova-arsenal-lab ."]
    DockerBuild --> DockerRun["docker run -p 3000:3000 nova-arsenal-lab"]
    DockerRun --> LabReady

    AgentReady --> Combined["Point Nova at the lab or another authorized target"]
    LabReady --> Combined
```

---

## Prerequisites

| Requirement | Version | Needed for |
|---|---:|---|
| Python | 3.10+ | Nova agent modules and installer. |
| Node.js | 22-25 | TypeScript/Node lab app from `package.json`. |
| npm | Bundled with Node | Installing and running the lab app. |
| Docker | Current stable | Optional container run for the lab app. |
| Ollama | Current stable | Local LLM used by Nova. |
| Playwright Chromium | Current stable | Browser-based recon and visual analysis. |
| Go | 1.21+ | Optional external tools such as `nuclei`, `subfinder`, `httpx`, and `ffuf`. |

Optional security tools such as `nmap`, `nuclei`, `sqlmap`, `ffuf`, `subfinder`, `httpx`, `amass`, `trivy`, `semgrep`, and `bandit` expand Nova's coverage. Nova can still run with a smaller toolset, but results will be narrower.

---

## Install Nova Agent

### Option A: One-shot installer

```bash
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
chmod +x nova_install.sh
./nova_install.sh
```

The installer checks Python, installs `requirements.txt`, verifies optional tools, installs or starts Ollama, pulls the configured model, creates `~/nova_workspace`, writes `.env`, and syntax-checks core Nova modules.

### Option B: Manual setup

```bash
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

python3 -m venv ~/nova_workspace/.venv
source ~/nova_workspace/.venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
playwright install chromium
```

Install and start Ollama:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve
```

In a second terminal, pull a model:

```bash
ollama pull qwen3:8b
```

Create the workspace folders if you skipped the installer:

```bash
mkdir -p ~/nova_workspace/{bin,wordlists,reports,logs,screenshots,backups,tools,memory}
cp nova_config.json ~/nova_workspace/nova_config.json
```

Create `.env` in the repository root:

```env
NOVA_LLM_URL=http://localhost:11434
NOVA_LLM_MODEL=qwen3:8b
NOVA_WORKSPACE=~/nova_workspace
NOVA_MAX_STEPS=40
NOVA_TARGET=http://localhost:3000
```

---

## Install And Run The Local Lab App

### Native Node.js

```bash
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
npm install
npm run build
npm run serve
```

Open `http://localhost:3000`.

Useful scripts from `package.json`:

| Command | Purpose |
|---|---|
| `npm run serve` | Run TypeScript server and frontend dev server together. |
| `npm run serve:dev` | Watch-mode development run. |
| `npm run build` | Build frontend and server output. |
| `npm start` | Run built server from `build/app`. |
| `npm test` | Run frontend, server, and API tests. |
| `npm run test:e2e` | Run Cypress end-to-end tests. |
| `npm run lint` | Lint server, tests, views, and frontend. |

### Docker

```bash
docker build -t nova-arsenal-lab .
docker run --rm -p 3000:3000 nova-arsenal-lab
```

Open `http://localhost:3000`.

---

## Usage

### Verify Nova basics

```bash
source ~/nova_workspace/.venv/bin/activate
python3 nova.py "Run a health check"
```

### Scan the local lab

Start the lab first:

```bash
npm run serve
```

Then run Nova from another terminal:

```bash
source ~/nova_workspace/.venv/bin/activate
python3 nova.py "Scan http://localhost:3000 for SQL injection and XSS"
python3 nova.py "Build a threat model for ."
python3 nova.py "Scan git history for leaked secrets"
python3 nova.py "Run container security checks for this Dockerfile"
```

### Scan an authorized external target

```bash
source ~/nova_workspace/.venv/bin/activate
python3 nova.py "Run recon against https://example.com"
python3 nova.py "Check JWT, IDOR, GraphQL, and access control on https://example.com"
python3 nova.py "Create an audit report for https://example.com"
```

Only use external examples after replacing the target with a system you own or have explicit written permission to test.

---

## Configuration

Nova reads defaults from environment variables and `nova_config.json`.

| Setting | Default | Meaning |
|---|---|---|
| `NOVA_LLM_URL` | `http://localhost:11434` | Ollama API endpoint. |
| `NOVA_LLM_MODEL` | `qwen3:8b` / `auto` in config | Model used for intent and reasoning. |
| `NOVA_WORKSPACE` | `~/nova_workspace` | Reports, logs, memory, screenshots, backups, and tool cache. |
| `NOVA_MAX_STEPS` | `40` | Agent step cap for a run. |
| `NOVA_TARGET` | `http://localhost:3000` | Fallback target if a prompt does not include one. |

Example override:

```bash
NOVA_LLM_MODEL=llama3.2 NOVA_MAX_STEPS=20 python3 nova.py "Quick scan of http://localhost:3000"
```

Key `nova_config.json` sections:

| Section | Controls |
|---|---|
| `llm` | Ollama URL, model, fallback model, timeout, streaming. |
| `recon` | Subdomain, probe, URL collection tools, result limits, thread count. |
| `attack` | Enabled vulnerability classes, payload limits, redirect behavior, robots handling. |
| `tools` | On-demand tool installation and parallel installs. |
| `notifications` | Start, critical, completion, and evolution notifications. |
| `evolution` | Self-improvement toggle, test requirement, backups, forbidden files. |
| `reporting` | Output formats and report commit behavior. |
| `rate_limiting` | Request rate, host delay, and concurrency. |

---

## Output Locations

```mermaid
flowchart LR
    Run["Nova run"] --> Logs["~/nova_workspace/logs"]
    Run --> Reports["~/nova_workspace/reports"]
    Run --> Screens["~/nova_workspace/screenshots"]
    Run --> Memory["~/nova_workspace/memory"]
    Run --> JSON["nova_*_report.json files"]
    Reports --> HTML["HTML reports"]
    Reports --> MD["Markdown reports"]
    Reports --> Machine["JSON findings"]
```

Typical report content includes verified finding title, affected target, severity, CVSS context where available, evidence, reproduction steps, impact, and remediation guidance.

---

## Testing And Quality Checks

For Nova Python files:

```bash
python3 -m py_compile nova.py nova_agent_core.py nova_tool_kit.py nova_vuln_tracker.py
```

For the Node/TypeScript lab:

```bash
npm run lint
npm test
npm run test:e2e
```

For Docker:

```bash
docker build -t nova-arsenal-lab .
docker run --rm -p 3000:3000 nova-arsenal-lab
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ollama` is not reachable | Run `ollama serve`, then verify with `curl http://localhost:11434/api/tags`. |
| Model not found | Run `ollama list` and `ollama pull qwen3:8b` or set `NOVA_LLM_MODEL` to an installed model. |
| Playwright browser missing | Run `playwright install chromium` inside the Nova virtual environment. |
| Python dependency conflicts | Use a clean virtual environment under `~/nova_workspace/.venv`. |
| Node install fails | Confirm Node.js is version 22-25, then retry `npm install`. |
| Lab app does not open | Check that port `3000` is free and rerun `npm run serve` or Docker with `-p 3000:3000`. |
| External tool missing | Install the tool shown in Nova's warning, then make sure it is on `PATH`. |

---

## Repository Hygiene Notes

This repository currently includes generated outputs, screenshots, run reports, virtual-environment folders, and large lab assets. That can make clones slow. For a cleaner production fork, consider moving generated findings and virtual environments outside the Git repository and keeping only source, config templates, tests, and docs under version control.

---

## Legal And Safety Notice

Nova Arsenal is for authorized security testing, education, and local lab work. Do not scan or exploit systems without explicit permission. Keep request rates reasonable, preserve evidence responsibly, and follow the rules of any bug bounty or assessment scope you operate under.

---

## License

This repository is published under the [MIT License](LICENSE).
