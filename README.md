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

1. [Architecture](#architecture)
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

## Architecture

Nova is a **layered pipeline**. Every run shares the same provider layer before dispatching to specialist modules.

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                       NOVA ARSENAL v4.2 — ARCHITECTURE                          ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  ┌────────────────────────────────────────────────────────────────────────────┐ ║
║  │                             ENTRY POINTS                                   │ ║
║  │  nova.py  (natural-language dispatch)                                      │ ║
║  │  nova_cli.py  (interactive REPL + tab-completion + live finding counts)    │ ║
║  │  nova_bootstrap.py  (health check · module verify · capability summary)    │ ║
║  └─────────────────────────────┬──────────────────────────────────────────────┘ ║
║                                │                                                 ║
║                                ▼                                                 ║
║  ┌────────────────────────────────────────────────────────────────────────────┐ ║
║  │                    PROVIDER LAYER  (shared by every module)                │ ║
║  │                                                                            │ ║
║  │  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐   │ ║
║  │  │  LLM Router  │  │  Hook Bus   │  │Session Store │  │   Tracer     │   │ ║
║  │  │  OpenAI  ──► │  │  lifecycle  │  │  SQLite +    │  │  spans →     │   │ ║
║  │  │  Anthropic►  │  │  events     │  │  resume +    │  │  HTML flame  │   │ ║
║  │  │  Gemini  ──► │  │  Telegram   │  │  history     │  │  graph       │   │ ║
║  │  │  Ollama      │  │  email      │  │              │  │              │   │ ║
║  │  └──────────────┘  └─────────────┘  └──────────────┘  └──────────────┘   │ ║
║  │                                                                            │ ║
║  │  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐   │ ║
║  │  │  Nova Brain  │  │ Findings DB │  │ RAG Builder  │  │ Error Handler│   │ ║
║  │  │  cross-sess  │  │  SQLite     │  │  knowledge   │  │  structured  │   │ ║
║  │  │  memory      │  │  persistent │  │  retrieval   │  │  error class │   │ ║
║  │  └──────────────┘  └─────────────┘  └──────────────┘  └──────────────┘   │ ║
║  │                                                                            │ ║
║  │  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐   │ ║
║  │  │Context Engine│  │ LLM Bridge  │  │Output Parser │  │ Retry Policy │   │ ║
║  │  │  dynamic ctx │  │  HTTP LLM   │  │ nmap / nikto │  │  exp backoff │   │ ║
║  │  └──────────────┘  └─────────────┘  └──────────────┘  └──────────────┘   │ ║
║  └─────────────────────────────┬──────────────────────────────────────────────┘ ║
║                                │                                                 ║
║                                ▼                                                 ║
║  ┌────────────────────────────────────────────────────────────────────────────┐ ║
║  │               PHASE 0 — CODEBASE MAPPER  (auto-runs before every scan)    │ ║
║  │                                                                            │ ║
║  │  nova_codebase_mapper ─────────────────────────────────────────────────   │ ║
║  │    • Languages & frameworks detected from source                           │ ║
║  │    • Every route / API endpoint extracted from code                        │ ║
║  │    • Auth patterns, DB connections, data models catalogued                │ ║
║  │    • Secrets & CVE-affected deps pre-detected                              │ ║
║  │    • AI-ranked attack-priority order generated                             │ ║
║  │    • Map injected into ALL downstream phases                               │ ║
║  └─────────────────────────────┬──────────────────────────────────────────────┘ ║
║                                │                                                 ║
║                                ▼                                                 ║
║  ┌────────────────────────────────────────────────────────────────────────────┐ ║
║  │                       DISPATCH — 54 MODES                                  │ ║
║  │                                                                            │ ║
║  │  ┌───────────────────┐  ┌───────────────────┐  ┌──────────────────────┐   │ ║
║  │  │  STATIC ANALYSIS  │  │  ACTIVE TESTING   │  │    INTELLIGENCE      │   │ ║
║  │  │  sast  dataflow   │  │  hunt  auth  idor  │  │  daybreak            │   │ ║
║  │  │  sca  supply_ch   │  │  sqli  xss  ssrf   │  │  threat_model        │   │ ║
║  │  │  git_scan  cicd   │  │  csrf  graphql jwt │  │  zero_day            │   │ ║
║  │  │  container  pypi  │  │  race  fuzz        │  │  hypothesis_engine   │   │ ║
║  │  │  ecosystem  recon │  │  business_logic    │  │  chain_of_thought    │   │ ║
║  │  │  github_scan  map │  │  llm_injection     │  │  vuln_synthesis      │   │ ║
║  │  │                   │  │  browser           │  │  patch  detect       │   │ ║
║  │  └───────────────────┘  └───────────────────┘  └──────────────────────┘   │ ║
║  │                                                                            │ ║
║  │  ┌───────────────────┐  ┌───────────────────┐  ┌──────────────────────┐   │ ║
║  │  │  ORCHESTRATION    │  │    BUG BOUNTY     │  │ REPORTING & SYSTEM   │   │ ║
║  │  │  orchestrate      │  │  wild_hunt  ibb   │  │  triage              │   │ ║
║  │  │  swarm(v2+v3+par) │  │  0din  attack     │  │  audit_report        │   │ ║
║  │  │  multi_target     │  │  kali  full_stack  │  │  report  vuln_track  │   │ ║
║  │  │  pipeline  nextgen│  │                   │  │  sandbox  bootstrap  │   │ ║
║  │  └───────────────────┘  └───────────────────┘  └──────────────────────┘   │ ║
║  └─────────────────────────────┬──────────────────────────────────────────────┘ ║
║                                │                                                 ║
║                                ▼                                                 ║
║  ┌────────────────────────────────────────────────────────────────────────────┐ ║
║  │                          OUTPUT LAYER                                      │ ║
║  │  ~/nova_workspace/                                                         │ ║
║  │    nova_<mode>_<ts>.json        structured findings (every run)            │ ║
║  │    nova_report_<mode>.html      HTML report with CVSS scores               │ ║
║  │    nova_report_<mode>.md        Markdown report                            │ ║
║  │    nova_trace_<ts>.html         interactive execution flame graph          │ ║
║  │    nova_triage_report.json      H1-ranked triage output                    │ ║
║  │    nova_vulns.db                SQLite vulnerability tracker                │ ║
║  │    nova_findings.db             persistent findings database                │ ║
║  │    nova_bootstrap_status.json   last health-check result                   │ ║
║  └────────────────────────────────────────────────────────────────────────────┘ ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

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
# Verify all 75 modules load
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
