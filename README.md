<div align="center">

```
  ███╗   ██╗ ██████╗ ██╗   ██╗  █████╗
  ████╗  ██║██╔═══██╗██║   ██║ ██╔══██╗
  ██╔██╗ ██║██║   ██║██║   ██║ ███████║
  ██║╚██╗██║██║   ██║╚██╗ ██╔╝ ██╔══██║
  ██║ ╚████║╚██████╔╝ ╚████╔╝  ██║  ██║
  ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝   ╚═╝  ╚═╝  ARSENAL v4.0
```

**Autonomous AI-powered bug bounty hunting agent.**  
Give Nova one command. She handles everything.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/github/license/Informant254/Nova-arsenal)](LICENSE)
[![GitHub Actions](https://img.shields.io/badge/Cloud-GitHub%20Actions-black?logo=github)](https://github.com/features/actions)
[![Ollama](https://img.shields.io/badge/LLM-Ollama%20(local)-orange)](https://ollama.com)

</div>

---

## What Nova Does

Nova is a fully autonomous security research agent. Point her at an authorized target and she:

- Plans and executes a complete bug bounty hunt from a single plain-English command
- Selects the right tools from a 1,000+ tool arsenal per mission phase
- Reasons with a **local Ollama LLM** — no paid API required
- Operates a **real headless Playwright browser** for JavaScript-heavy targets
- **Chains vulnerabilities** together (SSRF → metadata, SQLi → RCE, JWT → privilege escalation)
- **Learns from every hunt** — persistent memory across runs
- **Self-evolves** — safely rewrites her own modules to improve over time
- Sends **real-time alerts** to Telegram / Discord / Slack
- Runs **24/7 on GitHub Actions** (free Ubuntu cloud environment)

---

## Architecture

```
nova.py                     ← Entry point — natural-language dispatcher (v4.0)
├── nova_reasoning_core.py  ← LLM reasoning engine (Ollama, streaming, self-correction)
├── nova_recon.py           ← Recon pipeline (subdomains, URLs, JS, ports, cloud assets)
├── nova_attack.py          ← Attack chain orchestrator (SSRF, SQLi, XSS, JWT, SSTI…)
├── nova_toolbox.py         ← 1,000+ tools — auto-selects per mission, auto-installs
├── nova_browser_agent.py   ← Real Playwright headless browser
├── nova_memory_system.py   ← Persistent learning (brain across all hunts)
├── nova_evolution.py       ← Safe self-modification engine
├── nova_continuous.py      ← 24/7 hunting loop + NovaBrain learning
├── nova_report.py          ← Professional HTML / MD / JSON report generator
├── nova_vuln_tracker.py    ← SQLite vulnerability tracker across runs
├── nova_orchestrator.py    ← Swarm coordinator for parallel module execution
└── nova_cloud.py           ← Cloud hunt trigger / monitor CLI
```

The `nova.py` orchestrator accepts plain-English commands, parses intent, and routes work to specialist modules. All modules share a common findings schema and feed into `nova_vuln_tracker`.

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | 3.12 recommended |
| Git | any | For cloning and evolution commits |
| Go | 1.21+ | For `nuclei`, `subfinder`, `httpx`, `ffuf` |
| Ollama | latest | Installed automatically by `nova_install.sh` |
| curl / bash | any | Required for install scripts |

> **Optional but recommended:** `nmap`, `nuclei`, `sqlmap`, `ffuf`, `subfinder`, `httpx`, `amass`, `trivy` — Nova will warn you which are missing and print exact install commands.

---

## Installation

### Option A — Full One-Shot Installer (recommended)

The `nova_install.sh` script handles everything: Python deps, Ollama, LLM model pull, tool verification, workspace setup, and a self-test.

```bash
# 1. Clone the repository
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

# 2. Run the installer
chmod +x nova_install.sh
./nova_install.sh
```

The installer will:
1. Verify Python 3.10+ is available
2. Install all Python packages from `requirements.txt`
3. Install and start Ollama
4. Pull the default LLM model (`qwen3:8b` — ~5 GB, one-time download)
5. Create `~/nova_workspace/` with all required subdirectories
6. Generate a `.env` config file with sensible defaults
7. Syntax-check all Nova modules
8. Run a bootstrap health check

---

### Option B — Manual Setup (step by step)

Use this if you want more control or are setting up on a restricted system.

#### Step 1 — Clone

```bash
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
```

#### Step 2 — Python virtual environment

```bash
python3 -m venv ~/nova_workspace/.venv
source ~/nova_workspace/.venv/bin/activate
```

#### Step 3 — Install Python dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> **Heavy packages** (angr, volatility3, eth-brownie) are optional. Install them only if you need binary exploitation, malware analysis, or smart contract auditing:
> ```bash
> pip install angr volatility3 eth-brownie
> ```

#### Step 4 — Install Playwright browser

```bash
playwright install chromium
```

#### Step 5 — Install Ollama

```bash
# Linux / macOS
curl -fsSL https://ollama.com/install.sh | sh

# macOS with Homebrew
brew install ollama
```

#### Step 6 — Pull the LLM model

```bash
ollama serve &          # start Ollama in background
ollama pull qwen3:8b    # default model (~5 GB)

# Lighter alternative if disk space is limited:
ollama pull llama3.2    # ~2 GB
```

#### Step 7 — Create workspace

```bash
mkdir -p ~/nova_workspace/{bin,wordlists,reports,logs,screenshots,backups,tools,memory}
```

#### Step 8 — Configure environment

Copy and edit the config:

```bash
cp nova_config.json ~/nova_workspace/nova_config.json
```

Create `.env` in the repo root:

```env
NOVA_LLM_URL=http://localhost:11434
NOVA_LLM_MODEL=qwen3:8b
NOVA_WORKSPACE=~/nova_workspace
NOVA_MAX_STEPS=40
NOVA_TARGET=http://localhost:3000
```

---

## Configuration

All settings live in `nova_config.json` (or `~/nova_workspace/nova_config.json`). Key sections:

| Section | Key settings |
|---|---|
| `llm` | `url`, `model`, `fallback_model`, `timeout` |
| `recon` | `subdomain_tools`, `max_subdomains`, `max_urls`, `threads` |
| `attack` | `enabled_chains`, `severity_threshold`, `max_payloads_per_param` |
| `tools` | `install_on_demand`, `tier1_on_start`, `parallel_installs` |
| `evolution` | `enabled`, `require_tests`, `forbidden_files` |
| `reporting` | `formats`, `auto_generate`, `commit_to_repo` |
| `rate_limiting` | `requests_per_second`, `delay_between_hosts` |

### Override with environment variables

Any config value can be overridden at runtime:

```bash
NOVA_LLM_MODEL=llama3.2 NOVA_MAX_STEPS=20 python3 nova.py "Quick scan of target.com"
```

---

## Usage

### Activate the virtual environment first

```bash
source ~/nova_workspace/.venv/bin/activate
```

### Local hunt — plain English commands

```bash
# Full autonomous hunt
python3 nova.py "Hunt https://target.com for all vulnerabilities" --autonomous

# Targeted attack types
python3 nova.py "Run full-stack Mythos+Daybreak pipeline on https://target.com"
python3 nova.py "Scan for SQL injection and XSS on https://target.com/api"
python3 nova.py "Check JWT implementation on https://target.com"
python3 nova.py "Scan git history for leaked secrets"
python3 nova.py "Build a threat model for ./my-app"
python3 nova.py "Run SSRF chain scan on https://target.com"
```

### Add your targets

Edit `targets.txt` — one URL per line:

```
# Authorized targets
https://target.com
https://api.target.com

# Practice targets (intentionally vulnerable — safe to scan)
http://testphp.vulnweb.com
http://juice-shop.example.com
```

### Cloud hunt (GitHub Actions)

Nova can run 24/7 on GitHub's free cloud Linux environment. Set your `GITHUB_TOKEN` as a repo secret, then use the CLI from anywhere:

```bash
export GITHUB_TOKEN=your_token

python3 nova_cloud.py hunt https://target.com           # start a hunt
python3 nova_cloud.py hunt https://target.com --evolve  # hunt + self-evolve after
python3 nova_cloud.py watch 12345678                    # tail a live run by workflow ID
python3 nova_cloud.py results                           # fetch latest findings
python3 nova_cloud.py brain                             # inspect what Nova has learned
```

**GitHub Secrets to set** (repo → Settings → Secrets → Actions):

| Secret | Required | Description |
|---|---|---|
| `GITHUB_TOKEN` | Yes | Automatically available in Actions |
| `TELEGRAM_BOT_TOKEN` | Optional | Create via @BotFather |
| `TELEGRAM_CHAT_ID` | Optional | Your Telegram user or group ID |
| `DISCORD_WEBHOOK_URL` | Optional | Server Settings → Integrations → Webhooks |
| `SLACK_WEBHOOK_URL` | Optional | api.slack.com → Your App → Incoming Webhooks |

---

## Self-Evolution

Nova can rewrite her own modules to improve. The pipeline is safe:

1. LLM proposes a code change
2. Syntax check (`ast.parse`)
3. Import test
4. If all pass → apply. If any fail → automatic rollback.

```bash
python3 nova_evolution.py --file nova_attack.py \
  --goal "Add blind SQLI time-based detection to the attack pipeline"
```

Files listed in `evolution.forbidden_files` (config) are never touched.

---

## Reporting

After every hunt, Nova generates reports in `~/nova_workspace/reports/`:

| File | Format | Use |
|---|---|---|
| `nova_report_<target>_<date>.html` | HTML | Full visual report |
| `nova_report_<target>_<date>.md` | Markdown | HackerOne-ready submission |
| `nova_report_<target>_<date>.json` | JSON | Machine-readable / pipeline input |

Each finding includes:
- **CVSS score** with vector string
- **Reproduction steps** (curl / browser steps)
- **Impact analysis**
- **Remediation advice**

---

## Tool Arsenal

### Tier 1 — Elite AI-Agent Weapons

| Category | Tools |
|---|---|
| Kernel fuzzing | syzkaller, AFL++, honggfuzz, libFuzzer, LibAFL |
| Symbolic execution | angr, Manticore, Triton, KLEE, Z3 |
| Static analysis | CodeQL, Joern, Semgrep, Infer, Bandit |
| Binary exploitation | pwntools, ropper, ROPgadget, pwndbg |
| Binary analysis | Ghidra, radare2, Frida, Capstone, Unicorn |
| Smart contracts | Slither, Mythril, Echidna, Foundry |
| Web attacks | HTTP smuggling, SSRF chains, CORS bypass, SSTI→RCE |
| Secrets | TruffleHog, GitLeaks, detect-secrets |
| Cloud | Pacu, CloudSploit, Prowler, Trivy, ScoutSuite |

### Tier 2 — Extended Arsenal
200+ tools covering full web, network, post-exploitation, Windows/AD, C2, password cracking, and OSINT.

### Tier 3 — Specialist Tools
300+ tools for hardware/IoT, wireless, Bluetooth, SDR, ICS/SCADA, blockchain/Web3, malware analysis, forensics, mobile, AI/ML attacks, cryptographic attacks, and supply chain security.

---

## Troubleshooting

**Ollama not responding**
```bash
ollama serve &                     # start the Ollama server
curl http://localhost:11434/api/tags  # verify it's running
```

**Model not found**
```bash
ollama list                        # see what's pulled
ollama pull qwen3:8b               # re-pull the default model
```

**Python package conflicts**
```bash
# Always use the virtual environment
source ~/nova_workspace/.venv/bin/activate
pip install -r requirements.txt --upgrade
```

**Missing tool warnings**
Nova prints exact install commands when it detects a missing tool. For Go-based tools:
```bash
# Ensure Go is installed and ~/go/bin is in your PATH
export PATH=$PATH:$(go env GOPATH)/bin
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest
```

**Module syntax error after evolution**
```bash
# Restore from backup
ls ~/nova_workspace/backups/
cp ~/nova_workspace/backups/<module>.bak nova_<module>.py
```

---

## Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12, Go 1.21+, Node.js, Ruby, Rust |
| LLM | Ollama (local — zero API cost) |
| Browser | Playwright (headless Chromium) |
| Cloud | GitHub Actions (Ubuntu, free tier) |
| Database | SQLite (vulnerability tracker) |
| Tools | 1,000+ security tools across all categories |

---

## Legal Notice

Nova Arsenal is built for **authorised security testing only.**

The default `targets.txt` contains intentionally vulnerable practice targets.  
**Never hunt targets without explicit written permission.**  
You are solely responsible for all use of this tool.  
The author assumes no liability for misuse.

---

<div align="center">

Made with precision by [@Informant254](https://github.com/Informant254)

</div>
