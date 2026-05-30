# 🦅 Nova Arsenal

> **Autonomous AI-powered bug bounty hunting agent.**  
> Give Nova one command. She handles everything.

---

## What Nova Does

Nova is a fully autonomous security research agent that:
- Plans and executes complete bug bounty hunts from a single command
- Uses 1,000+ security tools, selecting the right ones per mission
- Thinks with a local Ollama LLM (no paid API required)
- Runs a real headless browser (Playwright) for JS-heavy targets
- Chains vulnerabilities together (SSRF → metadata, SQLi → RCE, etc.)
- Learns from every hunt — remembers what works, what doesn't
- Evolves her own code to improve over time
- Sends real-time findings to Telegram/Discord/Slack
- Runs 24/7 on GitHub's cloud Linux environment (free)

---

## Quick Start

### 1. One-time setup (local)
```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
chmod +x nova_setup.sh && ./nova_setup.sh
```

### 2. Hunt (local)
```bash
source ~/nova_workspace/.venv/bin/activate
python nova_autonomous.py --target https://target.com --verbose
```

### 3. Hunt (cloud — GitHub Actions)
```bash
# From anywhere, using just Python + your GitHub token
export GITHUB_TOKEN=your_token
python nova_cloud.py hunt https://target.com
python nova_cloud.py hunt https://target.com --evolve  # evolve after hunt
python nova_cloud.py watch 12345678                     # watch live
python nova_cloud.py results                            # get findings
python nova_cloud.py brain                              # see what she learned
```

---

## Architecture

```
nova_autonomous.py          ← Main orchestrator (one command → full hunt)
├── nova_reasoning_core.py  ← LLM reasoning engine (Ollama, streaming, self-correction)
├── nova_recon.py           ← Recon pipeline (subdomains, URLs, JS, ports, cloud)
├── nova_attack.py          ← Attack chain orchestrator (SSRF, SQLi, XSS, JWT, SSTI...)
├── nova_toolbox.py         ← 1,000+ tools, auto-selects per mission, auto-installs
├── nova_browser.py         ← Real Playwright headless browser
├── nova_shell.py           ← Nova's own Linux environment
├── nova_memory_system.py   ← Persistent learning (brain across all hunts)
├── nova_evolution.py       ← Safe self-modification engine
├── nova_continuous.py      ← 24/7 hunting loop + NovaBrain learning
├── nova_report.py          ← Professional HTML/MD/JSON report generator
├── nova_notify.py          ← Real-time Telegram/Discord/Slack alerts
└── nova_cloud.py           ← Cloud hunt trigger/monitor CLI
```

---

## Tool Arsenal — 1,000+ Tools in 3 Tiers

### Tier 1 — Elite AI-Agent Weapons (Top 100)
What state-of-the-art AI security agents use to find vulnerabilities nobody else finds:

| Category | Tools |
|---|---|
| Kernel fuzzing | syzkaller, AFL++, honggfuzz, libFuzzer, LibAFL, radamsa |
| Symbolic execution | angr, Manticore, Triton, KLEE, Z3 |
| Static analysis | CodeQL, Joern, Semgrep, Infer, flawfinder |
| Binary exploitation | pwntools, ropper, ROPgadget, one_gadget, pwndbg, GEF |
| Binary analysis | Ghidra, radare2, Frida, Capstone, Unicorn, Qiling, PIN |
| Smart contracts | Slither, Mythril, Echidna, Foundry, Manticore |
| Novel web attacks | HTTP smuggling, SSRF chains, CORS bypass, SSTI→RCE |
| Secrets | TruffleHog, GitLeaks |
| Cloud | Pacu, CloudSploit, Prowler, Trivy, kubeaudit |

### Tier 2 — Extended Arsenal
200+ tools: full web, network, post-exploitation, Windows/AD, C2, password cracking, OSINT

### Tier 3 — Specialist Tools
300+ tools: hardware/IoT, wireless, Bluetooth, SDR, ICS/SCADA, blockchain/Web3,  
malware analysis, forensics, mobile, AI/ML attacks, cryptographic attacks, supply chain

---

## Cloud Environment Setup

Nova runs on GitHub Actions — full Ubuntu Linux, every tool, free.

### Required GitHub Secret
`GITHUB_TOKEN` — already configured if you're running from this repo.

### Optional Notification Secrets
Add these in **repo Settings → Secrets → Actions**:

| Secret | Source |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Create bot via @BotFather |
| `TELEGRAM_CHAT_ID` | Your Telegram user/group ID |
| `DISCORD_WEBHOOK_URL` | Server Settings → Integrations → Webhooks |
| `SLACK_WEBHOOK_URL` | api.slack.com/apps → Incoming Webhooks |

---

## Workflows

| Workflow | Trigger | Purpose |
|---|---|---|
| `nova_hunt.yml` | Manual / every 12h | Single-target hunt |
| `nova_continuous.yml` | Manual / every 6h | All targets in targets.txt |

---

## Adding Targets

Edit `targets.txt` — one URL per line, comments with `#`:
```
# My targets
https://target.com
https://api.target.com
```

---

## Self-Evolution

Nova can modify her own code to improve. Safe evolution pipeline:
1. LLM proposes code change
2. Syntax check (ast.parse)
3. Import test
4. If all pass → apply. If any fail → rollback.

```bash
python nova_evolution.py --file nova_autonomous.py \
  --goal "Add blind SQLI detection to the attack pipeline"
```

---

## Report Format

After every hunt, Nova generates:
- `cloud_reports/nova_report_<target>_<date>.html` — full visual report
- `cloud_reports/nova_report_<target>_<date>.md` — Markdown (HackerOne-ready)
- `cloud_reports/nova_report_<target>_<date>.json` — machine-readable

Each finding includes: CVSS score, reproduction steps, impact, remediation advice.

---

## Legal Notice

Nova is built for **authorised security testing only**.  
The default `targets.txt` contains intentionally vulnerable practice targets.  
Never hunt targets without explicit written permission.  
You are responsible for all use of this tool.

---

## Stack

- Python 3.12, Go 1.21+, Node.js, Ruby, Rust/Cargo
- Ollama (local LLM, no API cost)
- Playwright (real browser)
- GitHub Actions (cloud Linux environment)
- 1,000+ security tools across all categories
