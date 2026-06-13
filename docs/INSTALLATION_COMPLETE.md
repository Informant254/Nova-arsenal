# 🦅 Nova Arsenal — Post-Installation Capabilities Guide

**After running the setup scripts, here's what you can now do:**

---

## ✅ Quick Start (What Most Users Will Do)

```bash
# Basic vulnerability hunt
python3 nova.py "Hunt http://localhost:3000 for vulnerabilities"

# Full pipeline (map + SAST + SCA + active scans)
python3 nova.py "Full stack pipeline on ./my-app"

# Structured CLI mode
nova hunt http://localhost:3000
nova full ./my-app
nova map ./my-app
nova sast ./my-app
nova sca ./my-app
```

---

## 🎯 Core Capabilities Matrix

| Task | Command | Output | Time | Expert? |
|---|---|---|---|---|
| **Codebase Intelligence** | `python3 nova.py "Map ./my-app"` | `_CMAP.json` (endpoints, auth, tech stack, secrets) | 2-15s | Any |
| **Static Analysis (SAST)** | `nova sast ./my-app` | `findings.json` (code issues, injection points) | 10-60s | Any |
| **Dependency Scan (SCA)** | `nova sca ./my-app` | `vulnerabilities.json` (CVE list + severity) | 5-30s | Any |
| **Git Secret Scanning** | `nova scan secrets ./my-app` | `leaked_secrets.json` (API keys, creds, tokens) | 5-20s | Any |
| **Active Scanning** | `nova hunt http://target.com` | `findings.json` (verified vulns + CVSS score) | 5-30m | Any |
| **Multi-Agent Orchestration** | `nova orch http://target.com` | `recon → attack → report` (full pipeline) | 30m-2h | Intermediate |
| **Threat Modeling** | `nova threat-model ./my-app` | `STRIDE threats + attack vectors` | 5-10s | Advanced |
| **Patch Generation** | `nova generate-patch <finding-id>` | `patch.diff` (AI-generated code fix) | 10-30s | Advanced |
| **Detection Rules** | `nova generate-detection <finding-id>` | `sigma_rules.yml` (SIEM detection logic) | 5-10s | Advanced |
| **Real-Time Monitoring** | `nova-watch ./my-app` | Triggers scans on file changes | Continuous | Any |
| **Cloud Hunting (GitHub)** | `nova-cloud hunt http://target.com` | Full hunt on GitHub Actions runners | 30m-2h | Intermediate |

---

## 🔍 All Scanning Modes

### Built-in Single-Purpose Scanners

```bash
# SQL Injection
nova scan sqli http://target.com

# Cross-Site Scripting (XSS)
nova scan xss http://target.com

# Insecure Direct Object References (IDOR)
nova scan idor http://target.com

# Server-Side Request Forgery (SSRF)
nova scan ssrf http://target.com

# JWT Token Attacks (alg:none, key confusion, etc.)
nova scan jwt http://target.com

# Cross-Site Request Forgery (CSRF)
nova scan csrf http://target.com

# Race Conditions
nova scan race http://target.com

# GraphQL Vulnerabilities (introspection, batching, IDOR)
nova scan graphql http://target.com

# Business Logic Flaws
nova scan business-logic http://target.com

# LLM Prompt Injection
nova scan llm-injection http://target.com
```

**Each scanner:**
- Takes 5-30 minutes depending on scope
- Outputs `findings.json` with reproducible PoCs
- Requires CVSS scoring via triage system

---

## 🤖 Multi-Agent Orchestration

The **true power** of Nova: 3 LLM-driven agents that hand off discoveries.

### Manual Agent Invocation

```bash
# Phase 1: Reconnaissance Agent (discovers endpoints, tech stack, attack surface)
python3 nova_orchestrator.py --mode recon http://target.com

# Phase 2: Attack Agent (chains exploits, crafts payloads, verifies findings)
python3 nova_orchestrator.py --mode attack http://target.com --map <_CMAP.json>

# Phase 3: Report Agent (writes findings, prioritizes by CVSS, generates patches)
python3 nova_orchestrator.py --mode report --findings <findings.json>

# All 3 in sequence (automatic handoff)
python3 nova_orchestrator.py --mode full http://target.com
```

---

## 🧠 AI/LLM Provider Configuration

Nova supports multiple LLM backends with automatic fallback:

### Available Providers

```bash
# OpenAI (requires OPENAI_API_KEY)
export OPENAI_API_KEY=sk-...
python3 nova.py "Hunt http://target.com"

# Anthropic Claude (requires ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-ant-...
python3 nova.py "Hunt http://target.com"

# Google Gemini (requires GOOGLE_API_KEY)
export GOOGLE_API_KEY=AIza...
python3 nova.py "Hunt http://target.com"

# Local Ollama (no cost, no API keys)
export NOVA_LLM_URL=http://localhost:11434
export NOVA_LLM_MODEL=qwen3:8b
python3 nova.py "Hunt http://target.com"
```

### Model Selection Strategy

Models are auto-selected by Nova based on task type:

| Task Type | Recommended Model | Why |
|---|---|---|
| **Reasoning/Chain-of-Thought** | `deepseek-r1:32b` | Best for complex exploit chains |
| **Code Auditing** | `devstral-small` | Specialized for code review |
| **Fast Checks** | `qwen3:8b` | Quick parsing + decisions |
| **General Tasks** | `qwen3:30b` | Best all-around reasoning |
| **Security Specialized** | `xploiter/the-xploiter` | Built for security analysis |

**View routing table:**
```bash
python3 nova_model_router.py
```

**Check provider availability:**
```bash
nova providers --test
```

---

## 💾 Session Management

Nova saves scan state so you can resume interrupted hunts:

```bash
# List all past sessions
nova session list

# Resume a previous session
nova session resume abc123def456

# Export findings from a session
nova session export abc123def456 --format json

# Save current session
nova session save my-important-hunt

# Clear old sessions (> 30 days)
nova session cleanup --older-than 30
```

**Sessions stored in:** `~/nova_workspace/sessions/`

---

## 📊 Reporting & Output Formats

After each hunt, Nova generates multiple report formats:

```bash
# View latest report (HTML — open in browser)
nova report --latest --format html

# Generate fresh report from findings file
nova report --findings findings.json --format html

# All supported formats
nova report --format html    # Visual dashboard
nova report --format json    # Machine-readable
nova report --format md      # Markdown (HackerOne-ready)
nova report --format csv     # Spreadsheet-compatible
nova report --format html --template executive  # C-suite summary
nova report --format html --template technical  # Developer details
```

**Report location:** `~/nova_workspace/reports/`

---

## 🔐 Permission Profiles

Nova enforces tool governance based on your threat model:

```bash
# read_only — No network calls, no shell execution (safe for CI/CD)
export NOVA_PERMISSION_PROFILE=read_only
nova.py "Map ./my-app"

# scoped — Network calls limited to declared scope (DEFAULT)
export NOVA_PERMISSION_PROFILE=scoped
nova hunt http://target.com  # MUST set NOVA_TARGET or provide URL

# full — All tools enabled (use locally only with trusted code)
export NOVA_PERMISSION_PROFILE=full
nova hunt http://target.com
```

**View current profile:**
```bash
nova status --show-permissions
```

**Tool audit log** (tracks all tool calls):
```bash
cat ~/nova_workspace/logs/nova_tool_audit.jsonl | grep "bash_exec\|http_request"
```

---

## 🔔 Notifications (Real-Time Alerts)

Set up instant alerts when findings are discovered:

### Configure Notifications

**1. Telegram** (best for mobile alerts):
```bash
# Get bot token: @BotFather on Telegram
# Get chat ID: Send /start to your bot, then get ID

export TELEGRAM_BOT_TOKEN="123456789:ABCdefGHIjklmnoPQRstuvWXYZ"
export TELEGRAM_CHAT_ID="987654321"

python3 nova.py "Hunt http://target.com"  # Alerts sent to Telegram
```

**2. Discord** (team notifications):
```bash
# Create webhook: Server Settings → Integrations → Webhooks → New Webhook

export DISCORD_WEBHOOK_URL="https://discordapp.com/api/webhooks/..."

python3 nova.py "Hunt http://target.com"  # Posts to Discord channel
```

**3. Slack** (enterprise):
```bash
# Create incoming webhook at api.slack.com/apps

export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."

python3 nova.py "Hunt http://target.com"  # Posts to Slack
```

**What gets sent:**
- Finding title + severity (HIGH, MEDIUM, LOW)
- CVSS score
- Reproducible PoC summary
- Link to full report

---

## 🌍 Cloud Hunting (GitHub Actions)

Hunt targets 24/7 on GitHub's free cloud runners (no local resources):

```bash
# Trigger hunt from CLI
nova-cloud hunt https://target.com

# Trigger hunt + evolve Nova's code if successful
nova-cloud hunt https://target.com --evolve

# Watch live progress
nova-cloud watch <job-id>

# Get results
nova-cloud results <job-id>

# See what Nova learned across all hunts
nova-cloud brain
```

**Setup required:**
1. Fork/clone Nova-arsenal to your GitHub account
2. Add secrets:
   - `GITHUB_TOKEN` (auto-configured)
   - `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` (optional, falls back to Ollama)
   - Notification tokens (Telegram, Discord, Slack)

**Workflows:**
- `nova_hunt.yml` — Single-target hunt (manual trigger)
- `nova_continuous.yml` — Multiple targets on schedule (edit `targets.txt`)

---

## 🚀 Self-Evolution (Advanced)

Nova can modify her own code to improve:

```bash
# Propose a code improvement
python3 nova_evolution.py \
  --file nova_attack.py \
  --goal "Add blind SQLi detection to the attack pipeline"

# What happens:
# 1. LLM proposes code change
# 2. Syntax check (must parse)
# 3. Import test (must not break dependencies)
# 4. If all pass → apply to file
# 5. If any fail → rollback + show error

# Evolve a specific function
python3 nova_evolution.py \
  --file nova_idor_scanner.py \
  --function test_param_in_different_users \
  --improvement "Reduce false positives by 50%"

# Safe? Yes. All changes are:
# - Syntax validated
# - Dependency checked
# - Tested before commit
# - Reversible (old file backed up)
```

**Disable evolution (for production):**
```bash
export NOVA_ALLOW_EVOLUTION=false
```

---

## 📈 Evaluation & Benchmarking

Test Nova's capabilities against known challenges:

```bash
# Quick test (no live targets needed, 2-5 minutes)
nova_eval.py --quick

# Live test (requires Juice Shop or DVWA running)
EVAL_JUICE_SHOP=http://localhost:3000 nova_eval.py --live

# Specific mission
nova_eval.py --mission map_01

# All 20 missions with detailed output
nova_eval.py --full --verbose

# Results
cat ~/nova_workspace/eval_results.json
```

**20 Mission Benchmark:**
- `map_*` — Codebase intelligence accuracy
- `sca_*` — Dependency vulnerability detection
- `secret_*` — Hardcoded credential discovery
- `diff_*` — Real-time change detection
- `idor_*` — Access control testing
- `jwt_*` — Token manipulation
- `sast_*` — Code flaw detection
- `infra_*` — Target reachability
- `orch_*` — Multi-agent orchestration
- `perf_*` — Performance benchmarks
- `e2e_*` — End-to-end integration

---

## 👀 Real-Time File Watcher (Dev Integration)

Automatically scan code as it's being written:

```bash
# Watch for changes and run lightweight scans
nova-watch ./my-app

# Watch only staged files (perfect pre-commit hook)
nova-watch ./my-app --staged

# Watch last commit (perfect for post-commit CI)
nova-watch ./my-app --on-commit

# Watch with specific scan types
nova-watch ./my-app --scan secrets,sast
```

**Install as Git pre-commit hook:**
```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
python3 /path/to/nova_diff_watcher.py . --staged
exit $?
EOF
chmod +x .git/hooks/pre-commit
```

**What happens on file change:**
1. Detects new/modified files
2. Runs SCA on dependency changes
3. Runs SAST on code changes
4. Runs secret scan on config changes
5. Blocks commit if HIGH/CRITICAL found
6. Allows commit if LOW/MEDIUM (with warning)

---

## 🗄️ Vulnerability Database

All findings are stored in a local SQLite database with trend analysis:

```bash
# View all findings ever discovered
nova vuln-db list

# Filter by severity
nova vuln-db list --severity HIGH

# Filter by status
nova vuln-db list --status open

# Search for specific vulnerability
nova vuln-db search "SQL Injection in login endpoint"

# Export for compliance (SOC 2, ISO 27001)
nova vuln-db export --format json > audit_report.json

# Trend analysis (how many new vulns per week?)
nova vuln-db trend

# Database location
ls -lah ~/nova_workspace/nova_vulnerabilities.db
```

---

## 🛠️ Advanced Customization

### LLM System Prompts

View/edit the prompts Nova uses to reason:

```bash
# Recon agent system prompt
cat nova_skills.py | grep -A 50 "RECON_PROMPT"

# Attack agent system prompt
cat nova_skills.py | grep -A 50 "ATTACK_PROMPT"

# Custom prompt (advanced users)
export NOVA_CUSTOM_RECON_PROMPT="You are a bug bounty hacker. Find all endpoints and..."
python3 nova_orchestrator.py --mode recon
```

### RAG Knowledge Base

Nova learns from past hunts. Improve learning:

```bash
# Rebuild knowledge base from reports
python3 nova_rag_builder.py ~/nova_workspace/reports

# Query what Nova knows
python3 - << 'EOF'
from nova_rag_builder import RAGBuilder
rag = RAGBuilder()
results = rag.search("IDOR vulnerability patterns")
for r in results:
    print(r)
EOF

# Add custom knowledge
echo "IDOR on user ID in URL parameter: check /api/user/{id} endpoints" >> ~/nova_workspace/knowledge.txt
```

---

## 🐛 Troubleshooting & Debugging

### Module Health Check

```bash
# Check all 35+ modules are working
nova status

# Check specific module
python3 -c "import nova_codebase_mapper; print('OK')"

# View detailed logs
tail -f ~/nova_workspace/logs/nova.log

# Enable debug mode (verbose output)
export DEBUG=true
python3 nova.py "Hunt http://target.com"
```

### Common Issues

| Issue | Fix |
|---|---|
| "No module named 'nova_llm_router'" | `pip install -r requirements.txt` |
| "Ollama connection refused" | `ollama serve` (start Ollama) |
| "Permission denied for tool: bash_exec" | Set `NOVA_PERMISSION_PROFILE=full` |
| "Target out of scope" | Set `NOVA_TARGET` or use `nova hunt --target http://...` |
| "Playwright browser not found" | `python3 -m playwright install chromium` |

---

## 📖 Next Steps

### Beginner
- [ ] Run `nova status` to verify setup
- [ ] Run `nova_eval.py --quick` to test
- [ ] Run `nova hunt http://localhost:3000` on local target
- [ ] Check generated report in `~/nova_workspace/reports/`

### Intermediate
- [ ] Set up notifications (Telegram/Discord)
- [ ] Configure provider (OpenAI/Anthropic)
- [ ] Try multi-agent orchestration: `nova orch http://target.com`
- [ ] Run with permission profile: `NOVA_PERMISSION_PROFILE=scoped nova hunt ...`

### Advanced
- [ ] Enable real-time watcher: `nova-watch ./my-app`
- [ ] Set up cloud hunting: `nova-cloud hunt http://target.com`
- [ ] Use threat modeling: `nova threat-model ./my-app`
- [ ] Generate patches: `nova generate-patch <finding-id>`
- [ ] Enable self-evolution: `python3 nova_evolution.py --file nova_attack.py --goal "..."`

---

## 📚 Related Documentation

- **[README.md](README.md)** — Architecture & design decisions
- **[AGENTS.md](AGENTS.md)** — AI assistant guidelines
- **[CAPABILITIES.md](CAPABILITIES.md)** — Feature matrix (coming soon)
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** — Detailed debugging (coming soon)

---

**Last Updated:** June 2026  
**Version:** Nova Arsenal v4.2
