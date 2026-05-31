# 🦅 Nova Arsenal v4.0

> **Fully autonomous AI security research agent — give her one command, she handles everything.**  
> 100% local · Zero cloud cost · HackerOne safe-harbor ready

---

## What Nova Does

Nova is a fully autonomous security research agent that:

- Plans and executes complete bug bounty hunts from a single plain-English command
- Uses **80+ specialist modules** covering the full security research lifecycle
- **Thinks with local Ollama** — no paid API, no data leaves your machine
- Runs a real headless browser (Playwright) for JS-heavy targets
- Chains vulnerabilities together (SSRF → metadata, SQLi → RCE, XSS → account takeover)
- **Orchestrates multi-agent pipelines** with handoffs, guardrails, and full execution tracing
- **Connects to any MCP server** — same protocol as Claude Desktop and GitHub Copilot
- **AI-triages and ranks** all findings so you always work the highest-impact bugs first
- Learns from every hunt — remembers what works, what doesn't
- Evolves her own code to improve over time
- Sends real-time findings to Telegram / Discord / Slack
- Runs 24/7 on GitHub Actions (free cloud Linux environment)

---

## Architecture

```
nova.py                     ← Single plain-English entry point (NLP → dispatch)
│
├── 🧠 Agent Layer (NEW in v4.0)
│   ├── nova_orchestrator.py    ← OpenAI Agents SDK-style multi-agent engine
│   │     Agents · Handoffs · Guardrails · Tracing · Parallel fan-out
│   ├── nova_mcp_client.py      ← Model Context Protocol client
│   │     GitHub · Filesystem · Puppeteer · Fetch · Git · Postgres MCP
│   └── nova_triage.py          ← AI-powered findings prioritiser
│         Dedup · LLM scoring · Attack-chain grouping · H1-ready ranking
│
├── 🔭 Assessment Layer
│   ├── nova_daybreak.py         ← Scope-aware AI threat assessment
│   ├── nova_scope_manager.py    ← HackerOne scope loader & enforcer
│   ├── nova_autonomous.py       ← Full autonomous hunt orchestrator
│   ├── nova_agent_core.py       ← ReAct-loop agentic core
│   └── nova_swarm_v3.py         ← Parallel multi-agent swarm
│
├── 🔬 Scanning Layer (27 dispatch modes)
│   ├── nova_source_auditor.py   ← SAST: source code + secrets
│   ├── nova_recon.py            ← Passive recon (subdomains, JS, ports)
│   ├── nova_attack.py           ← Active attack chains
│   ├── nova_fuzzer.py           ← Fuzzing + SQLi
│   ├── nova_idor_scanner.py     ← IDOR / BOLA detection
│   ├── nova_graphql_tester.py   ← GraphQL introspection + injection
│   ├── nova_csrf_tester.py      ← CSRF / SameSite analysis
│   ├── nova_business_logic.py   ← Business logic flaws
│   ├── nova_jwt_forge.py        ← JWT attack suite
│   ├── nova_race_engine.py      ← Race conditions
│   ├── nova_sca_scanner.py      ← Dependency / SCA scanning
│   ├── nova_git_scanner.py      ← Git history / secret leak scan
│   ├── nova_cicd_scanner.py     ← CI/CD pipeline security
│   ├── nova_container_scanner.py← Docker / Kubernetes audit
│   └── nova_zero_day_correlator.py ← Live CVE correlation
│
├── 📊 Output Layer
│   ├── nova_threat_model.py     ← STRIDE threat modeling
│   ├── nova_patch_generator.py  ← AI-generated code fixes
│   ├── nova_detection_engineer.py ← Sigma / SIEM rules
│   ├── nova_audit_reporter.py   ← Executive / compliance reports
│   └── nova_vuln_tracker.py     ← Persistent vulnerability database
│
└── 🧬 Learning Layer
    ├── nova_memory_system.py    ← Persistent hunt memory (NovaBrain)
    ├── nova_evolution.py        ← Safe self-modification engine
    └── nova_continuous.py       ← 24/7 hunt loop
```

---

## Quick Start

### Local
```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
chmod +x nova_setup.sh && ./nova_setup.sh

source ~/nova_workspace/.venv/bin/activate

# Single command — Nova figures out everything else
python3 nova.py "Daybreak AI assessment on https://target.com"
python3 nova.py "Orchestrate multi-agent hunt on https://target.com"
python3 nova.py "Hunt https://target.com for IDOR and SQLi"
python3 nova.py "Triage my findings and show me what to report to H1"
```

### Cloud (GitHub Actions)
```bash
export GITHUB_TOKEN=your_token
python3 nova_cloud.py hunt https://target.com
python3 nova_cloud.py watch 12345678
python3 nova_cloud.py results
```

---

## Dispatch Modes — Plain English Commands

| Say something like… | Mode | What runs |
|---|---|---|
| `"daybreak assessment on target.com"` | `daybreak` | NovaDaybreak + NovaScopeManager (scope-enforced AI assessment) |
| `"orchestrate multi-agent hunt"` | `orchestrate` | NovaOrchestrator → ReconAgent → AttackAgent → ReportAgent |
| `"triage my findings"` | `triage` | NovaTriage: dedup → LLM score → chain → H1-ready ranking |
| `"hunt target.com for bugs"` | `hunt` | NovaAgentCore full ReAct loop |
| `"everything / full stack"` | `full_stack` | All 27+ modules + auto-triage |
| `"swarm target.com"` | `swarm` | 10+ parallel agents |
| `"recon target.com"` | `recon` | Passive subdomain + endpoint discovery |
| `"fuzz target.com"` | `fuzz` | Directory + parameter fuzzing |
| `"sql injection on target.com"` | `sqli` | NovaFuzzer SQLi suite |
| `"test graphql"` | `graphql` | Introspection + injection |
| `"csrf test"` | `csrf` | SameSite + origin validation |
| `"idor scan"` | `idor` | BOLA / IDOR horizontal escalation |
| `"jwt attack"` | `jwt` | alg:none, key confusion, claim tampering |
| `"race condition"` | `race` | Concurrent request engine |
| `"sast scan ./src"` | `sast` | Source code + secret analysis |
| `"check dependencies"` | `sca` | npm/pip/cargo CVE audit |
| `"git scan for secrets"` | `git_scan` | Git history secret detection |
| `"ci/cd pipeline security"` | `cicd` | GitHub Actions / Jenkins audit |
| `"docker security"` | `container` | Dockerfile + k8s audit |
| `"threat model ./app"` | `threat_model` | STRIDE model generation |
| `"patch these findings"` | `patch` | AI code fix generation |
| `"detection rules"` | `detect` | Sigma / KQL / Suricata rules |
| `"audit report"` | `audit_report` | Executive / compliance report |
| `"zero day correlate"` | `zero_day` | Live NVD/OSV CVE correlation |
| `"tracker dashboard"` | `vuln_track` | Vulnerability trend dashboard |
| `"health check"` | `bootstrap` | Verify all modules are working |
| `"continuous monitor"` | `continuous` | 24/7 hunt loop |

---

## v4.0 Agent Layer — What's New

### 🧠 nova_orchestrator.py — OpenAI Agents SDK style, 100% local

The same patterns that power Claude agents and OpenAI's Agents SDK, running on your local Ollama:

```python
from nova_orchestrator import Agent, Tool, Runner, Guardrail, build_security_network

# Build a 3-agent network: Recon → Attack → Report
runner = build_security_network("https://target.com", scope=["target.com"])
result = runner.run("Find all vulnerabilities in this web app")

print(result.findings)   # structured findings
print(result.steps)      # how many reasoning steps
result.trace.save(...)   # full execution trace
```

**Features:**
- Named agents with `instructions`, `tools`, `handoffs`, `guardrails`, and `output_schema`
- Structured agent-to-agent handoffs with full state transfer
- Input/output guardrails (scope enforcement, safety checks)
- Full execution tracing — every THINK / tool_call / tool_result / handoff logged
- Parallel agent fan-out with `runner.run_parallel()`
- JSON Schema-validated structured outputs
- Built-in tools: `http_probe`, `shell`, `read_file`, `python_eval`

---

### 🔌 nova_mcp_client.py — Connect to Any MCP Server

Plugs Nova into the Model Context Protocol ecosystem — the same standard that Claude Desktop and GitHub Copilot use:

```python
from nova_mcp_client import MCPClient, MCPToolbox, BUILTIN_SERVERS

# Use any built-in server
with MCPClient(BUILTIN_SERVERS["github"]) as client:
    tools = client.discover_tools()   # auto-converts to Nova Tool format
    result = client.call_tool("search_repositories", {"query": "nova security"})

# Load multiple servers at once
with MCPToolbox(["fetch", "filesystem", "git"]) as box:
    all_tools = box.tools  # plug directly into nova_orchestrator agents
```

**Built-in MCP servers:**

| Server | What it gives Nova |
|---|---|
| `fetch` | Web fetch + HTML/markdown extraction |
| `filesystem` | Sandboxed local file read/write |
| `git` | git log, diff, blame, show |
| `github` | Repos, issues, PRs, search, code read |
| `puppeteer` | Real browser: click, type, screenshot, DOM |
| `postgres` | Direct SQL queries |
| `brave-search` | Web search API |
| `memory` | Persistent key-value memory across runs |
| `sequential-thinking` | Structured multi-step reasoning |

---

### 🎯 nova_triage.py — AI-Powered Findings Prioritiser

Sits between raw scanner output and the HackerOne report pipeline:

```python
from nova_triage import NovaTriage, triage_findings

# One-liner
prioritised = triage_findings(raw_findings)

# Full pipeline
triage = NovaTriage()
triage.ingest_file("nova_sast_20260530.json")
triage.ingest_file("nova_idor_20260530.json")
ranked = triage.run()
triage.print_summary()
triage.save("nova_triage_report.json")

# Get only H1-ready findings
h1 = triage.h1_ready_findings()  # P1 + P2 only
```

**CLI:**
```bash
python3 nova_triage.py nova_*.json              # triage everything
python3 nova_triage.py nova_*.json --h1-only    # show H1-ready only
python3 nova_triage.py nova_*.json --chains     # show attack chains
python3 nova_triage.py nova_*.json --no-llm     # heuristic mode (no Ollama needed)
```

**What it produces:**
- 🔴 P1-Critical / 🟠 P2-High / 🟡 P3-Medium / 🟢 P4-Low priority labels
- LLM-generated exploitability + impact + novelty scores (0-10)
- Attack chain grouping (e.g. SSRF→metadata→RCE → one chain, one report)
- `h1_report_ready` flag on every finding
- Deduplication of near-identical findings from multiple scanners

---

### 🔭 nova_daybreak.py + nova_scope_manager.py — Scope-Enforced AI Assessment

```bash
# Fully scoped Daybreak run
python3 nova.py "Daybreak assessment on https://target.hackerone.com"

# With explicit scope init
python3 nova_scope_manager.py init-config
python3 nova.py "Run daybreak on target.com"
```

- Loads HackerOne scope automatically from local config or `.nova_scope.json`
- Blocks out-of-scope requests at the guardrail level
- Produces structured findings with CVSS scores and H1-formatted reproduction steps

---

## MCP Quick Setup

```bash
# Install Node.js MCP servers
npm install -g @modelcontextprotocol/server-fetch \
               @modelcontextprotocol/server-filesystem \
               @modelcontextprotocol/server-github \
               @modelcontextprotocol/server-puppeteer \
               @modelcontextprotocol/server-brave-search

# Install Python MCP servers  
pip install mcp-server-git

# Check what's available
python3 nova_mcp_client.py list-servers

# Discover tools from a server
python3 nova_mcp_client.py discover github
python3 nova_mcp_client.py discover fetch

# Call a tool directly
python3 nova_mcp_client.py call fetch fetch '{"url":"https://target.com"}'
```

---

## Tool Arsenal

### Tier 1 — AI Agent Weapons
| Category | Tools |
|---|---|
| Multi-agent orchestration | nova_orchestrator.py (Agents SDK), nova_swarm_v3.py |
| MCP connectivity | nova_mcp_client.py (5,000+ MCP servers) |
| AI prioritisation | nova_triage.py (LLM scoring + chain analysis) |
| Kernel fuzzing | syzkaller, AFL++, honggfuzz, LibAFL |
| Symbolic execution | angr, Manticore, Triton, Z3 |
| Static analysis | CodeQL, Joern, Semgrep, Infer |
| Binary exploitation | pwntools, ropper, ROPgadget |
| Smart contracts | Slither, Mythril, Echidna, Foundry |
| Novel web attacks | HTTP smuggling, SSRF chains, CORS bypass, SSTI→RCE |
| Secrets | TruffleHog, GitLeaks |
| Cloud | Pacu, CloudSploit, Prowler, Trivy |

### Tier 2 — Extended Arsenal
200+ tools: full web, network, post-exploitation, Windows/AD, password cracking, OSINT

### Tier 3 — Specialist Tools
300+ tools: hardware/IoT, wireless, Bluetooth, ICS/SCADA, blockchain, mobile, AI/ML attacks

---

## Cloud Environment Setup

Nova runs on GitHub Actions — full Ubuntu Linux, every tool, free.

### Required GitHub Secret
`GITHUB_TOKEN` — already configured if you're running from this repo.

### Optional Notification Secrets
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

Nova can modify her own code to improve:
1. LLM proposes code change
2. Syntax check (`ast.parse`)
3. Import test
4. If all pass → apply. If any fail → rollback.

```bash
python3 nova_evolution.py --file nova_autonomous.py \
  --goal "Add blind SQLI detection to the attack pipeline"
```

---

## Module Reference

| Module | Class | Purpose |
|---|---|---|
| `nova_orchestrator.py` | `Runner`, `Agent`, `Tool` | Multi-agent orchestration with handoffs + tracing |
| `nova_mcp_client.py` | `MCPClient`, `MCPToolbox` | MCP protocol client for 5,000+ external tools |
| `nova_triage.py` | `NovaTriage` | AI findings prioritiser, dedup, chain analysis |
| `nova_daybreak.py` | `NovaDaybreak` | Scope-aware AI threat assessment |
| `nova_scope_manager.py` | `NovaScopeManager` | HackerOne scope loading + enforcement |
| `nova_autonomous.py` | `NovaAutonomous` | Full autonomous hunt orchestrator |
| `nova_agent_core.py` | `NovaAgentCore` | ReAct-loop agentic core |
| `nova_swarm_v3.py` | `NovaSwarm` | Parallel multi-agent swarm |
| `nova_source_auditor.py` | `NovaSourceAuditor` | SAST + secrets scanner |
| `nova_recon.py` | `NovaRecon` | Passive recon pipeline |
| `nova_attack.py` | `NovaAttack` | Attack chain orchestrator |
| `nova_idor_scanner.py` | `NovaIDORScanner` | IDOR / BOLA scanner |
| `nova_graphql_tester.py` | `NovaGraphQLTester` | GraphQL introspection + injection |
| `nova_jwt_forge.py` | `NovaJWTForge` | JWT attack suite |
| `nova_race_engine.py` | `NovaRaceEngine` | Race condition tester |
| `nova_sca_scanner.py` | `NovaSCAScanner` | Dependency / CVE scanner |
| `nova_git_scanner.py` | `NovaGitScanner` | Git history secret scanner |
| `nova_cicd_scanner.py` | `NovaCICDScanner` | CI/CD pipeline auditor |
| `nova_container_scanner.py` | `NovaContainerScanner` | Docker / k8s auditor |
| `nova_zero_day_correlator.py` | `NovaZeroDayCorrelator` | Live CVE correlator |
| `nova_threat_model.py` | `NovaThreatModel` | STRIDE threat modeler |
| `nova_patch_generator.py` | `NovaPatchGenerator` | AI patch generator |
| `nova_detection_engineer.py` | `NovaDetectionEngineer` | Sigma / SIEM rule generator |
| `nova_audit_reporter.py` | `NovaAuditReporter` | Compliance / executive reporter |
| `nova_vuln_tracker.py` | `NovaVulnTracker` | Persistent vuln database |
| `nova_memory_system.py` | `NovaMemorySystem` | Persistent hunt memory |
| `nova_evolution.py` | `NovaEvolution` | Safe self-modification engine |

---

## Stack

- Python 3.12, Go 1.21+, Node.js, Ruby, Rust/Cargo
- Ollama (local LLM — qwen3:8b default, no API cost)
- Playwright (real headless browser)
- GitHub Actions (cloud Linux environment)
- MCP (Model Context Protocol — 5,000+ tool servers)

---

## Legal Notice

Nova is built for **authorised security testing only**.  
All hunting must target programs you have explicit permission to test (e.g. HackerOne safe-harbor programs).  
The default `targets.txt` contains intentionally vulnerable practice targets.  
Never test targets without written permission.  
You are responsible for all use of this tool.
