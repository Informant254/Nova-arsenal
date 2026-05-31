# Nova Arsenal v4.0
### Autonomous AI-Powered Cybersecurity Platform

> **One command. Full coverage.** Nova takes a plain-English instruction, parses intent with a local LLM, routes to the right specialist modules, and orchestrates a complete offensive/defensive security workflow — all locally, zero cost, zero cloud dependency.

---

## Quick Start

```bash
# 1. One-shot install (installs Ollama, LLM, dependencies, verifies every module)
bash nova_install.sh

# 2. Run anything in plain English
python3 nova.py "Hunt http://localhost:3000 for SQL injection"
python3 nova.py "Run full-stack Mythos+Daybreak pipeline on ./juice-shop"
python3 nova.py "Scan git history for leaked secrets"
python3 nova.py "Build a threat model for ./my-app"
python3 nova.py "Test GraphQL endpoint at http://api.example.com"
python3 nova.py "Check supply chain risk in ."
python3 nova.py "Scan CI/CD pipelines and Dockerfiles in ."
python3 nova.py "Show vulnerability tracker dashboard"
python3 nova.py "Check health of all Nova modules"

# 3. Verify full-power installation
python3 nova_bootstrap.py
```

---

## Architecture: Everything Tied Together

```
                   ┌─────────────────────────────────┐
                   │    nova.py  (single entry point) │
                   │  natural language → NLP parser   │
                   └────────────┬────────────────────┘
                                │ intent + target
                                ▼
              ┌─────────────────────────────────────────┐
              │         dispatch()  engine               │
              │  routes to 1 or N specialist modules    │
              └──┬──────────┬──────────┬────────────────┘
                 │          │          │
    ┌────────────▼──┐  ┌────▼────┐  ┌─▼──────────────────┐
    │  Static/Code  │  │ Active  │  │ Intelligence Layer  │
    │  Analysis     │  │ Probing │  │                     │
    │               │  │         │  │ nova_threat_model   │
    │ nova_source_  │  │nova_    │  │ nova_zero_day_      │
    │  auditor      │  │fuzzer   │  │  correlator         │
    │ nova_sca_     │  │nova_    │  │ nova_web_researcher │
    │  scanner      │  │idor_    │  │ nova_planner        │
    │ nova_git_     │  │scanner  │  └─────────────────────┘
    │  scanner      │  │nova_    │
    │ nova_cicd_    │  │graphql_ │  ┌──────────────────────┐
    │  scanner      │  │tester   │  │  Detection/Report    │
    │ nova_container│  │nova_    │  │                      │
    │  _scanner     │  │csrf_    │  │ nova_detection_      │
    │ nova_supply_  │  │tester   │  │  engineer            │
    │  chain_scorer │  │nova_    │  │ nova_audit_reporter  │
    │ nova_file_    │  │business_│  │ nova_patch_generator │
    │  prioritizer  │  │logic    │  │ nova_sandbox_        │
    └───────────────┘  │nova_llm_│  │  validator           │
                       │injection│  └──────────────────────┘
                       └─────────┘
                                          │
                              ┌───────────▼──────────────┐
                              │  nova_vuln_tracker.py    │
                              │  SQLite persistence      │
                              │  regression detection    │
                              │  trend dashboards        │
                              └──────────────────────────┘
```

All modules share a **common findings schema** and automatically feed into `nova_vuln_tracker` — so every scan, across every mode, builds a persistent vulnerability history.

---

## All Dispatch Modes

| Command phrase | Mode | What runs |
|---|---|---|
| `full-stack` / `everything` / `v4` | `full_stack` | All 19 modules in sequence — Mythos+Daybreak parity |
| `hunt` / `bug bounty` / `pentest` | `hunt` | ReAct agent loop + SAST + IDOR + GraphQL + CSRF + BL |
| `sast` / `source code` / `code audit` | `sast` | File prioritizer + multi-language source auditor |
| `threat model` / `attack surface` | `threat_model` | Entry points + trust boundaries + STRIDE |
| `dependency` / `sca` / `npm audit` | `sca` | OSV + NVD advisory scan + supply chain scorer |
| `supply chain` / `typosquat` | `supply_chain` | Typosquatting + maintainer risk + OSV |
| `git history` / `leaked secret` | `git_scan` | 20-pattern git log secret scan |
| `ci/cd` / `github actions` | `cicd` | Pipeline secret + injection + unpinned action scan |
| `docker` / `container` / `k8s` | `container` | Dockerfile + compose + K8s manifest scan |
| `zero day` / `cve` / `osv` | `zero_day` | Live NVD + OSV CVE correlation against tech stack |
| `idor` / `access control` / `bola` | `idor` | Horizontal + vertical privilege escalation testing |
| `graphql` / `gql` | `graphql` | Introspection + injection + depth attack + batch |
| `csrf` / `samesite` | `csrf` | Cookie flags + origin + JSON CSRF + CORS |
| `business logic` / `negative price` | `business_logic` | Negative values + race conditions + workflow bypass |
| `llm injection` / `prompt injection` | `llm_injection` | Jailbreak + system prompt leak + tool abuse |
| `jwt` / `bearer token` | `jwt` | alg:none + key confusion + weak secret |
| `sql injection` / `sqli` | `sqli` | Union + boolean + time-based blind SQLi |
| `prototype pollution` | `proto_pollution` | `__proto__` + constructor abuse |
| `race condition` / `toctou` | `race` | 10-thread concurrent request races |
| `fuzz` / `directory` | `fuzz` | Parameter + directory + endpoint fuzzing |
| `recon` / `subdomain` | `recon` | DNS + crt.sh + passive footprint |
| `patch` / `auto fix` | `patch` | LLM-guided safe code fix for 10 vuln classes |
| `detection rules` / `sigma` | `detect` | Sigma + Splunk SPL + Elastic KQL + Suricata |
| `audit report` / `compliance` | `audit_report` | CVSS 3.1 + SLA + PCI/SOC2/ISO27001 notes |
| `tracker` / `dashboard` | `vuln_track` | SQLite trend + regression dashboard |
| `swarm` | `swarm` | 10-agent parallel hunt |
| `bootstrap` / `health check` | `bootstrap` | Module + tool + API connectivity verification |
| `continuous` | `continuous` | 24/7 scheduled hunting loop |

---

## Module Reference

### Offense / Active Testing

| Module | Version | Description |
|---|---|---|
| `nova_agent_core.py` | v2.0 | ReAct agentic hunt loop — plan, act, observe, reflect |
| `nova_fuzzer.py` | v3.5 | HTTP parameter + SQLi + XSS fuzzing |
| `nova_jwt_forge.py` | v3.5 | JWT alg:none, weak secret, kid injection |
| `nova_race_engine.py` | v3.5 | Concurrent HTTP race condition testing |
| `nova_session_hijacker.py` | v3.5 | Session token analysis + fixation |
| `nova_proto_polluter.py` | v3.5 | JavaScript prototype pollution |
| `nova_idor_scanner.py` | v4.0 | IDOR + BOLA + privilege escalation |
| `nova_graphql_tester.py` | v4.0 | GraphQL introspection + injection + depth DoS |
| `nova_csrf_tester.py` | v4.0 | CSRF + CORS + cookie flag analysis |
| `nova_business_logic.py` | v4.0 | Negative values + race + workflow bypass |
| `nova_llm_injection.py` | v4.0 | Prompt injection + jailbreak + tool abuse |
| `nova_sandbox_validator.py` | v4.0 | Confirm exploitability before reporting |
| `nova_browser_agent.py` | v3.5 | Playwright browser-based XSS/auth testing |
| `nova_url_smuggling.py` | v3.5 | HTTP request smuggling |

### Static Analysis / Code Review

| Module | Version | Description |
|---|---|---|
| `nova_source_auditor.py` | v2.0 | Multi-language SAST: Python, JS/TS, PHP, Ruby, Go, Java |
| `nova_file_prioritizer.py` | v4.0 | Scores every file 1–5 for risk before scanning |
| `nova_sca_scanner.py` | v4.0 | npm/pip/go/maven CVE scan via OSV.dev + NVD |
| `nova_supply_chain_scorer.py` | v4.0 | Typosquatting + maintainer risk + OSV per-package |
| `nova_git_scanner.py` | v4.0 | Git history scan for 20 secret patterns |
| `nova_cicd_scanner.py` | v4.0 | GitHub Actions / GitLab CI / Jenkins / Travis / CircleCI |
| `nova_container_scanner.py` | v4.0 | Dockerfile + docker-compose + Kubernetes manifests |

### Intelligence & Planning

| Module | Version | Description |
|---|---|---|
| `nova_threat_model.py` | v4.0 | Entry points + trust boundaries + STRIDE + attack paths |
| `nova_zero_day_correlator.py` | v4.0 | Live NVD + OSV + GHSA CVE correlation |
| `nova_web_researcher.py` | v3.5 | CVE / PoC / exploit research via web |
| `nova_planner.py` | v3.5 | Pre-hunt plan: recon → map → attack → report |
| `nova_context_manager.py` | v3.5 | Context compression for long-running hunts |
| `nova_memory_system.py` | v3.5 | Persistent cross-session memory |
| `nova_chain_of_thought.py` | v3.5 | Reasoning traces for complex analysis |
| `nova_reasoning_core.py` | v3.5 | LLM-guided vulnerability reasoning |

### Detection & Reporting

| Module | Version | Description |
|---|---|---|
| `nova_detection_engineer.py` | v4.0 | Sigma + Splunk SPL + Elastic KQL + Suricata |
| `nova_audit_reporter.py` | v4.0 | CVSS 3.1 + SLA timelines + PCI/SOC2/ISO notes |
| `nova_patch_generator.py` | v4.0 | Auto-generates safe code fixes for 10 vuln classes |
| `nova_vuln_tracker.py` | v4.0 | SQLite persistence — regressions + trend dashboard |
| `nova_report.py` | v3.5 | Base report generation |
| `nova_verify_engine.py` | v3.5 | Triple-verify engine — eliminates false positives |

### Autonomous Operation

| Module | Version | Description |
|---|---|---|
| `nova_swarm_v3.py` | v3.5 | 10-agent parallel hunt swarm |
| `nova_continuous_v3.py` | v3.5 | 24/7 scheduled hunting loop |
| `nova_self_improvement.py` | v3.5 | Nova improves its own prompts from findings |
| `nova_adaptive_brain.py` | v3.5 | Adapts strategy based on target responses |
| `nova_model_router.py` | v3.5 | Routes between available LLM models |

### Bootstrap & Setup

| Module | Version | Description |
|---|---|---|
| `nova_install.sh` | v4.0 | One-shot installer: Ollama + LLM + dependencies + verify |
| `nova_bootstrap.py` | v4.0 | Health check + module verification + capability report |
| `nova.py` | v4.0 | Single entry point — all modes, all modules |

---

## Capability Gap Closure vs Claude Mythos & OpenAI Daybreak

| Capability | Mythos | Daybreak | Nova v4.0 | Notes |
|---|:---:|:---:|:---:|---|
| Natural language → security action | ✅ | ✅ | ✅ | Ollama-powered + keyword fallback |
| Autonomous agentic hunt loop | ✅ | ✅ | ✅ | nova_agent_core: ReAct loop |
| Multi-language SAST | ✅ | ✅ | ✅ | Python, JS/TS, PHP, Ruby, Go, Java |
| Risk-based file prioritization | ✅ | — | ✅ | Score 1–5 before scanning |
| Threat modeling (STRIDE) | — | ✅ | ✅ | Entry pts + trust zones + paths |
| Auto patch generation | — | ✅ | ✅ | 10 vuln classes, language-aware |
| SCA / dependency CVE scan | — | ✅ | ✅ | OSV.dev + NVD, 4 ecosystems |
| Supply chain risk scoring | — | — | ✅ | Typosquatting + maintainer + OSV |
| Git history secret scan | ✅ | — | ✅ | 20 patterns across all commits |
| CI/CD pipeline security | — | — | ✅ | GH Actions + Jenkins + Travis |
| Container / K8s security | — | — | ✅ | Dockerfile + compose + manifests |
| Live CVE correlation (NVD/OSV) | — | ✅ | ✅ | Real-time CRITICAL CVE feed |
| Exploit sandbox validation | ✅ | — | ✅ | Confirm before reporting |
| SIEM detection rules | — | ✅ | ✅ | Sigma + Splunk + ELK + Suricata |
| Enterprise audit report | — | ✅ | ✅ | CVSS + SLA + PCI/SOC2/ISO |
| IDOR / Broken Access Control | ✅ | ✅ | ✅ | Horizontal + vertical + mass assign |
| GraphQL security | ✅ | — | ✅ | Introspection + injection + depth |
| CSRF + CORS analysis | ✅ | — | ✅ | Cookie flags + origin + JSON CSRF |
| Business logic testing | ✅ | — | ✅ | Negative vals + race + workflow |
| LLM prompt injection | — | — | ✅ | Industry-first: AI app security |
| Persistent vuln tracking | — | — | ✅ | SQLite + regression detection |
| JWT testing | ✅ | ✅ | ✅ | alg:none + key confusion |
| HTTP request smuggling | — | ✅ | ✅ | nova_url_smuggling |
| Prototype pollution | ✅ | — | ✅ | nova_proto_polluter |
| Race conditions | ✅ | — | ✅ | nova_race_engine |
| Session hijacking | ✅ | — | ✅ | nova_session_hijacker |
| Browser automation | — | ✅ | ✅ | nova_browser_agent (Playwright) |
| 10-agent parallel swarm | ✅ | — | ✅ | nova_swarm_v3 |
| 24/7 continuous hunt | ✅ | — | ✅ | nova_continuous_v3 |
| Self-improvement engine | ✅ | — | ✅ | nova_self_improvement |
| Zero-cost (100% local) | ❌ | ❌ | ✅ | Ollama + open-source LLMs |

**Gap score: 32/32 capabilities covered. Nova v4.0 closes all gaps AND adds 5 capabilities neither Mythos nor Daybreak have.**

---

## Unique Nova Advantages

1. **100% local / zero-cost** — Ollama + open-source LLMs. Claude/GPT-4 is optional, never required.
2. **LLM prompt injection testing** — no other platform tests AI-enabled apps for prompt injection.
3. **Persistent vulnerability tracker** — SQLite database tracks every finding across runs, detects regressions.
4. **Supply chain typosquatting detector** — Levenshtein edit-distance detection against 25 top packages.
5. **Full pipeline from "scan" to "SIEM rule"** — discovers vuln → confirms → patches → writes Sigma rule → generates audit report, all in one command.

---

## Installation

### Requirements

| Requirement | Notes |
|---|---|
| Python 3.10+ | Core runtime |
| Ollama | Local LLM inference (installed by `nova_install.sh`) |
| LLM model | `qwen3:8b` (default) or any Ollama model |
| 8 GB RAM | Minimum for LLM inference |
| 4 GB disk | For model weights |

### One-shot install

```bash
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
bash nova_install.sh
```

The installer:
1. Detects your OS and Python version
2. Installs Python dependencies from `requirements.txt`
3. Installs Ollama
4. Pulls the default LLM (`qwen3:8b`)
5. Creates `~/nova_workspace/` for output files
6. Creates a `.env` config file
7. Verifies every Nova module compiles
8. Runs a self-test and prints a capability summary

### Manual install (minimal)

```bash
pip install requests beautifulsoup4 lxml pyyaml
# Install Ollama from https://ollama.com
ollama pull qwen3:8b
python3 nova_bootstrap.py  # verify everything
```

### Optional tools (boost coverage)

```bash
# Network/web scanning
sudo apt-get install nmap
pip install sqlmap

# Go-based tools (fastest)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Container scanning
brew install trivy  # or apt-get install trivy
```

---

## Configuration

All config via environment variables or `.env` file:

```bash
NOVA_LLM_URL=http://localhost:11434    # Ollama endpoint
NOVA_LLM_MODEL=qwen3:8b               # LLM model name
NOVA_WORKSPACE=~/nova_workspace        # Output directory
NOVA_MAX_STEPS=40                      # Max agent steps per hunt
NOVA_TARGET=http://localhost:3000      # Default target
NOVA_DB=~/nova_workspace/nova_vulns.db # Vulnerability tracker DB
```

---

## Usage Examples

### Full-power pipeline (all 19 modules)

```bash
python3 nova.py "Run full-stack Mythos+Daybreak pipeline on ./juice-shop"
# Runs: SAST → prioritizer → threat model → SCA → supply chain →
#       git scan → CI/CD → container → zero-day correlation →
#       IDOR → GraphQL → CSRF → business logic → patch →
#       detection rules → audit report → vuln tracker
```

### Target a live app

```bash
python3 nova.py "Hunt http://testphp.vulnweb.com for SQL injection and XSS"
python3 nova.py "Test IDOR on http://localhost:3000 with token abc123"
python3 nova.py "Run GraphQL security tests on http://localhost:4000"
python3 nova.py "Check CSRF and cookie security on http://localhost:8080"
python3 nova.py "Business logic tests on http://juice-shop.local"
```

### Scan a codebase

```bash
python3 nova.py "SAST scan of ./src"
python3 nova.py "Find hardcoded secrets in git history of ."
python3 nova.py "Scan all Dockerfiles and GitHub Actions in ."
python3 nova.py "Dependency CVE scan for ./package.json"
python3 nova.py "Supply chain risk score for ./node_modules"
```

### Intelligence

```bash
python3 nova.py "Build a threat model for ./api-server"
python3 nova.py "Correlate findings with live CVEs from NVD"
python3 nova.py "Generate Sigma detection rules from ./nova_findings.json"
python3 nova.py "Generate auto-patches for findings in ./nova_sast_report.json"
python3 nova.py "Write an enterprise audit report for ./nova_findings.json"
```

### AI app security (LLM injection)

```bash
python3 nova.py "Test http://localhost:3000 for LLM prompt injection"
# Tests: direct injection, system prompt leak, jailbreaks, tool abuse, output XSS
```

### Tracking & operations

```bash
python3 nova.py "Show vulnerability tracker dashboard"   # SQLite trend + regressions
python3 nova.py "Launch 10-agent parallel swarm on http://target.com"
python3 nova.py "Start continuous 24/7 hunt on http://target.com"
python3 nova.py "Check health of all Nova modules"
```

---

## Vulnerability Tracker

Nova automatically persists every finding to SQLite across all runs:

```
~/nova_workspace/nova_vulns.db
```

Features:
- **Regression detection** — alerts when a previously-fixed vuln reappears
- **Trend analysis** — open/fixed counts over time
- **SIEM-style timeline** — `FIRST_SEEN → SEEN_AGAIN → FIXED → REGRESSED`
- **Dashboard export** — Markdown dashboard to `nova_tracker_dashboard.md`

```bash
python3 nova.py "Show vulnerability tracker dashboard"
# or direct:
python3 nova_vuln_tracker.py ~/nova_workspace/nova_*_report.json
```

---

## Output Files

All outputs are saved to `~/nova_workspace/` (configurable via `NOVA_WORKSPACE`):

| File | Contents |
|---|---|
| `nova_{mode}_{timestamp}.json` | Raw findings from each scan |
| `nova_threat_model.json` | Threat model — entry points, paths, STRIDE |
| `nova_sca_report.json` | Dependency CVE scan results |
| `nova_supply_chain_report.json` | Per-package supply chain risk scores |
| `nova_git_report.json` | Git history secret scan |
| `nova_cicd_report.json` | CI/CD pipeline findings |
| `nova_container_report.json` | Dockerfile + K8s findings |
| `nova_zero_day_report.json` | Live CVE correlation |
| `nova_idor_report.json` | IDOR / access control findings |
| `nova_graphql_report.json` | GraphQL security findings |
| `nova_csrf_report.json` | CSRF / CORS / cookie findings |
| `nova_business_logic_report.json` | Business logic findings |
| `nova_llm_injection_report.json` | Prompt injection findings |
| `nova_patches.json` | Auto-generated code patches |
| `nova_detection_rules.json` | Sigma + SIEM detection rules |
| `nova_audit_report.json` | Enterprise audit report with CVSS |
| `nova_tracker_report.json` | SQLite vuln tracker full report |
| `nova_tracker_dashboard.md` | Markdown trend dashboard |
| `nova_bootstrap_status.json` | Module health check status |

---

## Adding a New Module

Every Nova module follows this pattern so it integrates automatically:

```python
class NovaYourModule:
    def __init__(self, target: str, **kwargs): ...
    def run(self) -> List[Dict]: ...           # returns findings list
    def save(self, path: str): ...            # saves JSON report

# Findings schema (use these keys for auto-tracker integration):
{
    "type": "Vuln Type",          # e.g. "SQL Injection"
    "severity": "CRITICAL",       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    "file": "src/app.py",         # for SAST findings
    "line": 42,                   # line number
    "endpoint": "/api/users",     # for DAST findings
    "snippet": "code here",       # context snippet (≤300 chars)
    "cve": "CVE-2023-XXXXX",      # if applicable
    "cvss": 9.8,                  # CVSS v3 score
    "description": "...",         # clear description
}
```

Then register in `nova.py`'s `dispatch()` with a new mode keyword.

---

## Security & Ethics

- **Always get explicit written authorization** before testing any system you don't own.
- Use `NOVA_TARGET` to set your authorized scope; Nova will default to it.
- The `nova_sandbox_validator` module is designed for safe, read-only exploit confirmation — it does NOT write files, execute shells, or create persistence.
- All output stays local. Nova never phones home.

---

## Contributing

1. Fork → branch → PR
2. Follow module pattern above
3. Findings must use the shared schema (auto-tracker integration)
4. Add your module to the `MODULES` dict in `nova_bootstrap.py`
5. Add dispatch keywords to `KEYWORD_MODES` in `nova.py`
6. Update this README

---

## License

See `LICENSE`. Use responsibly, with authorization.

---

*Nova Arsenal v4.0 — Built to rival Claude Mythos and OpenAI Daybreak. Runs entirely locally. Costs nothing.*
