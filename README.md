<div align="center">

```
███╗   ██╗ ██████╗ ██╗   ██╗  █████╗
████╗  ██║██╔═══██╗██║   ██║ ██╔══██╗
██╔██╗ ██║██║   ██║██║   ██║ ███████║
██║╚██╗██║██║   ██║╚██╗ ██╔╝ ██╔══██║
██║ ╚████║╚██████╔╝ ╚████╔╝  ██║  ██║
╚═╝  ╚═══╝ ╚═════╝   ╚═══╝   ╚═╝  ╚═╝
         A R S E N A L  v4.0
```

**Fully Autonomous AI-Powered Cybersecurity Platform**

*Tell Nova what you want in plain English. She plans, probes, verifies, and reports — fully autonomously.*

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![Ollama](https://img.shields.io/badge/LLM-Ollama%20Local-green)](https://ollama.com)
[![Cost](https://img.shields.io/badge/LLM%20Cost-%240%2Frun-brightgreen)](#)
[![Parity](https://img.shields.io/badge/Frontier%20Gap-8%2F8%20Closed-red)](#8-capability-parity-table)

</div>

---

## Table of Contents

1. [What Nova Is](#1-what-nova-is)
2. [Architecture Overview](#2-architecture-overview)
3. [Installation](#3-installation)
4. [Talking to Nova in Plain English](#4-talking-to-nova-in-plain-english)
5. [v3.5 Gap-Closing Capabilities](#5-v35-gap-closing-capabilities)
6. [v4.0 NEW — Mythos + Daybreak Parity](#6-v40-new--mythos--daybreak-parity)
   - [File Prioritization](#61-file-prioritization--nova_file_prioritizerpy)
   - [Threat Modeling](#62-threat-modeling--nova_threat_modelpy)
   - [Patch Generator](#63-patch-generator--nova_patch_generatorpy)
   - [SCA Scanner](#64-sca-scanner--nova_sca_scannerpy)
   - [Git History Scanner](#65-git-history-scanner--nova_git_scannerpy)
   - [Sandbox Validator](#66-sandbox-validator--nova_sandbox_validatorpy)
   - [Detection Engineer](#67-detection-engineer--nova_detection_engineerpy)
   - [Audit Reporter](#68-audit-reporter--nova_audit_reporterpy)
7. [Module Reference](#7-module-reference)
8. [Capability Parity Table](#8-capability-parity-table)
9. [Configuration](#9-configuration)
10. [HackerOne Integration](#10-hackerone-integration)

---

## 1. What Nova Is

Nova is a **fully autonomous, locally-run AI security research system**. Talk to her in plain English. She decides what to do and does it — no confirmation prompts, no menus, no configuration.

```
You:  "Run full-stack Mythos+Daybreak pipeline on ./juice-shop"
Nova: [1/7] prioritize files (Mythos 1-5 scoring)
      [2/7] build threat model (attack surface + trust boundaries)
      [3/7] audit source code (TypeScript + Python taint tracing)
      [4/7] SCA — scan 127 npm packages for CVEs
      [5/7] git history — 3 leaked AWS keys found, rotate now
      [6/7] generate 23 auto-patches
      [7/7] generate Sigma/Splunk/Elastic/Suricata rules + audit report
```

Everything runs **100% locally**. Zero cloud cost. Zero API keys for LLM.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NOVA ARSENAL v4.0                               │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │             NATURAL LANGUAGE ENTRY POINT  (nova.py)               │  │
│  │   "Hunt X"  "Threat model Y"  "SCA scan"  "Full stack pipeline"   │  │
│  │   LLM intent parser → keyword fallback → dispatch                 │  │
│  └─────────────────────────────┬─────────────────────────────────────┘  │
│                                 │                                        │
│   ┌────────────────┐   ┌────────▼───────────┐   ┌─────────────────┐   │
│   │ nova_          │   │ nova_agent_core v2  │   │ launch_swarm    │   │
│   │ continuous_v3  │   │ (ReAct loop)        │   │ (10 parallel)   │   │
│   │ (24/7 + self-  │   └────────────────────-┘   └─────────────────┘   │
│   │  improvement)  │                                                     │
│   └────────────────┘                                                     │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │              v3.5 GAP-CLOSING MODULES                              │ │
│  │  nova_planner        — structured multi-phase planning  [Code]    │ │
│  │  nova_vision         — screenshot + LLM visual analysis [Mythos]  │ │
│  │  nova_verify_engine  — triple-confirm + CVSS + H1 pack  [Daybreak]│ │
│  │  nova_web_researcher — NVD/GitHub/OSV CVE + PoC lookup  [All 3]   │ │
│  │  nova_context_manager— rolling compression, 200+ steps  [Code]    │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │              v4.0 NEW — MYTHOS + DAYBREAK PARITY (8 modules)       │ │
│  │                                                                    │ │
│  │  nova_file_prioritizer   — Mythos 1-5 risk scoring before scan    │ │
│  │  nova_threat_model       — editable threat model + attack paths   │ │
│  │  nova_patch_generator    — auto-patch confirmed findings           │ │
│  │  nova_sca_scanner        — npm/pip/go CVE scan via OSV.dev         │ │
│  │  nova_git_scanner        — git history secret + regression scan   │ │
│  │  nova_sandbox_validator  — isolated exploit validation             │ │
│  │  nova_detection_engineer — Sigma/Splunk/Elastic/Suricata rules    │ │
│  │  nova_audit_reporter     — enterprise audit report + CVSS         │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │              SOURCE AUDITOR v2.0 (updated)                         │ │
│  │  nova_source_auditor — TypeScript/JS/Python multi-language sinks  │ │
│  │                        + Mythos-style file prioritization (1-5)   │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Installation

```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
pip3 install -r requirements.txt    # requests, beautifulsoup4, etc.

# Install Ollama + a model (optional — keyword fallback works without it)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:8b                # or llama3.2, mistral, etc.
```

---

## 4. Talking to Nova in Plain English

```bash
# Original modes
python3 nova.py "Hunt hackerone.com for SQL injection and SSRF"
python3 nova.py "Run a full swarm on localhost:3000"
python3 nova.py "Assess notion.so with Daybreak"
python3 nova.py "Recon target.com — subdomains and ports"
python3 nova.py "Improve yourself"
python3 nova.py "Run 24/7 continuous hunting"
python3 nova.py "Code review audit of ./src"

# v4.0 NEW modes
python3 nova.py "Build a threat model for ./juice-shop"
python3 nova.py "Scan dependencies for CVEs"
python3 nova.py "Scan git history for leaked secrets"
python3 nova.py "Patch all confirmed findings"
python3 nova.py "Generate SIEM detection rules"
python3 nova.py "Generate an enterprise audit report"
python3 nova.py "Run full-stack Mythos+Daybreak pipeline on ./juice-shop"

# Direct module usage
python3 nova_threat_model.py ./juice-shop
python3 nova_sca_scanner.py ./juice-shop
python3 nova_git_scanner.py ./juice-shop
python3 nova_audit_reporter.py nova_*_report.json
python3 nova_detection_engineer.py nova_audit_report.json
```

---

## 5. v3.5 Gap-Closing Capabilities

### 5.1 Pre-Hunt Strategic Planning — `nova_planner.py`
Generates a structured 8-phase attack plan before any tool call — matching Claude Code's planning capability.

### 5.2 Visual Screenshot Analysis — `nova_vision.py`
Screenshots the target and uses a vision-capable Ollama model to identify forms, auth state, admin links, and attack vectors.

### 5.3 Triple-Verify Engine — `nova_verify_engine.py`
Before reporting any finding: HTTP re-probe → browser re-probe → parameter variation test. Eliminates false positives.
Scores every confirmed finding with CVSS 3.1 and packages a HackerOne-ready bug report.

### 5.4 CVE/PoC Web Research — `nova_web_researcher.py`
Detects the tech stack (Express, Django, Rails, etc.), then queries NVD, GitHub Security Advisories, and OSV.dev for known CVEs and PoC exploits. Injects results into the agent context before the first tool call.

### 5.5 Context Window Compression — `nova_context_manager.py`
Rolling token budget manager. When the context exceeds 70% of the model's limit, it summarises and compresses older steps — enabling 200+ step hunts without context overflow.

### 5.6 20-Tool Agent Kit — `nova_tool_kit.py`
Full tool suite: bash, browser_navigate, http_request, take_screenshot, read_file, write_file, grep_code, install_package, self_review_code, self_remember, repo_index, run_nuclei, run_sqlmap, run_ffuf, run_nmap, run_nikto, check_cve, generate_poc, search_exploitdb, validate_finding.

---

## 6. v4.0 NEW — Mythos + Daybreak Parity

### 6.1 File Prioritization — `nova_file_prioritizer.py`

Replicates Mythos's critical capability: score every file 1–5 before scanning so the agent focuses on high-risk surfaces first.

| Score | Meaning | Examples |
|---|---|---|
| 5 | Direct user-input → sink | route handlers, auth, DB queries |
| 4 | Indirect high-risk | redirects, crypto, CORS config |
| 3 | Business logic | controllers, middleware |
| 2 | Utility / model | helpers, schemas |
| 1 | Static | constants, config reads |

```bash
python3 nova_file_prioritizer.py ./juice-shop
```

### 6.2 Threat Modeling — `nova_threat_model.py`

Daybreak-style editable threat model. Scans the codebase and outputs:

- **Entry points** — all HTTP routes, WebSocket events, CLI handlers
- **Trust boundaries** — DB, filesystem, external HTTP, session layer
- **Sensitive data flows** — passwords, keys, PII, payment data
- **Prioritised attack paths** — CRITICAL/HIGH ranked by type

Outputs JSON + Markdown. Directly editable and shareable.

```bash
python3 nova_threat_model.py ./juice-shop
# → nova_threat_model_report.json
# → nova_threat_model_report.md
```

### 6.3 Patch Generator — `nova_patch_generator.py`

For every confirmed finding, generates a safe code fix. Two modes:

- **AUTO-APPLIED** — regex-matched fix with high confidence (e.g. `innerHTML =` → `textContent =`)
- **GENERIC GUIDANCE** — correct-by-construction template for the vuln class

Supports: SQL injection, XSS, path traversal, open redirect, command injection, SSRF, XXE, insecure deserialization, auth bypass, prototype pollution.

```bash
python3 nova_patch_generator.py nova_audit_report.json
# → nova_patches.json
# → nova_patches.md
```

### 6.4 SCA Scanner — `nova_sca_scanner.py`

Software Composition Analysis — scans `package.json`, `requirements.txt`, `go.mod`, `pom.xml` and more.

- Built-in DB of 25+ high-impact npm/pip CVEs (lodash, axios, express, jsonwebtoken, etc.)
- Live OSV.dev API queries for packages not in the built-in DB
- Zero API keys required

```bash
python3 nova_sca_scanner.py ./juice-shop
# → nova_sca_report.json
```

### 6.5 Git History Scanner — `nova_git_scanner.py`

Scans **all git commits** (not just the working tree) for:

- 20 secret patterns: AWS keys, GitHub tokens, Stripe keys, RSA private keys, DB URLs, JWT secrets, etc.
- Security regression patterns: `eval()`, `innerHTML`, wildcard CORS, debug mode, disabled SSL
- Working tree scan as well

Masked output (no actual secrets printed).

```bash
python3 nova_git_scanner.py ./juice-shop
# → nova_git_scan_report.json
```

### 6.6 Sandbox Validator — `nova_sandbox_validator.py`

Mythos-style isolated exploit validation. For each confirmed finding, fires up to 3 targeted probes against a live target and checks responses for positive indicators.

```bash
python3 nova_sandbox_validator.py http://localhost:3000 nova_findings.json
# → nova_sandbox_validation.json
```

### 6.7 Detection Engineer — `nova_detection_engineer.py`

Converts confirmed findings into detection rules in **4 SIEM formats simultaneously**:

| Format | Use |
|---|---|
| **Sigma** | Universal — import to any SIEM |
| **Splunk SPL** | Direct paste into Splunk |
| **Elastic KQL** | Elastic Security / Kibana |
| **Suricata** | IDS/IPS rule file |

Covers: SQLi, XSS, path traversal, SSRF, command injection, open redirect, XXE, auth bypass.

```bash
python3 nova_detection_engineer.py nova_audit_report.json
# → nova_detection_rules.json
# → nova_detection_rules_sigma.yml
# → nova_detection_rules_suricata.rules
```

### 6.8 Audit Reporter — `nova_audit_reporter.py`

Enterprise-grade compliance report aggregating all Nova findings:

- **CVSS 3.1 base scores** for every finding
- **Remediation SLA timeline** (Critical: 7d, High: 30d, Medium: 90d)
- **Compliance notes** — PCI DSS, SOC 2, ISO 27001, OWASP ASVS
- **Executive summary** with risk rating
- **Remediation roadmap** with due dates
- JSON + Markdown output

```bash
python3 nova_audit_reporter.py nova_*_report.json
# → nova_audit_report.json
# → nova_audit_report.md
```

---

## 7. Module Reference

| Module | Version | Purpose | Gap Closed |
|---|---|---|---|
| `nova.py` | v4.0 | Natural language entry point + dispatcher | — |
| `nova_agent_core.py` | v2 | ReAct hunt loop, 20 tools | — |
| `nova_continuous_v3.py` | v3 | 24/7 hunting with self-improvement | — |
| `launch_swarm.py` | v1 | 10-agent parallel swarm | — |
| `nova_planner.py` | v1 | Pre-hunt 8-phase planning | Code |
| `nova_vision.py` | v1 | Screenshot + visual LLM analysis | Mythos |
| `nova_verify_engine.py` | v1 | Triple-verify + CVSS + H1 report | Daybreak |
| `nova_web_researcher.py` | v1 | CVE/PoC web research | All 3 |
| `nova_context_manager.py` | v1 | Rolling context compression | Code |
| `nova_tool_kit.py` | v2 | 20-tool agent kit | All 3 |
| `nova_source_auditor.py` | **v2.0** | Multi-language taint tracing (TS+JS+Python) + file prioritization | Mythos |
| `nova_file_prioritizer.py` | **v1.0 NEW** | Mythos 1-5 risk scoring before scan | **Mythos** |
| `nova_threat_model.py` | **v1.0 NEW** | Attack surface + trust boundary + attack paths | **Daybreak** |
| `nova_patch_generator.py` | **v1.0 NEW** | Auto-patch generation for confirmed findings | **Daybreak** |
| `nova_sca_scanner.py` | **v1.0 NEW** | SCA — npm/pip/go/maven CVE scanning | **Daybreak** |
| `nova_git_scanner.py` | **v1.0 NEW** | Git history secret + regression scanning | **Mythos** |
| `nova_sandbox_validator.py` | **v1.0 NEW** | Isolated exploit validation | **Mythos** |
| `nova_detection_engineer.py` | **v1.0 NEW** | Sigma/Splunk/Elastic/Suricata rule generation | **Daybreak** |
| `nova_audit_reporter.py` | **v1.0 NEW** | Enterprise audit report + CVSS + SLA | **Daybreak** |

---

## 8. Capability Parity Table

| Capability | Claude Mythos | OpenAI Daybreak | Nova v3.5 | **Nova v4.0** |
|---|---|---|---|---|
| File risk prioritization (1-5) | ✅ | ❌ | ❌ | **✅** |
| Editable threat modeling | ❌ | ✅ | ❌ | **✅** |
| Auto patch generation | ❌ | ✅ | ❌ | **✅** |
| SCA / dependency CVE scan | ❌ | ✅ | ❌ | **✅** |
| Git history secret scanning | ✅ | ❌ | ❌ | **✅** |
| Sandbox exploit validation | ✅ | ❌ | ❌ | **✅** |
| SIEM detection rule generation | ❌ | ✅ | ❌ | **✅** |
| Enterprise audit report | ❌ | ✅ | ❌ | **✅** |
| Pre-hunt strategic planning | ✅ | ✅ | ✅ | ✅ |
| Visual screenshot analysis | ✅ | ✅ | ✅ | ✅ |
| Triple-verify findings | ✅ | ✅ | ✅ | ✅ |
| CVE/PoC web research | ✅ | ✅ | ✅ | ✅ |
| Context window compression | ✅ | ✅ | ✅ | ✅ |
| 20-tool agent kit | ✅ | ✅ | ✅ | ✅ |
| TypeScript taint tracing | ✅ | ✅ | partial | **✅** |
| Zero LLM cost | ❌ | ❌ | ✅ | ✅ |
| **Gap score** | | | **7/8 gaps** | **0/8 gaps** |

---

## 9. Configuration

| Environment Variable | Default | Purpose |
|---|---|---|
| `NOVA_LLM_URL` | `http://localhost:11434` | Ollama endpoint |
| `NOVA_LLM_MODEL` | auto-detect | Override LLM model |
| `NOVA_WORKSPACE` | `~/nova_workspace` | Output directory |
| `NOVA_MAX_STEPS` | `40` | Max ReAct loop steps |
| `NOVA_TARGET` | `http://localhost:3000` | Default target |
| `NOVA_ORG_NAME` | `Target Organization` | Audit report org name |
| `HACKERONE_PROGRAM` | _(required for H1)_ | HackerOne program handle |

---

## 10. HackerOne Integration

Nova's `nova_verify_engine.py` produces HackerOne-ready bug reports automatically:

```json
{
  "title": "SQL Injection in /rest/products/search",
  "severity": "critical",
  "cvss_score": 9.8,
  "weakness": "CWE-89",
  "description": "...",
  "steps_to_reproduce": "...",
  "impact": "...",
  "proof_of_concept": "curl ..."
}
```

Set `HACKERONE_PROGRAM` and Nova will format every confirmed finding as a submission-ready JSON object.

---

<div align="center">

*Nova Arsenal v4.0 — Built for small enterprises. Rivaling frontier AI security systems. Zero cost.*

</div>
