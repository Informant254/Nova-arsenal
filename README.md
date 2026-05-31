# 🦅 Nova Arsenal v4.1

> **Fully autonomous AI security research agent — as powerful as OpenAI Agents SDK and Anthropic Claude Agent SDK, running 100% locally.**  
> Multi-provider LLM · Lifecycle hooks · Typed context · Session memory · Full execution tracing · 80+ specialist modules

---

## What Nova Does

Nova is a production-grade autonomous security research agent that:

- Plans and executes complete bug bounty hunts from a single plain-English command
- Uses **80+ specialist modules** covering the full security research lifecycle
- **Supports OpenAI, Anthropic, Gemini, and Ollama** — auto-fallback chain, zero single-provider lock-in
- Runs a real headless browser (Playwright) for JS-heavy targets
- Chains vulnerabilities together (SSRF → metadata, SQLi → RCE, XSS → account takeover)
- **Orchestrates multi-agent pipelines** with handoffs, guardrails, typed context, and full execution tracing
- **Lifecycle hooks** (PreRun, PostRun, PreTool, PostTool, OnFinding, OnError…) — same pattern as Anthropic Claude Agent SDK
- **Persistent sessions** across runs — Nova remembers everything she learned
- **Structured outputs** with JSON schema validation across all providers
- **Streaming support** across all LLM providers
- **Reusable Skills** — parameterised prompt templates for every attack class
- AI-triages and ranks all findings so you always work the highest-impact bugs first
- Runs 24/7 on GitHub Actions (free cloud Linux)

---

## Architecture

```
nova.py                         ← Single plain-English entry point (NLP → dispatch)
│
├── 🔀 Provider Layer (NEW v4.1)
│   ├── nova_llm_router.py          ← Multi-provider LLM: OpenAI · Anthropic · Gemini · Ollama
│   │     Auto-fallback · Streaming · Structured outputs · Cost tracking · Circuit breaker
│   ├── nova_hooks.py               ← Lifecycle hook system (Anthropic Agent SDK pattern)
│   │     PreRun · PostRun · PreTool · PostTool · OnFinding · OnError · OnHandoff
│   ├── nova_context.py             ← Typed context variables (OpenAI Agents SDK pattern)
│   │     Shared state · Child contexts · Scope enforcement · Audit trail
│   ├── nova_sessions.py            ← Persistent session management
│   │     Conversation history · Cross-run findings · Working memory · Cost accounting
│   ├── nova_retry.py               ← Retry + circuit breaker
│   │     Exponential backoff · Per-service circuit breaker · Budget enforcement
│   ├── nova_skills.py              ← Reusable skill/prompt templates (Anthropic Skills pattern)
│   │     20+ built-in skills: SQLi · XSS · IDOR · SSRF · JWT · STRIDE · H1 reports
│   └── nova_observability.py       ← OpenTelemetry-compatible execution tracing
│         Span trees · Token attribution · Cost per span · HTML + JSON export
│
├── 🧠 Agent Layer
│   ├── nova_orchestrator.py    ← Multi-agent engine (Agents · Handoffs · Guardrails · Tracing)
│   ├── nova_mcp_client.py      ← Model Context Protocol client
│   └── nova_triage.py          ← AI-powered findings prioritiser
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

## Installation

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 20.04 / macOS 12 / Kali 2023 | Kali Linux 2024 / Ubuntu 22.04 |
| Python | 3.10 | 3.12 |
| RAM | 8 GB | 16 GB+ |
| Storage | 20 GB | 50 GB+ |
| CPU | 4 cores | 8+ cores |
| GPU | None (CPU inference) | NVIDIA 8 GB VRAM (for local models) |

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/Informant254/Nova-arsenal
cd Nova-arsenal
```

---

### Step 2 — Run the Setup Script

The setup script installs everything: Python venv, all dependencies, security tools, Playwright, and Ollama models.

```bash
chmod +x nova_setup.sh
./nova_setup.sh
```

**Options:**

```bash
./nova_setup.sh --minimal        # Python + deps only (no security tools, no models)
./nova_setup.sh --models-only    # Pull Ollama models only
```

The script installs:
- Python virtual environment with all pip dependencies
- Ollama (local LLM runtime)
- Recommended Ollama models: `qwen3:8b` (primary), `llama3.2` (fallback), `nomic-embed-text` (RAG)
- System security tools: `nmap`, `nuclei`, `subfinder`, `httpx`, `gau`, `katana`, `ffuf`
- Playwright headless browser (Chromium)
- Nova workspace at `~/nova_workspace/`

---

### Step 3 — Activate the Virtual Environment

```bash
source ~/nova_workspace/.venv/bin/activate
```

Add this to your `~/.bashrc` or `~/.zshrc` to activate automatically:

```bash
echo 'source ~/nova_workspace/.venv/bin/activate' >> ~/.bashrc
```

---

### Step 4 — Configure LLM Providers

Nova supports four LLM providers with automatic fallback. Ollama is always the final fallback (free, local).

#### Option A: Local Only (Ollama — zero cost, zero data leakage)

```bash
# Ollama is started automatically. Verify it's running:
ollama list

# Pull the recommended model if not already installed:
ollama pull qwen3:8b
```

#### Option B: OpenAI (GPT-4o, o3)

```bash
export OPENAI_API_KEY="sk-..."
export NOVA_OPENAI_MODEL="gpt-4o"          # default
# or: gpt-4o-mini (faster/cheaper), o3 (most powerful)
```

#### Option C: Anthropic (Claude Sonnet 4, Claude Opus 4)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export NOVA_ANTHROPIC_MODEL="claude-sonnet-4-5"   # default
# or: claude-opus-4-5 (most powerful), claude-haiku-3-5 (fastest)
```

#### Option D: Google Gemini

```bash
export GEMINI_API_KEY="AIza..."
export NOVA_GEMINI_MODEL="gemini-2.0-flash"       # default
# or: gemini-2.5-pro (most powerful)
```

#### Recommended: Set Multiple Providers (Auto-Fallback)

```bash
# Nova tries providers in this order: OpenAI → Anthropic → Gemini → Ollama
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="AIza..."

# Persist to shell profile:
cat >> ~/.bashrc << 'EOF'
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="AIza..."
EOF
```

#### Test Your LLM Setup

```bash
python3 nova_llm_router.py "Hello Nova. What providers are available?"
python3 nova_llm_router.py --stream "Summarise OWASP Top 10 in 5 bullets"
python3 nova_llm_router.py --provider anthropic "What is SSRF?"
```

---

### Step 5 — Configure Notifications (Optional)

#### Telegram

```bash
export NOVA_TELEGRAM_TOKEN="bot123:ABC..."
export NOVA_TELEGRAM_CHAT_ID="123456789"
```

Nova will send real-time alerts for CRITICAL/HIGH findings and agent errors.

#### Discord

```bash
export NOVA_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
```

#### Slack

```bash
export NOVA_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
```

---

### Step 6 — Configure the Workspace (Optional)

Copy and edit the default config:

```bash
cp nova_config.json ~/nova_workspace/nova_config.json
nano ~/nova_workspace/nova_config.json
```

Key settings:

```json
{
  "llm": {
    "model":          "auto",
    "fallback_model": "llama3.2",
    "timeout":        120
  },
  "recon": {
    "max_subdomains": 500,
    "max_urls":       10000,
    "threads":        10
  },
  "attack": {
    "severity_threshold": "low",
    "max_payloads_per_param": 50,
    "respect_robots": false
  },
  "notifications": {
    "min_severity": "high"
  }
}
```

---

### Step 7 — Verify Installation

```bash
python3 nova.py "health check"
```

Expected output:
```
🦅 Nova Arsenal v4.1 — Health Check
  ✅ LLM router: 3 providers available (openai, anthropic, ollama)
  ✅ Hooks system: ready
  ✅ Session store: ~/nova_workspace/sessions/
  ✅ Observability: tracing ready
  ✅ Skills library: 20 skills loaded
  ✅ Security tools: nuclei, subfinder, httpx, nmap, gau
  ✅ Browser: Playwright Chromium
  ✅ Workspace: ~/nova_workspace/
Nova is ready. 🦅
```

---

## Quick Start

```bash
# Activate venv first
source ~/nova_workspace/.venv/bin/activate

# Single command — Nova figures out everything else
python3 nova.py "Hunt https://target.com for all bugs"
python3 nova.py "Daybreak AI assessment on https://target.com"
python3 nova.py "Orchestrate multi-agent hunt on https://target.com"
python3 nova.py "Triage my findings and show me what to report to H1"
python3 nova.py "Full stack scan of https://target.com"
```

---

## Dispatch Modes — Plain English Commands

| Say something like… | Mode | What runs |
|---|---|---|
| `"daybreak assessment on target.com"` | `daybreak` | NovaDaybreak + NovaScopeManager |
| `"orchestrate multi-agent hunt"` | `orchestrate` | NovaOrchestrator → ReconAgent → AttackAgent → ReportAgent |
| `"triage my findings"` | `triage` | NovaTriage: dedup → LLM score → chain → H1 ranking |
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

## v4.1 Provider Layer — New in This Release

### 🔀 nova_llm_router.py — Multi-Provider with Auto-Fallback

The same provider-agnostic pattern used by OpenAI Agents SDK, running on any LLM:

```python
from nova_llm_router import LLMRouter, Provider

router = LLMRouter()
print("Available:", router.available_providers())

# Auto-selects best available provider
resp = router.chat("Analyse this JWT: eyJhbGci...")
print(f"[{resp.provider}/{resp.model}] {resp.latency_ms:.0f}ms ${resp.cost_usd:.5f}")
print(resp.content)

# Force a specific provider
resp = router.chat("...", provider=Provider.ANTHROPIC)

# Streaming
for token in router.stream("Summarise these findings: ..."):
    print(token, end="", flush=True)

# Structured output (JSON schema enforced)
schema = {
    "type": "object",
    "properties": {
        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        "cvss":     {"type": "number"},
        "summary":  {"type": "string"}
    },
    "required": ["severity", "cvss", "summary"]
}
result = router.chat_structured("Score this finding: SQL injection in /api/search", schema=schema)
print(result)  # {"severity": "HIGH", "cvss": 8.2, "summary": "..."}
```

---

### 🪝 nova_hooks.py — Lifecycle Hooks (Anthropic Agent SDK Pattern)

```python
from nova_hooks import HookBus, attach_logging_hooks, attach_telegram_hooks

bus = HookBus(verbose=True)
attach_logging_hooks(bus)  # writes events to nova_events.jsonl
attach_telegram_hooks(bus, token=TELEGRAM_TOKEN, chat_id=CHAT_ID)

# Custom hooks
@bus.on("OnFinding")
def save_to_db(ctx):
    finding = ctx["finding"]
    if finding["severity"] in ("CRITICAL", "HIGH"):
        my_db.insert(finding)

@bus.on("PreTool", priority=0)
def check_scope(ctx):
    if "out-of-scope.com" in ctx.get("args", {}).get("url", ""):
        ctx["_hook_event"].cancelled = True   # block the tool call
        print("⛔ Blocked out-of-scope request")

# Fire hooks manually
bus.fire("PreRun", {"agent": "ReconAgent", "target": "example.com"})
bus.fire_finding({"type": "XSS", "severity": "HIGH", "endpoint": "/search"})
```

---

### 📦 nova_context.py — Typed Context (OpenAI Agents SDK Pattern)

```python
from nova_context import RunContext

ctx = RunContext(
    target="https://example.com",
    scope=["example.com", "*.example.com"],
    max_steps=40,
    verbose=True
)

# Set / get typed values
ctx.set("phase", "recon")
ctx.append("subdomains", "api.example.com", dedupe=True)
ctx.add_finding({"type": "SQLi", "severity": "HIGH", "endpoint": "/api/search"})

# Scope enforcement
print(ctx.in_scope("https://api.example.com/users"))  # True
print(ctx.in_scope("https://evil.com"))               # False

# Child context per agent
recon_ctx = ctx.child("ReconAgent")
attack_ctx = ctx.child("AttackAgent")

# Merge results back
ctx.sync_from_child(recon_ctx)
ctx.sync_from_child(attack_ctx)

# Persist
ctx.save()  # ~/nova_workspace/context_{session_id}.json
print(ctx.summary())
```

---

### 🗂️ nova_sessions.py — Persistent Sessions

```python
from nova_sessions import SessionStore

store = SessionStore()

# Create a session for a target
session = store.create(target="https://example.com", mission="full_stack")

# Conversation history (survives restarts)
session.add_message("user", "Hunt example.com for IDOR and SQLi")
session.add_message("assistant", "Starting multi-mode scan...")

# Persistent findings (deduplicated)
session.add_finding({"type": "SQLi", "severity": "HIGH", "endpoint": "/api/users"})

# Working memory
session.remember("admin_endpoint", "/api/admin/users")
endpoint = session.recall("admin_endpoint")

# Run tracking
run = session.start_run("sqli")
# ... run the scan ...
session.end_run(run, findings_count=3, cost_usd=0.04, token_total=12000)

store.save(session)

# Resume later
session = store.load(session.session_id)
print(session.all_findings(min_severity="HIGH"))
```

---

### 🔭 nova_observability.py — Execution Tracing

```python
from nova_observability import Tracer

tracer = Tracer(run_id="hunt_20260601", verbose=True)

with tracer.span("ReconAgent", kind="agent") as recon_span:
    recon_span.set("target", "example.com")

    with tracer.tool_span("subfinder", args={"domain": "example.com"},
                          parent=recon_span) as tool:
        # ... run subfinder ...
        tool.set("result_count", 42)

    with tracer.llm_span("gpt-4o", "openai", parent=recon_span) as llm:
        llm.tokens_in  = 800
        llm.tokens_out = 300
        llm.cost_usd   = 0.005

tracer.print_tree()        # coloured tree in terminal
tracer.save()              # ~/nova_workspace/trace_hunt_20260601.json
tracer.export_html()       # ~/nova_workspace/trace_hunt_20260601.html
print(tracer.summary())
```

---

### 🎯 nova_skills.py — Reusable Skills (Anthropic Skills Pattern)

```python
from nova_skills import SkillLibrary

lib = SkillLibrary()
print(lib.list_skills())                    # all 20+ built-in skills

# Render a skill with parameters → get system + user prompts
prompts = lib.render("sqli_analysis",
    target="example.com",
    endpoint="/api/search",
    param="q",
    method="GET",
    request_sample="GET /api/search?q=test HTTP/1.1\nHost: example.com")

# Feed directly to the LLM router
from nova_llm_router import get_router
router = get_router()
resp = router.chat(prompts["user"], system=prompts["system"])
import json
payloads = json.loads(resp.content)

# Register custom skill
from nova_skills import Skill
lib.register(Skill(
    name="my_custom_skill",
    category="attack",
    description="My custom attack template",
    system="You are a security expert...",
    template="Target: {target}\nAnalyse for: {vuln_type}",
    params=["target", "vuln_type"],
))
```

---

## Cloud: GitHub Actions (24/7 Free)

```bash
# Set repository secrets in GitHub:
# GITHUB_TOKEN (already set), OPENAI_API_KEY, ANTHROPIC_API_KEY, NOVA_TELEGRAM_TOKEN

python3 nova_cloud.py hunt https://target.com
python3 nova_cloud.py watch <run-id>
python3 nova_cloud.py results
```

The workflow runs on `ubuntu-latest` with all dependencies pre-installed.

---

## Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | OpenAI API key |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `GEMINI_API_KEY` | — | Google Gemini API key |
| `NOVA_LLM_URL` | `http://localhost:11434` | Ollama server URL |
| `NOVA_LLM_MODEL` | `qwen3:8b` | Ollama model name |
| `NOVA_OPENAI_MODEL` | `gpt-4o` | OpenAI model to use |
| `NOVA_ANTHROPIC_MODEL` | `claude-sonnet-4-5` | Anthropic model to use |
| `NOVA_GEMINI_MODEL` | `gemini-2.0-flash` | Gemini model to use |
| `NOVA_WORKSPACE` | `~/nova_workspace` | Nova workspace directory |
| `NOVA_MAX_STEPS` | `40` | Max ReAct loop steps |
| `NOVA_TARGET` | `http://localhost:3000` | Default target |
| `NOVA_TELEGRAM_TOKEN` | — | Telegram bot token |
| `NOVA_TELEGRAM_CHAT_ID` | — | Telegram chat ID |
| `NOVA_DISCORD_WEBHOOK` | — | Discord webhook URL |
| `NOVA_SLACK_WEBHOOK` | — | Slack webhook URL |

---

## Troubleshooting

### Ollama not found

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull qwen3:8b
```

### "All LLM providers failed"

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Check API keys
echo $OPENAI_API_KEY
echo $ANTHROPIC_API_KEY

# Test router directly
python3 nova_llm_router.py "test"
```

### Module import errors

```bash
source ~/nova_workspace/.venv/bin/activate
pip install -r requirements.txt    # if requirements.txt exists
# or re-run setup:
./nova_setup.sh --minimal
```

### Playwright browser not found

```bash
playwright install chromium
playwright install-deps chromium
```

### Circuit breaker open (provider temporarily blocked)

Circuit breakers reset automatically after 60 seconds. Or restart Nova:

```bash
# The circuit breaker is in-process; restarting clears it.
python3 nova.py "health check"
```

---

## Comparison: Nova vs OpenAI Agents SDK vs Anthropic Agent SDK

| Feature | Nova Arsenal v4.1 | OpenAI Agents SDK | Anthropic Agent SDK |
|---|---|---|---|
| **Multi-agent orchestration** | ✅ | ✅ | ✅ |
| **Agent handoffs** | ✅ | ✅ | ✅ |
| **Input/output guardrails** | ✅ | ✅ | ✅ |
| **Lifecycle hooks** | ✅ | Partial | ✅ (PreToolUse, PostToolUse…) |
| **Typed context variables** | ✅ | ✅ | — |
| **Structured outputs** | ✅ All providers | ✅ OpenAI only | ✅ Claude only |
| **Streaming** | ✅ All providers | ✅ | ✅ |
| **Execution tracing** | ✅ | ✅ | Partial |
| **Persistent sessions** | ✅ | ✅ | — |
| **Skills / prompt templates** | ✅ 20+ built-in | — | ✅ |
| **Multi-provider LLM** | ✅ 4 providers | Partial | ❌ Claude only |
| **Local / offline mode** | ✅ Ollama | ❌ | ❌ |
| **Security domain built-in** | ✅ 80+ modules | ❌ General purpose | ❌ General purpose |
| **Circuit breaker** | ✅ | ❌ | ❌ |
| **GitHub Actions 24/7** | ✅ | Partial | — |
| **Zero cost option** | ✅ Ollama | ❌ | ❌ |
| **HackerOne integration** | ✅ | — | — |

---

## License

MIT — see `LICENSE` for details.

Bug bounty responsibly. Only test systems you have written permission to test.  
HackerOne safe-harbor applies when targeting programs that explicitly grant it.
