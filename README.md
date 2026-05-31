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
- **Orchestrates multi-agent pipelines** with hooks, typed context, sessions, and full span-based tracing — wired into every run automatically
- **Lifecycle hooks** (PreRun, PostRun, PreTool, PostTool, OnFinding, OnError…) — same pattern as Anthropic Claude Agent SDK
- **Persistent sessions** across runs — Nova remembers everything she learned
- **Structured outputs** with JSON schema validation across all providers
- **Streaming support** across all LLM providers
- **Reusable Skills** — 20+ parameterised prompt templates for every attack class
- AI-triages and ranks all findings so you always work the highest-impact bugs first
- Runs 24/7 on GitHub Actions (free cloud Linux)

---

## Architecture

```
nova.py                         ← Single plain-English entry point (NLP → dispatch)
│
├── 🔀 Provider Layer (v4.1)
│   ├── nova_llm_router.py          ← Multi-provider LLM: OpenAI · Anthropic · Gemini · Ollama
│   │     Auto-fallback · Streaming · Structured outputs · Cost tracking · Circuit breaker
│   ├── nova_hooks.py               ← Lifecycle hook system (Anthropic Agent SDK pattern)
│   │     PreRun · PostRun · PreTool · PostTool · OnFinding · OnError · OnHandoff
│   ├── nova_context.py             ← Typed context variables (OpenAI Agents SDK pattern)
│   │     Shared state · Child contexts · Scope enforcement · Audit trail
│   ├── nova_sessions.py            ← Persistent session management
│   │     Conversation history · Cross-run findings · Working memory · Cost accounting
│   ├── nova_retry.py               ← Retry + circuit breaker
│   │     Exponential backoff · Per-tool circuit breaker · Budget enforcement
│   ├── nova_skills.py              ← Reusable skill/prompt templates (Anthropic Skills pattern)
│   │     20+ built-in skills: SQLi · XSS · IDOR · SSRF · JWT · STRIDE · H1 reports
│   └── nova_observability.py       ← OpenTelemetry-compatible execution tracing
│         Span trees · Token attribution · Cost per span · HTML + JSON export
│
├── 🧠 Agent Layer
│   ├── nova_orchestrator.py    ← v2.0: all 7 provider-layer modules wired in automatically
│   │     LLMRouter · HookBus · RunContext · Session · Tracer · Retry on every run
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
- Ollama (local LLM runtime) + recommended models: `qwen3:8b`, `llama3.2`, `nomic-embed-text`
- System security tools: `nmap`, `nuclei`, `subfinder`, `httpx`, `gau`, `katana`, `ffuf`
- Playwright headless browser (Chromium)
- Nova workspace at `~/nova_workspace/`

---

### Step 3 — Activate the Virtual Environment

```bash
source ~/nova_workspace/.venv/bin/activate

# Optional: auto-activate in every terminal session
echo 'source ~/nova_workspace/.venv/bin/activate' >> ~/.bashrc
```

---

### Step 4 — Configure LLM Providers

Nova supports four providers with automatic fallback. Ollama is always the final fallback (free, local, zero data leakage).

#### Option A — Local Only (Ollama, zero cost)

```bash
ollama list                   # verify models are available
ollama pull qwen3:8b          # pull if missing
python3 nova_llm_router.py "Hello"   # test
```

#### Option B — OpenAI (GPT-4o, o3)

```bash
export OPENAI_API_KEY="sk-..."
export NOVA_OPENAI_MODEL="gpt-4o"        # default; or gpt-4o-mini / o3
```

#### Option C — Anthropic (Claude Sonnet 4, Claude Opus 4)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export NOVA_ANTHROPIC_MODEL="claude-sonnet-4-5"   # or claude-opus-4-5 / claude-haiku-3-5
```

#### Option D — Google Gemini

```bash
export GEMINI_API_KEY="AIza..."
export NOVA_GEMINI_MODEL="gemini-2.0-flash"       # or gemini-2.5-pro
```

#### Recommended — Multiple Providers (Auto-Fallback Chain)

Nova tries: **OpenAI → Anthropic → Gemini → Ollama**

```bash
cat >> ~/.bashrc << 'EOF'
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="AIza..."
EOF
source ~/.bashrc

# Test the router
python3 nova_llm_router.py "What providers are available?"
python3 nova_llm_router.py --stream "Summarise OWASP Top 10"
python3 nova_llm_router.py --provider anthropic "What is SSRF?"
```

---

### Step 5 — Configure Notifications (Optional)

#### Telegram (real-time CRITICAL/HIGH alerts)

```bash
export NOVA_TELEGRAM_TOKEN="bot123:ABC..."
export NOVA_TELEGRAM_CHAT_ID="123456789"
```

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

```bash
cp nova_config.json ~/nova_workspace/nova_config.json
nano ~/nova_workspace/nova_config.json
```

Key settings to review:

```json
{
  "llm": { "model": "auto", "fallback_model": "llama3.2", "timeout": 120 },
  "recon": { "max_subdomains": 500, "max_urls": 10000, "threads": 10 },
  "attack": { "severity_threshold": "low", "max_payloads_per_param": 50 },
  "notifications": { "min_severity": "high" }
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
  ✅ LLM router: 3 providers (openai, anthropic, ollama)
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
source ~/nova_workspace/.venv/bin/activate

python3 nova.py "Hunt https://target.com for all bugs"
python3 nova.py "Daybreak AI assessment on https://target.com"
python3 nova.py "Orchestrate multi-agent hunt on https://target.com"
python3 nova.py "Triage my findings and show me what to report to H1"
python3 nova.py "Full stack scan of https://target.com"
```

---

## Dispatch Modes

| Say something like… | Mode | What runs |
|---|---|---|
| `"daybreak assessment on target.com"` | `daybreak` | NovaDaybreak + NovaScopeManager |
| `"orchestrate multi-agent hunt"` | `orchestrate` | NovaOrchestrator v2.0 (all modules wired) |
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

## nova_orchestrator.py v2.0 — All Modules Wired In

Every `build_security_network()` call and `Runner` automatically uses all 7 provider-layer modules. No extra setup needed.

### What happens on every run

```
nova_orchestrator.Runner.run("Hunt example.com")
│
├── LLMRouter       — picks best available provider (OpenAI → Anthropic → Gemini → Ollama)
│                     with exponential backoff and circuit breaker per provider
│
├── HookBus         — fires PreRun at start; PostRun on completion
│   │                 PreTool/PostTool wraps every tool call
│   └── logging     — writes all events to ~/nova_workspace/nova_events.jsonl
│   └── telegram    — fires CRITICAL/HIGH findings to Telegram (if configured)
│
├── RunContext       — typed shared state flows through all 3 agents
│   ├── scope check — blocks out-of-scope URLs before every tool call
│   ├── findings    — deduplicated findings merged from all agents
│   └── audit trail — every mutation recorded with agent + timestamp
│
├── Session          — persisted to ~/nova_workspace/sessions/<id>.json
│   ├── messages    — full conversation history survives restarts
│   ├── findings    — cross-run deduplication
│   └── cost/tokens — per-run accounting
│
├── Tracer           — span tree: Run → Agent → Tool/LLM spans
│   ├── timing      — ms for every operation
│   ├── tokens/cost — attributed to each LLM span
│   └── export      — JSON + HTML flame graph saved after every run
│
└── ResilientCaller  — wraps every tool with retry (3 attempts, exponential backoff)
                       + per-tool circuit breaker (opens after 3 consecutive failures)
```

### Using the orchestrator directly

```python
from nova_orchestrator import build_security_network, Runner, Agent, Tool, Guardrail

# Quickstart — full wired network
runner = build_security_network(
    target="https://example.com",
    scope=["example.com", "*.example.com"])
result = runner.run("Hunt for IDOR, SQLi, and XSS vulnerabilities")

print(f"Findings: {len(result.findings)}")
print(f"Cost:     ${result.cost_usd:.5f}")
print(f"Tokens:   {result.tokens_used}")

# With session resume
from nova_sessions import SessionStore
store   = SessionStore()
session = store.create(target="https://example.com", mission="full_stack")

runner = build_security_network(
    "https://example.com",
    scope=["example.com"],
    session=session)
result = runner.run("Orchestrate multi-agent hunt")

# Resume next time
session2 = store.load(session.session_id)
print(f"Previous findings: {len(session2.findings)}")
```

### Injecting custom hooks

```python
from nova_hooks import get_bus

bus = get_bus()

@bus.on("OnFinding")
def alert_on_critical(ctx):
    f = ctx["finding"]
    if f.get("severity") == "CRITICAL":
        send_pagerduty_alert(f)

@bus.on("PreTool")
def block_out_of_scope(ctx):
    url = ctx.get("args", {}).get("url", "")
    if "forbidden.com" in url:
        ctx["_hook_event"].cancelled = True

runner = build_security_network("https://example.com")
# bus is already wired in — hooks fire automatically
result = runner.run("Full scan")
```

### Parallel agent fan-out

```python
runner = build_security_network("https://example.com")
results = runner.run_parallel(
    task="Hunt for XSS, SQLi, and IDOR",
    agent_names=["ReconAgent", "AttackAgent"])  # run both in parallel

all_findings = [f for r in results for f in r.findings]
```

---

## Provider Layer — Reference

### nova_llm_router.py

```python
from nova_llm_router import LLMRouter, Provider

router = LLMRouter()
print(router.available_providers())   # ['openai', 'anthropic', 'ollama']

resp = router.chat("Analyse this JWT: eyJhbGci...")
print(f"[{resp.provider}/{resp.model}] {resp.latency_ms:.0f}ms ${resp.cost_usd:.5f}")

# Force provider
resp = router.chat("...", provider=Provider.ANTHROPIC)

# Streaming
for token in router.stream("Summarise these findings"):
    print(token, end="", flush=True)

# Structured output
result = router.chat_structured(
    "Score this finding",
    schema={"type":"object","properties":{"severity":{"type":"string"},"cvss":{"type":"number"}}})
```

### nova_hooks.py

```python
from nova_hooks import HookBus, attach_logging_hooks, attach_telegram_hooks

bus = HookBus(verbose=True)
attach_logging_hooks(bus)

@bus.on("OnFinding")
def on_finding(ctx):
    print(f"  🐛 [{ctx['finding']['severity']}] {ctx['finding']['type']}")

@bus.on("PreTool", priority=0)
def scope_check(ctx):
    if "evil.com" in str(ctx.get("args", {})):
        ctx["_hook_event"].cancelled = True
```

### nova_context.py

```python
from nova_context import RunContext

ctx = RunContext(target="https://example.com", scope=["example.com"])
ctx.set("phase", "attack")
ctx.append("subdomains", "api.example.com", dedupe=True)
ctx.add_finding({"type": "SQLi", "severity": "HIGH", "endpoint": "/api/search"})
print(ctx.in_scope("https://api.example.com"))   # True
print(ctx.summary())
ctx.save()
```

### nova_sessions.py

```python
from nova_sessions import SessionStore

store   = SessionStore()
session = store.create(target="https://example.com", mission="full_stack")
session.add_finding({"type": "XSS", "severity": "HIGH", "endpoint": "/search"})
session.remember("admin_token", "Bearer abc123")
store.save(session)

session = store.load(session.session_id)
print(session.all_findings(min_severity="HIGH"))
```

### nova_retry.py

```python
from nova_retry import retry, CircuitBreaker, ResilientCaller

@retry(max_attempts=5, base_delay=1.0, max_delay=30.0)
def call_nuclei(target):
    ...

cb = CircuitBreaker("nuclei", threshold=3, reset_after=60)
if cb.is_open():
    print("nuclei is down, skipping")
```

### nova_observability.py

```python
from nova_observability import Tracer

tracer = Tracer(run_id="hunt_20260601", verbose=True)

with tracer.span("ReconAgent", kind="agent") as span:
    span.set("target", "example.com")
    with tracer.tool_span("subfinder", parent=span) as t:
        t.set("result_count", 42)
    with tracer.llm_span("gpt-4o", "openai", parent=span) as llm:
        llm.tokens_in = 800; llm.tokens_out = 300

tracer.print_tree()
tracer.save()          # JSON spans
tracer.export_html()   # HTML flame graph
```

### nova_skills.py

```python
from nova_skills import SkillLibrary

lib = SkillLibrary()
print(lib.list_skills(category="attack"))

prompts = lib.render("sqli_analysis",
    target="example.com", endpoint="/api/search",
    param="q", method="GET",
    request_sample="GET /api/search?q=test HTTP/1.1")

from nova_llm_router import get_router
resp = get_router().chat(prompts["user"], system=prompts["system"])
```

---

## Cloud: GitHub Actions (24/7 Free)

```bash
# Set in GitHub → Settings → Secrets:
#   OPENAI_API_KEY, ANTHROPIC_API_KEY, NOVA_TELEGRAM_TOKEN

python3 nova_cloud.py hunt https://target.com
python3 nova_cloud.py watch <run-id>
python3 nova_cloud.py results
```

---

## Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | OpenAI API key |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `GEMINI_API_KEY` | — | Google Gemini API key |
| `NOVA_LLM_URL` | `http://localhost:11434` | Ollama server URL |
| `NOVA_LLM_MODEL` | `qwen3:8b` | Ollama model |
| `NOVA_OPENAI_MODEL` | `gpt-4o` | OpenAI model |
| `NOVA_ANTHROPIC_MODEL` | `claude-sonnet-4-5` | Anthropic model |
| `NOVA_GEMINI_MODEL` | `gemini-2.0-flash` | Gemini model |
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
curl http://localhost:11434/api/tags   # check Ollama
echo $OPENAI_API_KEY                  # check keys
python3 nova_llm_router.py "test"     # test router
```

### Module import errors

```bash
source ~/nova_workspace/.venv/bin/activate
pip install -r requirements.txt
./nova_setup.sh --minimal
```

### Playwright browser not found

```bash
playwright install chromium && playwright install-deps chromium
```

### Circuit breaker open for a tool

Circuit breakers reset after 60 seconds automatically. Restart Nova to clear immediately.

---

## Feature Comparison

| Feature | Nova Arsenal v4.1 | OpenAI Agents SDK | Anthropic Agent SDK |
|---|---|---|---|
| **Multi-agent orchestration** | ✅ | ✅ | ✅ |
| **Agent handoffs** | ✅ | ✅ | ✅ |
| **Input / output guardrails** | ✅ | ✅ | ✅ |
| **Lifecycle hooks** | ✅ PreRun · PostRun · PreTool · PostTool · OnFinding | Partial | ✅ PreToolUse · PostToolUse · Stop |
| **Typed context variables** | ✅ | ✅ | — |
| **Structured outputs** | ✅ All 4 providers | ✅ OpenAI only | ✅ Claude only |
| **Streaming** | ✅ All 4 providers | ✅ | ✅ |
| **Span-based tracing** | ✅ + HTML export | ✅ | Partial |
| **Persistent sessions** | ✅ | ✅ | — |
| **Skills / prompt templates** | ✅ 20+ built-in | — | ✅ |
| **Multi-provider LLM** | ✅ 4 providers | Partial | ❌ Claude only |
| **Per-tool circuit breaker** | ✅ | ❌ | ❌ |
| **Retry with backoff** | ✅ | Partial | Partial |
| **Cost tracking per span** | ✅ | Partial | ❌ |
| **Local / offline mode** | ✅ Ollama | ❌ | ❌ |
| **Security domain built-in** | ✅ 80+ modules | ❌ General purpose | ❌ General purpose |
| **GitHub Actions 24/7** | ✅ | Partial | — |
| **Zero cost option** | ✅ Ollama | ❌ | ❌ |
| **HackerOne integration** | ✅ | — | — |

---

## License

MIT — see `LICENSE` for details.

Bug bounty responsibly. Only test systems you have written permission to test.  
HackerOne safe-harbor applies when targeting programs that explicitly grant it.
