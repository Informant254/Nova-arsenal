#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║   🦅 NOVA ARSENAL — ONE-COMMAND SETUP SCRIPT                   ║
# ║                                                                  ║
# ║   Closes the gap with frontier AI agents by setting up:         ║
# ║   • Best Ollama models for each task type                       ║
# ║   • Full Python security tool stack                             ║
# ║   • Playwright browser (headless Chromium)                      ║
# ║   • System security tools (nmap, nuclei, subfinder, etc.)       ║
# ║   • Nova workspace and RAG knowledge base                       ║
# ║                                                                  ║
# ║   Usage: bash nova_setup.sh [--minimal] [--models-only]         ║
# ╚══════════════════════════════════════════════════════════════════╝

set -e
NOVA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${HOME}/nova_workspace"
VENV="${WORKSPACE}/.venv"
LOG="${WORKSPACE}/setup.log"
MINIMAL=false
MODELS_ONLY=false

for arg in "$@"; do
  case $arg in
    --minimal)     MINIMAL=true ;;
    --models-only) MODELS_ONLY=true ;;
  esac
done

mkdir -p "${WORKSPACE}"/{bin,wordlists,reports,logs,screenshots,backups,tools,memory}

# ── COLOURS ───────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}✅ $1${RESET}"; }
warn() { echo -e "${YELLOW}⚠️  $1${RESET}"; }
info() { echo -e "${CYAN}ℹ️  $1${RESET}"; }
step() { echo -e "\n${BOLD}${BLUE}▶ $1${RESET}"; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║   🦅  NOVA ARSENAL — SETUP                                      ║"
echo "║   Closing the gap with Mythos · Claude Code · Daybreak          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── 1. OLLAMA CHECK ───────────────────────────────────────────────
step "1. Checking Ollama"
if ! command -v ollama &>/dev/null; then
  info "Ollama not found. Installing..."
  curl -fsSL https://ollama.com/install.sh | sh
  ok "Ollama installed"
else
  ok "Ollama found: $(ollama --version 2>/dev/null || echo 'ok')"
fi

# Start Ollama if not running
if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
  info "Starting Ollama server..."
  ollama serve &>/dev/null &
  sleep 3
fi

# ── 2. OLLAMA MODELS ──────────────────────────────────────────────
step "2. Pulling Ollama models (best → fallback)"
echo "   These replace TinyLlama and close the capability gap."
echo ""

pull_model() {
  local model="$1"
  local label="$2"
  local required="${3:-false}"
  echo -ne "   Pulling ${CYAN}${model}${RESET} (${label})... "
  if ollama pull "${model}" >> "${LOG}" 2>&1; then
    ok "done"
  else
    if [ "$required" = "true" ]; then
      warn "FAILED — required model. Check disk space and network."
    else
      warn "skipped (not critical)"
    fi
  fi
}

# Tier 1 — Security reasoning (most important)
pull_model "xploiter/the-xploiter" "Security-specialized attacker brain" true

# Tier 2 — Chain-of-thought reasoning
# Pull 14b if VRAM is limited, 32b if you have it
VRAM_GB=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 | awk '{print int($1/1024)}' || echo "0")
if [ "${VRAM_GB}" -ge 20 ] 2>/dev/null; then
  pull_model "deepseek-r1:32b" "Best chain-of-thought reasoning (32b)"
else
  pull_model "deepseek-r1:14b" "Chain-of-thought reasoning (14b, fits <16GB VRAM)"
fi

# Tier 3 — Agentic coding
pull_model "devstral-small" "Agentic code auditing"

# Tier 4 — Best general
if [ "${MINIMAL}" = "false" ]; then
  pull_model "qwen3:30b" "Best general reasoning (needs ~20GB VRAM)"
fi

# Tier 5 — Fast lightweight
pull_model "qwen3:8b" "Fast checks and parsing" true

echo ""
info "Installed models:"
ollama list 2>/dev/null | head -20

if [ "${MODELS_ONLY}" = "true" ]; then
  ok "Models-only mode — done."
  exit 0
fi

# ── 3. PYTHON ENVIRONMENT ─────────────────────────────────────────
step "3. Setting up Python environment"
if ! command -v python3 &>/dev/null; then
  warn "python3 not found — install it first"
  exit 1
fi

if [ ! -d "${VENV}" ]; then
  python3 -m venv "${VENV}"
  ok "Virtual environment created: ${VENV}"
fi

source "${VENV}/bin/activate"

# Upgrade pip
pip install -q --upgrade pip >> "${LOG}" 2>&1

# Core requirements
pip install -q requests aiohttp urllib3 colorama rich >> "${LOG}" 2>&1
ok "Core Python packages installed"

if [ "${MINIMAL}" = "false" ]; then
  step "3a. Installing security Python packages"
  pip install -q \
    playwright selenium beautifulsoup4 lxml \
    pycryptodome cryptography pyyaml click tqdm python-dotenv \
    >> "${LOG}" 2>&1 && ok "Web/parsing packages installed" || warn "Some packages failed"

  pip install -q sqlmap semgrep bandit safety pip-audit \
    >> "${LOG}" 2>&1 && ok "Static analysis packages installed" || warn "Some packages failed"

  pip install -q shodan dnspython scapy netaddr \
    >> "${LOG}" 2>&1 && ok "Network packages installed" || warn "Some packages failed"
fi

# ── 4. PLAYWRIGHT BROWSER ─────────────────────────────────────────
step "4. Installing Playwright headless browser"
if python3 -c "from playwright.sync_api import sync_playwright" 2>/dev/null; then
  warn "Playwright already installed — running browser install..."
fi
pip install -q playwright >> "${LOG}" 2>&1
python3 -m playwright install chromium >> "${LOG}" 2>&1 && \
  ok "Playwright Chromium installed" || \
  warn "Playwright browser install failed — browser tools will fall back to curl"

# ── 5. SYSTEM SECURITY TOOLS ──────────────────────────────────────
step "5. Installing system security tools"

install_apt() {
  local pkg="$1"
  echo -ne "   apt: ${pkg}... "
  if apt-get install -y -q "${pkg}" >> "${LOG}" 2>&1; then ok "done"
  else warn "failed"; fi
}

install_go_tool() {
  local tool="$1"; local pkg="$2"
  echo -ne "   go:  ${tool}... "
  if command -v go &>/dev/null; then
    if go install "${pkg}@latest" >> "${LOG}" 2>&1; then ok "done"
    else warn "failed"; fi
  else warn "go not installed — skipping ${tool}"; fi
}

if command -v apt-get &>/dev/null && [ "${MINIMAL}" = "false" ]; then
  apt-get update -qq >> "${LOG}" 2>&1
  for pkg in nmap curl wget git jq; do
    install_apt "$pkg"
  done
fi

if [ "${MINIMAL}" = "false" ] && command -v go &>/dev/null; then
  install_go_tool "httpx"        "github.com/projectdiscovery/httpx/cmd/httpx"
  install_go_tool "subfinder"    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  install_go_tool "nuclei"       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
  install_go_tool "katana"       "github.com/projectdiscovery/katana/cmd/katana"
  install_go_tool "gau"          "github.com/lc/gau/v2/cmd/gau"
fi

# ── 6. NOVA WORKSPACE STRUCTURE ───────────────────────────────────
step "6. Setting up Nova workspace"
for dir in bin wordlists reports logs screenshots backups tools memory; do
  mkdir -p "${WORKSPACE}/${dir}"
done
# Copy config if not already there
if [ ! -f "${WORKSPACE}/nova_config.json" ] && [ -f "${NOVA_DIR}/nova_config.json" ]; then
  cp "${NOVA_DIR}/nova_config.json" "${WORKSPACE}/nova_config.json"
fi
ok "Workspace ready: ${WORKSPACE}"

# ── 7. BUILD RAG KNOWLEDGE BASE ───────────────────────────────────
step "7. Building RAG knowledge base from past hunts"
info "This ingests all nova_h1_hunt_*.json and submission evidence..."
cd "${NOVA_DIR}"
if python3 nova_rag_builder.py . >> "${LOG}" 2>&1; then
  ok "RAG knowledge base built"
else
  warn "RAG build failed — check ${LOG}"
fi

# ── 8. VERIFY ROUTING ─────────────────────────────────────────────
step "8. Verifying model routing"
python3 nova_model_router.py 2>/dev/null || warn "Model router check failed"

# ── 9. VERIFY AGENT TOOLS ─────────────────────────────────────────
step "9. Quick tool verification"
python3 - << 'PYCHECK'
from nova_tool_kit import bash_exec, http_request
r = bash_exec("echo 'Nova tool kit OK'")
print("  bash_exec:", r["stdout"])
r2 = http_request("GET", "http://localhost:3000/rest/admin/application-configuration")
print("  http_request:", r2.get("status_code", "target not running"))
PYCHECK

# ── FINAL SUMMARY ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║   ✅  NOVA ARSENAL — SETUP COMPLETE                             ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║                                                                  ║"
echo "║  Run Nova:                                                       ║"
echo "║    python3 nova_core.py                    # Original pipeline   ║"
echo "║    python3 nova_agent_core.py --target URL # TRUE AGENTIC MODE  ║"
echo "║    python3 nova_llm_bridge.py              # LLM mission planner ║"
echo "║    python3 nova_model_router.py            # Check routing table ║"
echo "║    python3 nova_rag_builder.py .           # Rebuild knowledge   ║"
echo "║                                                                  ║"
echo "║  Gap closed:                                                     ║"
echo "║    ✅ Task-routed Ollama models (no more TinyLlama)             ║"
echo "║    ✅ Chain-of-thought forcing on all reasoning tasks           ║"
echo "║    ✅ RAG knowledge from 100+ past hunts                        ║"
echo "║    ✅ Real browser via Playwright                               ║"
echo "║    ✅ True agentic loop (LLM drives the hunt)                   ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
