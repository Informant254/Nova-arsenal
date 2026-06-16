#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  🦅 Nova Arsenal — GitHub Codespace Setup                      ║
# ║  Installs Ollama + local models + Python dependencies           ║
# ╚══════════════════════════════════════════════════════════════════╝
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }

echo ""
echo "══════════════════════════════════════════════════════"
echo "  🦅  NOVA ARSENAL — CODESPACE BOOTSTRAP"
echo "══════════════════════════════════════════════════════"
echo ""

# ── Step 1: Install Ollama ──────────────────────────────────────────
info "Step 1/5 — Installing Ollama..."
curl -fsSL https://ollama.ai/install.sh | sh
info "Ollama installed: $(ollama --version 2>/dev/null || echo 'unknown')"

# ── Step 2: Start Ollama server ─────────────────────────────────────
info "Step 2/5 — Starting Ollama server..."
nohup ollama serve > /tmp/ollama.log 2>&1 &
OLLAMA_PID=$!
echo "  PID: $OLLAMA_PID"

# Wait for Ollama to be ready (up to 60s)
info "  Waiting for Ollama API..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
    info "  Ollama ready ✓"
    break
  fi
  [ $i -eq 30 ] && { error "Ollama failed to start. Check /tmp/ollama.log"; cat /tmp/ollama.log; exit 1; }
  sleep 2
done

# ── Step 3: Pull models based on available RAM ──────────────────────
info "Step 3/5 — Pulling LLM models..."

TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
info "  Available RAM: ${TOTAL_RAM_MB}MB"

# Always pull the lightweight model (works on free tier ~4GB Codespace)
info "  → Pulling qwen3:1.7b  (~1.1GB, fast, free-tier safe)..."
if ollama pull qwen3:1.7b; then
  info "  qwen3:1.7b ready ✓"
else
  warn "  qwen3:1.7b pull failed"
fi

# Pull phi3:mini as a fallback (Microsoft, very reliable)
info "  → Pulling phi3:mini (~2.2GB, fast fallback)..."
ollama pull phi3:mini 2>/dev/null && info "  phi3:mini ready ✓" || warn "  phi3:mini skipped"

# Pull qwen3:8b only if 12GB+ RAM available (Pro Codespace tier)
if [ "${TOTAL_RAM_MB}" -ge 12000 ]; then
  info "  → 12GB+ RAM — pulling qwen3:8b (~5.2GB, full-power)..."
  ollama pull qwen3:8b 2>/dev/null && info "  qwen3:8b ready ✓" || warn "  qwen3:8b pull failed, falling back to qwen3:1.7b"
  # Set env to prefer 8b model
  echo 'export NOVA_LLM_MODEL=qwen3:8b' >> ~/.bashrc
else
  info "  RAM < 12GB — using qwen3:1.7b (upgrade to 4-core Codespace for qwen3:8b)"
  echo 'export NOVA_LLM_MODEL=qwen3:1.7b' >> ~/.bashrc
fi

# deepseek-r1:1.5b — reasoning model, tiny footprint
info "  → Pulling deepseek-r1:1.5b (~900MB, reasoning)..."
ollama pull deepseek-r1:1.5b 2>/dev/null && info "  deepseek-r1:1.5b ready ✓" || warn "  deepseek-r1:1.5b skipped"

echo ""
info "  Models installed:"
ollama list

# ── Step 4: Add Ollama auto-start to shell ──────────────────────────
info "Step 4/5 — Configuring shell auto-start..."
cat >> ~/.bashrc << 'BASHRC'

# ── Nova Arsenal: Auto-start Ollama if not running ──────────────────
_nova_start_ollama() {
  if ! curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "🦅 Starting Ollama server..."
    nohup ollama serve > /tmp/ollama.log 2>&1 &
    sleep 3
  fi
}
_nova_start_ollama

export NOVA_LLM_URL="http://localhost:11434"
export NOVA_WORKSPACE="${CODESPACE_VSCODE_FOLDER:-$HOME}/nova_workspace"
export NOVA_PERMISSION_PROFILE="scoped"
export PATH="$PATH:/usr/local/bin"
BASHRC

# ── Step 5: Install Python dependencies ────────────────────────────
info "Step 5/5 — Installing Python dependencies..."
pip install --quiet --upgrade pip
pip install --quiet requests aiohttp beautifulsoup4 lxml colorama rich tabulate \
  pyyaml python-dotenv click tqdm ollama openai anthropic 2>/dev/null || true

# Install full requirements (best-effort — some heavy packages may fail)
pip install --quiet -r requirements.txt 2>/dev/null || warn "Some packages in requirements.txt failed (expected for heavy deps like angr/frida)"
pip install --quiet -r requirements-ci.txt 2>/dev/null || true

# Create workspace directories
mkdir -p nova_workspace/{reports,sessions,chains,evidence,wordlists,weapons}
info "Nova workspace created at ./nova_workspace"

echo ""
echo "══════════════════════════════════════════════════════"
echo "  ✅  NOVA ARSENAL CODESPACE READY"
echo "══════════════════════════════════════════════════════"
echo ""
echo "  Quick start:"
echo "    python3 nova.py 'Hunt https://target.com for all bugs'"
echo ""
echo "  LLM:       http://localhost:11434"
echo "  Model:     qwen3:1.7b (switch with NOVA_LLM_MODEL=qwen3:8b)"
echo "  Workspace: ./nova_workspace"
echo ""
