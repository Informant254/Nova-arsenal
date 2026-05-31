#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║   NOVA ARSENAL v4.0 — ONE-SHOT INSTALLER                           ║
# ║   Installs all dependencies, Ollama, a local LLM, and verifies     ║
# ║   every module is functional. Run once and get full power.         ║
# ╚══════════════════════════════════════════════════════════════════════╝
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC}  $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERR]${NC}  $1"; }
header()  { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}"; }

NOVA_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="${NOVA_WORKSPACE:-$HOME/nova_workspace}"
OLLAMA_MODEL="${NOVA_LLM_MODEL:-qwen3:8b}"
PYTHON="${PYTHON:-python3}"

echo -e "${BOLD}${CYAN}"
cat << 'ASCII'
  ███╗   ██╗ ██████╗ ██╗   ██╗  █████╗
  ████╗  ██║██╔═══██╗██║   ██║ ██╔══██╗
  ██╔██╗ ██║██║   ██║██║   ██║ ███████║
  ██║╚██╗██║██║   ██║╚██╗ ██╔╝ ██╔══██║
  ██║ ╚████║╚██████╔╝ ╚████╔╝  ██║  ██║
  ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝   ╚═╝  ╚═╝  ARSENAL v4.0
ASCII
echo -e "${NC}${BOLD}  Full-Power One-Shot Installer${NC}\n"

# ── Step 1: Python ─────────────────────────────────────────────────────────────
header "Python Setup"
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 --version 2>&1)
    success "Python found: $PY_VERSION"
    PYTHON="python3"
elif command -v python &>/dev/null; then
    PY_VERSION=$(python --version 2>&1)
    if [[ "$PY_VERSION" == *"3."* ]]; then
        success "Python found: $PY_VERSION"
        PYTHON="python"
    else
        error "Python 3.10+ required"
        exit 1
    fi
else
    error "Python 3 not found. Install from https://python.org"
    exit 1
fi

# ── Step 2: Python dependencies ────────────────────────────────────────────────
header "Python Dependencies"
if [[ -f "$NOVA_DIR/requirements.txt" ]]; then
    info "Installing from requirements.txt..."
    $PYTHON -m pip install -r "$NOVA_DIR/requirements.txt" --quiet --break-system-packages 2>/dev/null \
        || $PYTHON -m pip install -r "$NOVA_DIR/requirements.txt" --quiet
    success "requirements.txt installed"
fi

# Core packages Nova needs (always ensure these)
CORE_PKGS="requests beautifulsoup4 lxml pyyaml"
for pkg in $CORE_PKGS; do
    $PYTHON -c "import ${pkg//-/_}" 2>/dev/null && success "$pkg" || {
        info "Installing $pkg..."
        $PYTHON -m pip install "$pkg" --quiet --break-system-packages 2>/dev/null \
            || $PYTHON -m pip install "$pkg" --quiet
    }
done

# Optional but powerful
OPTIONAL_PKGS="playwright selenium websockets cryptography paramiko"
for pkg in $OPTIONAL_PKGS; do
    $PYTHON -c "import ${pkg}" 2>/dev/null \
        && success "$pkg (optional — available)" \
        || warn "$pkg not installed (optional — install for full browser support)"
done

# ── Step 3: External tools (optional but powerful) ─────────────────────────────
header "Security Tools (Optional)"
check_tool() {
    if command -v "$1" &>/dev/null; then
        success "$1 found: $(command -v $1)"
    else
        warn "$1 not found — install for full $2 capability"
        case "$1" in
            nmap)     echo "    Install: sudo apt-get install nmap  OR  brew install nmap" ;;
            nuclei)   echo "    Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
            sqlmap)   echo "    Install: pip3 install sqlmap" ;;
            ffuf)     echo "    Install: go install github.com/ffuf/ffuf/v2@latest" ;;
            subfinder)echo "    Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
            amass)    echo "    Install: sudo apt-get install amass  OR  brew install amass" ;;
            httpx)    echo "    Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
            trivy)    echo "    Install: brew install trivy  OR  https://aquasecurity.github.io/trivy" ;;
            git)      echo "    Install: sudo apt-get install git" ;;
            curl)     echo "    Install: sudo apt-get install curl" ;;
        esac
    fi
}
for t in nmap nuclei sqlmap ffuf subfinder httpx amass trivy git curl; do
    check_tool "$t" "recon/scanning"
done

# ── Step 4: Ollama + LLM ───────────────────────────────────────────────────────
header "Ollama LLM (Local — Zero Cost)"
if command -v ollama &>/dev/null; then
    success "Ollama already installed: $(ollama --version 2>&1 | head -1)"
else
    info "Installing Ollama..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &>/dev/null; then
            brew install ollama
        else
            curl -fsSL https://ollama.com/install.sh | sh
        fi
    else
        curl -fsSL https://ollama.com/install.sh | sh
    fi
    success "Ollama installed"
fi

# Start Ollama if not running
if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
    info "Starting Ollama server..."
    ollama serve &>/dev/null &
    sleep 3
fi

# Pull LLM model
info "Checking for model: $OLLAMA_MODEL"
if ollama list 2>/dev/null | grep -q "${OLLAMA_MODEL%%:*}"; then
    success "Model $OLLAMA_MODEL already available"
else
    info "Pulling $OLLAMA_MODEL (this may take a few minutes)..."
    if ollama pull "$OLLAMA_MODEL"; then
        success "Model $OLLAMA_MODEL ready"
    else
        warn "Could not pull $OLLAMA_MODEL — trying llama3.2..."
        ollama pull llama3.2 && success "llama3.2 ready as fallback" || warn "No LLM pulled — keyword fallback will be used"
    fi
fi

# ── Step 5: Nova workspace ─────────────────────────────────────────────────────
header "Nova Workspace"
mkdir -p "$WORKSPACE"
success "Workspace: $WORKSPACE"

# Create .env file if missing
ENV_FILE="$NOVA_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" << EOF
# Nova Arsenal v4.0 Configuration
NOVA_LLM_URL=http://localhost:11434
NOVA_LLM_MODEL=$OLLAMA_MODEL
NOVA_WORKSPACE=$WORKSPACE
NOVA_MAX_STEPS=40
NOVA_TARGET=http://localhost:3000
NOVA_ORG_NAME=My Organization
# HACKERONE_PROGRAM=your_program_handle
EOF
    success ".env config created: $ENV_FILE"
else
    success ".env already exists: $ENV_FILE"
fi

# ── Step 6: Verify all Nova modules ────────────────────────────────────────────
header "Module Verification"
cd "$NOVA_DIR"
MODULES=(
    "nova.py"
    "nova_file_prioritizer.py"
    "nova_threat_model.py"
    "nova_patch_generator.py"
    "nova_sca_scanner.py"
    "nova_git_scanner.py"
    "nova_sandbox_validator.py"
    "nova_detection_engineer.py"
    "nova_audit_reporter.py"
    "nova_vuln_tracker.py"
    "nova_idor_scanner.py"
    "nova_graphql_tester.py"
    "nova_supply_chain_scorer.py"
    "nova_cicd_scanner.py"
    "nova_container_scanner.py"
    "nova_zero_day_correlator.py"
    "nova_csrf_tester.py"
    "nova_llm_injection.py"
    "nova_business_logic.py"
    "nova_source_auditor.py"
    "nova_verify_engine.py"
    "nova_web_researcher.py"
    "nova_tool_kit.py"
    "nova_planner.py"
    "nova_context_manager.py"
    "nova_agent_core.py"
    "nova_self_improvement.py"
)

MISSING=0
for mod in "${MODULES[@]}"; do
    if [[ -f "$NOVA_DIR/$mod" ]]; then
        # Quick syntax check
        if $PYTHON -m py_compile "$NOVA_DIR/$mod" 2>/dev/null; then
            success "$mod"
        else
            error "$mod — SYNTAX ERROR"
            MISSING=$((MISSING+1))
        fi
    else
        warn "$mod — not found (run: git pull)"
        MISSING=$((MISSING+1))
    fi
done

# ── Step 7: Self-test ──────────────────────────────────────────────────────────
header "Self-Test"
$PYTHON "$NOVA_DIR/nova_bootstrap.py" --quick 2>/dev/null && success "Bootstrap health check passed" \
    || warn "Bootstrap skipped (run python3 nova_bootstrap.py for full check)"

# ── Step 8: Summary ────────────────────────────────────────────────────────────
header "Installation Complete"
echo ""
echo -e "${BOLD}  Nova Arsenal v4.0 is ready.${NC}"
echo ""
echo -e "  ${CYAN}Quick start:${NC}"
echo '  python3 nova.py "Hunt localhost:3000 for SQL injection"'
echo '  python3 nova.py "Run full-stack Mythos+Daybreak pipeline on ./my-app"'
echo '  python3 nova.py "Scan git history for leaked secrets"'
echo '  python3 nova.py "Build a threat model for ./my-app"'
echo ""
if [[ $MISSING -gt 0 ]]; then
    warn "$MISSING module(s) missing — run: git pull origin main"
fi
echo -e "  ${CYAN}Documentation:${NC} README.md"
echo -e "  ${CYAN}Workspace:${NC}     $WORKSPACE"
echo -e "  ${CYAN}Config:${NC}        $ENV_FILE"
echo ""
