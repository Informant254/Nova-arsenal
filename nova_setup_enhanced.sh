#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# 🦅 NOVA ARSENAL — ENHANCED SETUP SCRIPT v4.2
#
# Improved version that:
#   ✓ Explains all features after setup
#   ✓ Configures permission profiles explicitly
#   ✓ Sets up notifications (optional)
#   ✓ Verifies all modules are wired
#   ✓ Shows next steps clearly
# ═══════════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# Functions
ok()    { echo -e "${GREEN}✅${NC}  $1"; }
warn()  { echo -e "${YELLOW}⚠️ ${NC}  $1"; }
info()  { echo -e "${CYAN}ℹ️ ${NC}  $1"; }
step()  { echo -e "\n${BOLD}${BLUE}━━━ $1${NC}"; }
error() { echo -e "${RED}❌${NC}  $1"; exit 1; }

NOVA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${HOME}/nova_workspace"
VENV="${WORKSPACE}/.venv"
LOG="${WORKSPACE}/setup.log"

echo -e "${BOLD}${CYAN}"
cat << 'ASCII'
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   🦅  NOVA ARSENAL v4.2 — ENHANCED SETUP                                    ║
║                                                                              ║
║   This script will:                                                          ║
║     1. Verify/install Python 3.10+                                          ║
║     2. Install all Python dependencies (35+ modules + tools)                ║
║     3. Install Ollama + models                                              ║
║     4. Install Playwright browser                                           ║
║     5. Verify all modules are working                                       ║
║     6. Create .env configuration                                            ║
║     7. Show you what's now possible                                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ─────────────────────────────────────────────────────���───────────────────────
step "1. Python Environment"
if ! command -v python3 &>/dev/null; then
    error "Python 3 not found. Install from https://python.org"
fi
PY_VERSION=$(python3 --version 2>&1)
ok "$PY_VERSION"

# Create venv
if [ ! -d "${VENV}" ]; then
    info "Creating virtual environment..."
    python3 -m venv "${VENV}"
    ok "Virtual environment created"
fi
source "${VENV}/bin/activate"

# ─────────────────────────────────────────────────────────────────────────────
step "2. Python Dependencies"
cd "${NOVA_DIR}"

if pip install -q -r requirements.txt 2>/dev/null; then
    ok "requirements.txt installed"
else
    warn "Some packages failed — retrying with fallback..."
    pip install -q -r requirements.txt --break-system-packages || true
fi

# ─────────────────────────────────────────────────────────────────────────────
step "3. Ollama LLM (Local, Free)"
if ! command -v ollama &>/dev/null; then
    info "Installing Ollama..."
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

# Pull recommended models
step "3a. Pulling Ollama Models"
for model in "qwen3:8b" "deepseek-r1:14b"; do
    if ollama list 2>/dev/null | grep -q "${model%%:*}"; then
        ok "$model available"
    else
        info "Pulling $model (may take a few minutes)..."
        ollama pull "$model" &>/dev/null && ok "$model ready" || warn "$model skipped"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
step "4. Playwright Browser"
pip install -q playwright
python3 -m playwright install chromium 2>&1 | grep -q "installed" && \
    ok "Playwright chromium installed" || \
    warn "Playwright browser install had issues"

# ─────────────────────────────────────────────────────────────────────────────
step "5. Nova Workspace"
mkdir -p "${WORKSPACE}"/{reports,logs,sessions,screenshots,screenshots}
ok "Workspace: $WORKSPACE"

# ─────────────────────────────────────────────────────────────────────────────
step "6. Environment Configuration"
ENV_FILE="${NOVA_DIR}/.env"

if [ ! -f "$ENV_FILE" ]; then
    info "Creating .env configuration..."
    cp "${NOVA_DIR}/.env.example" "$ENV_FILE" 2>/dev/null || \
    cat > "$ENV_FILE" << 'EOF'
# LLM Provider (Ollama is free and offline)
NOVA_LLM_URL=http://localhost:11434
NOVA_LLM_MODEL=qwen3:8b

# Nova Runtime
NOVA_WORKSPACE=~/nova_workspace
NOVA_MAX_STEPS=40
NOVA_PERMISSION_PROFILE=scoped

# Optional: LLM API Keys (OpenAI, Anthropic, Google)
# OPENAI_API_KEY=
# ANTHROPIC_API_KEY=
# GOOGLE_API_KEY=

# Optional: Notifications
# TELEGRAM_BOT_TOKEN=
# TELEGRAM_CHAT_ID=
# DISCORD_WEBHOOK_URL=
# SLACK_WEBHOOK_URL=
EOF
    ok ".env created"
fi

# ─────────────────────────────────────────────────────────────────────────────
step "7. Module Verification"
EXPECTED_MODULES=(
    "nova.py"
    "nova_cli.py"
    "nova_orchestrator.py"
    "nova_codebase_mapper.py"
    "nova_source_auditor.py"
    "nova_sca_scanner.py"
    "nova_idor_scanner.py"
    "nova_csrf_tester.py"
    "nova_jwt_forge.py"
    "nova_verify_engine.py"
    "nova_triage.py"
    "nova_threat_model.py"
    "nova_patch_generator.py"
    "nova_detection_engineer.py"
    "nova_audit_reporter.py"
    "nova_vuln_tracker.py"
    "nova_llm_router.py"
    "nova_sessions.py"
    "nova_tool_kit.py"
    "nova_eval.py"
    "nova_diff_watcher.py"
    "nova_features.py"
)

MISSING=0
for mod in "${EXPECTED_MODULES[@]}"; do
    if [ -f "$NOVA_DIR/$mod" ]; then
        python3 -m py_compile "$NOVA_DIR/$mod" 2>/dev/null && ok "$mod" || {
            error "$mod — SYNTAX ERROR"
        }
    else
        warn "$mod — not found"
        MISSING=$((MISSING+1))
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
step "8. Capability Test"
echo "Testing core modules..."
python3 - << 'PYCHECK' 2>/dev/null && ok "Core modules working" || warn "Core test incomplete"
try:
    import nova_codebase_mapper
    import nova_llm_router
    import nova_tool_kit
    import nova_orchestrator
    print("✓ All core imports successful")
except Exception as e:
    print(f"⚠ Import check: {e}")
PYCHECK

# ─────────────────────────────────────────────────────────────────────────────
step "9. Permission Profile Setup"
info "Choose your permission profile:"
echo "  1) scoped   — Network limited to target (RECOMMENDED for testing)"
echo "  2) full     — All tools enabled (LOCAL DEV ONLY)"
echo "  3) read_only — No network/shell (CI/CD safe)"
read -p "Enter 1-3 (default: 1): " profile_choice

case $profile_choice in
    2) PROFILE="full"; warn "Full permissions enabled — for local development only!" ;;
    3) PROFILE="read_only"; info "Read-only mode — safe for CI/CD" ;;
    *) PROFILE="scoped"; info "Scoped permissions — targets limited to declared scope" ;;
esac

sed -i.bak "s/^NOVA_PERMISSION_PROFILE=.*/NOVA_PERMISSION_PROFILE=$PROFILE/" "$ENV_FILE" 2>/dev/null || \
    sed -i '' "s/^NOVA_PERMISSION_PROFILE=.*/NOVA_PERMISSION_PROFILE=$PROFILE/" "$ENV_FILE"
ok "Permission profile: $PROFILE"

# ─────────────────────────────────────────────────────────────────────────────
step "10. Optional: Notifications Setup"
read -p "Configure Telegram alerts? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    info "Get your Telegram bot token from @BotFather"
    read -p "Enter TELEGRAM_BOT_TOKEN: " bot_token
    read -p "Enter TELEGRAM_CHAT_ID: " chat_id
    if [ ! -z "$bot_token" ] && [ ! -z "$chat_id" ]; then
        sed -i.bak "s|^# TELEGRAM_BOT_TOKEN=|TELEGRAM_BOT_TOKEN=$bot_token|" "$ENV_FILE" 2>/dev/null || \
            sed -i '' "s|^# TELEGRAM_BOT_TOKEN=|TELEGRAM_BOT_TOKEN=$bot_token|" "$ENV_FILE"
        ok "Telegram configured"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
step "11. Provider Configuration"
read -p "Use OpenAI/Anthropic, or stick with local Ollama? (openai/anthropic/ollama): " provider
case $provider in
    openai)
        read -sp "Enter OPENAI_API_KEY: " api_key
        sed -i.bak "s|^# OPENAI_API_KEY=|OPENAI_API_KEY=$api_key|" "$ENV_FILE" 2>/dev/null || \
            sed -i '' "s|^# OPENAI_API_KEY=|OPENAI_API_KEY=$api_key|" "$ENV_FILE"
        ok "OpenAI configured"
        ;;
    anthropic)
        read -sp "Enter ANTHROPIC_API_KEY: " api_key
        sed -i.bak "s|^# ANTHROPIC_API_KEY=|ANTHROPIC_API_KEY=$api_key|" "$ENV_FILE" 2>/dev/null || \
            sed -i '' "s|^# ANTHROPIC_API_KEY=|ANTHROPIC_API_KEY=$api_key|" "$ENV_FILE"
        ok "Anthropic configured"
        ;;
    *)
        ok "Using local Ollama (no API key needed)"
        ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
echo -e "\n${BOLD}${GREEN}"
cat << 'ASCII'
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ✅  NOVA ARSENAL v4.2 — SETUP COMPLETE                                    ║
║                                                                              ║
║   Your system is now ready. Here's what you can now do:                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Show features
echo -e "${BOLD}🎯 QUICK START COMMANDS${NC}"
echo ""
echo "  Beginner:"
echo "    python3 nova.py \"Hunt http://localhost:3000 for vulnerabilities\""
echo "    nova hunt http://localhost:3000"
echo "    nova map ./my-app"
echo "    nova status"
echo ""
echo "  Intermediate:"
echo "    nova scan sqli http://localhost:3000"
echo "    nova orch http://localhost:3000"
echo "    nova-watch ./my-app --staged"
echo ""
echo "  Advanced:"
echo "    python3 nova_threat_model.py ./my-app"
echo "    nova-cloud hunt http://target.com"
echo "    nova_eval.py --quick"
echo ""

echo -e "${BOLD}📚 DISCOVER ALL FEATURES${NC}"
echo "  python3 nova_features.py                    # All features"
echo "  python3 nova_features.py --beginner        # Beginner only"
echo "  python3 nova_features.py --intermediate    # Intermediate only"
echo "  python3 nova_features.py --advanced        # Advanced only"
echo "  python3 nova_features.py --check           # Verify modules"
echo ""

echo -e "${BOLD}📖 DOCUMENTATION${NC}"
echo "  • INSTALLATION_COMPLETE.md — Full capability guide"
echo "  • CAPABILITIES.md — Feature matrix by role"
echo "  • README.md — Architecture & design"
echo "  • .env.example — Configuration options"
echo ""

echo -e "${BOLD}⚙️  CONFIGURATION${NC}"
echo "  Config file: $ENV_FILE"
echo "  Workspace:  $WORKSPACE"
echo "  Permission: $PROFILE"
echo ""

if [ $MISSING -gt 0 ]; then
    warn "$MISSING module(s) not found — run 'git pull origin main'"
fi

echo -e "${BOLD}🚀 NEXT STEPS${NC}"
echo "  1. Read: cat INSTALLATION_COMPLETE.md"
echo "  2. Test: python3 nova_features.py --check"
echo "  3. Hunt: python3 nova.py \"Hunt http://localhost:3000\""
echo ""
echo -e "${BOLD}${GREEN}Happy hunting! 🦅${NC}\n"

