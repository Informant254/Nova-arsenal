# Nova Arsenal — Installation Manual

> Autonomous AI Bug Bounty Framework · All Platforms

---

## Quick Start (any platform)

```bash
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
pip install -r requirements.txt
python3 nova.py "Hunt https://target.com for all bugs"
```

---

## Platform Guides

### 🐧 Kali Linux / Parrot OS (Recommended)

Kali is the primary supported platform. All tools pre-installed.

```bash
# 1. Clone
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

# 2. Python deps
pip install -r requirements.txt

# 3. (Optional) Local LLM via Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:8b          # best for security tasks
# OR use cloud LLM (set API key below)

# 4. Configure
cp .env.example .env
nano .env                     # add your API key

# 5. Run
python3 nova.py "Full stack scan on https://target.com"
```

---

### 🐧 Ubuntu 22.04 / 24.04 / Debian

```bash
# 1. System deps
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv \
    nmap curl git whatweb \
    golang-go ruby                  # optional tool deps

# 2. Clone + install
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. LLM setup (choose one)
# Option A — Ollama (free, local)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:8b

# Option B — Cloud (faster)
echo 'OPENAI_API_KEY=sk-...' >> .env
# OR
echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env

# 4. Run
source .venv/bin/activate
python3 nova.py "Hunt https://target.com"
```

---

### 🍎 macOS (Apple Silicon & Intel)

```bash
# 1. Prerequisites
brew install python3 nmap git curl

# 2. Clone + install
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
pip3 install -r requirements.txt

# 3. LLM (choose one)
# Option A — Ollama Desktop
open https://ollama.com/download    # download .app
ollama pull qwen3:8b

# Option B — Cloud API key
export OPENAI_API_KEY="sk-..."

# 4. Run
python3 nova.py "Hunt https://target.com"
```

---

### 🪟 Windows (WSL2 — Recommended)

Nova runs inside WSL2 on Windows. Direct native Windows is not supported.

```powershell
# ── In PowerShell (Admin) ──────────────────────────────────────
wsl --install                  # installs Ubuntu 22.04 by default
# Restart when prompted
```

```bash
# ── Inside WSL2 (Ubuntu) ──────────────────────────────────────
sudo apt update && sudo apt install -y python3 python3-pip git curl

git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
pip3 install -r requirements.txt

# Ollama (runs inside WSL2 fine)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:8b

python3 nova.py "Hunt https://target.com"
```

> **Tip:** Open WSL2 folder in VS Code with `code .` from within WSL2 terminal.

---

### 📱 Android — Termux (ARM64)

Nova runs fully on Android via Termux. No root required.

```bash
# ── Install Termux ─────────────────────────────────────────────
# Download from F-Droid (NOT Google Play — outdated):
# https://f-droid.org/packages/com.termux/

# ── Inside Termux ─────────────────────────────────────────────
pkg update && pkg upgrade -y
pkg install -y python git curl openssl libffi

# Python deps (some need build tools)
pkg install -y clang make libxml2 libxslt
pip install -r requirements.txt

# Clone Nova
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

# LLM: use cloud API (Ollama is too heavy for most phones)
# Add to ~/.bashrc:
export OPENAI_API_KEY="sk-..."
export NOVA_LLM_MODEL="gpt-4o-mini"    # lighter model for mobile

# Run
python nova.py "Recon https://target.com"

# Storage: output goes to ~/nova_workspace
# Access from Files app: Internal Storage → Android → data → com.termux → files → home
```

**Known Termux limitations:**
- Ollama not supported (model too large for mobile RAM)
- `nmap` requires root or use `pkg install nmap` + run as root if rooted
- Some modules with heavy deps (torch, etc.) may fail — Nova degrades gracefully

---

### 📱 Android — Kali NetHunter

Full Kali environment on Android. Best mobile experience.

```bash
# ── Prerequisites ──────────────────────────────────────────────
# Install Kali NetHunter from: https://nethunter.kali.org/
# Open NetHunter terminal (Kali chroot)

# ── Inside NetHunter Kali chroot ──────────────────────────────
apt update && apt install -y python3 python3-pip git nmap curl

git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal
pip3 install -r requirements.txt

# Configure LLM (use cloud — Ollama not supported on NetHunter)
export OPENAI_API_KEY="sk-..."

# Run
python3 nova.py "Hunt https://target.com"

# Or use the included install script:
bash install-nethunter-termux
```

---

### ☁️ GitHub Codespaces / Cloud IDE

One-click cloud environment — no local install needed.

```bash
# Codespaces auto-creates the environment.
# Once open, in the terminal:

pip install -r requirements.txt

# Set secrets in Codespaces:
# Settings → Secrets → New repository secret
# Add: OPENAI_API_KEY, NOVA_TRUTH_THRESHOLD, etc.

python3 nova.py "Hunt https://target.com"
```

---

### 🐳 Docker

```dockerfile
# Dockerfile included in repo root
docker build -t nova-arsenal .
docker run -it \
  -e OPENAI_API_KEY="sk-..." \
  -e NOVA_TARGET="https://target.com" \
  nova-arsenal \
  python3 nova.py "Full scan on https://target.com"
```

---

## LLM Provider Setup

Nova uses a cascade: OpenAI → Anthropic → Gemini → Ollama (local).
Set ONE key and Nova uses it automatically.

| Provider   | Speed    | Cost      | Setup                                |
|------------|----------|-----------|--------------------------------------|
| OpenAI     | ⚡ Fast  | 💰 Paid   | `OPENAI_API_KEY=sk-...`             |
| Anthropic  | ⚡ Fast  | 💰 Paid   | `ANTHROPIC_API_KEY=sk-ant-...`      |
| Gemini     | ⚡ Fast  | 🆓 Free tier | `GEMINI_API_KEY=AIza...`         |
| Ollama     | 🐢 Slow  | 🆓 Free   | `ollama pull qwen3:8b`              |

```bash
# .env file (copy from .env.example)
OPENAI_API_KEY=sk-...
NOVA_TRUTH_THRESHOLD=0.85
NOVA_WORKSPACE=~/nova_workspace
NOVA_TELEGRAM_TOKEN=          # optional: real-time alerts
NOVA_TELEGRAM_CHAT_ID=        # optional
```

---

## Verify Installation

```bash
python3 nova.py "bootstrap"   # health check of all modules
```

Expected output:
```
🦅 Nova Arsenal v4.2
✅ LLM Router      : OpenAI gpt-4o
✅ Truth Engine    : initialized (threshold: 85%)
✅ Hook Bus        : ready
✅ Session Store   : ready
✅ Memory System   : ready
...
```

---

## Common Issues

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError: requests` | `pip install -r requirements.txt` |
| `LLM not available` | Set `OPENAI_API_KEY` or install Ollama + pull a model |
| `Truth Engine disabled` | Remove `NOVA_TRUTH_DISABLED=1` from env |
| Termux SSL errors | `pkg install openssl && pip install certifi` |
| macOS SIP blocks nmap | `sudo nmap` or use `--privileged` flag |
| Windows: `python not found` | Use WSL2, not native Windows CMD |
