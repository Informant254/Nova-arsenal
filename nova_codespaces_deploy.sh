#!/bin/bash
# NOVA CODESPACES DEPLOYMENT
# Creates a full cloud execution environment for Nova
# Termux = Control Center | Codespaces = Execution Engine

echo "🦅 NOVA CODESPACES DEPLOYMENT"
echo "=============================="
echo ""
echo "This script creates a GitHub Codespace for Nova."
echo "It installs all tools and clones her entire arsenal."
echo ""
echo "INSTRUCTIONS:"
echo "1. Go to https://github.com/codespaces"
echo "2. Click 'New codespace'"
echo "3. Select this repository or create a blank one"
echo "4. Once the VS Code web editor opens, paste the commands below into the terminal"
echo ""

cat << 'CODESPACE_SETUP'
# ===== RUN THESE COMMANDS IN THE CODESPACE TERMINAL =====

# 1. Install Nova's core dependencies
pip install requests selenium playwright anthropic openai semgrep bandit

# 2. Install browser for Selenium
playwright install chromium

# 3. Clone Nova's entire arsenal from your Termux
# (First, push your juice-shop directory to GitHub from Termux)
# cd ~/juice-shop
# git init && git add . && git commit -m "Nova Arsenal" 
# git remote add origin https://github.com/YOUR_USERNAME/nova-arsenal.git
# git push

# Then in Codespaces:
# git clone https://github.com/YOUR_USERNAME/nova-arsenal.git

# 4. Create Nova's persistent brain directory
mkdir -p ~/nova_brain
mkdir -p ~/nova_evidence
mkdir -p ~/nova_reports

# 5. Run Nova's full ecosystem audit with Semgrep (professional-grade)
echo "Running professional static analysis..."
semgrep --config=auto --scan-unknown-extensions --json -o ~/nova_reports/semgrep_scan.json .

# 6. Run CodeQL analysis (GitHub's own vulnerability scanner)
echo "CodeQL analysis ready. Run from GitHub Security tab."

# 7. Start Nova's parallel swarm
python3 nova_swarm_parallel.py &

echo "✅ Nova Codespace is ready!"
echo "Control her from Termux via SSH or GitHub API"
CODESPACE_SETUP

echo ""
echo "📁 Save this script and run it in your Codespace terminal"
