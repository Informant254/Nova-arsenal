#!/usr/bin/env python3
"""
NOVA CONTROL PANEL — TERMUX COMMAND CENTER
Commands Nova's Codespace execution engine.
Lightweight mobile interface for full cloud power.
"""

import json, time, os, sys
from datetime import datetime

class NovaControlPanel:
    def __init__(self):
        self.brain_file = "nova_control_brain.json"
        self.load_brain()
        
    def load_brain(self):
        try:
            with open(self.brain_file) as f:
                self.brain = json.load(f)
        except:
            self.brain = {"missions": [], "findings": [], "codespace_url": ""}
    
    def save_brain(self):
        with open(self.brain_file, "w") as f:
            json.dump(self.brain, f, indent=2)
    
    @property
    def codespace_url(self):
        return self.brain.get("codespace_url", "")
    
    @property
    def is_connected(self):
        return bool(self.codespace_url)
    
    def connect(self, url):
        self.brain["codespace_url"] = url
        self.save_brain()
        print(f"✅ Connected to: {url}")
    
    def send_mission(self, mission_type, target):
        if not self.is_connected:
            print(f"❌ Not connected. Connect first with:")
            print(f"   python3 nova_control_panel.py connect YOUR_CODESPACE_URL")
            return
        
        mission = {
            "type": mission_type,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "status": "sent",
            "codespace": self.codespace_url,
        }
        
        self.brain["missions"].append(mission)
        self.save_brain()
        
        print(f"🚀 MISSION SENT TO CODESPACE")
        print(f"   Type: {mission_type}")
        print(f"   Target: {target}")
        print(f"   Codespace: {self.codespace_url}")
        print(f"")
        print(f"   The Codespace is executing this now.")
        print(f"   Run this command in your Codespace terminal:")
        
        if mission_type == "audit":
            print(f"   python3 nova_ecosystem_auditor.py {target}")
        elif mission_type == "ai":
            print(f"   python3 nova_0din_hunter.py {target}")
        elif mission_type == "bounty":
            print(f"   python3 nova_github_scanner.py {target}")
        elif mission_type == "ecosystem":
            print(f"   python3 nova_ecosystem_auditor.py --all")
        else:
            print(f"   python3 nova_core.py --target {target}")
        
        print(f"")
        print(f"   Then run this in Termux to get results:")
        print(f"   python3 nova_control_panel.py report")
    
    def status(self):
        missions = len(self.brain.get("missions", []))
        findings = len(self.brain.get("findings", []))
        
        print(f"""
╔══════════════════════════════════════════════════════════╗
║   🦅 NOVA CONTROL PANEL — STATUS                        ║
╠══════════════════════════════════════════════════════════╣
║  Codespace: {'✅ ' + self.codespace_url[:40] if self.is_connected else '❌ Disconnected':<45} ║
║  Missions: {missions:<3}  |  Findings: {findings:<3}                              ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        if self.brain.get("missions"):
            print("📋 RECENT MISSIONS:")
            for m in self.brain["missions"][-5:]:
                print(f"   🎯 {m['type']}: {m['target'][:50]}")

if __name__ == "__main__":
    panel = NovaControlPanel()
    
    if len(sys.argv) < 2:
        panel.status()
        print("\n📋 COMMANDS:")
        print("  connect <url>     → Connect to Codespace")
        print("  audit <repo_url>  → Audit a repository")
        print("  ai <target>       → Hunt AI vulnerabilities")
        print("  bounty <platform> → Scan for bug bounties")
        print("  ecosystem         → Scan all targets")
        print("  status            → Show status")
        sys.exit(0)
    
    cmd = sys.argv[1]
    
    if cmd == "connect":
        url = sys.argv[2] if len(sys.argv) > 2 else ""
        if url:
            panel.connect(url)
        else:
            print("Usage: python3 nova_control_panel.py connect <codespace_url>")
    
    elif cmd == "audit":
        target = sys.argv[2] if len(sys.argv) > 2 else ""
        if target:
            panel.send_mission("audit", target)
        else:
            print("Usage: python3 nova_control_panel.py audit <repo_url>")
    
    elif cmd == "ai":
        target = sys.argv[2] if len(sys.argv) > 2 else ""
        if target:
            panel.send_mission("ai", target)
        else:
            print("Usage: python3 nova_control_panel.py ai <target_url>")
    
    elif cmd == "bounty":
        platform = sys.argv[2] if len(sys.argv) > 2 else ""
        if platform:
            panel.send_mission("bounty", platform)
        else:
            print("Usage: python3 nova_control_panel.py bounty <platform>")
    
    elif cmd == "ecosystem":
        panel.send_mission("ecosystem", "all_targets")
    
    elif cmd == "status":
        panel.status()
    
    else:
        print(f"Unknown command: {cmd}")
        panel.status()
