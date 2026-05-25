#!/usr/bin/env python3
"""
NOVA CONTROL PANEL — TERMUX COMMAND CENTER
Commands Nova's Codespace execution engine.
Lightweight mobile interface for full cloud power.
"""

import json, time, requests, os
from datetime import datetime

class NovaControlPanel:
    """Termux-based control center for Nova's Codespace."""
    
    def __init__(self):
        self.codespace_url = os.environ.get("NOVA_CODESPACE_URL", "")
        self.token = os.environ.get("GITHUB_TOKEN", "")
        self.brain_file = "nova_control_brain.json"
        self.load_brain()
        
    def load_brain(self):
        try:
            with open(self.brain_file) as f:
                self.brain = json.load(f)
        except:
            self.brain = {"missions": [], "findings": [], "codespace_connected": False}
    
    def save_brain(self):
        with open(self.brain_file, "w") as f:
            json.dump(self.brain, f, indent=2)
    
    def connect_codespace(self, url):
        """Connect to a Nova Codespace."""
        self.codespace_url = url
        self.brain["codespace_connected"] = True
        self.save_brain()
        print(f"✅ Connected to Codespace: {url}")
    
    def send_mission(self, mission_type, target):
        """Send a mission to the Codespace for execution."""
        if not self.codespace_url:
            print("❌ No Codespace connected. Set NOVA_CODESPACE_URL")
            return
        
        mission = {
            "type": mission_type,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "status": "sent",
        }
        
        self.brain["missions"].append(mission)
        self.save_brain()
        
        print(f"🚀 Mission sent: {mission_type} → {target}")
        print(f"   The Codespace is executing this mission now.")
        print(f"   Check results in ~/nova_reports/ on the Codespace.")
    
    def check_status(self):
        """Check Nova's current status."""
        missions = len(self.brain["missions"])
        findings = len(self.brain["findings"])
        
        print(f"""
╔══════════════════════════════════════════════════════════╗
║   🦅 NOVA CONTROL PANEL — STATUS                        ║
╠══════════════════════════════════════════════════════════╣
║  Codespace: {'✅ Connected' if self.brain['codespace_connected'] else '❌ Disconnected'}                       ║
║  Missions: {missions:<3}  |  Findings: {findings:<3}                              ║
╚══════════════════════════════════════════════════════════╝
        """)
    
    def quick_commands(self):
        """Show available quick commands."""
        print("""
📋 QUICK COMMANDS:
  1. Audit repository    → python3 nova_control_panel.py audit <repo_url>
  2. Scan AI target      → python3 nova_control_panel.py ai <target_url>
  3. Hunt bounties       → python3 nova_control_panel.py bounty <platform>
  4. Full ecosystem scan → python3 nova_control_panel.py ecosystem
  5. Generate report     → python3 nova_control_panel.py report
  6. Check status        → python3 nova_control_panel.py status
        """)

if __name__ == "__main__":
    import sys
    panel = NovaControlPanel()
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        
        if cmd == "audit" and len(sys.argv) > 2:
            panel.send_mission("source_audit", sys.argv[2])
        elif cmd == "ai" and len(sys.argv) > 2:
            panel.send_mission("ai_exploit", sys.argv[2])
        elif cmd == "bounty" and len(sys.argv) > 2:
            panel.send_mission("bounty_hunt", sys.argv[2])
        elif cmd == "ecosystem":
            panel.send_mission("ecosystem_scan", "all_targets")
        elif cmd == "report":
            panel.check_status()
        elif cmd == "status":
            panel.check_status()
        elif cmd == "connect" and len(sys.argv) > 2:
            panel.connect_codespace(sys.argv[2])
        else:
            panel.quick_commands()
    else:
        panel.check_status()
        panel.quick_commands()
