#!/usr/bin/env python3
"""
NOVA TERMUX CLIENT
Sends missions to Codespace server and gets results back.
"""

import json, requests, sys, os

class NovaTermuxClient:
    def __init__(self):
        self.server_url = self.load_server_url()
    
    def load_server_url(self):
        try:
            with open("nova_control_brain.json") as f:
                brain = json.load(f)
                url = brain.get("codespace_url", "")
                if url:
                    # Convert github.dev URL to port URL
                    # Codespaces forward ports to: https://CODESPACE_NAME-8765.preview.app.github.dev
                    name = url.replace("https://", "").replace(".github.dev", "")
                    return f"https://{name}-8765.preview.app.github.dev"
        except:
            pass
        return ""
    
    def send_mission(self, mission_type, target):
        """Send a mission to the Codespace."""
        if not self.server_url:
            print("❌ No server URL. Run this in Codespace first:")
            print("   python3 nova_codespace_server.py")
            print("   Then make port 8765 public in Codespace ports tab")
            return
        
        mission = {"type": mission_type, "target": target}
        
        try:
            print(f"🚀 Sending mission to Codespace...")
            print(f"   Type: {mission_type}")
            print(f"   Target: {target}")
            print(f"")
            
            resp = requests.post(
                f"{self.server_url}/execute",
                json=mission,
                timeout=300
            )
            
            if resp.status_code == 200:
                result = resp.json()
                print(f"✅ Mission complete!")
                print(f"   Findings: {result.get('findings', 'N/A')}")
                print(f"   Critical: {result.get('critical', 'N/A')}")
                print(f"   Report: {result.get('report_file', 'N/A')}")
                if result.get("output"):
                    print(f"\n📊 OUTPUT:")
                    print(result["output"][:500])
            else:
                print(f"❌ Server error: HTTP {resp.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"❌ Cannot reach Codespace server")
            print(f"   Make sure port 8765 is public in Codespace")
        except Exception as e:
            print(f"❌ Error: {str(e)[:100]}")

if __name__ == "__main__":
    client = NovaTermuxClient()
    
    if len(sys.argv) < 2:
        print("📋 COMMANDS:")
        print("  audit <repo_url>  → Audit a repository")
        print("  ai <target>       → Hunt AI vulnerabilities")
        print("  ecosystem         → Scan all targets")
        print("  status            → Check server status")
        sys.exit(0)
    
    cmd = sys.argv[1]
    
    if cmd == "status":
        try:
            resp = requests.get(f"{client.server_url}/status", timeout=10)
            print(json.dumps(resp.json(), indent=2))
        except:
            print("❌ Server unreachable")
    
    elif cmd in ["audit", "ai", "ecosystem"]:
        target = sys.argv[2] if len(sys.argv) > 2 else ""
        if cmd == "ecosystem":
            target = "all"
        client.send_mission(cmd, target)
    
    else:
        print(f"Unknown command: {cmd}")
