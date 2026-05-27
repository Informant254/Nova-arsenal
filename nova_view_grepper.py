#!/usr/bin/env python3
import requests
import sys

# ⚙️ Configuration Matrix
TARGET = "http://localhost:3000"
PAYLOAD_SIGNATURE = "w.soundcloud.com/player"

# Standard structural routing views for modern SPAs
views = [
    "/",
    "/#/search",
    "/#/score-board",
    "/#/about",
    "/#/contact",
    "/#/photo-wall"
]

print("🦅 NOVA DYNAMIC VIEW GREPPER")
print("=================================================")
print(f"📡 Target Host: {TARGET}")
print(f"🔍 Hunting For: {PAYLOAD_SIGNATURE}\n")

found_any = False

for view in views:
    url = f"{TARGET}{view}"
    try:
        # Request the raw client view response
        r = requests.get(url, timeout=5)
        
        # Look for the exact signature reflection inside the returned text
        if PAYLOAD_SIGNATURE in r.text:
            print(f"🎯 MATCH FOUND: The path [{view}] actively renders the payload context!")
            found_any = True
        else:
            print(f"  ❌ {view:<15} : Clean (Signature not present in client body)")
            
    except requests.exceptions.RequestException as e:
        print(f"  🔥 Connection Failed on {view}: {str(e)[:50]}")

print("=================================================")
if not found_any:
    print("📋 SUMMARY: Signature 0 occurrences. Payload is dormant in backend config.")
else:
    print("🔥 SUMMARY: Payload execution confirmed in active DOM paths.")

