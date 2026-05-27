#!/usr/bin/env python3
import requests
import sys

DOMAIN = "konghq.com"
URL = f"https://crt.sh/?q=%25.{DOMAIN}&output=json"

print(f"🦅 NOVA INTEL HARVESTER — Target: {DOMAIN}")
print("=================================================")
print("📡 Connecting to Certificate Transparency Logs...")

try:
    response = requests.get(URL, timeout=30)
    if response.status_code != 200:
        print(f"❌ Error: crt.sh returned HTTP status code {response.status_code}")
        sys.exit(1)
        
    data = response.json()
    subdomains = set()
    
    for record in data:
        name = record.get("name_value", "")
        for sub in name.split("\n"):
            sub = sub.strip().lower()
            if sub and not sub.startswith("*."):
                subdomains.add(sub)
                
    with open("targets.txt", "w") as f:
        for sub in sorted(subdomains):
            f.write(f"{sub}\n")
            
    print(f"✅ SUCCESS: Collected {len(subdomains)} unique subdomains.")
    print("📁 Saved directly to targets.txt")

except requests.exceptions.Timeout:
    print("❌ Error: crt.sh took too long to respond.")
except Exception as e:
    print(f"❌ Harvester failed: {str(e)}")
