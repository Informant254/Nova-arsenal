#!/usr/bin/env python3
import requests, sys

TARGET = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else "http://localhost:9090"

print("🔥 TRACING THE CRASH\n")
tests = [
    ("Bare", "/jnlpJars"), ("Empty", "/jnlpJars/"), ("Double slash", "/jnlpJars///"),
    ("Query", "/jnlpJars/?test=1"), ("Dot dot", "/jnlpJars/../"), ("Long", "/jnlpJars/" + "A" * 500),
]
s = requests.Session()
for name, path in tests:
    try:
        r = s.get(f"{TARGET}{path}", timeout=10)
        icon = "💥" if r.status_code == 500 else "✅" if r.status_code == 200 else "❌" if r.status_code == 404 else "⚠️"
        print(f"  {icon} {name}: HTTP {r.status_code} ({len(r.text)} bytes)")
        if "StringIndexOutOfBoundsException" in r.text:
            print(f"     💀 CRASH CONFIRMED")
    except Exception as e:
        print(f"  🔥 {name}: {str(e)[:60]}")
