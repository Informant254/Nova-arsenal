#!/usr/bin/env python3
"""
NOVA CSRF TESTER v1.0
Cross-Site Request Forgery detection:
SameSite cookie analysis, CSRF token validation, origin checking,
custom header reliance, JSON CSRF, and multipart CSRF testing.
"""
import json, re, urllib.request, urllib.error, urllib.parse
from typing import Dict, List, Tuple
from datetime import datetime

STATE_CHANGE_METHODS = ["POST","PUT","PATCH","DELETE"]
CSRF_HEADER_NAMES    = ["x-csrf-token","x-xsrf-token","x-requested-with","csrf-token","_csrf","csrftoken"]

def _req(url, method="GET", data=None, headers=None, timeout=10):
    h = {"User-Agent":"Mozilla/5.0 Nova/4.0",(headers or {}).get("k",""):(headers or {}).get("v","")
         if headers and "k" in headers else ""}
    h = {k:v for k,v in {**(headers or {}), "User-Agent":"Mozilla/5.0 Nova/4.0"}.items() if v}
    req = urllib.request.Request(url, method=method)
    for k,v in h.items(): req.add_header(k,v)
    if data: req.data = data.encode() if isinstance(data,str) else data
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8","replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try: body = e.read().decode("utf-8","replace")
        except: body=""
        return e.code, body, {}
    except Exception as e:
        return 0, str(e), {}


class NovaCsrfTester:
    def __init__(self, base_url: str, session_cookie: str = None):
        self.base_url = base_url.rstrip("/")
        self.session_cookie = session_cookie
        self.base_headers = {}
        if session_cookie:
            self.base_headers["Cookie"] = session_cookie
        self.findings: List[Dict] = []

    def _analyze_set_cookie(self, headers: Dict) -> List[Dict]:
        findings = []
        set_cookie = headers.get("Set-Cookie","")
        if not set_cookie: return findings
        cookies = set_cookie if isinstance(set_cookie, list) else [set_cookie]
        for cookie in cookies:
            name = cookie.split("=")[0].strip()
            if "samesite" not in cookie.lower():
                findings.append({"type":"Missing SameSite Cookie Attribute","severity":"MEDIUM",
                    "description":f"Cookie '{name}' missing SameSite attribute — vulnerable to CSRF in some browsers",
                    "cookie": cookie[:100]})
            elif "samesite=none" in cookie.lower() and "secure" not in cookie.lower():
                findings.append({"type":"SameSite=None without Secure","severity":"HIGH",
                    "description":f"Cookie '{name}' has SameSite=None but missing Secure flag",
                    "cookie": cookie[:100]})
            if "httponly" not in cookie.lower() and any(s in name.lower() for s in ("sess","auth","token","jwt")):
                findings.append({"type":"Missing HttpOnly on Session Cookie","severity":"MEDIUM",
                    "description":f"Session-like cookie '{name}' missing HttpOnly flag — accessible via JavaScript",
                    "cookie": cookie[:100]})
            if "secure" not in cookie.lower() and any(s in name.lower() for s in ("sess","auth","token","jwt")):
                findings.append({"type":"Missing Secure Flag on Session Cookie","severity":"MEDIUM",
                    "description":f"Session-like cookie '{name}' missing Secure flag — transmitted over HTTP",
                    "cookie": cookie[:100]})
        return findings

    def _check_csrf_token_validation(self, endpoint: str, method: str = "POST") -> List[Dict]:
        findings = []
        url = self.base_url + endpoint
        # Step 1: Get page to extract CSRF token
        code, body, hdrs = _req(url, headers=self.base_headers)
        if code not in (200,): return findings

        token_match = re.search(r'(?:csrf[_-]?token|_csrf|csrfmiddlewaretoken)["\s]*[=:]["\s]*([A-Za-z0-9+/\-_]{16,})', body, re.IGNORECASE)
        if not token_match:
            # Try to POST without a CSRF token
            code2, body2, _ = _req(url, method=method,
                data=urllib.parse.urlencode({"test":"nova_csrf_probe"}),
                headers={**self.base_headers, "Content-Type":"application/x-www-form-urlencoded"})
            if code2 in (200, 201, 302):
                findings.append({"type":"CSRF — No Token Required","severity":"HIGH",
                    "endpoint": url, "method": method,
                    "description":"State-changing request accepted without CSRF token"})
        else:
            token = token_match.group(1)
            # Replay with invalid token
            code3, body3, _ = _req(url, method=method,
                data=urllib.parse.urlencode({"csrfmiddlewaretoken":"INVALID_TOKEN_NOVA","test":"value"}),
                headers={**self.base_headers, "Content-Type":"application/x-www-form-urlencoded"})
            if code3 in (200, 201):
                findings.append({"type":"CSRF Token Not Validated","severity":"HIGH",
                    "endpoint": url, "method": method,
                    "description":"Invalid CSRF token accepted — token validation not enforced"})
        return findings

    def _check_origin_referer(self, endpoint: str, method: str = "POST") -> List[Dict]:
        findings = []
        url = self.base_url + endpoint
        evil_origin = "https://evil-attacker.com"
        # Test with evil Origin header
        code, body, _ = _req(url, method=method,
            data=urllib.parse.urlencode({"test":"nova"}),
            headers={**self.base_headers, "Origin": evil_origin,
                     "Content-Type": "application/x-www-form-urlencoded"})
        if code in (200, 201):
            findings.append({"type":"CSRF — Evil Origin Accepted","severity":"HIGH",
                "endpoint": url, "description": f"Request from Origin: {evil_origin} accepted",
                "status_code": code})
        # Test with null Origin
        code2, body2, _ = _req(url, method=method,
            data=urllib.parse.urlencode({"test":"nova"}),
            headers={**self.base_headers, "Origin": "null",
                     "Content-Type": "application/x-www-form-urlencoded"})
        if code2 in (200, 201):
            findings.append({"type":"CSRF — Null Origin Accepted","severity":"HIGH",
                "endpoint": url, "description": "Null Origin header accepted — possible CSRF via sandboxed iframe"})
        return findings

    def _check_json_csrf(self, endpoint: str) -> List[Dict]:
        findings = []
        url = self.base_url + endpoint
        code, body, _ = _req(url, method="POST",
            data=json.dumps({"action":"test","csrf_probe":"nova"}),
            headers={**self.base_headers, "Content-Type":"application/json",
                     "Origin":"https://evil-attacker.com"})
        if code in (200, 201):
            findings.append({"type":"JSON CSRF","severity":"MEDIUM",
                "endpoint": url,
                "description":"JSON POST with evil Origin accepted — may allow CSRF if SameSite not enforced"})
        # Attempt with text/plain (browser-sendable without preflight)
        code2, _, _ = _req(url, method="POST",
            data='{"action":"test"}',
            headers={**self.base_headers, "Content-Type":"text/plain"})
        if code2 in (200, 201):
            findings.append({"type":"JSON CSRF via text/plain","severity":"MEDIUM",
                "endpoint": url,
                "description":"JSON POST with Content-Type: text/plain accepted — no CORS preflight needed"})
        return findings

    def _check_cors(self, endpoint: str) -> List[Dict]:
        findings = []
        url = self.base_url + endpoint
        evil_origin = "https://evil-attacker.com"
        code, body, hdrs = _req(url, headers={**self.base_headers, "Origin": evil_origin})
        acao = hdrs.get("Access-Control-Allow-Origin","")
        acac = hdrs.get("Access-Control-Allow-Credentials","")
        if acao == "*":
            findings.append({"type":"CORS Wildcard Origin","severity":"MEDIUM",
                "endpoint": url,
                "description":"Access-Control-Allow-Origin: * — restricts reading responses but not secure for credentialed requests"})
        if acao == evil_origin and acac.lower() == "true":
            findings.append({"type":"CORS Arbitrary Origin + Credentials","severity":"CRITICAL",
                "endpoint": url,
                "description":f"CORS reflects arbitrary Origin AND allows credentials — full CSRF/data theft possible"})
        if acao and acao != "*" and evil_origin in acao:
            findings.append({"type":"CORS Reflected Origin","severity":"HIGH",
                "endpoint": url,
                "description":"CORS reflects attacker-controlled Origin header"})
        return findings

    def run(self, endpoints: List[str] = None) -> List[Dict]:
        print(f"\n🔐 NOVA CSRF TESTER — {self.base_url}")
        print("=" * 60)
        test_paths = endpoints or ["/", "/api/user", "/api/account", "/profile",
                                    "/settings", "/api/login", "/api/transfer"]
        all_findings = []

        # Cookie analysis
        _, _, hdrs = _req(self.base_url, headers=self.base_headers)
        all_findings.extend(self._analyze_set_cookie(hdrs))

        for path in test_paths[:8]:
            all_findings.extend(self._check_csrf_token_validation(path))
            all_findings.extend(self._check_origin_referer(path))
            all_findings.extend(self._check_json_csrf(path))
            all_findings.extend(self._check_cors(path))

        self.findings = all_findings
        print(f"  📊 CSRF Scan: {len(all_findings)} findings")
        return all_findings

    def save(self, path):
        with open(path,"w") as f:
            json.dump({"generated":datetime.now().isoformat(),"target":self.base_url,
                       "findings":self.findings},f,indent=2)
        print(f"  💾 CSRF report → {path}")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv)>1 else "http://localhost:3000"
    t = NovaCsrfTester(target)
    t.run(); t.save("nova_csrf_report.json")
