#!/usr/bin/env python3
"""
NOVA BUSINESS LOGIC TESTER v1.1
Tests business logic vulnerabilities:
negative price/quantity, coupon stacking, race conditions,
TOCTOU, workflow bypass, integer overflow, and state machine abuse.

FIX (v1.1): All endpoint tests now include a pre-flight existence check.
Endpoints are only reported as vulnerable if:
  1. The endpoint returns HTTP 200/201 (not 404/405)
  2. The response body contains meaningful API content (not generic HTML)
  3. The response indicates the endpoint actually processed the request
This eliminates false positives from testing Juice Shop paths against targets
that don't have those routes.
"""
import json, re, urllib.request, urllib.error, threading, time
from typing import Dict, List, Optional, Tuple
from datetime import datetime

def _req(url, method="GET", data=None, headers=None, timeout=10):
    h = {**(headers or {}), "User-Agent":"Nova/4.0"}
    req = urllib.request.Request(url, method=method)
    for k,v in h.items(): req.add_header(k,v)
    if data:
        req.data = data.encode() if isinstance(data,str) else data
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8","replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try: body=e.read().decode("utf-8","replace")
        except: body=""
        return e.code, body, {}
    except Exception as e:
        return 0, str(e), {}


def _is_real_api_response(code: int, body: str, headers: Dict) -> bool:
    """
    Returns True only if the response looks like a real API endpoint response,
    not a generic HTML catch-all (SPA fallback page).
    This prevents false positives where any path returns HTTP 200 with the
    full HTML page body.
    """
    if code not in (200, 201):
        return False
    content_type = headers.get("Content-Type", headers.get("content-type", ""))
    # JSON API response — strong signal
    if "application/json" in content_type:
        return True
    # HTML response that is very large is likely a SPA catch-all
    if "text/html" in content_type and len(body) > 3000:
        return False
    # Short non-HTML body with recognizable API keywords
    if len(body) < 5000 and any(k in body for k in ('"success"', '"error"', '"message"', '"data"', '"result"', '"status"')):
        return True
    return False


def _endpoint_exists(base_url: str, path: str, headers: Dict = None) -> bool:
    """Pre-flight probe: confirm endpoint exists on live target before testing."""
    url = base_url.rstrip("/") + path
    code, body, hdrs = _req(url, headers=headers or {})
    if code in (0, 404, 410):
        return False
    return _is_real_api_response(code, body, hdrs) or code in (401, 403)


class NovaBusinessLogicTester:
    def __init__(self, base_url: str, auth_headers: Dict = None):
        self.base_url = base_url.rstrip("/")
        self.headers  = auth_headers or {}
        self.findings: List[Dict] = []

    def _u(self, path): return self.base_url + path

    def test_negative_values(self) -> List[Dict]:
        findings = []
        endpoints = [("/api/basket","quantity"),("/api/order","amount"),("/api/cart","qty"),
                     ("/api/purchase","count"),("/shop/cart","quantity")]
        for path, param in endpoints:
            if not _endpoint_exists(self.base_url, path, self.headers):
                continue
            for val in [-1, -999, 0, -0.01]:
                code,body,hdrs = _req(self._u(path), "POST",
                    data=json.dumps({param:val,"product_id":1,"item_id":1}),
                    headers={**self.headers,"Content-Type":"application/json"})
                if _is_real_api_response(code, body, hdrs) and ('"success"' in body or '"total"' in body):
                    findings.append({"type":"Business Logic — Negative Value Accepted","severity":"HIGH",
                        "endpoint":path,"payload":{param:val},
                        "description":f"Negative {param}={val} accepted — potential credit/refund abuse"})
        return findings

    def test_price_manipulation(self) -> List[Dict]:
        findings = []
        endpoints = ["/api/basket","/api/cart","/api/order","/shop/checkout"]
        for path in endpoints:
            if not _endpoint_exists(self.base_url, path, self.headers):
                continue
            for price in [0.01, 0.00, -1.00, 0]:
                code,body,hdrs = _req(self._u(path), "POST",
                    data=json.dumps({"price":price,"quantity":1,"product_id":1}),
                    headers={**self.headers,"Content-Type":"application/json"})
                if _is_real_api_response(code, body, hdrs) and '"price"' in body:
                    findings.append({"type":"Business Logic — Client-Side Price Manipulation","severity":"HIGH",
                        "endpoint":path,"payload":{"price":price},
                        "description":"Server accepted client-supplied price — price should be server-authoritative"})
        return findings

    def test_coupon_stacking(self) -> List[Dict]:
        findings = []
        path = "/api/coupon/apply"
        if not _endpoint_exists(self.base_url, path, self.headers):
            return findings
        codes = ["FREESHIP","SAVE10","DISCOUNT","TEST100","NOVAFREE"]
        applied = 0
        for code in codes:
            status,body,hdrs = _req(self._u(path), "POST",
                data=json.dumps({"coupon":code}),
                headers={**self.headers,"Content-Type":"application/json"})
            if _is_real_api_response(status, body, hdrs) and ('"discount"' in body or '"success"' in body):
                applied += 1
        if applied >= 2:
            findings.append({"type":"Business Logic — Coupon Stacking","severity":"MEDIUM",
                "endpoint":path,"applied":applied,
                "description":f"{applied} coupons applied simultaneously — may allow unlimited discounts"})
        return findings

    def test_race_condition(self, endpoint: str = "/api/redeem") -> List[Dict]:
        findings = []

        # Pre-flight: only test if endpoint exists on the live target
        if not _endpoint_exists(self.base_url, endpoint, self.headers):
            print(f"  ℹ️  Race: {endpoint} not found on target — skipping")
            return findings

        results = []
        errors  = []

        def fire():
            try:
                code,body,hdrs = _req(self._u(endpoint),"POST",
                    data=json.dumps({"code":"ONEUSE_NOVA","amount":100}),
                    headers={**self.headers,"Content-Type":"application/json"})
                results.append((code,body[:50],hdrs))
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=fire) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()

        # Only count successes that look like real API responses
        successes = [r for r in results if _is_real_api_response(r[0], r[1], r[2])]
        if len(successes) >= 2:
            findings.append({"type":"Race Condition / TOCTOU","severity":"CRITICAL",
                "endpoint":endpoint,"successful_concurrent_requests":len(successes),
                "description":f"Race condition — {len(successes)} concurrent requests both succeeded (one-time use bypass)"})
        return findings

    def test_workflow_bypass(self) -> List[Dict]:
        findings = []
        skip_tests = [
            ("/api/checkout/confirm","POST",{"skip_payment":True,"paid":True},"Payment step bypass"),
            ("/api/verify/skip","GET",{},"Verification step bypass"),
            ("/api/order/complete","POST",{"status":"completed","verified":True},"Order completion bypass"),
            ("/api/admin/users","GET",{},"Admin endpoint without admin role"),
        ]
        for path, method, payload, desc in skip_tests:
            # Pre-flight: only test if the endpoint exists on live target
            if not _endpoint_exists(self.base_url, path, self.headers):
                continue
            code,body,hdrs = _req(self._u(path), method,
                data=json.dumps(payload) if payload else None,
                headers={**self.headers,"Content-Type":"application/json"})
            # Require real API response — not a generic HTML catch-all
            if _is_real_api_response(code, body, hdrs):
                findings.append({"type":"Business Logic — Workflow Step Bypass","severity":"HIGH",
                    "endpoint":path,"description":desc,"status_code":code})
        return findings

    def test_integer_overflow(self) -> List[Dict]:
        findings = []
        overflow_vals = [2**31-1, 2**31, 2**32, 2**63-1, -2**31, 999999999999]
        for path in ["/api/basket","/api/order","/api/cart"]:
            if not _endpoint_exists(self.base_url, path, self.headers):
                continue
            for val in overflow_vals[:3]:
                code,body,hdrs = _req(self._u(path),"POST",
                    data=json.dumps({"quantity":val,"product_id":1}),
                    headers={**self.headers,"Content-Type":"application/json"})
                if _is_real_api_response(code, body, hdrs):
                    findings.append({"type":"Integer Overflow / Large Value","severity":"MEDIUM",
                        "endpoint":path,"value":val,
                        "description":f"Extreme quantity {val} accepted — potential integer overflow"})
                    break
        return findings

    def run(self) -> List[Dict]:
        print(f"\n🎯 NOVA BUSINESS LOGIC TESTER — {self.base_url}")
        print("=" * 60)
        all_findings = []
        print("  🔢 Testing negative values...")
        all_findings.extend(self.test_negative_values())
        print("  💰 Testing price manipulation...")
        all_findings.extend(self.test_price_manipulation())
        print("  🎟  Testing coupon stacking...")
        all_findings.extend(self.test_coupon_stacking())
        print("  🏎  Testing race condition (10 concurrent requests)...")
        all_findings.extend(self.test_race_condition())
        print("  🚦 Testing workflow bypass...")
        all_findings.extend(self.test_workflow_bypass())
        print("  💥 Testing integer overflow...")
        all_findings.extend(self.test_integer_overflow())
        self.findings = all_findings
        print(f"\n  📊 Business Logic: {len(all_findings)} findings")
        return all_findings

    def save(self, path):
        with open(path,"w") as f:
            json.dump({"generated":datetime.now().isoformat(),"findings":self.findings},f,indent=2)
        print(f"  💾 Business logic report → {path}")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv)>1 else "http://localhost:3000"
    t = NovaBusinessLogicTester(target)
    t.run(); t.save("nova_business_logic_report.json")
