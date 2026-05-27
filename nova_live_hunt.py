#!/usr/bin/env python3
"""
NOVA LIVE HUNT — HACKERONE DEPLOYMENT READY
Profile 1: Enterprise SaaS (config/API exposure)
Profile 2: Logistics/Infrastructure (BOLA/param leakage)
Profile 3: Cloud Frameworks (path mutation/500 errors)

Defensive Layers:
- Strict Scope Enforcement
- Adjustable Rate Limiting
- Custom HackerOne Header Identification
"""

import json, hashlib, random, time, ssl, threading, urllib.request, re, sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

class NovaLiveHunt:
    def __init__(self, target, h1_username="Informant254", delay=0.1, workers=5):
        self.target = target.rstrip("/")
        self.scope_domain = urlparse(target).netloc
        self.h1_username = h1_username
        self.delay = delay
        self.workers = workers
        self.findings = []
        self.baseline = {}
        
        # HackerOne-compliant User-Agent
        self.user_agents = [
            f"BugBounty-Research-{h1_username}/1.0 (Nova Security Agent)",
            f"Mozilla/5.0 (compatible; {h1_username}-H1-Research; +https://hackerone.com/{h1_username})",
        ]
        self.counter = 0
        
        # ===== PROFILE 1: ENTERPRISE SAAS PATTERNS =====
        self.config_endpoints = [
            "/api/config", "/api/v1/config", "/api/v2/config",
            "/.env", "/debug", "/metrics", "/status",
            "/api/settings", "/admin/config", "/api/health",
            "/actuator", "/actuator/health", "/actuator/info",
            "/swagger.json", "/api-docs", "/openapi.json",
        ]
        
        # ===== PROFILE 2: LOGISTICS/INFRA PATTERNS =====
        self.integration_params = [
            "clientId", "clientSecret", "apiKey", "api_key",
            "authDomain", "auth_domain", "projectId", "project_id",
            "appId", "app_id", "tenantId", "tenant_id",
            "databaseUrl", "database_url", "redisUrl", "redis_url",
            "awsAccessKey", "aws_access_key", "gcpKey", "gcp_key",
        ]
        
        # ===== PROFILE 3: CLOUD FRAMEWORK PATTERNS =====
        self.path_mutations = [
            "//", "/../", "/%2e%2e/", "/..;/",
            "/%2f", "/%5c", "/./", "/?...",
            "//..//..//", "/%252e%252e/",
        ]
    
    def in_scope(self, url):
        """Strict scope enforcement - never leave the target domain."""
        parsed = urlparse(url)
        return self.scope_domain in parsed.netloc
    
    def get_headers(self):
        """Generate headers with HackerOne identification."""
        self.counter += 1
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "application/json, text/html, */*",
            "X-H1-Research": self.h1_username,
            "X-Nova-Request-ID": hashlib.md5(f"{time.time()}{self.counter}".encode()).hexdigest()[:12],
        }
    
    def establish_baseline(self):
        """Detect catch-all SPA routing to eliminate false positives."""
        print("📡 Establishing catch-all baseline...")
        test_paths = ["/nova_test_12345", "/definitely_not_real_xyz", "/fake_page_67890"]
        sizes = []
        
        for path in test_paths:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                url = urljoin(self.target + "/", path)
                req = urllib.request.Request(url, headers=self.get_headers())
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                sizes.append(len(resp.read()))
            except:
                pass
        
        if sizes:
            self.baseline["catch_all_size"] = max(set(sizes), key=sizes.count)
            print(f"   Catch-all size: {self.baseline['catch_all_size']} bytes")
            print(f"   Any response this size → FALSE POSITIVE\n")
    
    def probe_endpoint(self, endpoint, payload=""):
        """Probe a single endpoint with rate limiting and scope check."""
        time.sleep(self.delay)  # Rate limiting
        
        url = urljoin(self.target + "/", f"{endpoint}{payload}")
        if not self.in_scope(url):
            return None
        
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers=self.get_headers())
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            text = resp.read().decode("utf-8", errors="ignore")
            response_text = text
            
            # Skip catch-all responses
            catch_all = self.baseline.get("catch_all_size", 0)
            if catch_all > 0 and len(text) == catch_all:
                return None
            
            # Profile 1: Look for JSON config exposure
            if resp.status == 200 and len(text) > 100:
                try:
                    data = json.loads(text)
                    # Check for integration params in the response
                    exposed_params = []
                    for param in self.integration_params:
                        text_lower = text.lower()
                        if param.lower() in text_lower:
                            exposed_params.append(param)
                    
                    if exposed_params:
                        finding = {
                            "profile": "enterprise_saas",
                            "type": "config_exposure",
                            "endpoint": endpoint,
                            "exposed_params": exposed_params,
                            "size": len(text),
                        }
                        self.findings.append(finding)
                        print(f"   💀 CONFIG EXPOSURE: {endpoint}")
                        print(f"      Exposed: {exposed_params}")
                        return finding
                except json.JSONDecodeError:
                    pass
            
            # Profile 3: Look for 500 errors on path mutations
            if resp.status == 500:
                finding = {
                    "profile": "cloud_framework",
                    "type": "unhandled_server_error",
                    "endpoint": endpoint,
                    "payload": payload,
                    "status": resp.status,
                    "response_text": text[:500],
                }
                self.findings.append(finding)
                print(f"   💀 500 ERROR: {endpoint}{payload}")
                return finding
            
        except urllib.error.HTTPError as e:
            if e.code == 500:
                finding = {
                    "profile": "cloud_framework",
                    "type": "unhandled_server_error",
                    "endpoint": endpoint,
                    "payload": payload,
                    "status": e.code,
                }
                self.findings.append(finding)
                print(f"   💀 500 ERROR: {endpoint}{payload}")
                return finding
        except:
            pass
        
        return None
    
    def run_profile_1(self):
        """Enterprise SaaS: Hunt for config/API exposure."""
        print("\n🎯 PROFILE 1: Enterprise SaaS Config Exposure")
        print("-" * 40)
        
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = [ex.submit(self.probe_endpoint, ep) for ep in self.config_endpoints]
            for f in as_completed(futures): f.result()
    
    def run_profile_3(self):
        """Cloud Frameworks: Path mutation for 500 errors."""
        print("\n🎯 PROFILE 3: Cloud Framework Path Mutations")
        print("-" * 40)
        
        for mutation in self.path_mutations[:5]:
            with ThreadPoolExecutor(max_workers=self.workers) as ex:
                futures = [ex.submit(self.probe_endpoint, ep, mutation) for ep in ["/api", "/admin", "/login"]]
                for f in as_completed(futures): f.result()
    

    
    def classify_finding(self, finding):
        """Classify severity. Stack traces from unmatched routes = LOW hardening, not HIGH vuln."""
        response_text = finding.get("response_text", "")
        
        # Noise patterns - structural hardening, not vulnerabilities
        noise_patterns = [
            "Error: Unexpected path",
            "Unexpected path:",
            "at Layer.handle",
            "at trim_prefix",
            "at router.process_params",
            "StringIndexOutOfBoundsException",
        ]
        
        is_noise = any(p in response_text for p in noise_patterns)
        
        if is_noise:
            finding["severity"] = "LOW"
            finding["classification"] = "structural_hardening"
            finding["submission_ready"] = False
            return finding
        
        # Real findings
        if finding.get("type") == "config_exposure":
            finding["severity"] = "HIGH"
            finding["classification"] = "information_disclosure"
            finding["submission_ready"] = True
        elif finding.get("type") == "unhandled_server_error" and not is_noise:
            finding["severity"] = "MEDIUM"
            finding["classification"] = "error_handling"
            finding["submission_ready"] = True
        else:
            finding["severity"] = "LOW"
            finding["classification"] = "structural_hardening"
            finding["submission_ready"] = False
        
        return finding
    
    def summarize_terminal(self):
        """Clean terminal output - only show submission-ready findings."""
        ready = [f for f in self.findings if f.get("submission_ready")]
        hardening = [f for f in self.findings if not f.get("submission_ready")]
        
        print(f"\n{'='*50}")
        print(f"📊 HUNT SUMMARY")
        print(f"   Submission-Ready Findings: {len(ready)}")
        print(f"   Structural Hardening Items: {len(hardening)} (logged, not submitted)")
        
        if ready:
            print(f"\n💀 READY FOR HACKERONE:")
            for f in ready[:5]:
                print(f"   [{f['severity']}] {f['type']}: {f.get('endpoint', '')}")
        
        if hardening:
            print(f"\n📋 HARDENING ITEMS (not for submission):")
            for f in hardening[:3]:
                print(f"   [LOW] {f['type']}: {f.get('endpoint', '')}")

    def generate_report(self):
        self.summarize_terminal()

        """Generate HackerOne-ready report."""
        print(f"\n{'='*50}")
        print(f"📊 LIVE HUNT COMPLETE")
        print(f"   Target: {self.target}")
        print(f"   Findings: {len(self.findings)}")
        
        if self.findings:
            print(f"\n💀 FINDINGS FOR HACKERONE SUBMISSION:")
            for f in self.findings[:10]:
                print(f"   [{f['profile']}] {f['type']}: {f.get('endpoint', '')}")
                if 'exposed_params' in f:
                    print(f"      Exposed: {f['exposed_params']}")
        
        report = {
            "h1_researcher": self.h1_username,
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "findings": self.findings,
            "total": len(self.findings),
            "safe_harbor": "Traffic identifiable via User-Agent header",
        }
        
        filename = f"nova_h1_hunt_{urlparse(self.target).netloc}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📁 {filename}")
        print(f"🦅 Ready for HackerOne submission.")
        return report

if __name__ == "__main__":
    print("🦅 NOVA LIVE HUNT — HACKERONE READY\n")
    
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    delay = float(sys.argv[2]) if len(sys.argv) > 2 else 0.1
    
    hunter = NovaLiveHunt(target=target, h1_username="Informant254", delay=delay, workers=5)
    hunter.establish_baseline()
    hunter.run_profile_1()
    hunter.run_profile_3()
    hunter.generate_report()
