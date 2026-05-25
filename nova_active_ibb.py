#!/usr/bin/env python3
"""
NOVA ACTIVE IBB TESTING v1.0
Authorized security testing for Internet Bug Bounty scope.
Operates under IBB Safe Harbor policy.
"""

import json, time, re, socket, ssl, requests
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

class NovaActiveIBB:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; Nova/9.0; IBB Authorized Research)",
            "Accept": "application/json, text/html",
        })
        self.findings = []
        self.tested_endpoints = []
        
        # IBB authorized scope - confirmed in policy
        self.authorized_targets = {
            "gnu.org": {
                "components": ["bash", "coreutils", "wget", "grub2", "glibc", "gcc"],
                "test_endpoints": ["/software/bash/", "/software/coreutils/", "/software/wget/"],
            },
            "python.org": {
                "components": ["cpython", "pip", "python.org infrastructure"],
                "test_endpoints": ["/", "/downloads/", "/doc/", "/api/"],
            },
            "kernel.org": {
                "components": ["linux kernel", "kernel.org infrastructure"],
                "test_endpoints": ["/", "/pub/", "/doc/"],
            },
            "openssl.org": {
                "components": ["openssl", "openssl.org infrastructure"],
                "test_endpoints": ["/", "/source/", "/docs/"],
            },
            "openbsd.org": {
                "components": ["OpenBSD", "OpenSSH", "LibreSSL"],
                "test_endpoints": ["/", "/faq/", "/ftp.html"],
            },
        }

    def passive_fingerprint(self, domain):
        """Fingerprint a domain's tech stack and security posture."""
        print(f"\n🔍 FINGERPRINTING: {domain}")
        print("-" * 40)
        
        info = {"domain": domain}
        
        try:
            # HTTPS connection
            resp = self.s.get(f"https://{domain}", timeout=15, allow_redirects=True)
            info["status"] = resp.status_code
            info["final_url"] = resp.url
            info["size"] = len(resp.text)
            
            # Server identification
            server = resp.headers.get("Server", "Not disclosed")
            powered = resp.headers.get("X-Powered-By", "Not disclosed")
            print(f"   Server: {server}")
            print(f"   Powered by: {powered}")
            
            # Security headers audit
            security = {
                "HSTS": resp.headers.get("Strict-Transport-Security", "MISSING"),
                "CSP": bool(resp.headers.get("Content-Security-Policy")),
                "XFO": resp.headers.get("X-Frame-Options", "MISSING"),
                "XCTO": resp.headers.get("X-Content-Type-Options", "MISSING"),
                "CORS": resp.headers.get("Access-Control-Allow-Origin", "Not set"),
            }
            
            missing = [k for k, v in security.items() if v in ["MISSING", "Not set", False]]
            if missing:
                print(f"   ⚠️  Missing: {', '.join(missing)}")
                self.findings.append({
                    "domain": domain,
                    "type": "Missing Security Headers",
                    "detail": missing,
                    "severity": "Low",
                    "evidence": f"Headers missing: {missing}",
                })
            
            # Technology detection
            body = resp.text.lower()[:5000]
            tech_found = []
            if "wordpress" in body: tech_found.append("WordPress")
            if "drupal" in body: tech_found.append("Drupal")
            if "joomla" in body: tech_found.append("Joomla")
            if "nginx" in body or server.lower().find("nginx") > -1: tech_found.append("nginx")
            if "apache" in body or server.lower().find("apache") > -1: tech_found.append("Apache")
            if "cloudflare" in body: tech_found.append("Cloudflare")
            
            if tech_found:
                print(f"   📦 Detected: {', '.join(tech_found)}")
            
            info["technologies"] = tech_found
            info["security_headers"] = security
            
        except Exception as e:
            print(f"   ❌ Failed: {str(e)[:80]}")
            info["error"] = str(e)[:100]
        
        return info

    def test_common_endpoints(self, domain):
        """Test common endpoints for information disclosure."""
        print(f"\n📡 ENDPOINT SCAN: {domain}")
        print("-" * 40)
        
        endpoints = [
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/security.txt",
            "/.env",
            "/.git/config",
            "/backup/",
            "/admin/",
            "/api/",
            "/docs/",
            "/debug/",
            "/phpinfo.php",
            "/server-status",
        ]
        
        for path in endpoints:
            try:
                url = f"https://{domain}{path}"
                resp = self.s.get(url, timeout=10, allow_redirects=False)
                
                if resp.status_code in [200, 301, 302, 403]:
                    sensitive = any(k in resp.text.lower()[:500] for k in 
                        ["password", "secret", "key", "token", "admin", "debug", "config"])
                    
                    self.tested_endpoints.append({
                        "domain": domain,
                        "path": path,
                        "status": resp.status_code,
                        "size": len(resp.text),
                        "sensitive": sensitive,
                    })
                    
                    icon = "🔥" if sensitive else "📄"
                    if resp.status_code == 200 or sensitive:
                        print(f"   {icon} {path}: {resp.status_code} ({len(resp.text)} bytes)")
                    
                    if sensitive:
                        self.findings.append({
                            "domain": domain,
                            "type": "Sensitive Endpoint Exposed",
                            "endpoint": path,
                            "severity": "High",
                            "evidence": f"Status: {resp.status_code}, Size: {len(resp.text)} bytes",
                        })
            except:
                pass

    def test_vulnerability_indicators(self, domain):
        """Test for vulnerability indicators without exploitation."""
        print(f"\n🔬 VULNERABILITY INDICATORS: {domain}")
        print("-" * 40)
        
        # SQL injection indicators
        sqli_tests = [
            ("/", {"q": "'"}),
            ("/search", {"q": "'"}),
        ]
        
        for path, params in sqli_tests:
            try:
                url = f"https://{domain}{path}"
                resp = self.s.get(url, params=params, timeout=10)
                
                sql_errors = ["sql", "mysql", "sqlite", "postgresql", "syntax error", "ORA-", "unclosed"]
                found = [e for e in sql_errors if e in resp.text.lower()[:1000]]
                
                if found:
                    self.findings.append({
                        "domain": domain,
                        "type": "Potential SQL Injection Surface",
                        "endpoint": path,
                        "indicators": found,
                        "severity": "Medium",
                        "evidence": f"SQL keywords found in response: {found}",
                    })
                    print(f"   💉 Potential SQLi surface at {path}: {found}")
            except:
                pass
        
        # XSS indicators
        xss_test = "<script>test</script>"
        try:
            resp = self.s.get(f"https://{domain}/search", params={"q": xss_test}, timeout=10)
            if xss_test in resp.text:
                self.findings.append({
                    "domain": domain,
                    "type": "Reflected XSS Indicator",
                    "severity": "High",
                    "evidence": "XSS payload reflected in response",
                })
                print(f"   💚 XSS reflection detected!")
        except:
            pass

    def generate_active_report(self, fingerprints):
        """Generate comprehensive active testing report."""
        print(f"""
╔══════════════════════════════════════════════════════════╗
║     ACTIVE IBB ASSESSMENT COMPLETE                      ║
╠══════════════════════════════════════════════════════════╣
║  Domains Assessed: {len(fingerprints):>3}                                   ║
║  Endpoints Tested: {len(self.tested_endpoints):>3}                                  ║
║  Findings: {len(self.findings):>3}                                         ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        if self.findings:
            print("🔍 ACTIVE FINDINGS:")
            for f in self.findings:
                sev = f.get("severity", "Info")
                icon = {"Critical": "💀", "High": "🔥", "Medium": "⚠️", "Low": "📋"}.get(sev, "📄")
                print(f"   {icon} [{sev}] {f.get('domain')}: {f.get('type')}")
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "program": "Internet Bug Bounty",
            "authorization": "IBB Safe Harbor Policy",
            "domains_assessed": fingerprints,
            "endpoints_tested": self.tested_endpoints,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        
        with open("nova_active_ibb_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n📁 Report: nova_active_ibb_report.json")

    def run(self):
        print("""
╔══════════════════════════════════════════════════════════╗
║   🦅 NOVA ACTIVE IBB TESTING v1.0                      ║
║   Authorized Security Assessment                        ║
║   Operating under IBB Safe Harbor Policy                ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        fingerprints = {}
        
        for domain in self.authorized_targets:
            # Fingerprint
            info = self.passive_fingerprint(domain)
            fingerprints[domain] = info
            
            # Only proceed if domain is reachable
            if "error" in info:
                continue
            
            # Test common endpoints
            self.test_common_endpoints(domain)
            
            # Test vulnerability indicators
            self.test_vulnerability_indicators(domain)
            
            time.sleep(2)  # Rate limiting
        
        # Generate report
        self.generate_active_report(fingerprints)

if __name__ == "__main__":
    NovaActiveIBB().run()
