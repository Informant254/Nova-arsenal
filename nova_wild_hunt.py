#!/usr/bin/env python3
"""
NOVA WILD HUNT v1.0
Beyond Juice Shop — real-world target assessment engine.
- Automated subdomain discovery
- Technology stack fingerprinting
- CVE-to-exploit mapping
- Vulnerability scanning with OWASP coverage
- Bug bounty reconnaissance automation
"""

import json, re, time, socket, ssl, requests, concurrent.futures
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin
import os, sys

class NovaWildHunt:
    """Real-world target assessment and exploitation framework."""
    
    def __init__(self, target: str):
        self.target = target
        self.base_url = f"https://{target}" if not target.startswith("http") else target
        self.domain = urlparse(self.base_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
        })
        self.findings = []
        self.subdomains = []
        self.open_ports = []
        self.tech_stack = {}
        self.endpoints = []
        self.start_time = None
        
        # Bug bounty targets for safe testing
        self.safe_targets = [
            "testphp.vulnweb.com",
            "httpbin.org",
            "jsonplaceholder.typicode.com",
        ]

    def log(self, msg, level="INFO"):
        print(f"  [{datetime.now().strftime('%H:%M:%S')}] [{level}] {msg}")

    # ===== RECONNAISSANCE =====
    def discover_subdomains(self):
        """Discover subdomains using multiple techniques."""
        self.log(f"🔍 Discovering subdomains for {self.domain}")
        
        # DNS brute-force with common subdomains
        common_subs = [
            "www", "mail", "admin", "api", "dev", "staging", "test",
            "blog", "shop", "app", "portal", "cdn", "status", "docs",
            "vpn", "ftp", "ssh", "git", "jenkins", "jira", "confluence",
            "monitor", "grafana", "prometheus", "kibana", "elastic",
            "auth", "login", "signup", "account", "billing", "pay",
            "api-dev", "api-staging", "internal", "corp", "m", "mobile",
        ]
        
        for sub in common_subs:
            hostname = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(hostname)
                self.subdomains.append(hostname)
                self.log(f"  📡 Found: {hostname}")
            except:
                pass
        
        self.log(f"📊 Found {len(self.subdomains)} subdomains")

    def scan_ports(self, ports=None):
        """Scan common ports on the target."""
        if ports is None:
            ports = [80, 443, 8080, 8443, 3000, 3001, 5000, 8000, 8081, 9000, 9090, 3306, 5432, 27017, 6379]
        
        self.log(f"🔍 Scanning {len(ports)} ports on {self.domain}")
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.domain, port))
                if result == 0:
                    service = self._identify_service(port)
                    self.open_ports.append({"port": port, "service": service})
                    self.log(f"  🔓 Port {port}: OPEN ({service})")
                sock.close()
            except:
                pass
        
        self.log(f"📊 Found {len(self.open_ports)} open ports")

    def _identify_service(self, port):
        """Identify service running on a port."""
        common = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
                  3000: "Node.js/Grafana", 3306: "MySQL", 5432: "PostgreSQL",
                  27017: "MongoDB", 6379: "Redis", 22: "SSH", 21: "FTP"}
        return common.get(port, "Unknown")

    def fingerprint_technology(self):
        """Identify technologies used by the target."""
        self.log(f"🔍 Fingerprinting {self.base_url}")
        
        try:
            resp = self.session.get(self.base_url, timeout=10, verify=False)
            headers = resp.headers
            body = resp.text.lower()
            
            # Server header
            server = headers.get("Server", "")
            if server:
                self.tech_stack["server"] = server
                self.log(f"  🖥️ Server: {server}")
            
            # Framework detection
            if "x-powered-by" in headers:
                self.tech_stack["powered_by"] = headers["x-powered-by"]
                self.log(f"  ⚡ Powered by: {headers['x-powered-by']}")
            
            # JavaScript frameworks
            frameworks = {
                "react": "React", "vue": "Vue.js", "angular": "Angular",
                "jquery": "jQuery", "bootstrap": "Bootstrap",
            }
            for key, name in frameworks.items():
                if key in body:
                    self.tech_stack["frontend"] = name
                    self.log(f"  🎨 Frontend: {name}")
                    break
            
            # CMS detection
            cms = {"wp-content": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
                   "shopify": "Shopify", "magento": "Magento"}
            for key, name in cms.items():
                if key in body:
                    self.tech_stack["cms"] = name
                    self.log(f"  📦 CMS: {name}")
                    break
            
            # Security headers check
            security_headers = {
                "strict-transport-security": "HSTS",
                "content-security-policy": "CSP",
                "x-frame-options": "X-Frame-Options",
                "x-content-type-options": "X-Content-Type-Options",
                "x-xss-protection": "X-XSS-Protection",
            }
            missing = []
            for header, name in security_headers.items():
                if header not in headers:
                    missing.append(name)
            if missing:
                self.log(f"  ⚠️ Missing security headers: {', '.join(missing)}")
                self.findings.append({
                    "type": "missing_security_headers",
                    "severity": "medium",
                    "detail": missing,
                })
            
        except Exception as e:
            self.log(f"  ❌ Fingerprint failed: {str(e)[:80]}")

    # ===== VULNERABILITY SCANNING =====
    def scan_common_vulnerabilities(self):
        """Scan for common vulnerabilities."""
        self.log(f"🔍 Scanning common vulnerabilities...")
        
        # Test endpoints that commonly leak info
        common_paths = [
            "/.git/config", "/.env", "/.DS_Store", "/robots.txt",
            "/sitemap.xml", "/crossdomain.xml", "/phpinfo.php",
            "/wp-config.php", "/.well-known/security.txt",
            "/api-docs", "/swagger.json", "/graphql",
            "/admin", "/wp-admin", "/administrator",
            "/debug", "/test", "/backup",
        ]
        
        for path in common_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, allow_redirects=False, verify=False)
                if resp.status_code in [200, 301, 302, 403]:
                    sensitive = any(k in resp.text.lower() for k in 
                        ["password", "secret", "key", "token", "db_", "database"])
                    if resp.status_code == 200 or sensitive:
                        self.findings.append({
                            "type": "exposed_path",
                            "endpoint": path,
                            "status": resp.status_code,
                            "size": len(resp.text),
                            "severity": "high" if sensitive else "low",
                        })
                        self.log(f"  🔍 {path}: {resp.status_code} ({len(resp.text)} bytes)")
            except:
                pass

    def test_sql_injection(self):
        """Quick SQL injection test on common parameters."""
        self.log("💉 Testing SQL injection...")
        
        sqli_payloads = [
            "'", "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--",
            "1' AND '1'='1", "1' AND '1'='2",
        ]
        
        # Test on target's known endpoints or default paths
        test_urls = [
            f"{self.base_url}/search?q=",
            f"{self.base_url}/login",
            f"{self.base_url}/api/search?q=",
        ]
        
        for url in test_urls:
            for payload in sqli_payloads[:3]:
                try:
                    if "?" in url:
                        resp = self.session.get(f"{url}{payload}", timeout=5)
                    else:
                        resp = self.session.post(url, json={"q": payload}, timeout=5)
                    
                    error_indicators = ["sql", "mysql", "sqlite", "postgresql", "syntax", "ORA-"]
                    if any(ind in resp.text.lower() for ind in error_indicators):
                        self.findings.append({
                            "type": "potential_sqli",
                            "endpoint": url,
                            "payload": payload,
                            "severity": "critical",
                        })
                        self.log(f"  🔥 Potential SQLi: {url} with '{payload[:30]}'")
                        break
                except:
                    pass

    def test_xss(self):
        """Quick XSS test."""
        self.log("💚 Testing XSS...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            '"><script>alert("XSS")</script>',
        ]
        
        test_urls = [f"{self.base_url}/search?q="]
        for url in test_urls:
            for payload in xss_payloads[:2]:
                try:
                    resp = self.session.get(f"{url}{payload}", timeout=5)
                    if payload in resp.text:
                        self.findings.append({
                            "type": "potential_xss",
                            "endpoint": url,
                            "payload": payload,
                            "severity": "high",
                        })
                        self.log(f"  🔥 Potential XSS: {url}")
                        break
                except:
                    pass

    # ===== CVE MATCHING =====
    def check_known_cves(self):
        """Check if target's tech stack has known vulnerabilities."""
        self.log("🔐 Checking known CVEs...")
        
        # Vulnerability database (abbreviated for local use)
        cve_db = {
            "nginx": ["CVE-2021-23017", "CVE-2019-9511"],
            "apache": ["CVE-2021-41773", "CVE-2021-42013", "CVE-2020-9484"],
            "wordpress": ["CVE-2022-21661", "CVE-2021-29447"],
            "jquery": ["CVE-2020-11023", "CVE-2019-11358"],
            "php": ["CVE-2021-21703", "CVE-2019-11043"],
            "express": ["CVE-2022-24999"],
            "node.js": ["CVE-2023-30589", "CVE-2023-30588"],
        }
        
        for tech, cves in cve_db.items():
            stack_str = str(self.tech_stack).lower()
            if tech in stack_str:
                for cve in cves:
                    self.findings.append({
                        "type": "known_cve",
                        "technology": tech,
                        "cve": cve,
                        "severity": "critical",
                    })
                    self.log(f"  🔥 {tech}: {cve}")

    # ===== REPORTING =====
    def generate_report(self):
        """Generate comprehensive assessment report."""
        elapsed = round(time.time() - self.start_time, 2)
        
        critical = [f for f in self.findings if f.get("severity") == "critical"]
        high = [f for f in self.findings if f.get("severity") == "high"]
        medium = [f for f in self.findings if f.get("severity") == "medium"]
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "domain": self.domain,
            "duration_seconds": elapsed,
            "reconnaissance": {
                "subdomains": len(self.subdomains),
                "open_ports": self.open_ports,
                "tech_stack": self.tech_stack,
            },
            "findings_summary": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "total": len(self.findings),
            },
            "findings": self.findings,
        }
        
        print(f"""
╔══════════════════════════════════════════════════╗
║     WILD HUNT MISSION COMPLETE                  ║
╠══════════════════════════════════════════════════╣
║  Target: {self.target[:40]:<40} ║
║  Time: {elapsed:.1f}s                                ║
║  Subdomains: {len(self.subdomains):>3}    Ports: {len(self.open_ports):>3}        ║
║  Findings: {len(self.findings):>3}  |  Crit: {len(critical)}  High: {len(high)}  Med: {len(medium)}  ║
╚══════════════════════════════════════════════════╝
        """)
        
        if critical:
            print("🔥 CRITICAL:")
            for f in critical[:5]:
                print(f"   💀 {f.get('type')}: {f.get('endpoint', f.get('cve', f.get('detail', '')))}")
        
        # Save report
        filename = f"nova_wild_hunt_{self.domain.replace('.', '_')}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n📁 Report: {filename}")
        
        return report

    # ===== FULL MISSION =====
    def hunt(self):
        """Execute full reconnaissance and assessment mission."""
        self.start_time = time.time()
        
        print(f"""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🏹  NOVA WILD HUNT — BEYOND THE LAB                ║
║   Real-World Target Assessment & Exploitation         ║
║   Target: {self.domain[:45]:<45} ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        # Phase 1: Reconnaissance
        self.log("🟢 PHASE 1: RECONNAISSANCE")
        self.discover_subdomains()
        self.scan_ports()
        
        # Phase 2: Fingerprinting
        self.log("🟡 PHASE 2: FINGERPRINTING")
        self.fingerprint_technology()
        
        # Phase 3: Vulnerability scanning
        self.log("🔴 PHASE 3: VULNERABILITY SCANNING")
        self.scan_common_vulnerabilities()
        self.test_sql_injection()
        self.test_xss()
        
        # Phase 4: CVE matching
        self.log("🟣 PHASE 4: CVE MATCHING")
        self.check_known_cves()
        
        # Phase 5: Report
        self.log("📊 PHASE 5: REPORTING")
        return self.generate_report()


if __name__ == "__main__":
    import sys
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Default target - a safe testing ground
    target = sys.argv[1] if len(sys.argv) > 1 else "testphp.vulnweb.com"
    
    print(f"""
╔══════════════════════════════════════════════════╗
║   🦅 NOVA WILD HUNT v1.0                        ║
║   Zero Tokens • Zero Cloud • Pure On-Device      ║
║   Target: {target[:40]:<40} ║
╚══════════════════════════════════════════════════╝

⚠️  LEGAL NOTICE: Only test systems you own or have
    explicit permission to assess. The default target
    is a public test lab. Use responsibly.
    """)
    
    hunter = NovaWildHunt(target)
    hunter.hunt()
