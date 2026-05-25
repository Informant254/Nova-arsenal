#!/usr/bin/env python3
"""
NOVA DEEP STRIKE — OpenSSL.org Assessment
Authorized under IBB Safe Harbor Policy
Hunting for Critical/High severity bugs eligible for $3,000-$15,000 bounties
"""

import json, time, re, socket, ssl, requests, hashlib
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

class NovaDeepStrike:
    def __init__(self):
        self.target = "openssl.org"
        self.base = f"https://{self.target}"
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; Nova/9.0; IBB Authorized Security Research)",
            "Accept": "application/json, text/html, */*",
        })
        self.findings = []
        self.critical = []
        self.high = []
        self.medium = []
        self.low = []
        
        # Mozilla-level severity mapping[citation:1]
        self.severity_criteria = {
            "critical": ["RCE", "auth_bypass", "account_compromise", "secrets_disclosure"],
            "high": ["IDOR", "CSRF_significant", "XSS_significant", "XXE", "hardcoded_creds"],
            "medium": ["XSS_minor", "domain_takeover", "SSRF_internal", "info_disclosure"],
            "low": ["XSS_csp_blocked", "clickjacking", "missing_headers", "external_ssrf"],
        }

    def classify_severity(self, finding_type):
        """Classify finding severity per Mozilla/IBB criteria."""
        for severity, types in self.severity_criteria.items():
            if finding_type in types:
                return severity
        return "low"

    def add_finding(self, title, ftype, evidence, endpoint=""):
        """Add a classified finding."""
        severity = self.classify_severity(ftype)
        finding = {
            "title": title,
            "type": ftype,
            "severity": severity,
            "evidence": evidence,
            "endpoint": endpoint,
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
        }
        self.findings.append(finding)
        getattr(self, severity).append(finding)
        
        icon = {"critical": "💀", "high": "🔥", "medium": "⚠️", "low": "📋"}.get(severity, "📄")
        print(f"   {icon} [{severity.upper()}] {title}")
        return finding

    def fingerprint_server(self):
        """Deep server fingerprinting."""
        print(f"\n🔍 DEEP FINGERPRINT: {self.target}")
        print("=" * 50)
        
        try:
            resp = self.s.get(self.base, timeout=15)
            
            # Server identification
            server = resp.headers.get("Server", "Unknown")
            print(f"   Server: {server}")
            
            # Check for version disclosure
            version_patterns = [
                r'(\w+)/(\d+\.\d+\.\d+)',
                r'(\w+) (\d+\.\d+)',
            ]
            for pattern in version_patterns:
                match = re.search(pattern, server)
                if match:
                    self.add_finding(
                        "Server version disclosure",
                        "info_disclosure",
                        f"Server header reveals version: {server}",
                        "/"
                    )
                    break
            
            # SSL/TLS analysis
            try:
                import ssl as ssl_module
                ctx = ssl_module.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=self.target) as s:
                    s.settimeout(5)
                    s.connect((self.target, 443))
                    cert = s.getpeercert()
                    
                    # Check certificate expiration
                    expires = cert.get("notAfter", "")
                    print(f"   SSL Cert expires: {expires}")
                    
                    # Check TLS version
                    cipher = s.cipher()
                    print(f"   TLS: {cipher[1]} | Cipher: {cipher[0]}")
                    
                    # Check for weak ciphers
                    if "RC4" in cipher[0] or "DES" in cipher[0] or "3DES" in cipher[0]:
                        self.add_finding(
                            "Weak SSL cipher in use",
                            "info_disclosure",
                            f"Weak cipher: {cipher[0]}",
                            ":443"
                        )
            except Exception as e:
                print(f"   SSL check failed: {str(e)[:60]}")
            
            # Security headers audit
            security_headers = {
                "Strict-Transport-Security": resp.headers.get("Strict-Transport-Security"),
                "Content-Security-Policy": resp.headers.get("Content-Security-Policy"),
                "X-Frame-Options": resp.headers.get("X-Frame-Options"),
                "X-Content-Type-Options": resp.headers.get("X-Content-Type-Options"),
                "X-XSS-Protection": resp.headers.get("X-XSS-Protection"),
                "Referrer-Policy": resp.headers.get("Referrer-Policy"),
                "Permissions-Policy": resp.headers.get("Permissions-Policy"),
            }
            
            missing_headers = [h for h, v in security_headers.items() if not v]
            if missing_headers:
                print(f"   ⚠️  Missing headers: {', '.join(missing_headers)}")
            
            return resp
            
        except Exception as e:
            print(f"   ❌ Failed: {str(e)[:80]}")
            return None

    def discover_endpoints(self):
        """Discover and test endpoints from sitemap and common paths."""
        print(f"\n📡 ENDPOINT DISCOVERY: {self.target}")
        print("=" * 50)
        
        # Try to get sitemap
        sitemap_endpoints = []
        try:
            resp = self.s.get(f"{self.base}/sitemap.xml", timeout=10)
            if resp.status_code == 200:
                # Extract URLs from sitemap
                urls = re.findall(r'<loc>([^<]+)</loc>', resp.text)
                sitemap_endpoints = [urlparse(u).path for u in urls if urlparse(u).netloc == self.target]
                print(f"   📄 Sitemap: {len(sitemap_endpoints)} endpoints found")
        except:
            pass
        
        # Common endpoints to test
        common_endpoints = [
            "/", "/docs/", "/source/", "/news/", "/blog/",
            "/api/", "/download/", "/community/", "/support/",
            "/.well-known/security.txt", "/robots.txt",
            "/CHANGES", "/CHANGELOG", "/README", "/LICENSE",
            "/.git/HEAD", "/.svn/entries", "/.hg/store/",
            "/backup/", "/admin/", "/console/", "/debug/",
            "/phpinfo.php", "/server-status", "/status",
            "/metrics", "/actuator/health", "/swagger.json",
        ]
        
        all_endpoints = list(set(sitemap_endpoints + common_endpoints))
        discovered = []
        
        for path in all_endpoints[:30]:
            try:
                url = f"{self.base}{path}"
                resp = self.s.get(url, timeout=10, allow_redirects=False)
                
                if resp.status_code in [200, 301, 302, 403]:
                    discovered.append({
                        "path": path,
                        "status": resp.status_code,
                        "size": len(resp.text),
                        "content_type": resp.headers.get("Content-Type", ""),
                    })
                    
                    # Check for sensitive content
                    sensitive_indicators = ["password", "secret", "key", "token", "admin", "debug",
                                           "config", "database", "private", "credential"]
                    found_indicators = [i for i in sensitive_indicators if i in resp.text.lower()[:1000]]
                    
                    icon = "🔥" if found_indicators else "📄"
                    print(f"   {icon} {path}: {resp.status_code} ({len(resp.text)} bytes)")
                    
                    if found_indicators:
                        self.add_finding(
                            f"Sensitive content at {path}",
                            "info_disclosure",
                            f"Indicators: {found_indicators}",
                            path
                        )
                    
                    # Check for server version in error pages
                    if resp.status_code >= 400:
                        version_leak = re.findall(r'(\w+)/(\d+\.\d+\.\d+)', resp.text)
                        if version_leak:
                            self.add_finding(
                                "Version disclosure in error page",
                                "info_disclosure",
                                f"Versions: {version_leak[:3]}",
                                path
                            )
            except:
                pass
        
        print(f"   📊 Discovered {len(discovered)} accessible endpoints")
        return discovered

    def test_vulnerability_surface(self):
        """Test for vulnerability indicators without exploitation."""
        print(f"\n🔬 VULNERABILITY SURFACE: {self.target}")
        print("=" * 50)
        
        # Test for reflected parameters (potential XSS surface)
        test_params = ["q", "search", "query", "id", "page", "file", "url", "redirect", "next"]
        xss_payload = "novatest12345"
        
        for param in test_params:
            try:
                resp = self.s.get(f"{self.base}/", params={param: xss_payload}, timeout=10)
                if xss_payload in resp.text:
                    print(f"   🔄 Parameter '{param}' reflects input — potential XSS surface")
                    self.add_finding(
                        f"Reflected parameter: {param}",
                        "XSS_significant",
                        f"Parameter '{param}' reflects user input in response",
                        f"/?{param}="
                    )
            except:
                pass
        
        # Test for open redirect surface
        redirect_params = ["to", "url", "redirect", "next", "return", "target", "redir"]
        for param in redirect_params:
            try:
                resp = self.s.get(f"{self.base}/", params={param: "https://example.com"}, 
                                timeout=10, allow_redirects=False)
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("Location", "")
                    if "example.com" in location:
                        print(f"   ↪️  Open redirect surface at parameter '{param}'")
                        self.add_finding(
                            f"Open redirect surface: {param}",
                            "domain_takeover",
                            f"Parameter '{param}' triggers external redirect",
                            f"/?{param}="
                        )
            except:
                pass

    def generate_report(self):
        """Generate professional bounty-ready report."""
        total = len(self.findings)
        critical_count = len(self.critical)
        high_count = len(self.high)
        medium_count = len(self.medium)
        
        print(f"""
╔══════════════════════════════════════════════════════════╗
║     DEEP STRIKE COMPLETE — {self.target:<30} ║
╠══════════════════════════════════════════════════════════╣
║  Critical: {critical_count:<3}  High: {high_count:<3}  Medium: {medium_count:<3}  Total: {total:<3}        ║
║                                                        ║
║  💰 Bounty Eligibility (per Mozilla scale):            ║
║     Critical: $3,000 - $15,000                         ║
║     High: $1,000 - $6,000                              ║
║     Medium: $500 - $3,000                              ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        if self.critical:
            print("💀 CRITICAL FINDINGS (Bounty: $3,000-$15,000):")
            for f in self.critical:
                print(f"   • {f['title']}")
                print(f"     Evidence: {f['evidence'][:100]}")
        
        if self.high:
            print("\n🔥 HIGH FINDINGS (Bounty: $1,000-$6,000):")
            for f in self.high:
                print(f"   • {f['title']}")
                print(f"     Evidence: {f['evidence'][:100]}")
        
        if self.medium:
            print("\n⚠️  MEDIUM FINDINGS (Bounty: $500-$3,000):")
            for f in self.medium:
                print(f"   • {f['title']}")
        
        # Generate submission-ready report
        report = {
            "program": "Internet Bug Bounty / OpenSSL",
            "authorization": "IBB Safe Harbor Policy",
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "findings_summary": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": len(self.low),
                "total": total,
            },
            "findings": self.findings,
            "submission_guidelines": {
                "platform": "HackerOne",
                "program_url": "https://hackerone.com/internet-bug-bounty",
                "response_sla": "5 days first response, 10 days triage, 30 days bounty",
            },
        }
        
        with open(f"nova_deep_strike_{self.target}_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n📁 Report: nova_deep_strike_{self.target}_report.json")
        print(f"\n📋 Ready for HackerOne submission!")
        print(f"   Program: https://hackerone.com/internet-bug-bounty")
        print(f"   Template: Include reproduction steps + impact analysis")
        
        return report

    def run(self):
        print("""
╔══════════════════════════════════════════════════════════╗
║   🦅 NOVA DEEP STRIKE — BOUNTY HUNTING MODE           ║
║   Target: """ + f"{self.target:<45}" + """ ║
║   Authorization: IBB Safe Harbor Policy                 ║
║   Hunting: Critical/High severity ($1,000-$15,000)     ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        # Phase 1: Deep fingerprinting
        self.fingerprint_server()
        
        # Phase 2: Endpoint discovery
        self.discover_endpoints()
        
        # Phase 3: Vulnerability surface mapping
        self.test_vulnerability_surface()
        
        # Phase 4: Generate report
        self.generate_report()

if __name__ == "__main__":
    NovaDeepStrike().run()
