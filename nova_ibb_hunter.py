#!/usr/bin/env python3
"""
NOVA INTERNET BUG BOUNTY HUNTER v1.0
Targeted assessment for Internet Bug Bounty & public programs.
Recon only - exploitation requires program authorization.
"""

import json, time, re, socket, ssl, requests
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

class NovaIBBHunter:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; Nova/8.0; IBB Research)",
            "Accept": "application/json",
        })
        self.findings = []
        self.recon_data = {}
        
        # IBB scope - open source infrastructure
        self.ibb_scope = {
            "core_infrastructure": [
                "openssl.org", "openbsd.org", "freebsd.org",
                "netbsd.org", "python.org", "ruby-lang.org",
                "php.net", "apache.org", "nginx.org",
                "gnu.org", "kernel.org", "postgresql.org",
                "mariadb.org", "sqlite.org",
            ],
            "dns_servers": [
                "a.root-servers.net", "b.root-servers.net",
                "c.root-servers.net", "d.root-servers.net",
            ],
            "certificate_authorities": [
                "letsencrypt.org", "cert.org",
            ],
        }
        
        # Mozilla program details from search results
        self.mozilla_scope = {
            "domains": [
                "mozilla.org", "mozilla.com", "mozilla.net",
                "firefox.com", "mozgcp.net", "mozaws.net",
            ],
            "bounties": {
                "critical": "$3,000 - $15,000",
                "high": "$1,000 - $6,000",
                "medium": "$500 - $3,000",
                "low": "$1 - $1,000",
            },
            "response_sla": {
                "first_response": "5 days",
                "triage": "10 days",
                "bounty": "30 days",
            },
        }

    def passive_recon(self, domain):
        """Passive reconnaissance on a domain - no active scanning."""
        info = {"domain": domain, "timestamp": datetime.now().isoformat()}
        
        try:
            # DNS resolution
            info["ip"] = socket.gethostbyname(domain)
            
            # SSL certificate check
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                    s.settimeout(5)
                    s.connect((domain, 443))
                    cert = s.getpeercert()
                    info["ssl"] = {
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "expires": cert.get("notAfter"),
                        "subject_alt_names": [x[1] for x in cert.get("subjectAltName", [])],
                    }
            except:
                info["ssl"] = "No HTTPS or connection failed"
            
            # HTTP headers
            try:
                resp = self.s.get(f"https://{domain}", timeout=10, allow_redirects=True)
                info["http"] = {
                    "status": resp.status_code,
                    "server": resp.headers.get("Server", "Not disclosed"),
                    "security_headers": {
                        "HSTS": resp.headers.get("Strict-Transport-Security", "Missing"),
                        "CSP": bool(resp.headers.get("Content-Security-Policy")),
                        "XFO": resp.headers.get("X-Frame-Options", "Missing"),
                    }
                }
            except:
                info["http"] = "HTTP connection failed"
            
        except Exception as e:
            info["error"] = str(e)[:100]
        
        return info

    def map_ibb_surface(self):
        """Map the Internet Bug Bounty attack surface."""
        print("\n🗺️ MAPPING IBB ATTACK SURFACE\n" + "="*50)
        
        all_domains = []
        for category, domains in self.ibb_scope.items():
            all_domains.extend(domains)
        
        print(f"   🎯 {len(all_domains)} domains in IBB scope")
        
        recon_results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.passive_recon, d): d for d in all_domains[:12]}
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    result = future.result()
                    recon_results[domain] = result
                    
                    if "error" not in result:
                        ip = result.get("ip", "unknown")
                        server = result.get("http", {}).get("server", "?")
                        hsts = result.get("http", {}).get("security_headers", {}).get("HSTS", "?")
                        print(f"   ✅ {domain} → {ip} | Server: {server} | HSTS: {hsts}")
                        
                        # Flag missing security controls
                        if hsts == "Missing":
                            self.findings.append({
                                "domain": domain,
                                "finding": "Missing HSTS header",
                                "severity": "Low",
                                "category": "Security Misconfiguration",
                            })
                            print(f"      ⚠️ Missing HSTS")
                except:
                    print(f"   ❌ {domain}: Recon failed")
        
        self.recon_data["ibb"] = recon_results
        return recon_results

    def analyze_mozilla_program(self):
        """Analyze Mozilla's bug bounty program from search data."""
        print("\n🦊 MOZILLA PROGRAM ANALYSIS\n" + "="*50)
        
        print("""
   📋 Program: Mozilla Web Bug Bounty
   💰 Bounties: $500 - $15,000
   ⏱️  First Response: 5 days
   🔒 Safe Harbor: Gold Standard
   
   🎯 In-Scope Vulnerabilities:
      • Remote Code Execution (Critical - up to $15K)
      • Auth/Session flaws leading to account compromise
      • XSS resulting in significant action (High - up to $6K)
      • IDORs bypassing authentication (High)
      • CSRF on significant actions (High)
      • XXE attacks (High)
      • SSRF to internal hosts (Medium - up to $3K)
      • Domain takeovers with PoC (Medium)
      
   🚫 Out of Scope:
      • XSS blocked by CSP
      • Clickjacking without demonstrated impact
      • External SSRF
      • Missing security headers alone
      • Automated scanning that degrades service
        """)
        
        # Map Mozilla domains
        print("   📡 Mapping Mozilla attack surface...")
        for domain in self.mozilla_scope["domains"][:4]:
            try:
                ip = socket.gethostbyname(domain)
                print(f"      {domain} → {ip}")
            except:
                print(f"      {domain} → DNS resolution failed")

    def generate_ibb_report(self):
        """Generate IBB assessment report."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "program": "Internet Bug Bounty",
            "platform": "HackerOne",
            "reconnaissance": self.recon_data,
            "findings": self.findings,
            "total_domains_scanned": len(self.recon_data.get("ibb", {})),
            "total_findings": len(self.findings),
            "recommendations": [
                "Review IBB scope at https://hackerone.com/internet-bug-bounty",
                "Focus on critical infrastructure: OpenSSL, OpenBSD, FreeBSD",
                "Test for RCE, auth bypass, and XSS - highest bounties",
                "Document with reproducible steps and impact analysis",
                "Use Mozilla's Gold Standard Safe Harbor for protection",
            ],
        }
        
        with open("nova_ibb_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        return report

    def run(self):
        print("""
╔══════════════════════════════════════════════════════════╗
║   🦅 NOVA IBB HUNTER v1.0                              ║
║   Internet Bug Bounty Reconnaissance                    ║
║   ⚠️  PASSIVE RECON ONLY - NO EXPLOITATION              ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        # Map IBB surface
        self.map_ibb_surface()
        
        # Analyze Mozilla program
        self.analyze_mozilla_program()
        
        # Generate report
        report = self.generate_ibb_report()
        
        print(f"""
╔══════════════════════════════════════════════════════════╗
║     IBB HUNT COMPLETE                                   ║
╠══════════════════════════════════════════════════════════╣
║  Domains Scanned: {report['total_domains_scanned']:>3}                                  ║
║  Findings: {report['total_findings']:>3}                                        ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        if self.findings:
            print("🔍 PASSIVE FINDINGS:")
            for f in self.findings:
                print(f"   [{f['severity']}] {f['domain']}: {f['finding']}")
        
        print(f"\n📁 Report: nova_ibb_report.json")
        print(f"""
🎯 READY FOR ACTIVE TESTING:
   1. Choose an IBB in-scope domain
   2. Read program policy on HackerOne
   3. Set up isolated testing environment
   4. Run Nova's exploit modules with authorization
   5. Submit findings with PoC evidence
        """)

if __name__ == "__main__":
    NovaIBBHunter().run()
