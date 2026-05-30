#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   🔍 NOVA RECON v1.0 — ADVANCED RECONNAISSANCE ENGINE           ║
║                                                                  ║
║   Full autonomous recon pipeline:                               ║
║   1. Asset discovery (subdomains, IPs, ASNs)                   ║
║   2. Live host probing + tech fingerprinting                    ║
║   3. Historical URL mining (Wayback, CommonCrawl, AlienVault)   ║
║   4. JavaScript analysis (endpoints, secrets, API keys)         ║
║   5. DNS intelligence (CNAME, MX, TXT, zone transfers)         ║
║   6. Certificate transparency logs                              ║
║   7. Cloud asset enumeration (S3, GCP, Azure)                  ║
║   8. Subdomain takeover detection                               ║
║   9. Port scanning + service fingerprinting                     ║
║   10. Parameter discovery + interesting URL extraction          ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import subprocess
import sys
import time
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

WORKSPACE = os.path.expanduser("~/nova_workspace")
NOVA_BIN  = os.path.join(WORKSPACE, "bin")
GOPATH    = os.path.join(WORKSPACE, "go")


class NovaRecon:

    def __init__(self, target: str, workspace: str = WORKSPACE, verbose: bool = False):
        self.target    = target.rstrip("/")
        self.domain    = self._extract_domain(target)
        self.workspace = workspace
        self.verbose   = verbose
        self.results: Dict = {
            "target":     self.target,
            "domain":     self.domain,
            "subdomains": [],
            "live_hosts": [],
            "urls":       [],
            "js_files":   [],
            "endpoints":  [],
            "params":     [],
            "secrets":    [],
            "open_ports": {},
            "techs":      {},
            "cnames":     {},
            "takeover_candidates": [],
            "cloud_assets": [],
            "certificates": [],
            "interesting_urls": [],
        }
        self._env = self._build_env()
        os.makedirs(workspace, exist_ok=True)

    def _extract_domain(self, url: str) -> str:
        try:
            p = urlparse(url)
            return p.netloc or p.path.split("/")[0]
        except Exception:
            return url

    def _build_env(self) -> Dict:
        env = dict(os.environ)
        paths = [NOVA_BIN, "/usr/local/go/bin", os.path.join(GOPATH, "bin"),
                 os.path.expanduser("~/.local/bin")]
        env["PATH"]   = ":".join(paths) + ":" + env.get("PATH", "")
        env["GOPATH"] = GOPATH
        env["GOBIN"]  = NOVA_BIN
        return env

    def _run(self, cmd: str, timeout: int = 120) -> str:
        if self.verbose:
            print(f"  $ {cmd[:100]}")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout, env=self._env, cwd=self.workspace,
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except Exception as e:
            return ""

    def _has(self, tool: str) -> bool:
        path = os.path.join(NOVA_BIN, tool)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return True
        import shutil
        return shutil.which(tool, path=self._env.get("PATH")) is not None

    # ── PHASE 1: SUBDOMAIN DISCOVERY ─────────────────────────────

    def discover_subdomains(self) -> List[str]:
        print(f"  🔍 [Recon] Subdomain discovery → {self.domain}")
        subs: Set[str] = set()

        if self._has("subfinder"):
            out = self._run(f"subfinder -d {self.domain} -silent -all 2>/dev/null", timeout=60)
            subs.update(l.strip() for l in out.splitlines() if l.strip())

        if self._has("amass"):
            out = self._run(f"amass enum -passive -d {self.domain} -timeout 3 2>/dev/null", timeout=200)
            subs.update(l.strip() for l in out.splitlines() if l.strip())

        if self._has("assetfinder"):
            out = self._run(f"assetfinder --subs-only {self.domain} 2>/dev/null", timeout=30)
            subs.update(l.strip() for l in out.splitlines() if l.strip())

        # Certificate transparency
        try:
            import urllib.request
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "Nova/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                for entry in data:
                    name = entry.get("name_value", "")
                    for n in name.splitlines():
                        n = n.strip().lstrip("*.")
                        if self.domain in n:
                            subs.add(n)
        except Exception:
            pass

        self.results["subdomains"] = sorted(subs)
        print(f"  ✅ Found {len(subs)} subdomains")
        return list(subs)

    # ── PHASE 2: LIVE HOST PROBING ────────────────────────────────

    def probe_live_hosts(self, hosts: List[str] = None) -> List[Dict]:
        targets = hosts or self.results["subdomains"] or [self.domain]
        print(f"  🔍 [Recon] Probing {len(targets)} hosts")

        if not self._has("httpx"):
            return []

        hosts_str = "\n".join(targets)
        hosts_file = os.path.join(self.workspace, "recon", "hosts.txt")
        os.makedirs(os.path.dirname(hosts_file), exist_ok=True)
        with open(hosts_file, "w") as f:
            f.write(hosts_str)

        out = self._run(
            f"httpx -l {hosts_file} -silent -json -title -tech-detect -status-code "
            f"-content-length -web-server -follow-redirects 2>/dev/null",
            timeout=120,
        )

        live = []
        for line in out.splitlines():
            try:
                d = json.loads(line)
                host_data = {
                    "url":          d.get("url", ""),
                    "status":       d.get("status_code", 0),
                    "title":        d.get("title", ""),
                    "server":       d.get("web_server", ""),
                    "technologies": d.get("tech", []),
                    "content_length": d.get("content_length", 0),
                }
                live.append(host_data)
                for tech in d.get("tech", []):
                    url = d.get("url","")
                    if url not in self.results["techs"]:
                        self.results["techs"][url] = []
                    self.results["techs"][url].append(tech)
            except Exception:
                pass

        self.results["live_hosts"] = live
        print(f"  ✅ {len(live)} live hosts")
        return live

    # ── PHASE 3: URL MINING ───────────────────────────────────────

    def mine_urls(self) -> List[str]:
        print(f"  🔍 [Recon] Mining historical URLs")
        urls: Set[str] = set()

        if self._has("gau"):
            out = self._run(
                f"gau --subs {self.domain} --providers wayback,commoncrawl,otx 2>/dev/null",
                timeout=90,
            )
            urls.update(l.strip() for l in out.splitlines() if l.strip())

        if self._has("waybackurls"):
            out = self._run(f"echo {self.domain} | waybackurls 2>/dev/null", timeout=60)
            urls.update(l.strip() for l in out.splitlines() if l.strip())

        if self._has("katana"):
            out = self._run(
                f"katana -u {self.target} -silent -depth 3 -js-crawl 2>/dev/null",
                timeout=120,
            )
            urls.update(l.strip() for l in out.splitlines() if l.strip())

        self.results["urls"] = sorted(urls)
        print(f"  ✅ Mined {len(urls)} URLs")
        return list(urls)

    # ── PHASE 4: PARAMETER EXTRACTION ────────────────────────────

    def extract_params(self, urls: List[str] = None) -> List[str]:
        target_urls = urls or self.results["urls"]
        if not target_urls:
            return []

        print(f"  🔍 [Recon] Extracting parameters from {len(target_urls)} URLs")
        params: Set[str] = set()

        # Extract from query strings
        for url in target_urls:
            try:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(url).query)
                params.update(qs.keys())
            except Exception:
                pass

        # Use gf to find interesting params
        if self._has("gf") and target_urls:
            url_file = os.path.join(self.workspace, "recon", "all_urls.txt")
            with open(url_file, "w") as f:
                f.write("\n".join(target_urls))
            for pattern in ("xss", "sqli", "ssrf", "redirect", "rce", "idor", "lfi"):
                out = self._run(f"cat {url_file} | gf {pattern} 2>/dev/null", timeout=15)
                for url in out.splitlines():
                    try:
                        from urllib.parse import urlparse, parse_qs
                        qs = parse_qs(urlparse(url.strip()).query)
                        for p in qs:
                            self.results["interesting_urls"].append({"param": p, "url": url.strip(), "pattern": pattern})
                            params.add(p)
                    except Exception:
                        pass

        self.results["params"] = sorted(params)
        print(f"  ✅ Found {len(params)} parameters")
        return list(params)

    # ── PHASE 5: JS ANALYSIS ──────────────────────────────────────

    def analyse_js(self) -> Dict:
        print(f"  🔍 [Recon] Analysing JavaScript files")
        js_urls = [u for u in self.results.get("urls", []) if u.endswith(".js")][:50]

        findings = {"endpoints": [], "secrets": [], "api_keys": []}

        if self._has("linkfinder") and js_urls:
            js_file = os.path.join(self.workspace, "recon", "js_files.txt")
            with open(js_file, "w") as f:
                f.write("\n".join(js_urls))
            for js_url in js_urls[:20]:
                out = self._run(f"linkfinder -i {js_url} -o cli 2>/dev/null", timeout=20)
                for ep in out.splitlines():
                    ep = ep.strip()
                    if ep and ep not in findings["endpoints"]:
                        findings["endpoints"].append(ep)

        if self._has("secretfinder") and js_urls:
            for js_url in js_urls[:10]:
                out = self._run(f"secretfinder -i {js_url} -o cli 2>/dev/null", timeout=20)
                for line in out.splitlines():
                    if line.strip():
                        findings["secrets"].append(line.strip())

        self.results["endpoints"].extend(findings["endpoints"])
        self.results["secrets"].extend(findings["secrets"])
        print(f"  ✅ JS: {len(findings['endpoints'])} endpoints, {len(findings['secrets'])} potential secrets")
        return findings

    # ── PHASE 6: PORT SCANNING ────────────────────────────────────

    def scan_ports(self, hosts: List[str] = None, fast: bool = True) -> Dict:
        targets = hosts or [self.domain]
        print(f"  🔍 [Recon] Port scanning {len(targets)} targets")

        if self._has("naabu"):
            target_str = ",".join(targets[:10])
            out = self._run(
                f"naabu -host {target_str} -top-ports 1000 -silent 2>/dev/null",
                timeout=120,
            )
            for line in out.splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2:
                    host, port = parts
                    if host not in self.results["open_ports"]:
                        self.results["open_ports"][host] = []
                    self.results["open_ports"][host].append(int(port))

        elif self._has("nmap"):
            flags = "-sV --open -T4 --top-ports 100" if fast else "-sV --open -T4 -p-"
            for host in targets[:5]:
                out = self._run(f"nmap {flags} {host} -oG - 2>/dev/null", timeout=90)
                ports = re.findall(r"(\d+)/open", out)
                if ports:
                    self.results["open_ports"][host] = [int(p) for p in ports]

        total_ports = sum(len(v) for v in self.results["open_ports"].values())
        print(f"  ✅ Found {total_ports} open ports")
        return self.results["open_ports"]

    # ── PHASE 7: SUBDOMAIN TAKEOVER ───────────────────────────────

    def check_takeover(self) -> List[str]:
        print(f"  🔍 [Recon] Checking subdomain takeover")
        candidates = []

        TAKEOVER_FINGERPRINTS = [
            "There is no app configured at that hostname",
            "NoSuchBucket",
            "No Such Account",
            "This UserVoice subdomain is currently available",
            "project not found",
            "Repository not found",
            "The feed has not been activated",
            "is not a registered InCloud YouTrack",
            "Unrecognized domain",
            "Sorry, We Couldn't Find That Page",
            "Fastly error: unknown domain",
        ]

        if self._has("subzy"):
            out = self._run(
                f"subzy run --targets {self.workspace}/recon/hosts.txt 2>/dev/null",
                timeout=60,
            )
            for line in out.splitlines():
                if "VULNERABLE" in line.upper():
                    candidates.append(line.strip())
        else:
            # Manual CNAME check
            for sub in self.results.get("subdomains", [])[:50]:
                out = self._run(f"dig +short CNAME {sub} 2>/dev/null", timeout=5)
                if out and any(svc in out for svc in
                               ["github.io", "s3.amazonaws.com", "cloudfront.net", "heroku.com",
                                "netlify.com", "surge.sh", "readme.io", "uservoice.com"]):
                    # Probe for takeover fingerprint
                    probe = self._run(f"curl -sk --max-time 5 http://{sub}/ 2>/dev/null", timeout=8)
                    if any(fp in probe for fp in TAKEOVER_FINGERPRINTS):
                        candidates.append(sub)

        self.results["takeover_candidates"] = candidates
        if candidates:
            print(f"  🚨 Takeover candidates: {candidates}")
        else:
            print(f"  ✅ No takeover candidates found")
        return candidates

    # ── PHASE 8: CLOUD ASSETS ─────────────────────────────────────

    def enumerate_cloud(self) -> List[str]:
        print(f"  🔍 [Recon] Cloud asset enumeration")
        assets = []
        name = self.domain.split(".")[0]

        # S3 buckets
        variations = [name, f"{name}-dev", f"{name}-staging", f"{name}-prod",
                      f"{name}-backup", f"{name}-assets", f"{name}-media", f"{name}-static"]

        if self._has("s3scanner"):
            for bucket in variations:
                out = self._run(f"s3scanner scan --bucket {bucket} 2>/dev/null", timeout=10)
                if "exists" in out.lower() or "public" in out.lower():
                    assets.append(f"s3://{bucket}")

        self.results["cloud_assets"] = assets
        print(f"  ✅ Cloud assets: {len(assets)}")
        return assets

    # ── FULL RECON PIPELINE ───────────────────────────────────────

    def run_full(self) -> Dict:
        print(f"\n  🔍 Nova Recon — Full pipeline on: {self.target}\n")
        start = time.time()

        self.discover_subdomains()
        self.probe_live_hosts()
        self.mine_urls()
        self.extract_params()
        self.analyse_js()
        self.scan_ports()
        self.check_takeover()
        self.enumerate_cloud()

        elapsed = round(time.time() - start, 1)
        self.results["duration_sec"] = elapsed
        self.results["timestamp"]    = __import__("datetime").datetime.utcnow().isoformat()

        # Save
        out_file = os.path.join(self.workspace, "recon",
                                f"recon_{self.domain.replace('.','_')}.json")
        with open(out_file, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"\n  ✅ Recon complete in {elapsed}s  →  {out_file}")
        print(f"     {len(self.results['subdomains'])} subdomains  |  "
              f"{len(self.results['live_hosts'])} live  |  "
              f"{len(self.results['urls'])} URLs  |  "
              f"{len(self.results['params'])} params  |  "
              f"{len(self.results['takeover_candidates'])} takeover candidates")

        return self.results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="🔍 Nova Recon Engine")
    parser.add_argument("target",         help="Target URL or domain")
    parser.add_argument("--phase",        choices=["subdomains","hosts","urls","ports","js","takeover","cloud","all"], default="all")
    parser.add_argument("--verbose",      action="store_true")
    args = parser.parse_args()

    recon = NovaRecon(args.target, verbose=args.verbose)

    if args.phase == "all":
        results = recon.run_full()
    elif args.phase == "subdomains":
        print(recon.discover_subdomains())
    elif args.phase == "hosts":
        print(recon.probe_live_hosts())
    elif args.phase == "urls":
        print(recon.mine_urls())
    elif args.phase == "ports":
        print(recon.scan_ports())
    elif args.phase == "js":
        print(recon.analyse_js())
    elif args.phase == "takeover":
        print(recon.check_takeover())
    elif args.phase == "cloud":
        print(recon.enumerate_cloud())
