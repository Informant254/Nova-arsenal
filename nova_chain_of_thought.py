#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🧠 NOVA CHAIN-OF-THOUGHT v1.0                                     ║
║                                                                      ║
║   THE core intelligence module that closes the gap between Nova     ║
║   and Claude Code / Daybreak-class agents.                          ║
║                                                                      ║
║   What Claude Code does that nobody else does:                      ║
║   1. Forms HYPOTHESES from code/response evidence                   ║
║   2. Tests each hypothesis with targeted probes                     ║
║   3. SELF-CORRECTS when evidence contradicts the hypothesis         ║
║   4. CHAINS discoveries: finding A implies trying B                 ║
║   5. Reasons about WHY, not just WHAT                               ║
║   6. Accumulates context — never forgets what it learned            ║
║                                                                      ║
║   Pattern:  OBSERVE → HYPOTHESIZE → PROBE → CONCLUDE → CHAIN       ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import json, os, re, time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

WORKSPACE = os.path.expanduser("~/nova_workspace")

CONFIDENT   = 0.85
PLAUSIBLE   = 0.60
SPECULATIVE = 0.35
DISMISSED   = 0.15


class Thought:
    def __init__(self, kind: str, content: str, confidence: float = 0.5,
                 evidence: List[str] = None, implies: List[str] = None):
        self.kind       = kind
        self.content    = content
        self.confidence = confidence
        self.evidence   = evidence or []
        self.implies    = implies or []
        self.ts         = datetime.utcnow().isoformat()

    def to_dict(self): return vars(self)

    def __repr__(self):
        bar = "█" * int(self.confidence * 10) + "░" * (10 - int(self.confidence * 10))
        return f"[{self.kind[:3].upper()}|{bar}|{self.confidence:.2f}] {self.content[:80]}"


class ReasoningChain:
    def __init__(self, topic: str):
        self.topic    = topic
        self.thoughts: List[Thought] = []
        self.context: Dict[str, Any] = {}
        self.verdict: Optional[str]  = None
        self.confidence: float       = 0.0

    def observe(self, obs: str, evidence: List[str] = None, confidence: float = 0.7):
        t = Thought("observation", obs, confidence, evidence)
        self.thoughts.append(t); print(f"  👁  {t}"); return self

    def hypothesize(self, hyp: str, evidence: List[str] = None, confidence: float = 0.5, implies: List[str] = None):
        t = Thought("hypothesis", hyp, confidence, evidence, implies)
        self.thoughts.append(t); print(f"  💡 {t}"); return self

    def probe_result(self, probe: str, result: str, supports: bool, new_confidence: float = None):
        delta = +0.2 if supports else -0.25
        if new_confidence is None:
            last_h = next((t for t in reversed(self.thoughts) if t.kind == "hypothesis"), None)
            new_confidence = max(0.0, min(1.0, (last_h.confidence if last_h else 0.5) + delta))
        t = Thought("probe", f"{'✅ CONFIRMS' if supports else '❌ REFUTES'}: {probe} → {result[:60]}", new_confidence, [result[:200]])
        self.thoughts.append(t); print(f"  🔬 {t}")
        for th in reversed(self.thoughts):
            if th.kind == "hypothesis": th.confidence = new_confidence; break
        return self

    def conclude(self, conclusion: str, confidence: float = None, implies: List[str] = None):
        if confidence is None:
            hyp = [t for t in self.thoughts if t.kind == "hypothesis"]
            confidence = sum(h.confidence for h in hyp) / max(len(hyp), 1)
        self.verdict    = conclusion
        self.confidence = confidence
        t = Thought("conclusion", conclusion, confidence, implies=implies or [])
        self.thoughts.append(t); print(f"  🎯 {t}"); return self

    def chain(self, next_action: str, reason: str = ""):
        t = Thought("chain", f"{next_action}" + (f" (because: {reason})" if reason else ""), 0.8)
        self.thoughts.append(t); print(f"  ⛓  {t}"); return self

    def revise(self, new_hyp: str, because: str):
        t = Thought("hypothesis", f"REVISED: {new_hyp} (previous refuted: {because})", 0.5, [because])
        self.thoughts.append(t); print(f"  🔄 {t}"); return self

    def summary(self):
        return {"topic": self.topic, "verdict": self.verdict,
                "confidence": round(self.confidence, 2),
                "steps": len(self.thoughts),
                "thoughts": [t.to_dict() for t in self.thoughts]}


class NovaChainOfThought:
    """
    Nova's deep reasoning engine — models the pattern Claude Code uses
    to find vulnerabilities nobody else finds.
    """

    TECH_VULN_MAP = {
        "php":         ["sqli","lfi","rfi","xxe","deserialization","type_juggling"],
        "python":      ["ssti","command_injection","deserialization","path_traversal"],
        "ruby":        ["ssti","mass_assignment","command_injection","deserialization"],
        "java":        ["deserialization","xxe","log4shell","sqli","ssrf"],
        "node":        ["prototype_pollution","sqli","nosqli","command_injection","open_redirect"],
        "express":     ["prototype_pollution","nosqli","header_injection","path_traversal"],
        "django":      ["sqli","open_redirect","ssti","csrf"],
        "laravel":     ["mass_assignment","sqli","deserialization","open_redirect"],
        "spring":      ["deserialization","ssrf","log4shell","xxe","sqli"],
        "wordpress":   ["sqli","xss","lfi","arbitrary_file_upload","priv_escalation"],
        "graphql":     ["introspection","batch_attack","depth_limit_bypass","sqli"],
        "jwt":         ["algorithm_confusion","none_algorithm","jwks_injection","key_confusion"],
        "oauth":       ["open_redirect","state_fixation","token_leakage","pkce_bypass"],
        "s3":          ["public_bucket","presigned_url","bucket_takeover","acl_misconfiguration"],
        "mongodb":     ["nosqli","js_injection","auth_bypass"],
        "redis":       ["ssrf","command_execution","unauth_access"],
        "elasticsearch":["unauth_access","data_exfil","ssrf"],
        "kubernetes":  ["api_server_exposure","rbac_bypass","pod_escape","secrets_exposure"],
        "solidity":    ["reentrancy","integer_overflow","access_control","flash_loan"],
        "nginx":       ["alias_traversal","http_smuggling","path_traversal"],
        "apache":      ["path_traversal","http_smuggling","mod_proxy_ssrf"],
    }

    BODY_SECRETS = [
        (r'AKIA[0-9A-Z]{16}', "aws_access_key", "critical"),
        (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', "api_key_exposure", "critical"),
        (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{6,})', "password_exposure", "critical"),
        (r'(?i)sql\s+syntax.*error|mysql_fetch|ORA-\d{5}|sqlite.*error', "sql_error_disclosure", "high"),
        (r'(?i)stack\s+trace|at\s+\w+\.\w+\(.*\.java:\d+\)|Traceback.*most recent', "stack_trace_disclosure", "medium"),
        (r'(?i)(phpinfo\(|<title>phpinfo|PHP Version)', "phpinfo_exposure", "high"),
        (r'(?i)(debug\s*=\s*true|APP_DEBUG\s*=\s*true)', "debug_mode_enabled", "high"),
        (r'(?i)eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', "jwt_in_response", "medium"),
    ]

    def __init__(self, target: str, llm=None, verbose: bool = True):
        self.target   = target
        self.domain   = urlparse(target).netloc or target
        self.llm      = llm
        self.verbose  = verbose
        self.chains:  List[ReasoningChain] = []
        self.facts:   Dict[str, Any]  = {}
        self.queue:   List[Dict]      = []
        self.findings: List[Dict]     = []

    def learn(self, key: str, value: Any, source: str = ""):
        self.facts[key] = value

    def enqueue(self, action: str, priority: int = 5):
        self.queue.append({"action": action, "priority": priority})
        self.queue.sort(key=lambda x: -x["priority"])

    def analyse_response(self, url: str, status: int, headers: Dict, body: str) -> ReasoningChain:
        chain = ReasoningChain(f"analyse:{url}")
        self.chains.append(chain)
        chain.observe(f"Status {status} from {url}")

        server  = headers.get("server","") or headers.get("Server","")
        powered = headers.get("x-powered-by","") or headers.get("X-Powered-By","")

        if server:
            chain.observe(f"Server: {server}", [server], 0.99)
            self.learn("server", server, "header")
        if powered:
            chain.observe(f"X-Powered-By: {powered}", [powered], 0.99)
            self.learn("powered_by", powered, "header")

        techs = self._infer_tech(server + " " + powered + " " + body[:2000])
        for tech, conf in techs:
            self.learn(f"tech:{tech}", True, "response")
            chain.observe(f"Tech detected: {tech}", confidence=conf)
            vulns = self.TECH_VULN_MAP.get(tech.lower(), [])
            if vulns:
                chain.hypothesize(f"{tech} → likely: {', '.join(vulns[:3])}", [tech], 0.55,
                                  implies=[f"test_{v}:{url}" for v in vulns[:3]])
                for v in vulns[:3]:
                    self.enqueue(f"test_{v}:{url}", priority=6)

        # AWS detection
        if any("x-amz" in h.lower() for h in headers):
            chain.hypothesize("AWS backend → test SSRF to 169.254.169.254", confidence=0.75)
            self.enqueue(f"test_ssrf_metadata:{url}", priority=9)

        # CORS
        acao = headers.get("access-control-allow-origin","") or headers.get("Access-Control-Allow-Origin","")
        if acao == "*":
            chain.hypothesize("CORS wildcard → test with credentials", [acao], 0.7)
            self.enqueue(f"test_cors_credentials:{url}", priority=8)
        elif acao:
            chain.hypothesize(f"CORS allows {acao} → test origin reflection", [acao], 0.55)

        # CSP
        csp = headers.get("content-security-policy","")
        if csp and "unsafe-inline" in csp:
            chain.hypothesize("CSP unsafe-inline → XSS filter bypassable", [csp], 0.65)

        # Body secret scanning
        for pattern, vuln_type, sev in self.BODY_SECRETS:
            m = re.search(pattern, body)
            if m:
                evidence = m.group(0)[:80]
                chain.hypothesize(f"{vuln_type} in response body", [evidence], 0.85)
                chain.conclude(f"FINDING: {vuln_type} at {url}", 0.85)
                self.findings.append({"type": vuln_type, "severity": sev, "url": url,
                                       "evidence": evidence, "tool": "nova_chain_of_thought"})
                self.enqueue(f"confirm_{vuln_type}:{url}", priority=10)

        chain.conclude(f"Analysis done — {len(techs)} techs, {len(self.queue)} probes queued", 0.9)
        return chain

    def _infer_tech(self, text: str) -> List[Tuple[str, float]]:
        signals = {
            "php":      [r'(?i)php/[\d\.]+', r'\.php'],
            "python":   [r'(?i)python', r'django', r'flask'],
            "ruby":     [r'(?i)ruby', r'rails'],
            "java":     [r'(?i)java', r'tomcat', r'spring'],
            "node":     [r'(?i)node\.?js', r'express'],
            "nginx":    [r'(?i)nginx/[\d\.]+'],
            "apache":   [r'(?i)apache/[\d\.]+'],
            "wordpress":[r'(?i)wp-content', r'wp-includes'],
            "graphql":  [r'(?i)graphql', r'"__typename"'],
            "jwt":      [r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+'],
            "mongodb":  [r'(?i)mongodb'],
            "spring":   [r'(?i)X-Application-Context'],
            "s3":       [r'(?i)s3\.amazonaws\.com'],
        }
        found = []
        for tech, pats in signals.items():
            for p in pats:
                if re.search(p, text):
                    found.append((tech, 0.85)); break
        return found

    def reason_about_sqli(self, url: str, param: str, normal: str, error_resp: str) -> ReasoningChain:
        chain = ReasoningChain(f"sqli:{url}:{param}")
        self.chains.append(chain)
        chain.observe(f"Testing '{param}' on {url}")
        has_sql_err = bool(re.search(r"(?i)sql|mysql|syntax|ORA-|SQLITE|pdoexception", error_resp))
        len_diff    = abs(len(normal) - len(error_resp))
        if has_sql_err:
            chain.hypothesize(f"SQL error → '{param}' reaches SQL unsanitised", confidence=0.9,
                              implies=["test_union","test_blind","test_time"])
            chain.conclude("SQL INJECTION CONFIRMED via error-based", 0.92)
            self.findings.append({"type":"SQL Injection","severity":"critical","url":url,
                                   "parameter":param,"tool":"nova_chain_of_thought"})
            chain.chain("Run sqlmap for full exploitation")
        elif len_diff > 100:
            chain.hypothesize(f"Length diff {len_diff}B → possible blind SQLi", confidence=0.55)
            chain.chain("Test boolean-blind: AND 1=1 vs AND 1=2")
        else:
            chain.revise("Try time-based blind injection", "no error and no length diff")
            chain.chain("Test SLEEP(5)/WAITFOR DELAY/pg_sleep(5)")
        return chain

    def reason_about_auth_flow(self, login_url: str, body: str, headers: Dict) -> ReasoningChain:
        chain = ReasoningChain(f"auth:{login_url}")
        self.chains.append(chain)
        chain.observe(f"Auth flow analysis at {login_url}")
        jwt_m = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]*)', body)
        if jwt_m:
            token = jwt_m.group(0)
            chain.observe(f"JWT token found: {token[:30]}...", confidence=0.99)
            self.learn("jwt_token", token, "auth_response")
            try:
                import base64
                h = json.loads(base64.b64decode(token.split('.')[0] + '==').decode('utf-8','replace'))
                alg = h.get('alg','')
                chain.observe(f"JWT alg: {alg}", [str(h)], 0.99)
                if alg.upper() in ("HS256","HS384","HS512"):
                    chain.hypothesize("HMAC JWT → algorithm confusion possible", confidence=0.7)
                    self.enqueue(f"test_jwt_alg_confusion:{login_url}", priority=9)
                elif alg.upper() == "NONE":
                    chain.conclude("CRITICAL: JWT alg=none! → forge unsigned tokens", 0.95)
                    self.findings.append({"type":"JWT None Algorithm","severity":"critical",
                                           "url":login_url,"tool":"nova_chain_of_thought"})
            except Exception: pass

        cookie = headers.get("set-cookie","") or headers.get("Set-Cookie","")
        if cookie:
            if "httponly" not in cookie.lower():
                chain.hypothesize("No HttpOnly → XSS can steal session", confidence=0.85)
            if "samesite" not in cookie.lower():
                chain.hypothesize("No SameSite → CSRF possible", confidence=0.65)
                self.enqueue(f"test_csrf:{login_url}", priority=7)
        chain.conclude("Auth analysis complete", 0.85)
        return chain

    def reason_about_finding(self, finding: Dict) -> List[str]:
        implications_map = {
            "sql injection":  ["test_second_order_sqli","test_sqli_oob","enumerate_databases"],
            "xss":            ["test_dom_xss","test_stored_xss","test_blind_xss","attempt_cookie_theft"],
            "ssrf":           ["ssrf_aws_metadata","ssrf_internal_scan","ssrf_to_rce"],
            "lfi":            ["lfi_rce_log_poison","lfi_read_etc_passwd","lfi_ssh_keys"],
            "open redirect":  ["open_redirect_oauth_hijack"],
            "xxe":            ["xxe_ssrf","xxe_file_read"],
            "cors":           ["cors_with_credentials"],
            "jwt":            ["jwt_alg_confusion","jwt_none","jwt_kid_injection"],
            "ssti":           ["ssti_rce","ssti_file_read"],
        }
        url = finding.get("url","")
        vt  = (finding.get("type","") + " " + finding.get("name","")).lower()
        implications = []
        for key, actions in implications_map.items():
            if key in vt:
                implications.extend(actions)
                for a in actions[:2]: self.enqueue(f"{a}:{url}", priority=9)
        if implications:
            chain = ReasoningChain(f"chaining:{vt}")
            chain.observe(f"Confirmed: {vt} at {url}")
            chain.chain(f"Implied: {', '.join(implications[:4])}", f"every {vt} implies these")
            self.chains.append(chain)
        return implications

    def run_reasoning_session(self, observations: List[Dict]) -> Dict:
        print(f"\n  🧠 Nova Chain-of-Thought — session on {self.target}\n")
        start = time.time()
        for obs in observations:
            ot = obs.get("type","response")
            if ot == "http_response":
                self.analyse_response(obs.get("url",""), obs.get("status",0),
                                       obs.get("headers",{}), obs.get("body",""))
            elif ot == "finding":
                self.reason_about_finding(obs)
            elif ot == "auth_response":
                self.reason_about_auth_flow(obs.get("url",""), obs.get("body",""), obs.get("headers",{}))
        seen, uq = set(), []
        for item in self.queue:
            k = item["action"]
            if k not in seen: seen.add(k); uq.append(item)
        self.queue = uq
        elapsed = round(time.time() - start, 2)
        result = {"target": self.target, "duration": elapsed, "chains": len(self.chains),
                  "findings": self.findings, "queue": self.queue[:30],
                  "facts": {k: str(v)[:100] for k, v in self.facts.items()}}
        print(f"\n  🧠 Done: {len(self.chains)} chains, {len(self.findings)} findings, {len(self.queue)} queued")
        return result


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="🧠 Nova Chain-of-Thought")
    p.add_argument("target"); p.add_argument("--demo", action="store_true")
    args = p.parse_args()
    cot = NovaChainOfThought(args.target, verbose=True)
    if args.demo:
        r = cot.run_reasoning_session([{
            "type": "http_response", "url": args.target, "status": 200,
            "headers": {"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.3",
                        "Access-Control-Allow-Origin": "*", "X-AMZ-Request-ID": "abc123"},
            "body": "Welcome! API_KEY=sk-test-abc123xyz AKIA1234567890ABCDEF",
        }])
        print(f"\nFindings: {len(r['findings'])}  Queue: {len(r['queue'])}")
        for a in r["queue"][:10]: print(f"  [{a['priority']}] {a['action']}")
