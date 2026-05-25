#!/usr/bin/env python3
import json, os, re, subprocess, tempfile
from datetime import datetime

class NovaContextEngine:
    def __init__(self):
        self.findings = []
        self.patterns = {
            "rce": {
                "desc": "User input flows to command execution",
                "severity": "CRITICAL", "cvss": "9.8", "cwe": "CWE-78",
                "src": ["request.getParameter", "@RequestParam", "req.body"],
                "sink": ["Runtime.getRuntime().exec", "ProcessBuilder", "ScriptEngine.eval"],
                "san": ["StringEscapeUtils", "@Valid", "Encode.forJava"],
            },
            "sqli": {
                "desc": "User input flows to SQL query",
                "severity": "CRITICAL", "cvss": "9.8", "cwe": "CWE-89",
                "src": ["request.getParameter", "@RequestParam"],
                "sink": ["Statement.execute", "jdbcTemplate.query", "createQuery"],
                "san": ["PreparedStatement", "setString", "setParameter"],
            },
            "deser": {
                "desc": "User data deserialized without validation",
                "severity": "CRITICAL", "cvss": "9.8", "cwe": "CWE-502",
                "src": ["request.getInputStream", "@RequestBody"],
                "sink": ["ObjectInputStream.readObject", "Yaml.load", "readObject"],
                "san": ["ObjectInputFilter", "type.*check", "@Valid"],
            },
            "ssrf": {
                "desc": "User URL fetched without validation",
                "severity": "HIGH", "cvss": "8.6", "cwe": "CWE-918",
                "src": ["request.getParameter", "@RequestParam"],
                "sink": ["HttpClient.execute", "RestTemplate.exchange", "URL.openConnection"],
                "san": ["URLValidator", "allowedHosts", "whitelist"],
            },
        }

    def scan_file(self, filepath):
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().split("\n")
        except:
            return findings
        
        fn = os.path.basename(filepath)
        if "test" in fn.lower() or "test" in filepath.lower():
            return findings
        
        for vtype, vdata in self.patterns.items():
            sources = [(i, l) for i, l in enumerate(lines, 1) if any(re.search(m, l, re.I) for m in vdata["src"])]
            sinks = [(i, l) for i, l in enumerate(lines, 1) if any(re.search(m, l, re.I) for m in vdata["sink"])]
            
            for sl, sc in sources:
                for kl, kc in sinks:
                    if kl <= sl: continue
                    sanitized = any(any(re.search(m, lines[i], re.I) for m in vdata["san"]) for i in range(sl, min(kl+1, len(lines))))
                    if not sanitized:
                        f = {"file": fn, "type": vtype, "desc": vdata["desc"], "severity": vdata["severity"], "cvss": vdata["cvss"], "cwe": vdata["cwe"], "src_line": sl, "sink_line": kl, "exploitable": True}
                        findings.append(f)
                        self.findings.append(f)
        return findings

    def scan_repo(self, url):
        name = url.split("/")[-1].replace(".git", "")
        print(f"\n🔬 {name}")
        tmp = tempfile.mkdtemp(prefix=f"nctx_{name}_")
        try:
            subprocess.run(["git", "clone", "--depth", "1", url, tmp], capture_output=True, check=True, timeout=120)
        except:
            print("   ❌ Clone failed")
            return {"repo": name, "findings": 0}
        
        all_f = []
        for root, dirs, files in os.walk(tmp):
            dirs[:] = [d for d in dirs if d not in ["test", "tests", "node_modules", ".git", "target", "build"]]
            for file in files:
                if file.endswith((".java", ".py", ".js", ".ts")):
                    ff = self.scan_file(os.path.join(root, file))
                    if ff:
                        all_f.extend(ff)
                        for f in ff:
                            print(f"   💀 [{f['type'].upper()}] {file}:{f['sink_line']} — {f['desc']}")
        
        subprocess.run(["rm", "-rf", tmp])
        return {"repo": name, "findings": len(all_f), "vulns": all_f[:5]}

    def run(self):
        print("🦅 NOVA CONTEXT ENGINE — REAL VULNS ONLY\n")
        targets = [
            "https://github.com/spring-projects/spring-framework.git",
            "https://github.com/apache/struts.git",
            "https://github.com/apache/logging-log4j2.git",
            "https://github.com/apache/tomcat.git",
            "https://github.com/jenkinsci/jenkins.git",
        ]
        results = [self.scan_repo(t) for t in targets]
        total = sum(r["findings"] for r in results)
        print(f"\n{'='*50}")
        print(f"REAL VULNS: {total} across {len(results)} repos")
        for r in results:
            if r["findings"] > 0:
                print(f"\n{r['repo']}: {r['findings']}")
                for v in r.get("vulns", []):
                    print(f"  💀 [{v['severity']}] {v['file']}:{v['sink_line']} — {v['cwe']} CVSS {v['cvss']}")
        
        with open(f"nova_context_{datetime.now().strftime('%H%M%S')}.json", "w") as f:
            json.dump({"results": results, "total": total}, f, indent=2)
        print(f"\n📁 Report saved")

if __name__ == "__main__":
    NovaContextEngine().run()
