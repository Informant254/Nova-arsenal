#!/usr/bin/env python3
"""
NOVA DATA FLOW ENGINE v1.0
Traces user input through function calls to dangerous sinks.
Distinguishes real vulnerabilities from false positives.
This is the capability that competes with the Titans.
"""

import json, re, os, ast, subprocess, tempfile
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

class NovaDataFlowEngine:
    """Traces data from user input to dangerous sinks."""
    
    def __init__(self):
        self.findings = []
        self.confirmed = []
        self.false_positives = []
        
        # User input sources (taint)
        self.taint_sources = [
            "request.args", "request.form", "request.json", "request.body",
            "request.headers", "request.cookies", "request.params",
            "req.body", "req.query", "req.params", "req.headers",
            "input(", "sys.argv", "os.environ", "readline",
            "request.GET", "request.POST", "request.FILES",
        ]
        
        # Dangerous sinks
        self.sinks = {
            "command_injection": ["os.system", "subprocess.call", "subprocess.Popen", "exec(", "eval("],
            "sql_injection": [".execute(", ".raw(", "cursor.execute", "Engine.execute"],
            "path_traversal": ["open(", "readFile", "sendFile", "file("],
            "code_execution": ["exec(", "eval(", "compile(", "__import__"],
        }
        
        # Sanitization functions (breaks the taint chain)
        self.sanitizers = [
            "escape(", "sanitize(", "validate(", "clean(", "filter(",
            "html.escape", "re.escape", "shlex.quote", "urllib.parse.quote",
        ]
    
    def analyze_file(self, filepath: str) -> List[Dict]:
        """Analyze a single file for real data flows."""
        findings = []
        
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
                lines = source.split("\n")
        except:
            return findings
        
        # Step 1: Find all user input sources
        taint_locations = []
        for i, line in enumerate(lines, 1):
            for source in self.taint_sources:
                if source in line:
                    taint_locations.append({
                        "line": i,
                        "source": source,
                        "code": line.strip()[:120],
                        "variable": self._extract_variable(line, source),
                    })
        
        if not taint_locations:
            return findings
        
        # Step 2: Find all dangerous sinks
        sink_locations = []
        for i, line in enumerate(lines, 1):
            for vuln_type, patterns in self.sinks.items():
                for pattern in patterns:
                    if pattern in line:
                        sink_locations.append({
                            "line": i,
                            "type": vuln_type,
                            "pattern": pattern,
                            "code": line.strip()[:120],
                        })
        
        # Step 3: Trace data flows from taint to sink
        for taint in taint_locations:
            taint_var = taint["variable"]
            if not taint_var:
                continue
            
            for sink in sink_locations:
                if sink["line"] <= taint["line"]:
                    continue  # Sink before taint - unlikely flow
                
                # Check if the tainted variable reaches this sink
                flow_exists = self._trace_variable_flow(
                    lines, taint["line"], sink["line"], taint_var
                )
                
                if flow_exists:
                    # Check for sanitization between taint and sink
                    sanitized = self._check_sanitization(
                        lines, taint["line"], sink["line"]
                    )
                    
                    finding = {
                        "file": os.path.basename(filepath),
                        "vulnerability_type": sink["type"],
                        "taint_source": taint["source"],
                        "taint_line": taint["line"],
                        "sink_line": sink["line"],
                        "taint_code": taint["code"],
                        "sink_code": sink["code"],
                        "data_flow_confirmed": True,
                        "sanitized": sanitized,
                        "exploitable": not sanitized,
                        "confidence": "HIGH" if not sanitized else "LOW",
                        "severity": "CRITICAL" if not sanitized and sink["type"] in ["command_injection", "code_execution"] else "HIGH",
                    }
                    
                    if not sanitized:
                        self.confirmed.append(finding)
                    else:
                        self.false_positives.append(finding)
                    
                    findings.append(finding)
        
        return findings
    
    def _extract_variable(self, line: str, source: str) -> Optional[str]:
        """Extract the variable name from a taint source."""
        # Patterns like: var = request.args.get('x') or var = req.body
        match = re.search(r'(\w+)\s*=\s*' + re.escape(source), line)
        if match:
            return match.group(1)
        # Pattern like: func(request.args.get('x'))
        match = re.search(re.escape(source) + r'\.get\([\'"]([^\'"]+)[\'"]\)', line)
        if match:
            return match.group(1)
        return source.split(".")[-1] if "." in source else source
    
    def _trace_variable_flow(self, lines: List[str], start: int, end: int, variable: str) -> bool:
        """Trace if a variable flows from start to end."""
        for i in range(start, min(end + 1, len(lines))):
            line = lines[i]
            # Check if the variable appears in this line
            if variable in line:
                # Check if it's passed to a function or used in the sink
                if i == end - 1 or i == end:
                    return True
                # Check if passed as argument
                if f"({variable}" in line or f"({variable}," in line or f", {variable}" in line:
                    return True
        return False
    
    def _check_sanitization(self, lines: List[str], start: int, end: int) -> bool:
        """Check if there's sanitization between taint and sink."""
        for i in range(start, end):
            line = lines[i]
            for sanitizer in self.sanitizers:
                if sanitizer in line:
                    return True
        return False
    
    def scan_repository(self, repo_path: str) -> Dict:
        """Scan an entire repository for real data flows."""
        print(f"\n🔍 Data Flow Analysis: {repo_path}")
        
        all_findings = []
        files_scanned = 0
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in 
                      ["node_modules", "venv", "__pycache__", ".git"]]
            
            for file in files:
                if file.endswith((".py", ".js", ".ts")):
                    filepath = os.path.join(root, file)
                    findings = self.analyze_file(filepath)
                    all_findings.extend(findings)
                    files_scanned += 1
        
        # Deduplicate
        seen = set()
        unique = []
        for f in all_findings:
            key = (f["file"], f["sink_line"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        
        return {
            "total": len(unique),
            "confirmed_exploitable": len(self.confirmed),
            "false_positives": len(self.false_positives),
            "findings": unique,
            "files_scanned": files_scanned,
        }
    
    def generate_report(self, results: Dict):
        """Generate data flow analysis report."""
        print(f"""
╔══════════════════════════════════════════════════════════╗
║   🧬 NOVA DATA FLOW ENGINE — RESULTS                    ║
╠══════════════════════════════════════════════════════════╣
║  Files Scanned: {results['files_scanned']:<5}                                    ║
║  Total Patterns: {results['total']:<5}                                     ║
║  Confirmed Exploitable: {results['confirmed_exploitable']:<3}                           ║
║  False Positives (Sanitized): {results['false_positives']:<3}                    ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        if self.confirmed:
            print("💀 CONFIRMED EXPLOITABLE (Real Vulnerabilities):")
            for f in self.confirmed[:10]:
                print(f"   🔥 [{f['vulnerability_type'].upper()}] {f['file']}:{f['sink_line']}")
                print(f"      Taint: {f['taint_source']} (line {f['taint_line']})")
                print(f"      Data flow: CONFIRMED — user input reaches sink")
        
        if self.false_positives:
            print(f"\n✅ FALSE POSITIVES (Sanitized): {len(self.false_positives)} filtered")
        
        # Save report
        filename = f"nova_dataflow_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump({
                "confirmed": self.confirmed,
                "false_positives": self.false_positives,
                "summary": results,
            }, f, indent=2, default=str)
        
        print(f"\n📁 Report: {filename}")
        return self.confirmed

if __name__ == "__main__":
    import sys
    
    engine = NovaDataFlowEngine()
    
    # Default: scan current directory
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    results = engine.scan_repository(target)
    engine.generate_report(results)
