#!/usr/bin/env python3
"""
NOVA THREAT MODEL v1.0
Daybreak-style editable threat model generation.
Scans a repository and builds: attack surface, trust boundaries,
sensitive data flows, and prioritised attack paths.
"""

import os
import re
import json
from typing import List, Dict, Optional
from datetime import datetime


ENTRY_POINT_PATTERNS = [
    (r'app\.(get|post|put|patch|delete|use)\s*\(["\']([^"\']+)', "HTTP route"),
    (r'router\.(get|post|put|patch|delete)\s*\(["\']([^"\']+)', "Router endpoint"),
    (r'@(Get|Post|Put|Delete|Patch)\s*\(["\']([^"\']+)', "Decorator route"),
    (r'path\s*:\s*["\']([^"\']+)["\']', "Path definition"),
    (r'addEventListener\s*\(["\']message["\']', "PostMessage listener"),
    (r'socket\.(on|emit)\s*\(["\']([^"\']+)', "WebSocket event"),
]

TRUST_BOUNDARY_PATTERNS = [
    (r'req\.(headers|cookies)\[', "HTTP header/cookie — external boundary"),
    (r'process\.env\[', "Environment variable — config boundary"),
    (r'fs\.(readFile|writeFile|unlink)', "Filesystem — OS boundary"),
    (r'child_process|exec\s*\(|spawn\s*\(', "Process execution — OS boundary"),
    (r'(mysql|postgres|sequelize|mongoose|sqlite)', "Database — persistence boundary"),
    (r'(redis|memcache|cache\.set)', "Cache — memory boundary"),
    (r'(http|https|axios|fetch|request)\.(get|post)', "External HTTP — network boundary"),
    (r'(jwt|session|cookie)', "Session/auth — trust boundary"),
]

SENSITIVE_DATA_PATTERNS = [
    (r'password|passwd|pwd', "Password"),
    (r'secret|api.?key|token|credential', "Credentials/Secrets"),
    (r'credit.?card|card.?number|cvv|ccn', "Payment card data"),
    (r'ssn|social.?security|national.?id', "Identity document"),
    (r'email|phone|address|dob|birth', "PII"),
    (r'private.?key|signing.?key|encryption.?key', "Cryptographic key"),
    (r'access.?token|refresh.?token|bearer', "OAuth/JWT token"),
    (r'health|medical|diagnosis|prescription', "Health data"),
]

ATTACK_PATH_PATTERNS = {
    "SQL Injection": [
        r'sequelize\.query\s*\(`',
        r'\.query\s*\(\s*["\'].*\$\{',
        r'\.execute\s*\(.*\+\s*req\.',
        r'knex\.raw\s*\(',
    ],
    "XSS": [
        r'innerHTML\s*=',
        r'dangerouslySetInnerHTML',
        r'document\.write\s*\(',
        r'\.html\s*\(.*req\.',
    ],
    "Path Traversal": [
        r'path\.join\s*\(.*req\.',
        r'readFile\s*\(.*req\.',
        r'sendFile\s*\(.*req\.',
        r'createReadStream\s*\(.*req\.',
    ],
    "SSRF": [
        r'fetch\s*\(.*req\.(body|query|params)',
        r'axios\.(get|post)\s*\(.*req\.',
        r'http\.get\s*\(.*req\.',
        r'urllib.*req\.',
    ],
    "Command Injection": [
        r'exec\s*\(.*req\.',
        r'execSync\s*\(.*req\.',
        r'spawn\s*\(.*req\.',
        r'child_process.*req\.',
    ],
    "Auth Bypass": [
        r'if\s*\(.*==\s*null\s*\|\|',
        r'token\s*===?\s*undefined',
        r'skip.*auth|bypass.*auth|no.*auth',
        r'jwt\.verify.*catch\s*\(\s*\)',
    ],
    "Insecure Deserialization": [
        r'JSON\.parse\s*\(.*req\.',
        r'yaml\.load\s*\(',
        r'pickle\.loads',
        r'deserialize\s*\(.*req\.',
    ],
    "XXE": [
        r'parseString\s*\(.*req\.',
        r'libxmljs.*parseXml',
        r'DOMParser.*parseFromString',
        r'xml2js.*parseString',
    ],
    "Open Redirect": [
        r'res\.redirect\s*\(.*req\.(body|query|params)',
        r'location\.href\s*=.*req\.',
        r'window\.location.*req\.',
    ],
    "Prototype Pollution": [
        r'Object\.assign\s*\(\s*\{\s*\}.*req\.',
        r'\.__proto__\s*=',
        r'merge\s*\(.*req\.',
        r'extend\s*\(.*req\.',
    ],
}


class NovaThreatModel:
    def __init__(self):
        self.entry_points: List[Dict] = []
        self.trust_boundaries: List[Dict] = []
        self.sensitive_data: List[Dict] = []
        self.attack_paths: List[Dict] = []
        self.model: Dict = {}

    def _scan_file(self, filepath: str, content: str):
        filename = os.path.relpath(filepath)
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            for pat, label in ENTRY_POINT_PATTERNS:
                m = re.search(pat, line, re.IGNORECASE)
                if m:
                    route = m.group(2) if len(m.groups()) >= 2 else m.group(1)
                    self.entry_points.append({
                        "file": filename, "line": i,
                        "type": label, "route": route,
                        "snippet": line.strip()[:100],
                    })

            for pat, label in TRUST_BOUNDARY_PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    self.trust_boundaries.append({
                        "file": filename, "line": i,
                        "boundary": label, "snippet": line.strip()[:100],
                    })

            for pat, label in SENSITIVE_DATA_PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    self.sensitive_data.append({
                        "file": filename, "line": i,
                        "data_type": label, "snippet": line.strip()[:80],
                    })

            for attack_type, patterns in ATTACK_PATH_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        self.attack_paths.append({
                            "file": filename, "line": i,
                            "attack_type": attack_type,
                            "snippet": line.strip()[:100],
                            "priority": "CRITICAL" if attack_type in
                                        ["SQL Injection", "Command Injection", "XXE", "Insecure Deserialization"]
                                        else "HIGH",
                        })
                        break

    def build_from_directory(self, directory: str) -> Dict:
        print("\n🗺  NOVA THREAT MODEL — Building threat model...")
        extensions = {'.ts', '.js', '.py', '.java', '.go', '.rb', '.php', '.cs'}
        skip = {'node_modules', '.git', 'dist', 'build', 'vendor', 'coverage'}
        files_scanned = 0

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in skip and not d.startswith('.')]
            for fname in files:
                if os.path.splitext(fname)[1].lower() in extensions:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        self._scan_file(fpath, content)
                        files_scanned += 1
                    except Exception:
                        pass

        self.model = self._compile_model(directory, files_scanned)
        self._print_summary()
        return self.model

    def build_from_files(self, file_contents: Dict[str, str]) -> Dict:
        print("\n🗺  NOVA THREAT MODEL — Building from provided files...")
        for filepath, content in file_contents.items():
            self._scan_file(filepath, content)
        self.model = self._compile_model("provided_files", len(file_contents))
        self._print_summary()
        return self.model

    def _compile_model(self, target: str, files_scanned: int) -> Dict:
        deduped_paths = {}
        for ap in self.attack_paths:
            key = (ap["attack_type"], ap["file"])
            if key not in deduped_paths:
                deduped_paths[key] = ap

        attack_paths_deduped = sorted(
            deduped_paths.values(),
            key=lambda x: (0 if x["priority"] == "CRITICAL" else 1)
        )

        unique_boundaries = {b["boundary"]: b for b in self.trust_boundaries}
        unique_data = {}
        for sd in self.sensitive_data:
            if sd["data_type"] not in unique_data:
                unique_data[sd["data_type"]] = sd

        return {
            "generated": datetime.now().isoformat(),
            "target": target,
            "files_scanned": files_scanned,
            "summary": {
                "entry_points": len(self.entry_points),
                "trust_boundaries": len(unique_boundaries),
                "sensitive_data_types": len(unique_data),
                "attack_paths": len(attack_paths_deduped),
                "critical_paths": sum(1 for ap in attack_paths_deduped if ap["priority"] == "CRITICAL"),
            },
            "entry_points": self.entry_points[:50],
            "trust_boundaries": list(unique_boundaries.values()),
            "sensitive_data": list(unique_data.values()),
            "attack_paths": attack_paths_deduped,
            "recommendations": self._generate_recommendations(attack_paths_deduped),
        }

    def _generate_recommendations(self, attack_paths: List[Dict]) -> List[str]:
        seen_types = set(ap["attack_type"] for ap in attack_paths)
        recs = []
        if "SQL Injection" in seen_types:
            recs.append("Use parameterised queries / ORM `.findAll({where: {id: req.params.id}})` — never template literals in SQL")
        if "XSS" in seen_types:
            recs.append("Replace innerHTML assignments with textContent; use DOMPurify for rich HTML")
        if "Path Traversal" in seen_types:
            recs.append("Resolve user-supplied paths with path.resolve() and assert they start with the expected base dir")
        if "SSRF" in seen_types:
            recs.append("Validate URLs against an allowlist of approved domains before making outbound requests")
        if "Command Injection" in seen_types:
            recs.append("Never pass user input to exec/spawn; use execFile with an argument array instead")
        if "Auth Bypass" in seen_types:
            recs.append("Ensure JWT verification errors are never silently swallowed — always reject on exception")
        if "Open Redirect" in seen_types:
            recs.append("Restrict redirect targets to a same-origin or allowlisted URL set")
        if "XXE" in seen_types:
            recs.append("Disable external entity loading in all XML parsers: `libxml.NOENT | libxml.DTDLOAD = false`")
        return recs

    def _print_summary(self):
        s = self.model.get("summary", {})
        print(f"\n  📊 Threat Model Summary")
        print(f"     Entry points    : {s.get('entry_points', 0)}")
        print(f"     Trust boundaries: {s.get('trust_boundaries', 0)}")
        print(f"     Sensitive data  : {s.get('sensitive_data_types', 0)} type(s)")
        print(f"     Attack paths    : {s.get('attack_paths', 0)} ({s.get('critical_paths', 0)} CRITICAL)")
        if self.model.get("recommendations"):
            print(f"\n  🛡  Recommendations:")
            for rec in self.model["recommendations"]:
                print(f"     • {rec}")

    def save(self, output_path: str):
        with open(output_path, "w") as f:
            json.dump(self.model, f, indent=2)
        print(f"\n  💾 Threat model saved → {output_path}")

    def to_markdown(self) -> str:
        m = self.model
        s = m.get("summary", {})
        lines = [
            f"# Nova Threat Model\n",
            f"**Generated:** {m.get('generated', 'unknown')}  ",
            f"**Target:** {m.get('target', 'unknown')}  ",
            f"**Files scanned:** {m.get('files_scanned', 0)}\n",
            f"## Summary\n",
            f"| Category | Count |",
            f"|---|---|",
            f"| Entry Points | {s.get('entry_points', 0)} |",
            f"| Trust Boundaries | {s.get('trust_boundaries', 0)} |",
            f"| Sensitive Data Types | {s.get('sensitive_data_types', 0)} |",
            f"| Attack Paths | {s.get('attack_paths', 0)} |",
            f"| Critical Paths | {s.get('critical_paths', 0)} |\n",
            f"## Attack Paths\n",
        ]
        for ap in m.get("attack_paths", [])[:20]:
            lines.append(f"- **[{ap['priority']}]** `{ap['attack_type']}` — `{ap['file']}:{ap['line']}`")
            lines.append(f"  ```\n  {ap['snippet']}\n  ```")
        lines.append("\n## Recommendations\n")
        for rec in m.get("recommendations", []):
            lines.append(f"- {rec}")
        return "\n".join(lines)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    tm = NovaThreatModel()
    if os.path.isdir(target):
        model = tm.build_from_directory(target)
    else:
        print("Usage: python3 nova_threat_model.py <directory>")
        sys.exit(1)
    out = "nova_threat_model_report.json"
    tm.save(out)
    md_out = "nova_threat_model_report.md"
    with open(md_out, "w") as f:
        f.write(tm.to_markdown())
    print(f"  📄 Markdown report → {md_out}")
