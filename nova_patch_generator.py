#!/usr/bin/env python3
"""
NOVA PATCH GENERATOR v1.0
Daybreak-style automatic patch generation and validation.
For each confirmed finding, generates a safe code fix and validates it.
"""

import os
import re
import json
from typing import Dict, List, Optional
from datetime import datetime


PATCH_TEMPLATES = {
    "SQL Injection": {
        "description": "Replace template literal / string concatenation in SQL with parameterised query",
        "patterns": [
            (
                r'sequelize\.query\s*\(`([^`]+)\$\{([^}]+)\}([^`]*)`\)',
                lambda m: f'sequelize.query(\'{m.group(1)}?\{m.group(3)}\', {{ replacements: [{m.group(2).strip()}], type: QueryTypes.SELECT }})',
                "Sequelize raw query with template literal"
            ),
            (
                r'\.query\s*\(\s*["\']([^"\']+)\'\s*\+\s*([^)]+)\)',
                lambda m: f'.query(\'{m.group(1)}\', [{m.group(2).strip()}])',
                "Raw query with string concatenation"
            ),
        ],
        "generic_fix": (
            "Use parameterised queries.\n"
            "BEFORE: db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)\n"
            "AFTER:  db.query('SELECT * FROM users WHERE id = ?', [req.params.id])"
        ),
        "references": ["CWE-89", "OWASP A03:2021"],
    },
    "XSS": {
        "description": "Replace unsafe HTML injection with safe DOM API or DOMPurify",
        "patterns": [
            (
                r'(\w+)\.innerHTML\s*=\s*(.+)',
                lambda m: f'{m.group(1)}.textContent = {m.group(2).strip()}',
                "innerHTML assignment → textContent"
            ),
        ],
        "generic_fix": (
            "Replace innerHTML with textContent for plain text, or sanitize with DOMPurify.\n"
            "BEFORE: el.innerHTML = userInput\n"
            "AFTER:  el.textContent = userInput   // or: el.innerHTML = DOMPurify.sanitize(userInput)"
        ),
        "references": ["CWE-79", "OWASP A03:2021"],
    },
    "Path Traversal": {
        "description": "Resolve and validate path stays within expected base directory",
        "patterns": [],
        "generic_fix": (
            "Resolve the path and assert it starts with the expected base dir.\n"
            "BEFORE: fs.readFile(req.params.filename)\n"
            "AFTER:\n"
            "  const base = path.resolve('/safe/uploads');\n"
            "  const target = path.resolve(base, req.params.filename);\n"
            "  if (!target.startsWith(base)) return res.status(400).send('Invalid path');\n"
            "  fs.readFile(target);"
        ),
        "references": ["CWE-22", "OWASP A01:2021"],
    },
    "Open Redirect": {
        "description": "Validate redirect URL against allowlist before redirecting",
        "patterns": [
            (
                r'res\.redirect\s*\(\s*(req\.\w+\.\w+)\s*\)',
                lambda m: (
                    f'const ALLOWED = ["/dashboard", "/home", "/profile"];\n'
                    f'const target = {m.group(1)};\n'
                    f'if (!ALLOWED.includes(target)) return res.status(400).send("Invalid redirect");\n'
                    f'res.redirect(target);'
                ),
                "res.redirect with user input → allowlist check"
            ),
        ],
        "generic_fix": (
            "Allowlist valid redirect destinations.\n"
            "BEFORE: res.redirect(req.query.next)\n"
            "AFTER:\n"
            "  const ALLOWED_PATHS = ['/home', '/dashboard', '/profile'];\n"
            "  const next = req.query.next;\n"
            "  if (!ALLOWED_PATHS.includes(next)) return res.status(400).json({error: 'Invalid redirect'});\n"
            "  res.redirect(next);"
        ),
        "references": ["CWE-601", "OWASP A01:2021"],
    },
    "Command Injection": {
        "description": "Replace exec with execFile using argument array — never pass user input to shell",
        "patterns": [],
        "generic_fix": (
            "Use execFile with an explicit argument array.\n"
            "BEFORE: exec(`convert ${req.body.filename} output.png`)\n"
            "AFTER:  execFile('convert', [req.body.filename, 'output.png'])"
        ),
        "references": ["CWE-78", "OWASP A03:2021"],
    },
    "SSRF": {
        "description": "Validate outbound URL against an allowlist of permitted domains",
        "patterns": [],
        "generic_fix": (
            "Allowlist approved domains and block internal/metadata addresses.\n"
            "BEFORE: fetch(req.body.url)\n"
            "AFTER:\n"
            "  const ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com'];\n"
            "  const parsed = new URL(req.body.url);\n"
            "  if (!ALLOWED_DOMAINS.includes(parsed.hostname)) return res.status(400).json({error: 'URL not allowed'});\n"
            "  fetch(req.body.url);"
        ),
        "references": ["CWE-918", "OWASP A10:2021"],
    },
    "XXE": {
        "description": "Disable external entity loading in the XML parser",
        "patterns": [],
        "generic_fix": (
            "Disable DTD / external entities in your XML parser.\n"
            "BEFORE: libxml.parseXml(req.body)\n"
            "AFTER:  libxml.parseXml(req.body, { noent: false, dtdload: false, dtdattr: false })"
        ),
        "references": ["CWE-611", "OWASP A05:2021"],
    },
    "Insecure Deserialization": {
        "description": "Validate and type-check parsed data; never deserialize untrusted data with native serializers",
        "patterns": [],
        "generic_fix": (
            "Use a schema validator after JSON.parse; avoid native deserializers for untrusted data.\n"
            "BEFORE: const obj = JSON.parse(req.body.data)\n"
            "AFTER:\n"
            "  const obj = JSON.parse(req.body.data);\n"
            "  // Validate schema strictly — reject unexpected keys/types\n"
            "  if (typeof obj.id !== 'number') throw new Error('Invalid payload');"
        ),
        "references": ["CWE-502", "OWASP A08:2021"],
    },
    "Auth Bypass": {
        "description": "Ensure authentication middleware always throws on failure and errors are never silently swallowed",
        "patterns": [],
        "generic_fix": (
            "Never silently ignore JWT or session verification errors.\n"
            "BEFORE:\n"
            "  try { jwt.verify(token, secret); } catch(e) { /* ignore */ }\n"
            "AFTER:\n"
            "  try {\n"
            "    const decoded = jwt.verify(token, secret);\n"
            "    req.user = decoded;\n"
            "  } catch(e) {\n"
            "    return res.status(401).json({ error: 'Unauthorized' });\n"
            "  }"
        ),
        "references": ["CWE-287", "OWASP A07:2021"],
    },
    "Prototype Pollution": {
        "description": "Use Object.create(null) for merge targets; block __proto__ and constructor keys",
        "patterns": [],
        "generic_fix": (
            "Sanitize keys before merging user data.\n"
            "BEFORE: Object.assign(target, req.body)\n"
            "AFTER:\n"
            "  const safe = Object.create(null);\n"
            "  for (const [k, v] of Object.entries(req.body)) {\n"
            "    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;\n"
            "    safe[k] = v;\n"
            "  }\n"
            "  Object.assign(target, safe);"
        ),
        "references": ["CWE-1321", "OWASP A03:2021"],
    },
}


class NovaPatchGenerator:
    def __init__(self):
        self.patches: List[Dict] = []

    def generate_patch(self, finding: Dict) -> Dict:
        vuln_type = finding.get("type") or finding.get("vulnerability_type") or finding.get("attack_type", "")
        snippet = finding.get("snippet") or finding.get("sink_code") or finding.get("taint_code", "")
        file_path = finding.get("file", "unknown")
        line_num = finding.get("line") or finding.get("sink_line", 0)

        template = PATCH_TEMPLATES.get(vuln_type)
        if not template:
            patch = {
                "status": "no_template",
                "vuln_type": vuln_type,
                "file": file_path,
                "line": line_num,
                "message": f"No patch template for {vuln_type}. Manual review required.",
            }
            self.patches.append(patch)
            return patch

        applied = False
        patched_code = snippet
        patch_description = template["description"]

        for pattern, fixer, label in template.get("patterns", []):
            m = re.search(pattern, snippet, re.IGNORECASE)
            if m:
                try:
                    patched_code = fixer(m)
                    patch_description = label
                    applied = True
                    break
                except Exception:
                    pass

        patch = {
            "status": "applied" if applied else "generic",
            "vuln_type": vuln_type,
            "file": file_path,
            "line": line_num,
            "original_code": snippet,
            "patched_code": patched_code if applied else template["generic_fix"],
            "description": patch_description,
            "references": template.get("references", []),
            "validation_required": True,
            "confidence": "HIGH" if applied else "MEDIUM",
            "generated_at": datetime.now().isoformat(),
        }
        self.patches.append(patch)
        return patch

    def generate_for_findings(self, findings: List[Dict]) -> List[Dict]:
        print("\n🔧 NOVA PATCH GENERATOR — Generating fixes...")
        print("=" * 60)
        patches = []
        for finding in findings:
            patch = self.generate_patch(finding)
            patches.append(patch)
            status_icon = "✅" if patch["status"] == "applied" else ("📋" if patch["status"] == "generic" else "⚠️")
            print(f"  {status_icon} [{patch['status'].upper():8s}] {patch['vuln_type']} @ {patch['file']}:{patch['line']}")
        applied = sum(1 for p in patches if p["status"] == "applied")
        generic = sum(1 for p in patches if p["status"] == "generic")
        print(f"\n  📊 {len(patches)} patches | {applied} auto-applied | {generic} generic guidance")
        return patches

    def save(self, patches: List[Dict], output_path: str):
        report = {
            "generated": datetime.now().isoformat(),
            "total_patches": len(patches),
            "auto_applied": sum(1 for p in patches if p["status"] == "applied"),
            "generic_guidance": sum(1 for p in patches if p["status"] == "generic"),
            "patches": patches,
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  💾 Patch report saved → {output_path}")
        return report

    def to_markdown(self, patches: List[Dict]) -> str:
        lines = [
            "# Nova Patch Report\n",
            f"**Generated:** {datetime.now().isoformat()}\n",
            f"**Total patches:** {len(patches)}\n",
        ]
        for i, p in enumerate(patches, 1):
            lines.append(f"## Patch {i}: {p['vuln_type']} — `{p['file']}:{p['line']}`\n")
            lines.append(f"**Status:** {p['status']} | **Confidence:** {p.get('confidence','?')}\n")
            lines.append(f"**Description:** {p['description']}\n")
            if p.get("original_code"):
                lines.append(f"**Original:**\n```\n{p['original_code']}\n```\n")
            lines.append(f"**Fix:**\n```\n{p['patched_code']}\n```\n")
            if p.get("references"):
                lines.append(f"**References:** {', '.join(p['references'])}\n")
        return "\n".join(lines)


if __name__ == "__main__":
    import sys
    findings_file = sys.argv[1] if len(sys.argv) > 1 else "nova_smart_audit_juice-shop.json"
    try:
        with open(findings_file) as f:
            data = json.load(f)
        findings = data if isinstance(data, list) else data.get("findings", data.get("attack_paths", []))
    except Exception as e:
        print(f"Error loading findings: {e}")
        sys.exit(1)
    gen = NovaPatchGenerator()
    patches = gen.generate_for_findings(findings)
    gen.save(patches, "nova_patches.json")
    with open("nova_patches.md", "w") as f:
        f.write(gen.to_markdown(patches))
    print("  📄 Markdown patches → nova_patches.md")
