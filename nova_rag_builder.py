#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   🧠 NOVA RAG BUILDER v1.0 — KNOWLEDGE BASE FROM PAST HUNTS    ║
║                                                                  ║
║   Turns every past finding Nova has ever made into searchable   ║
║   intelligence she can query before each attack phase.          ║
║                                                                  ║
║   Sources ingested:                                             ║
║     • nova_h1_hunt_*.json        (HackerOne recon runs)        ║
║     • nova_*_submission/         (submitted findings + evidence)║
║     • nova_*_report.json         (mission reports)             ║
║     • nova_verified_findings.json                               ║
║     • nova_real_findings.json                                   ║
║     • CVE patterns + OWASP Top 10 (built-in)                   ║
╚══════════════════════════════════════════════════════════════════╝
"""

import glob
import json
import os
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKSPACE   = os.path.expanduser("~/nova_workspace")
MEMORY_DIR  = os.path.join(WORKSPACE, "memory")
KB_FILE     = os.path.join(MEMORY_DIR, "nova_knowledge_base.json")
INDEX_FILE  = os.path.join(MEMORY_DIR, "nova_kb_index.json")


# ── BUILT-IN SECURITY KNOWLEDGE ───────────────────────────────────
BUILTIN_KNOWLEDGE = [
    # SQLi
    {
        "id": "builtin-sqli-001",
        "type": "sql_injection",
        "title": "SQL Injection via search parameter",
        "endpoint_pattern": "/rest/products/search",
        "param": "q",
        "payload": "' OR 1=1--",
        "severity": "critical", "cvss": 9.8, "cwe": "CWE-89",
        "tech": ["sqlite", "sequelize"],
        "indicators": ["SELECT", "UNION", "error in sql", "syntax error"],
        "tags": ["sqli", "owasp-a03", "data-exposure"],
        "source": "builtin",
    },
    {
        "id": "builtin-sqli-002",
        "type": "sql_injection",
        "title": "Boolean-based blind SQLi in login",
        "endpoint_pattern": "/rest/user/login",
        "param": "email",
        "payload": "' OR '1'='1",
        "severity": "critical", "cvss": 9.8, "cwe": "CWE-89",
        "tech": ["express", "sqlite"],
        "indicators": ["200 OK on invalid creds", "empty password accepted"],
        "tags": ["sqli", "auth-bypass", "owasp-a03"],
        "source": "builtin",
    },
    # JWT
    {
        "id": "builtin-jwt-001",
        "type": "jwt_forgery",
        "title": "JWT 'none' algorithm bypass",
        "endpoint_pattern": "/rest/user/whoami",
        "payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiZW1haWwiOiJhZG1pbkBqdWljZS1zaC5vcCJ9.",
        "severity": "critical", "cvss": 9.1, "cwe": "CWE-347",
        "tech": ["jsonwebtoken 0.4.0"],
        "indicators": ["admin access granted", "role: admin"],
        "tags": ["jwt", "auth-bypass", "owasp-a02"],
        "source": "builtin",
    },
    # XSS
    {
        "id": "builtin-xss-001",
        "type": "xss",
        "title": "Stored XSS in feedback/comments",
        "endpoint_pattern": "/api/Feedbacks",
        "param": "comment",
        "payload": "<iframe src=\"javascript:alert('xss')\">",
        "severity": "high", "cvss": 7.4, "cwe": "CWE-79",
        "tech": ["angular", "sanitize-html 1.4.2"],
        "indicators": ["payload reflected in DOM", "alert executed"],
        "tags": ["xss", "stored-xss", "owasp-a03"],
        "source": "builtin",
    },
    # Prototype Pollution
    {
        "id": "builtin-proto-001",
        "type": "prototype_pollution",
        "title": "Prototype pollution via merge/clone utilities",
        "endpoint_pattern": "/api/",
        "payload": "{\"__proto__\": {\"isAdmin\": true}}",
        "severity": "critical", "cvss": 8.8, "cwe": "CWE-915",
        "tech": ["lodash <4.17.21", "express"],
        "indicators": ["isAdmin: true on subsequent requests", "polluted Object.prototype"],
        "tags": ["prototype-pollution", "owasp-a08"],
        "source": "builtin",
    },
    # SSRF
    {
        "id": "builtin-ssrf-001",
        "type": "ssrf",
        "title": "SSRF via URL parameter",
        "endpoint_pattern": "/b2b/v2/orders",
        "payload": "http://localhost/server-status",
        "severity": "high", "cvss": 8.6, "cwe": "CWE-918",
        "tech": ["express", "node-fetch"],
        "indicators": ["internal response returned", "AWS metadata accessible"],
        "tags": ["ssrf", "owasp-a10"],
        "source": "builtin",
    },
    # Path Traversal
    {
        "id": "builtin-path-001",
        "type": "path_traversal",
        "title": "Directory traversal via file parameter",
        "endpoint_pattern": "/ftp/",
        "payload": "../../../../etc/passwd",
        "severity": "high", "cvss": 7.5, "cwe": "CWE-22",
        "tech": ["express", "serve-index"],
        "indicators": ["root:x:0:0", "file contents returned", "package.json exposed"],
        "tags": ["lfi", "path-traversal", "owasp-a01"],
        "source": "builtin",
    },
    # IDOR
    {
        "id": "builtin-idor-001",
        "type": "idor",
        "title": "IDOR on user basket — access other users' data",
        "endpoint_pattern": "/rest/basket/",
        "severity": "high", "cvss": 7.5, "cwe": "CWE-639",
        "indicators": ["other user basket returned", "no ownership check"],
        "tags": ["idor", "owasp-a01"],
        "source": "builtin",
    },
    # Race Condition
    {
        "id": "builtin-race-001",
        "type": "race_condition",
        "title": "Race condition on coupon redemption",
        "endpoint_pattern": "/rest/basket/",
        "severity": "medium", "cvss": 5.3, "cwe": "CWE-362",
        "indicators": ["negative balance", "double redemption", "concurrent 200 responses"],
        "tags": ["race-condition", "business-logic"],
        "source": "builtin",
    },
    # CORS
    {
        "id": "builtin-cors-001",
        "type": "cors",
        "title": "Overly permissive CORS allows credential theft",
        "endpoint_pattern": "/rest/",
        "severity": "medium", "cvss": 6.5, "cwe": "CWE-942",
        "indicators": ["Access-Control-Allow-Origin: *", "credentials reflected"],
        "tags": ["cors", "owasp-a05"],
        "source": "builtin",
    },
]


class NovaRAGBuilder:
    """
    Ingests all of Nova's past findings and recon data into a searchable
    knowledge base. Query this before each attack phase to get relevant
    context — closing the gap with frontier models' large context windows
    using structured retrieval instead.
    """

    def __init__(self, nova_dir: str = ".", workspace: str = WORKSPACE):
        self.nova_dir  = Path(nova_dir)
        self.workspace = Path(workspace)
        self.kb: List[Dict] = []
        self._load_existing()

    def _load_existing(self):
        """Load previously built knowledge base if it exists."""
        os.makedirs(MEMORY_DIR, exist_ok=True)
        if os.path.exists(KB_FILE):
            try:
                with open(KB_FILE) as f:
                    self.kb = json.load(f)
                print(f"  📚 RAG: Loaded {len(self.kb)} entries from knowledge base")
                return
            except Exception:
                pass
        self.kb = []

    # ── INGESTION ─────────────────────────────────────────────────

    def build(self, force_rebuild: bool = False) -> int:
        """
        Build the full knowledge base from all available sources.
        Returns the total number of entries added.
        """
        if self.kb and not force_rebuild:
            print(f"  📚 RAG: Knowledge base already has {len(self.kb)} entries. Use force_rebuild=True to refresh.")
            return len(self.kb)

        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║   🧠 NOVA RAG BUILDER — Building Knowledge Base             ║")
        print("╚══════════════════════════════════════════════════════════════╝\n")

        before = len(self.kb)

        self._ingest_builtins()
        self._ingest_h1_hunts()
        self._ingest_submissions()
        self._ingest_reports()
        self._ingest_verified_findings()

        # Deduplicate
        seen_ids = set()
        deduped  = []
        for entry in self.kb:
            if entry.get("id") not in seen_ids:
                seen_ids.add(entry["id"])
                deduped.append(entry)
        self.kb = deduped

        self._save()
        added = len(self.kb) - before
        print(f"\n  ✅ Knowledge base: {len(self.kb)} total entries ({added} added this run)")
        return len(self.kb)

    def _ingest_builtins(self):
        print("  📖 Loading built-in security knowledge...")
        count = 0
        for entry in BUILTIN_KNOWLEDGE:
            if not any(e["id"] == entry["id"] for e in self.kb):
                entry["ingested_at"] = datetime.utcnow().isoformat()
                self.kb.append(entry)
                count += 1
        print(f"     → {count} built-in entries loaded")

    def _ingest_h1_hunts(self):
        """Ingest HackerOne hunt result files."""
        pattern = str(self.nova_dir / "nova_h1_hunt_*.json")
        files   = glob.glob(pattern)
        print(f"  🌐 Loading HackerOne hunt data ({len(files)} files)...")
        count = 0
        for fp in files:
            try:
                with open(fp) as f:
                    data = json.load(f)
                entries = self._extract_h1_entries(data, fp)
                for e in entries:
                    self.kb.append(e)
                    count += 1
            except Exception:
                continue
        print(f"     → {count} recon entries loaded")

    def _extract_h1_entries(self, data: Any, source_file: str) -> List[Dict]:
        """Extract useful intelligence from an H1 hunt file."""
        entries   = []
        target    = Path(source_file).stem.replace("nova_h1_hunt_", "")
        base_id   = hashlib.md5(source_file.encode()).hexdigest()[:8]

        # Extract endpoints
        endpoints = []
        if isinstance(data, dict):
            endpoints = (data.get("endpoints", []) or
                         data.get("urls", []) or
                         data.get("live_hosts", []))
            # Extract vulnerabilities if present
            vulns = data.get("vulnerabilities", data.get("findings", []))
            for i, v in enumerate(vulns or []):
                if isinstance(v, dict):
                    entry = {
                        "id":          f"h1-{base_id}-{i}",
                        "type":        v.get("type", "unknown"),
                        "title":       v.get("title", v.get("type", "Finding")),
                        "target":      target,
                        "endpoint":    v.get("endpoint", v.get("url", "")),
                        "severity":    v.get("severity", "info"),
                        "cvss":        float(v.get("cvss", 0)),
                        "cwe":         v.get("cwe", ""),
                        "payload":     str(v.get("payload", ""))[:200],
                        "indicators":  v.get("indicators", []),
                        "tags":        ["h1-hunt", target.split(".")[0]],
                        "source":      source_file,
                        "ingested_at": datetime.utcnow().isoformat(),
                    }
                    entries.append(entry)

        # Condense endpoint list as recon intelligence
        if endpoints and len(endpoints) > 0:
            entry = {
                "id":          f"h1-recon-{base_id}",
                "type":        "recon",
                "title":       f"Attack surface: {target}",
                "target":      target,
                "endpoints":   endpoints[:100],
                "endpoint_count": len(endpoints),
                "tags":        ["recon", "attack-surface", target.split(".")[0]],
                "source":      source_file,
                "ingested_at": datetime.utcnow().isoformat(),
            }
            entries.append(entry)

        return entries

    def _ingest_submissions(self):
        """Ingest submission folders (nova_0din_submission, nova_nextgen_submission, etc.)."""
        submission_dirs = list(self.nova_dir.glob("nova_*submission*"))
        print(f"  📤 Loading submission evidence ({len(submission_dirs)} folders)...")
        count = 0
        for d in submission_dirs:
            if not d.is_dir():
                continue
            for fp in d.rglob("*.json"):
                try:
                    with open(fp) as f:
                        data = json.load(f)
                    entry = self._extract_submission_entry(data, str(fp), d.name)
                    if entry:
                        self.kb.append(entry)
                        count += 1
                except Exception:
                    continue
        print(f"     → {count} submission entries loaded")

    def _extract_submission_entry(self, data: Any, source: str, program: str) -> Optional[Dict]:
        if not isinstance(data, dict):
            return None
        fid = hashlib.md5(source.encode()).hexdigest()[:8]
        return {
            "id":           f"sub-{fid}",
            "type":         data.get("type", data.get("vulnerability_type", "unknown")),
            "title":        data.get("title", data.get("type", "Submission finding")),
            "target":       data.get("target", data.get("url", "")),
            "endpoint":     data.get("endpoint", data.get("url", "")),
            "severity":     data.get("severity", "medium"),
            "cvss":         float(data.get("cvss", 0)),
            "cwe":          data.get("cwe", ""),
            "payload":      str(data.get("payload", data.get("proof", "")))[:300],
            "evidence":     str(data.get("evidence", data.get("response", "")))[:300],
            "program":      program,
            "tags":         ["submitted", "confirmed", program],
            "source":       source,
            "ingested_at":  datetime.utcnow().isoformat(),
        }

    def _ingest_reports(self):
        """Ingest JSON mission reports for confirmed findings."""
        report_files = list(self.nova_dir.glob("nova_*report*.json"))
        report_files += list(self.nova_dir.glob("nova_*findings*.json"))
        print(f"  📊 Loading mission reports ({len(report_files)} files)...")
        count = 0
        for fp in report_files:
            try:
                with open(fp) as f:
                    data = json.load(f)
                entries = self._extract_report_entries(data, str(fp))
                for e in entries:
                    self.kb.append(e)
                    count += 1
            except Exception:
                continue
        print(f"     → {count} report entries loaded")

    def _extract_report_entries(self, data: Any, source: str) -> List[Dict]:
        entries = []
        base_id = hashlib.md5(source.encode()).hexdigest()[:8]

        findings = []
        if isinstance(data, dict):
            raw = data.get("findings", data.get("vulnerabilities", []))
            if isinstance(raw, list):
                findings = raw
            elif isinstance(raw, dict):
                for sev, items in raw.items():
                    for item in (items or []):
                        if isinstance(item, dict):
                            item.setdefault("severity", sev)
                            findings.append(item)

        for i, f in enumerate(findings):
            if not isinstance(f, dict):
                continue
            entry = {
                "id":          f"rpt-{base_id}-{i}",
                "type":        f.get("type", "unknown"),
                "title":       f.get("type", "Finding").replace("_", " ").title(),
                "endpoint":    f.get("endpoint", f.get("url", "")),
                "param":       f.get("parameter", f.get("param", "")),
                "payload":     str(f.get("payload", ""))[:200],
                "severity":    f.get("severity", "medium"),
                "cvss":        float(f.get("cvss", 0)),
                "cwe":         f.get("cwe", ""),
                "success":     f.get("success", False),
                "indicators":  f.get("indicators_found", f.get("data_exposed", [])),
                "tags":        ["mission-report"],
                "source":      source,
                "ingested_at": datetime.utcnow().isoformat(),
            }
            entries.append(entry)
        return entries

    def _ingest_verified_findings(self):
        """Ingest the verified/real findings files specifically."""
        special = [
            "nova_verified_findings.json",
            "nova_real_findings.json",
            "nova_verified_130329.json",
        ]
        count = 0
        for fname in special:
            fp = self.nova_dir / fname
            if fp.exists():
                try:
                    with open(fp) as f:
                        data = json.load(f)
                    entries = self._extract_report_entries(data, str(fp))
                    for e in entries:
                        e["tags"].append("verified")
                        e["id"] = "verified-" + e["id"]
                        self.kb.append(e)
                        count += 1
                except Exception:
                    continue
        if count:
            print(f"  ✅ {count} verified/confirmed findings loaded")

    # ── QUERY ─────────────────────────────────────────────────────

    def query(
        self,
        task_type: str,
        endpoint: str = "",
        tech: str = "",
        top_k: int = 5,
        min_severity: str = "low",
    ) -> List[Dict]:
        """
        Retrieve the most relevant knowledge base entries for a given task.

        Args:
            task_type:    attack type or recon task
            endpoint:     target endpoint path (for path-based matching)
            tech:         technology string (for tech-based matching)
            top_k:        number of results to return
            min_severity: minimum severity filter ("low", "medium", "high", "critical")

        Returns:
            Ranked list of relevant entries.
        """
        SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = SEV_RANK.get(min_severity, 0)

        scored = []
        for entry in self.kb:
            score = 0

            # Type match
            etype = entry.get("type", "")
            if task_type and (task_type in etype or etype in task_type):
                score += 10
            # Tag match
            for tag in entry.get("tags", []):
                if task_type in tag:
                    score += 3
            # Endpoint path similarity
            if endpoint:
                ep = entry.get("endpoint", entry.get("endpoint_pattern", ""))
                if ep and any(seg in endpoint for seg in ep.split("/") if len(seg) > 2):
                    score += 5
            # Tech match
            if tech:
                for t in entry.get("tech", []):
                    if tech.lower() in t.lower():
                        score += 4
            # Severity boost
            sev = entry.get("severity", "info")
            score += SEV_RANK.get(sev, 0)
            # Confirmed/verified boost
            if "verified" in entry.get("tags", []) or "submitted" in entry.get("tags", []):
                score += 5
            if entry.get("success"):
                score += 3
            # Severity filter
            if SEV_RANK.get(sev, 0) < min_rank:
                continue

            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:top_k]]

    def format_context(self, entries: List[Dict], max_chars: int = 2000) -> str:
        """
        Format RAG results into a compact context string for LLM injection.
        Fits within token limits while maximising useful signal.
        """
        if not entries:
            return "No prior knowledge found for this attack type."

        lines = ["=== NOVA PRIOR KNOWLEDGE (from past hunts) ==="]
        budget = max_chars - len(lines[0])

        for e in entries:
            chunk = (
                f"\n[{e.get('severity','?').upper()}] {e.get('title','?')}"
                f"\n  Type: {e.get('type','?')} | CWE: {e.get('cwe','?')} | CVSS: {e.get('cvss','?')}"
                f"\n  Endpoint: {e.get('endpoint', e.get('endpoint_pattern','?'))}"
            )
            if e.get("payload"):
                chunk += f"\n  Payload: {str(e['payload'])[:80]}"
            if e.get("indicators"):
                chunk += f"\n  Indicators: {', '.join(str(i) for i in e['indicators'][:3])}"

            if budget - len(chunk) < 50:
                break
            lines.append(chunk)
            budget -= len(chunk)

        return "\n".join(lines)

    # ── PERSISTENCE ───────────────────────────────────────────────

    def _save(self):
        """Persist knowledge base to disk."""
        os.makedirs(MEMORY_DIR, exist_ok=True)
        with open(KB_FILE, "w") as f:
            json.dump(self.kb, f, indent=2, default=str)
        # Also write a lightweight index
        index = {
            "total":      len(self.kb),
            "built_at":   datetime.utcnow().isoformat(),
            "by_type":    {},
            "by_severity":{},
        }
        for e in self.kb:
            t = e.get("type", "unknown")
            s = e.get("severity", "unknown")
            index["by_type"][t]     = index["by_type"].get(t, 0) + 1
            index["by_severity"][s] = index["by_severity"].get(s, 0) + 1
        with open(INDEX_FILE, "w") as f:
            json.dump(index, f, indent=2)
        print(f"  💾 Knowledge base saved: {KB_FILE}")

    def stats(self) -> Dict:
        """Return summary statistics."""
        by_type = {}
        by_sev  = {}
        for e in self.kb:
            t = e.get("type", "?")
            s = e.get("severity", "?")
            by_type[t] = by_type.get(t, 0) + 1
            by_sev[s]  = by_sev.get(s, 0) + 1
        return {"total": len(self.kb), "by_type": by_type, "by_severity": by_sev}


# ── Singleton ─────────────────────────────────────────────────────
_rag: Optional[NovaRAGBuilder] = None

def get_rag(nova_dir: str = ".") -> NovaRAGBuilder:
    global _rag
    if _rag is None:
        _rag = NovaRAGBuilder(nova_dir=nova_dir)
        if not _rag.kb:
            _rag.build()
    return _rag


if __name__ == "__main__":
    import sys
    nova_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    rag = NovaRAGBuilder(nova_dir=nova_dir)
    rag.build(force_rebuild=True)

    stats = rag.stats()
    print(f"\n📊 Knowledge Base Stats:")
    print(f"   Total entries: {stats['total']}")
    print(f"\n   By type:")
    for t, n in sorted(stats['by_type'].items(), key=lambda x: -x[1])[:10]:
        print(f"     {t:<30} {n}")
    print(f"\n   By severity:")
    for s, n in sorted(stats['by_severity'].items(), key=lambda x: -x[1]):
        print(f"     {s:<15} {n}")

    # Demo query
    print("\n🔍 Demo query: 'sql_injection' on '/rest/products/search'")
    results = rag.query("sql_injection", endpoint="/rest/products/search", top_k=3)
    print(rag.format_context(results))
