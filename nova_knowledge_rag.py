#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  📚 NOVA KNOWLEDGE RAG v1.0 — Retrieval-Augmented Generation   ║
║                                                                  ║
║  Lightweight knowledge base for Nova Arsenal.                   ║
║  Stores findings, techniques, and CVEs for retrieval-augmented  ║
║  prompting across all Nova agents.                              ║
║                                                                  ║
║  Storage: JSON-lines flat file (no external DB required).       ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    from nova_knowledge_rag import NovaKnowledgeRAG, get_rag

    rag = get_rag()
    rag.learn_from_finding({"type": "SQLi", "endpoint": "/api/users"})
    results = rag.query("SQL injection authentication bypass")
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
RAG_DB    = WORKSPACE / "nova_rag_db.jsonl"


class NovaKnowledgeRAG:
    """
    Simple JSON-lines RAG store.
    Each document: {id, title, content, tags, source, timestamp}
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._path = Path(db_path) if db_path else RAG_DB
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._docs: List[Dict] = self._load()

    def _load(self) -> List[Dict]:
        if not self._path.exists():
            return []
        docs = []
        with self._path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        docs.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return docs

    def _save_doc(self, doc: Dict):
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, default=str) + "\n")

    def add(self, title: str, content: str,
            tags: Optional[List[str]] = None,
            source: str = "manual") -> str:
        doc_id = f"doc_{int(time.time() * 1000)}"
        doc = {
            "id":        doc_id,
            "title":     title,
            "content":   content,
            "tags":      tags or [],
            "source":    source,
            "timestamp": datetime.now().isoformat(),
        }
        self._docs.append(doc)
        self._save_doc(doc)
        return doc_id

    def learn_from_finding(self, finding: Dict, target_url: str = "") -> str:
        """Ingest a security finding into the knowledge base."""
        vuln_type = finding.get("type", "unknown")
        endpoint  = finding.get("endpoint", finding.get("file", ""))
        severity  = finding.get("severity", "UNKNOWN")
        title     = f"[{severity}] {vuln_type} @ {endpoint or target_url}"
        content   = json.dumps(finding, indent=2, default=str)
        tags      = [vuln_type.lower(), severity.lower(), "finding"]
        if target_url:
            tags.append(target_url)
        return self.add(title=title, content=content, tags=tags, source="nova_finding")

    def query(self, query: str, limit: int = 5,
              use_llm_expansion: bool = False) -> Dict:
        """Keyword-based retrieval (no vector DB required)."""
        q_tokens = set(query.lower().split())
        scored: List[tuple] = []
        for doc in self._docs:
            text   = (doc.get("title", "") + " " + doc.get("content", "") +
                      " " + " ".join(doc.get("tags", []))).lower()
            score  = sum(1 for t in q_tokens if t in text)
            if score > 0:
                scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        results = [d for _, d in scored[:limit]]
        return {"query": query, "results": results, "total_docs": len(self._docs)}

    def get_attack_briefing(self, context: Dict) -> Dict:
        """Return top attack techniques and CVEs for the given context."""
        tech_stack = context.get("tech_stack", [])
        query      = " ".join(tech_stack) + " vulnerability exploit"
        results    = self.query(query, limit=10)
        techniques = []
        cves       = []
        for doc in results["results"]:
            tags = doc.get("tags", [])
            if "cve" in " ".join(tags).lower() or "CVE-" in doc.get("title", ""):
                cves.append({"title": doc["title"], "severity": "HIGH"})
            else:
                techniques.append({"title": doc["title"]})
        return {"techniques": techniques[:5], "cves": cves[:5]}

    def stats(self) -> Dict:
        return {
            "total":    len(self._docs),
            "db_path":  str(self._path),
            "size_kb":  round(self._path.stat().st_size / 1024, 1)
            if self._path.exists() else 0,
        }


# ── Singleton ──────────────────────────────────────────────────────────────────
_rag: Optional[NovaKnowledgeRAG] = None

def get_rag() -> NovaKnowledgeRAG:
    global _rag
    if _rag is None:
        _rag = NovaKnowledgeRAG()
    return _rag


if __name__ == "__main__":
    rag = get_rag()
    rag.add("SQLi Auth Bypass", "' OR 1=1 -- bypasses login", tags=["sqli", "auth"])
    r = rag.query("SQL injection login bypass")
    print(f"Found {len(r['results'])} results for query.")
    print(f"RAG stats: {rag.stats()}")
