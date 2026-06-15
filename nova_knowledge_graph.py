#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║  🕸️  NOVA KNOWLEDGE GRAPH v1.0                                          ║
║                                                                          ║
║  PentAGI-style semantic relationship graph — no Neo4j required.         ║
║  Pure JSON, runs inside GitHub Actions, queryable in microseconds.      ║
║                                                                          ║
║  Graph structure:                                                        ║
║    Nodes: Target, Endpoint, Finding, Chain, CVE, Module, Technique      ║
║    Edges: has_endpoint, has_finding, chains_to, affects, exploited_by,  ║
║           depends_on, correlates_with, patched_by                       ║
║                                                                          ║
║  Inspired by Graphiti (PentAGI's Neo4j knowledge layer) but serverless. ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import json, hashlib, os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
GRAPH_PATH = WORKSPACE / "knowledge_graph.json"


# ── Node Types ────────────────────────────────────────────────────────────────

class NodeType:
    TARGET    = "target"
    ENDPOINT  = "endpoint"
    FINDING   = "finding"
    CHAIN     = "chain"
    CVE       = "cve"
    TECHNIQUE = "technique"
    MODULE    = "module"
    PATCH     = "patch"


# ── Edge Types ────────────────────────────────────────────────────────────────

class EdgeType:
    HAS_ENDPOINT    = "has_endpoint"
    HAS_FINDING     = "has_finding"
    CHAINS_TO       = "chains_to"
    AFFECTS         = "affects"
    EXPLOITED_BY    = "exploited_by"
    DEPENDS_ON      = "depends_on"
    CORRELATES_WITH = "correlates_with"
    PATCHED_BY      = "patched_by"
    DISCOVERED_BY   = "discovered_by"
    CONFIRMED_BY    = "confirmed_by"


def _node_id(node_type: str, key: str) -> str:
    return f"{node_type}:{hashlib.md5(key.encode()).hexdigest()[:8]}"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


class NovaKnowledgeGraph:
    """
    Serverless knowledge graph.
    Stores targets, findings, chains and relationships.
    Queryable for: attack paths, related findings, technique coverage.
    """

    def __init__(self, path: Optional[Path] = None):
        self.path = path or GRAPH_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._g: Dict = self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> Dict:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except Exception:
                pass
        return {"nodes": {}, "edges": [], "meta": {"version": "1.0", "created": _ts()}}

    def save(self):
        self._g["meta"]["updated"] = _ts()
        self._g["meta"]["node_count"] = len(self._g["nodes"])
        self._g["meta"]["edge_count"] = len(self._g["edges"])
        self.path.write_text(json.dumps(self._g, indent=2, default=str))

    # ── Core graph ops ────────────────────────────────────────────────────────

    def add_node(self, node_type: str, key: str, properties: Dict) -> str:
        nid = _node_id(node_type, key)
        if nid not in self._g["nodes"]:
            self._g["nodes"][nid] = {
                "id": nid, "type": node_type, "key": key,
                "created": _ts(), "updated": _ts(), **properties
            }
        else:
            self._g["nodes"][nid].update({"updated": _ts(), **properties})
        return nid

    def add_edge(self, from_id: str, edge_type: str, to_id: str,
                 properties: Dict = None) -> bool:
        for e in self._g["edges"]:
            if e["from"] == from_id and e["type"] == edge_type and e["to"] == to_id:
                return False  # already exists
        self._g["edges"].append({
            "from": from_id, "type": edge_type, "to": to_id,
            "created": _ts(), **(properties or {})
        })
        return True

    def get_node(self, nid: str) -> Optional[Dict]:
        return self._g["nodes"].get(nid)

    def neighbors(self, nid: str, edge_type: str = None,
                  direction: str = "both") -> List[Dict]:
        results = []
        for e in self._g["edges"]:
            if direction in ("out", "both") and e["from"] == nid:
                if edge_type is None or e["type"] == edge_type:
                    n = self._g["nodes"].get(e["to"])
                    if n:
                        results.append({**n, "_via": e["type"]})
            if direction in ("in", "both") and e["to"] == nid:
                if edge_type is None or e["type"] == edge_type:
                    n = self._g["nodes"].get(e["from"])
                    if n:
                        results.append({**n, "_via": e["type"]})
        return results

    # ── High-level builders ───────────────────────────────────────────────────

    def add_target(self, url: str, metadata: Dict = None) -> str:
        nid = self.add_node(NodeType.TARGET, url, {
            "url": url, **(metadata or {})
        })
        return nid

    def add_endpoint(self, target_id: str, path: str, method: str = "GET",
                     properties: Dict = None) -> str:
        key = f"{method}:{path}"
        nid = self.add_node(NodeType.ENDPOINT, key, {
            "path": path, "method": method, **(properties or {})
        })
        self.add_edge(target_id, EdgeType.HAS_ENDPOINT, nid)
        return nid

    def add_finding(self, target_id: str, finding: Dict) -> str:
        key = f"{finding.get('type','')}{finding.get('url','')}{finding.get('parameter','')}"
        nid = self.add_node(NodeType.FINDING, key, finding)
        self.add_edge(target_id, EdgeType.HAS_FINDING, nid)
        # Link to endpoint if known
        if finding.get("url"):
            ep_key = f"GET:{finding['url']}"
            ep_id = _node_id(NodeType.ENDPOINT, ep_key)
            if ep_id in self._g["nodes"]:
                self.add_edge(ep_id, EdgeType.HAS_FINDING, nid)
        return nid

    def add_chain(self, chain: Dict, finding_ids: List[str]) -> str:
        key = chain.get("chain_id", chain.get("name", "chain"))
        nid = self.add_node(NodeType.CHAIN, key, chain)
        for fid in finding_ids:
            self.add_edge(fid, EdgeType.CHAINS_TO, nid)
        return nid

    def add_cve(self, cve_id: str, properties: Dict = None) -> str:
        return self.add_node(NodeType.CVE, cve_id, {
            "cve_id": cve_id, **(properties or {})
        })

    def link_cve_to_finding(self, cve_id: str, finding_id: str):
        cve_nid = _node_id(NodeType.CVE, cve_id)
        self.add_edge(cve_nid, EdgeType.AFFECTS, finding_id)

    def add_technique(self, technique: str, module_name: str = "",
                      confidence: float = 0.5) -> str:
        nid = self.add_node(NodeType.TECHNIQUE, technique, {
            "technique": technique, "module": module_name, "confidence": confidence
        })
        return nid

    # ── Query layer ───────────────────────────────────────────────────────────

    def all_findings(self, min_severity: str = None) -> List[Dict]:
        sev_rank = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}
        min_rank = sev_rank.get((min_severity or "").upper(), 0)
        return [
            n for n in self._g["nodes"].values()
            if n["type"] == NodeType.FINDING
            and sev_rank.get(str(n.get("severity","")).upper(),0) >= min_rank
        ]

    def attack_paths(self, target_id: str) -> List[List[Dict]]:
        """Return all endpoint → finding → chain paths for a target."""
        paths = []
        endpoints = self.neighbors(target_id, EdgeType.HAS_ENDPOINT, "out")
        for ep in endpoints:
            findings = self.neighbors(ep["id"], EdgeType.HAS_FINDING, "out")
            for f in findings:
                chains = self.neighbors(f["id"], EdgeType.CHAINS_TO, "out")
                if chains:
                    for ch in chains:
                        paths.append([ep, f, ch])
                else:
                    paths.append([ep, f])
        return paths

    def critical_chains(self) -> List[Dict]:
        return [
            n for n in self._g["nodes"].values()
            if n["type"] == NodeType.CHAIN
            and str(n.get("severity","")).upper() == "CRITICAL"
        ]

    def technique_coverage(self) -> Dict[str, float]:
        return {
            n["technique"]: n.get("confidence", 0)
            for n in self._g["nodes"].values()
            if n["type"] == NodeType.TECHNIQUE
        }

    def summary(self) -> Dict:
        nodes = self._g["nodes"].values()
        return {
            "targets":    sum(1 for n in nodes if n["type"] == NodeType.TARGET),
            "endpoints":  sum(1 for n in nodes if n["type"] == NodeType.ENDPOINT),
            "findings":   sum(1 for n in nodes if n["type"] == NodeType.FINDING),
            "chains":     sum(1 for n in nodes if n["type"] == NodeType.CHAIN),
            "cves":       sum(1 for n in nodes if n["type"] == NodeType.CVE),
            "techniques": sum(1 for n in nodes if n["type"] == NodeType.TECHNIQUE),
            "edges":      len(self._g["edges"]),
        }

    def to_markdown(self) -> str:
        s = self.summary()
        lines = [
            "## 🕸️ Nova Knowledge Graph",
            f"| Targets | Endpoints | Findings | Chains | CVEs | Techniques | Edges |",
            f"|---------|-----------|----------|--------|------|------------|-------|",
            f"| {s['targets']} | {s['endpoints']} | {s['findings']} | {s['chains']} | {s['cves']} | {s['techniques']} | {s['edges']} |",
            "",
            "### Critical Chains",
        ]
        for ch in self.critical_chains():
            lines.append(f"- **{ch.get('chain_id',ch.get('key','?'))}** — {ch.get('narrative','')[:120]}")
        lines += ["", "### All Findings"]
        for f in sorted(self.all_findings(), key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x.get("severity","").upper(),4)):
            sev = f.get("severity","?")
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}.get(sev.upper(),"⚪")
            lines.append(f"- {icon} **[{sev}]** {f.get('name',f.get('type','?'))} → `{f.get('url',f.get('endpoint','?'))}`")
        return "\n".join(lines)


def get_graph(path: Optional[Path] = None) -> NovaKnowledgeGraph:
    return NovaKnowledgeGraph(path)
