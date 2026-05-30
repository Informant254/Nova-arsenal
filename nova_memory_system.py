#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   🧠 NOVA MEMORY SYSTEM v1.0 — PERSISTENT INTELLIGENCE          ║
║                                                                  ║
║   Nova remembers everything across every hunt:                  ║
║   • What techniques worked on what target types                 ║
║   • Which payloads bypassed which WAFs                          ║
║   • Vulnerability patterns she's seen before                   ║
║   • Technology fingerprints and their weaknesses               ║
║   • Her own evolution history                                   ║
║   • Hunter intuition built from thousands of hunts             ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import os
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

WORKSPACE  = os.path.expanduser("~/nova_workspace")
BRAIN_FILE = os.path.join(WORKSPACE, "nova_brain.json")
MEMORY_DIR = os.path.join(WORKSPACE, "memory")


def _now() -> str:
    return datetime.utcnow().isoformat()

def _ts() -> float:
    return time.time()


class NovaBrain:
    """
    Nova's persistent intelligence — survives across hunts, restarts,
    cloud runs, and self-evolutions.
    """

    SCHEMA_VERSION = "2.0"

    def __init__(self, path: str = BRAIN_FILE):
        self.path = path
        os.makedirs(MEMORY_DIR, exist_ok=True)
        os.makedirs(WORKSPACE, exist_ok=True)
        self._data = self._load()

    # ── LOAD / SAVE ───────────────────────────────────────────────

    def _default(self) -> Dict:
        return {
            "schema_version":   self.SCHEMA_VERSION,
            "created":          _now(),
            "last_updated":     _now(),

            # Hunt statistics
            "hunts_total":      0,
            "hunts_successful": 0,
            "findings_total":   0,
            "critical_total":   0,
            "high_total":       0,

            # Evolution tracking
            "evolution_count":  0,
            "evolution_history": [],

            # What works — scored by success rate
            "technique_scores": {},   # technique → score
            "payload_scores":   {},   # payload → hit_count
            "tool_scores":      {},   # tool → {used, found, time}
            "waf_bypasses":     {},   # waf_name → [payloads_that_worked]

            # Technology intelligence
            "tech_vulns":       {},   # tech_name → [common_vulns]
            "tech_fingerprints": {},  # response_header → tech_name

            # Target profiles
            "target_profiles":  {},   # url → {hunts, findings, techs, notes}

            # Vulnerability patterns Nova has learned
            "vuln_patterns":    [],   # [{pattern, type, confidence, seen_count}]

            # Parameter intelligence
            "interesting_params": {},  # param_name → {vuln_types, hit_count}

            # Endpoint intelligence
            "interesting_paths": {},   # path → {vuln_types, hit_count}

            # Hunter notes (free-form lessons)
            "hunter_notes":    [],

            # Session history
            "session_history": [],
        }

    def _load(self) -> Dict:
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    data = json.load(f)
                # Migrate if needed
                for key, val in self._default().items():
                    if key not in data:
                        data[key] = val
                return data
            except Exception as e:
                print(f"  ⚠️  Brain load failed ({e}), starting fresh")
        return self._default()

    def save(self):
        self._data["last_updated"] = _now()
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._data, f, indent=2)
        os.replace(tmp, self.path)

    # ── HUNT TRACKING ─────────────────────────────────────────────

    def start_hunt(self, target: str, mission: str) -> str:
        """Register a new hunt. Returns session_id."""
        session_id = hashlib.md5(f"{target}{_ts()}".encode()).hexdigest()[:8]
        self._data["hunts_total"] += 1
        session = {
            "id":       session_id,
            "target":   target,
            "mission":  mission,
            "started":  _now(),
            "ended":    None,
            "findings": 0,
            "status":   "running",
        }
        self._data["session_history"].append(session)
        self._data["session_history"] = self._data["session_history"][-200:]

        # Init target profile
        if target not in self._data["target_profiles"]:
            self._data["target_profiles"][target] = {
                "first_seen":   _now(),
                "hunts":        0,
                "total_findings": 0,
                "techs":        [],
                "notes":        [],
            }
        self._data["target_profiles"][target]["hunts"] += 1
        self.save()
        return session_id

    def end_hunt(self, session_id: str, findings: List[Dict], duration_sec: float = 0):
        """Record hunt completion and learn from findings."""
        count = len(findings)
        self._data["findings_total"] += count

        sev_counts = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        self._data["critical_total"] += sev_counts.get("critical", 0)
        self._data["high_total"]     += sev_counts.get("high", 0)

        if count > 0:
            self._data["hunts_successful"] += 1

        # Update session record
        for s in reversed(self._data["session_history"]):
            if s["id"] == session_id:
                s["ended"]    = _now()
                s["findings"] = count
                s["status"]   = "completed"
                s["duration"] = duration_sec
                break

        # Learn from each finding
        for finding in findings:
            self._learn_from_finding(finding)

        self.save()

    def _learn_from_finding(self, finding: Dict):
        """Extract intelligence from a finding."""
        vuln_type = finding.get("type") or finding.get("name") or ""
        technique = finding.get("technique") or finding.get("tool") or ""
        payload   = finding.get("payload") or ""
        param     = finding.get("parameter") or ""
        path      = finding.get("path") or ""
        sev       = finding.get("severity", "info").lower()
        target    = finding.get("url", "")

        weight = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}.get(sev, 1)

        # Score techniques
        if technique:
            t = self._data["technique_scores"]
            t[technique] = t.get(technique, 0) + weight

        # Score payloads
        if payload:
            p = self._data["payload_scores"]
            p[payload] = p.get(payload, 0) + weight
            # Trim to top 500
            if len(p) > 500:
                top = sorted(p.items(), key=lambda x: -x[1])[:500]
                self._data["payload_scores"] = dict(top)

        # Score parameters
        if param:
            pi = self._data["interesting_params"]
            if param not in pi:
                pi[param] = {"vuln_types": [], "hit_count": 0}
            pi[param]["hit_count"] += 1
            if vuln_type and vuln_type not in pi[param]["vuln_types"]:
                pi[param]["vuln_types"].append(vuln_type)

        # Score paths
        if path:
            pp = self._data["interesting_paths"]
            if path not in pp:
                pp[path] = {"vuln_types": [], "hit_count": 0}
            pp[path]["hit_count"] += 1
            if vuln_type and vuln_type not in pp[path]["vuln_types"]:
                pp[path]["vuln_types"].append(vuln_type)

        # Update target profile
        domain = self._extract_domain(target)
        if domain and domain in self._data["target_profiles"]:
            p = self._data["target_profiles"][domain]
            p["total_findings"] = p.get("total_findings", 0) + 1

        # Add vuln pattern
        if vuln_type and payload:
            existing = next((v for v in self._data["vuln_patterns"]
                             if v["type"] == vuln_type and v["payload"] == payload), None)
            if existing:
                existing["seen_count"] += 1
                existing["confidence"] = min(1.0, existing["confidence"] + 0.05)
            else:
                self._data["vuln_patterns"].append({
                    "type":       vuln_type,
                    "payload":    payload,
                    "technique":  technique,
                    "seen_count": 1,
                    "confidence": 0.5,
                    "first_seen": _now(),
                })
            # Keep top 1000 patterns
            self._data["vuln_patterns"].sort(key=lambda x: -x["seen_count"])
            self._data["vuln_patterns"] = self._data["vuln_patterns"][:1000]

    def _extract_domain(self, url: str) -> str:
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc or url
        except Exception:
            return url

    # ── TOOL LEARNING ─────────────────────────────────────────────

    def record_tool_run(self, tool: str, found_count: int, duration_sec: float):
        t = self._data["tool_scores"]
        if tool not in t:
            t[tool] = {"used": 0, "found": 0, "total_time": 0}
        t[tool]["used"]       += 1
        t[tool]["found"]      += found_count
        t[tool]["total_time"] += duration_sec

    def best_tools_for(self, vuln_type: str = None, top_n: int = 10) -> List[str]:
        scores = self._data["tool_scores"]
        ranked = sorted(
            scores.items(),
            key=lambda x: x[1].get("found", 0) / max(x[1].get("used", 1), 1),
            reverse=True,
        )
        return [name for name, _ in ranked[:top_n]]

    # ── WAF INTELLIGENCE ──────────────────────────────────────────

    def record_waf_bypass(self, waf_name: str, payload: str):
        w = self._data["waf_bypasses"]
        if waf_name not in w:
            w[waf_name] = []
        if payload not in w[waf_name]:
            w[waf_name].append(payload)
            w[waf_name] = w[waf_name][-50:]  # keep last 50

    def get_waf_bypasses(self, waf_name: str) -> List[str]:
        return self._data["waf_bypasses"].get(waf_name, [])

    # ── TECHNOLOGY INTELLIGENCE ───────────────────────────────────

    def record_tech(self, target: str, tech: str, version: str = ""):
        domain = self._extract_domain(target)
        if domain not in self._data["target_profiles"]:
            self._data["target_profiles"][domain] = {"techs": [], "notes": [], "hunts": 0, "total_findings": 0}
        techs = self._data["target_profiles"][domain].get("techs", [])
        entry = f"{tech}/{version}" if version else tech
        if entry not in techs:
            techs.append(entry)
            self._data["target_profiles"][domain]["techs"] = techs

    def get_known_vulns_for_tech(self, tech: str) -> List[str]:
        return self._data["tech_vulns"].get(tech.lower(), [])

    def record_tech_vuln(self, tech: str, vuln: str):
        t = self._data["tech_vulns"]
        if tech.lower() not in t:
            t[tech.lower()] = []
        if vuln not in t[tech.lower()]:
            t[tech.lower()].append(vuln)

    # ── EVOLUTION TRACKING ────────────────────────────────────────

    def record_evolution(self, file: str, change_summary: str, success: bool):
        self._data["evolution_count"] += 1
        entry = {
            "file":    file,
            "summary": change_summary,
            "success": success,
            "when":    _now(),
            "n":       self._data["evolution_count"],
        }
        self._data["evolution_history"].append(entry)
        self._data["evolution_history"] = self._data["evolution_history"][-100:]
        self.save()

    # ── HUNTER NOTES ──────────────────────────────────────────────

    def note(self, text: str, category: str = "general"):
        self._data["hunter_notes"].append({
            "text":     text,
            "category": category,
            "when":     _now(),
        })
        self._data["hunter_notes"] = self._data["hunter_notes"][-500:]
        self.save()

    # ── RETRIEVAL / RECOMMENDATIONS ───────────────────────────────

    def recommend_techniques(self, target: str = None, top_n: int = 5) -> List[str]:
        scores = self._data["technique_scores"]
        ranked = sorted(scores.items(), key=lambda x: -x[1])
        return [name for name, _ in ranked[:top_n]]

    def recommend_payloads(self, vuln_type: str = None, top_n: int = 20) -> List[str]:
        if vuln_type:
            patterns = [p for p in self._data["vuln_patterns"]
                        if vuln_type.lower() in p.get("type", "").lower()]
            patterns.sort(key=lambda x: -x["seen_count"])
            return [p["payload"] for p in patterns[:top_n]]
        scores = self._data["payload_scores"]
        ranked = sorted(scores.items(), key=lambda x: -x[1])
        return [p for p, _ in ranked[:top_n]]

    def interesting_params(self, top_n: int = 20) -> List[str]:
        params = self._data["interesting_params"]
        ranked = sorted(params.items(), key=lambda x: -x[1].get("hit_count", 0))
        return [p for p, _ in ranked[:top_n]]

    def target_summary(self, target: str) -> Dict:
        domain = self._extract_domain(target)
        return self._data["target_profiles"].get(domain, {})

    # ── STATS ─────────────────────────────────────────────────────

    def stats(self) -> Dict:
        d = self._data
        top_techniques = sorted(d["technique_scores"].items(), key=lambda x: -x[1])[:5]
        top_payloads   = sorted(d["payload_scores"].items(),   key=lambda x: -x[1])[:5]
        top_tools      = self.best_tools_for(top_n=5)
        return {
            "hunts_total":      d["hunts_total"],
            "hunts_successful": d["hunts_successful"],
            "findings_total":   d["findings_total"],
            "critical_total":   d["critical_total"],
            "high_total":       d["high_total"],
            "evolution_count":  d["evolution_count"],
            "targets_known":    len(d["target_profiles"]),
            "patterns_learned": len(d["vuln_patterns"]),
            "top_techniques":   top_techniques,
            "top_payloads":     [(p[:40], s) for p, s in top_payloads],
            "top_tools":        top_tools,
            "last_updated":     d["last_updated"],
        }

    def __repr__(self) -> str:
        s = self.stats()
        return (f"NovaBrain(hunts={s['hunts_total']}, findings={s['findings_total']}, "
                f"patterns={s['patterns_learned']}, evolutions={s['evolution_count']})")


# ── SINGLETON ─────────────────────────────────────────────────────

_brain: Optional[NovaBrain] = None

def get_brain() -> NovaBrain:
    global _brain
    if _brain is None:
        _brain = NovaBrain()
    return _brain


# ── ENTRY POINT ───────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="🧠 Nova Memory System")
    parser.add_argument("--stats",          action="store_true", help="Show brain statistics")
    parser.add_argument("--techniques",     action="store_true", help="Show top techniques")
    parser.add_argument("--payloads",       help="Show top payloads for a vuln type (or 'all')")
    parser.add_argument("--params",         action="store_true", help="Show interesting parameters")
    parser.add_argument("--target",         help="Show profile for a specific target")
    parser.add_argument("--note",           help="Add a hunter note")
    parser.add_argument("--evolutions",     action="store_true", help="Show evolution history")
    args = parser.parse_args()

    brain = NovaBrain()

    if args.stats:
        s = brain.stats()
        print(f"\n  🧠 Nova Brain Stats\n")
        print(f"  Total hunts:       {s['hunts_total']}")
        print(f"  Successful hunts:  {s['hunts_successful']}")
        print(f"  Total findings:    {s['findings_total']}")
        print(f"  Critical:          {s['critical_total']}")
        print(f"  High:              {s['high_total']}")
        print(f"  Targets known:     {s['targets_known']}")
        print(f"  Patterns learned:  {s['patterns_learned']}")
        print(f"  Self-evolutions:   {s['evolution_count']}")
        print(f"  Last updated:      {s['last_updated'][:19]}")

        if s["top_techniques"]:
            print(f"\n  Top techniques:")
            for t, sc in s["top_techniques"]:
                print(f"    {t:35s} {sc}")

    elif args.techniques:
        recs = brain.recommend_techniques(top_n=20)
        print(f"\n  Top techniques ({len(recs)}):")
        for t in recs:
            sc = brain._data["technique_scores"].get(t, 0)
            print(f"    [{sc:4d}] {t}")

    elif args.payloads:
        vtype = None if args.payloads == "all" else args.payloads
        payloads = brain.recommend_payloads(vuln_type=vtype, top_n=30)
        print(f"\n  Top payloads{' for ' + args.payloads if vtype else ''} ({len(payloads)}):")
        for p in payloads:
            print(f"    {p[:80]}")

    elif args.params:
        params = brain.interesting_params(top_n=30)
        print(f"\n  Interesting parameters ({len(params)}):")
        for p in params:
            info = brain._data["interesting_params"][p]
            print(f"    {p:30s}  hits:{info['hit_count']}  types:{','.join(info['vuln_types'][:3])}")

    elif args.target:
        profile = brain.target_summary(args.target)
        print(f"\n  Target profile: {args.target}")
        print(json.dumps(profile, indent=2))

    elif args.note:
        brain.note(args.note)
        print(f"  ✅ Note saved")
        brain.save()

    elif args.evolutions:
        hist = brain._data.get("evolution_history", [])
        print(f"\n  Evolution history ({len(hist)} events):\n")
        for e in hist[-20:]:
            icon = "✅" if e.get("success") else "❌"
            print(f"  {icon}  #{e['n']}  {e['when'][:16]}  {e['file']}")
            print(f"       {e['summary'][:80]}")

    else:
        print(repr(brain))
        print(f"\n  Usage: python nova_memory_system.py --stats")
