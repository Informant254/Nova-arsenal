#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🎯 NOVA TRIAGE v1.0 — AI-Powered Findings Prioritizer                     ║
║                                                                              ║
║  Sits between raw scanner output and the HackerOne report pipeline.         ║
║  Uses Ollama to intelligently rank, deduplicate, and chain findings so      ║
║  you always work on the most impactful bugs first.                          ║
║                                                                              ║
║  What it does:                                                               ║
║  1. Ingests findings from ANY Nova module (common schema)                   ║
║  2. Deduplicates near-identical findings (same type + location)             ║
║  3. Uses LLM to score each finding: exploitability + impact + novelty      ║
║  4. Groups findings into attack chains (related vulnerabilities)            ║
║  5. Ranks the final list: highest combined score first                      ║
║  6. Generates a human-readable triage report for HackerOne submission       ║
║                                                                              ║
║  Think of it as the analyst between the scanner and the reporter.           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    # From command line — pass one or more finding JSON files
    python3 nova_triage.py nova_sast_20260530.json nova_idor_20260530.json

    # From Python
    from nova_triage import NovaTriage
    triage = NovaTriage()
    results = triage.run(findings_list)
    triage.save("nova_triage_report.json")
    triage.print_summary()
"""

import json
import os
import re
import sys
import time
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Config ─────────────────────────────────────────────────────────────────────
OLLAMA_URL   = os.getenv("NOVA_LLM_URL",   "http://localhost:11434")
OLLAMA_MODEL = os.getenv("NOVA_LLM_MODEL", "qwen3:8b")
WORKSPACE    = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)

# Severity weights for base score
SEVERITY_SCORE = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2, "INFO": 0}

# CVSS ranges → severity mapping
CVSS_TO_SEVERITY = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW")]


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class TriagedFinding:
    """A finding after triage — enriched with AI scoring and chain data."""
    # Original fields (preserved)
    type:         str
    severity:     str
    description:  str  = ""
    file:         str  = ""
    line:         int  = 0
    endpoint:     str  = ""
    snippet:      str  = ""
    cve:          str  = ""
    cvss:         float = 0.0
    evidence:     str  = ""

    # Triage-added fields
    triage_score:       float = 0.0   # 0-10 combined score
    exploitability:     int   = 0     # 0-10 LLM score
    impact:             int   = 0     # 0-10 LLM score
    novelty:            int   = 0     # 0-10 LLM score
    llm_reasoning:      str   = ""    # why this score
    chain_id:           str   = ""    # attack chain this belongs to
    chain_role:         str   = ""    # entry_point | amplifier | pivot | exfiltration
    h1_report_ready:    bool  = False
    deduplicated_count: int   = 1     # how many duplicates were merged
    source_module:      str   = ""

    @property
    def priority_label(self) -> str:
        if self.triage_score >= 8.5:  return "🔴 P1-Critical"
        if self.triage_score >= 7.0:  return "🟠 P2-High"
        if self.triage_score >= 5.0:  return "🟡 P3-Medium"
        if self.triage_score >= 2.0:  return "🟢 P4-Low"
        return                               "⚪ P5-Info"


@dataclass
class AttackChain:
    """A group of related findings that form a multi-step attack path."""
    chain_id:    str
    label:       str
    description: str
    findings:    List[str] = field(default_factory=list)   # finding type list
    severity:    str = "MEDIUM"
    chain_score: float = 0.0


# ── NovaTriage ─────────────────────────────────────────────────────────────────

class NovaTriage:
    """
    Main triage engine. Accepts raw findings, deduplicates, scores,
    chains, and outputs a prioritized list ready for reporting.
    """

    def __init__(self,
                 model:        str  = "",
                 skip_llm:     bool = False,
                 batch_size:   int  = 5):
        self.model       = model or OLLAMA_MODEL
        self.skip_llm    = skip_llm
        self.batch_size  = batch_size
        self._raw:        List[Dict] = []
        self._triaged:    List[TriagedFinding] = []
        self._chains:     List[AttackChain] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def ingest(self, findings: List[Dict], source: str = "unknown") -> "NovaTriage":
        """Add raw findings from any Nova module."""
        for f in findings:
            f.setdefault("source_module", source)
        self._raw.extend(findings)
        return self

    def ingest_file(self, path: str) -> "NovaTriage":
        """Load findings from a Nova JSON report file."""
        try:
            data = json.loads(Path(path).read_text())
            if isinstance(data, list):
                findings = data
            elif "findings" in data:
                findings = data["findings"]
            else:
                findings = []
            source = Path(path).stem
            self.ingest(findings, source)
            print(f"  📁 Loaded {len(findings)} findings from {Path(path).name}")
        except Exception as e:
            print(f"  ⚠️  Could not load {path}: {e}")
        return self

    def run(self, findings: List[Dict] = None) -> List[TriagedFinding]:
        """Full triage pipeline: ingest → dedupe → score → chain → rank."""
        if findings:
            self.ingest(findings)

        print(f"\n{'='*60}")
        print(f"🎯 NOVA TRIAGE — {len(self._raw)} raw findings")
        print(f"{'='*60}")

        if not self._raw:
            print("  ℹ️  No findings to triage.")
            return []

        # 1. Normalise
        normalised = [self._normalise(f) for f in self._raw]
        print(f"\n  [1/4] Normalised {len(normalised)} findings")

        # 2. Deduplicate
        deduped = self._deduplicate(normalised)
        print(f"  [2/4] After dedup: {len(deduped)} unique findings "
              f"({len(normalised)-len(deduped)} merged)")

        # 3. Score with LLM (or fallback to heuristic)
        scored = self._score_all(deduped)
        print(f"  [3/4] Scored {len(scored)} findings")

        # 4. Build attack chains
        self._chains = self._build_chains(scored)
        print(f"  [4/4] Identified {len(self._chains)} attack chains")

        # 5. Rank
        self._triaged = sorted(scored, key=lambda f: f.triage_score, reverse=True)
        return self._triaged

    def print_summary(self):
        """Print a prioritised findings table."""
        if not self._triaged:
            print("  No triaged findings. Run .run() first.")
            return
        print(f"\n{'='*75}")
        print(f"{'Priority':<14} {'Type':<28} {'Location':<25} {'Score'}")
        print(f"{'='*75}")
        for f in self._triaged:
            loc = (f.endpoint or f.file or "?")[:24]
            print(f"  {f.priority_label:<13} {f.type:<28} {loc:<25} {f.triage_score:.1f}/10")
        print(f"{'='*75}")
        print(f"  P1-Critical: {sum(1 for f in self._triaged if f.triage_score>=8.5)}")
        print(f"  P2-High:     {sum(1 for f in self._triaged if 7<=f.triage_score<8.5)}")
        print(f"  P3-Medium:   {sum(1 for f in self._triaged if 5<=f.triage_score<7)}")
        print(f"  P4-Low/Info: {sum(1 for f in self._triaged if f.triage_score<5)}")
        if self._chains:
            print(f"\n  Attack Chains ({len(self._chains)}):")
            for c in sorted(self._chains, key=lambda x: x.chain_score, reverse=True):
                print(f"    [{c.chain_score:.1f}] {c.label}: {c.description[:60]}")

    def save(self, path: str = None) -> str:
        """Save triage results to JSON."""
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = path or str(WORKSPACE / f"nova_triage_{ts}.json")
        report = {
            "generated":        datetime.now(timezone.utc).isoformat(),
            "raw_count":        len(self._raw),
            "triaged_count":    len(self._triaged),
            "attack_chains":    len(self._chains),
            "p1_critical":      sum(1 for f in self._triaged if f.triage_score >= 8.5),
            "p2_high":          sum(1 for f in self._triaged if 7 <= f.triage_score < 8.5),
            "findings":         [asdict(f) for f in self._triaged],
            "chains":           [asdict(c) for c in self._chains],
        }
        Path(path).write_text(json.dumps(report, indent=2))
        print(f"  💾 Triage report → {path}")
        return path

    def h1_ready_findings(self) -> List[TriagedFinding]:
        """Return only findings ready for HackerOne submission (P1 + P2)."""
        return [f for f in self._triaged if f.triage_score >= 7.0 and f.h1_report_ready]

    # ── Pipeline Steps ─────────────────────────────────────────────────────────

    @staticmethod
    def _normalise(raw: Dict) -> Dict:
        """Ensure all required fields exist with sensible defaults."""
        sev = str(raw.get("severity", "")).upper()
        if sev not in SEVERITY_SCORE:
            # Try to infer from CVSS
            cvss = float(raw.get("cvss", 0) or 0)
            for threshold, label in CVSS_TO_SEVERITY:
                if cvss >= threshold:
                    sev = label
                    break
            else:
                sev = "INFO"
        return {
            "type":         str(raw.get("type") or raw.get("vuln_type") or "Unknown"),
            "severity":     sev,
            "description":  str(raw.get("description") or raw.get("detail") or ""),
            "file":         str(raw.get("file") or ""),
            "line":         int(raw.get("line") or 0),
            "endpoint":     str(raw.get("endpoint") or raw.get("url") or ""),
            "snippet":      str(raw.get("snippet") or raw.get("code") or "")[:300],
            "cve":          str(raw.get("cve") or ""),
            "cvss":         float(raw.get("cvss") or 0),
            "evidence":     str(raw.get("evidence") or raw.get("proof") or ""),
            "source_module":str(raw.get("source_module") or "unknown"),
        }

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Merge findings that share the same type and location."""
        seen: Dict[str, Dict] = {}
        for f in findings:
            key = f"{f['type'].lower()}::{f.get('file','')}::{f.get('endpoint','')}::{f.get('line',0)}"
            # Fuzzy key: strip line numbers and normalise
            fkey = re.sub(r'\d+', 'N', key)
            if fkey in seen:
                seen[fkey]["_dup_count"] = seen[fkey].get("_dup_count", 1) + 1
                # Keep the higher severity
                if SEVERITY_SCORE.get(f["severity"], 0) > SEVERITY_SCORE.get(seen[fkey]["severity"], 0):
                    seen[fkey]["severity"] = f["severity"]
            else:
                f["_dup_count"] = 1
                seen[fkey] = f
        return list(seen.values())

    def _score_all(self, findings: List[Dict]) -> List[TriagedFinding]:
        """Score all findings, using LLM in batches."""
        triaged = []
        total   = len(findings)
        for i in range(0, total, self.batch_size):
            batch  = findings[i:i+self.batch_size]
            scores = self._score_batch(batch)
            triaged.extend(scores)
            print(f"  Scored {min(i+self.batch_size, total)}/{total}...", end="\r")
        print()
        return triaged

    def _score_batch(self, batch: List[Dict]) -> List[TriagedFinding]:
        """Score a batch of findings with one LLM call."""
        if self.skip_llm:
            return [self._heuristic_score(f) for f in batch]

        prompt = self._build_scoring_prompt(batch)
        raw    = self._ask_llm(prompt)
        parsed = self._parse_scores(raw, len(batch))

        results = []
        for i, f in enumerate(batch):
            if i < len(parsed):
                e, imp, nov, reason = parsed[i]
            else:
                e, imp, nov, reason = self._heuristic_values(f)

            base   = SEVERITY_SCORE.get(f["severity"], 0)
            cvss_b = min(f.get("cvss", 0) / 10 * 3, 3)
            score  = round(min(10, (e * 0.4 + imp * 0.35 + nov * 0.1 + base * 0.1 + cvss_b * 0.05)), 2)

            tf = TriagedFinding(
                type=f["type"], severity=f["severity"], description=f["description"],
                file=f["file"], line=f["line"], endpoint=f["endpoint"],
                snippet=f["snippet"], cve=f["cve"], cvss=f["cvss"],
                evidence=f["evidence"], source_module=f["source_module"],
                triage_score=score, exploitability=e, impact=imp, novelty=nov,
                llm_reasoning=reason, deduplicated_count=f.get("_dup_count", 1),
                h1_report_ready=(score >= 5.0 and f["severity"] not in ("INFO",)),
            )
            results.append(tf)
        return results

    def _heuristic_score(self, f: Dict) -> TriagedFinding:
        e, imp, nov, reason = self._heuristic_values(f)
        base  = SEVERITY_SCORE.get(f["severity"], 0)
        score = round(min(10, (e * 0.4 + imp * 0.35 + nov * 0.1 + base * 0.15)), 2)
        return TriagedFinding(
            type=f["type"], severity=f["severity"], description=f["description"],
            file=f["file"], line=f["line"], endpoint=f["endpoint"],
            snippet=f["snippet"], cve=f["cve"], cvss=f["cvss"], evidence=f["evidence"],
            source_module=f["source_module"], triage_score=score,
            exploitability=e, impact=imp, novelty=nov,
            llm_reasoning=reason, deduplicated_count=f.get("_dup_count", 1),
            h1_report_ready=(score >= 5.0),
        )

    @staticmethod
    def _heuristic_values(f: Dict) -> Tuple[int, int, int, str]:
        """Rule-based fallback scoring when LLM is unavailable."""
        sev_map = {"CRITICAL": (9,9), "HIGH": (7,7), "MEDIUM": (5,5), "LOW": (3,3), "INFO": (1,1)}
        e, imp  = sev_map.get(f["severity"], (3, 3))
        nov     = 6 if f.get("cve") else 5
        # Adjust exploitability by vuln type
        high_e  = ["sql injection","rce","xxe","ssrf","deserialization","path traversal","command injection"]
        low_e   = ["info disclosure","version disclosure","missing header"]
        vtype   = f["type"].lower()
        if any(h in vtype for h in high_e): e = min(10, e + 2)
        if any(l in vtype for l in low_e):  e = max(1, e - 2)
        return e, imp, nov, "Heuristic scoring (LLM unavailable)"

    def _build_scoring_prompt(self, batch: List[Dict]) -> str:
        items = []
        for i, f in enumerate(batch):
            items.append(
                f"Finding {i+1}:\n"
                f"  Type: {f['type']}\n"
                f"  Severity: {f['severity']}\n"
                f"  Location: {f.get('endpoint') or f.get('file','?')}\n"
                f"  Description: {f['description'][:200]}\n"
                f"  Snippet: {f['snippet'][:150]}\n"
                f"  CVE: {f['cve'] or 'none'}\n"
            )
        return (
            "You are a senior bug bounty analyst. Score each finding on three dimensions (0-10 integers):\n"
            "- exploitability: how easy is this to actually exploit in the real world?\n"
            "- impact: how severe is the worst-case business impact?\n"
            "- novelty: how unique/interesting is this vs common findings?\n\n"
            "Respond ONLY with a JSON array, one object per finding, in order:\n"
            '[{"e":N,"i":N,"n":N,"reason":"one sentence"},…]\n\n'
            + "\n\n".join(items)
        )

    @staticmethod
    def _parse_scores(raw: str, count: int) -> List[Tuple[int, int, int, str]]:
        try:
            arr = json.loads(re.search(r'\[[\s\S]*?\]', raw).group(0))
            return [(int(o.get("e",5)), int(o.get("i",5)), int(o.get("n",5)),
                     str(o.get("reason",""))) for o in arr[:count]]
        except Exception:
            return []

    def _build_chains(self, findings: List[TriagedFinding]) -> List[AttackChain]:
        """Group findings into attack chains using LLM reasoning."""
        if len(findings) < 2 or self.skip_llm:
            return []

        types    = [f.type for f in findings]
        prompt   = (
            "You are an attack chain analyst. Group these vulnerability types into logical multi-step "
            "attack chains (e.g. SSRF→metadata→credentials→RCE). Assign each finding to a chain.\n\n"
            f"Findings: {json.dumps(types)}\n\n"
            "Respond ONLY with JSON:\n"
            '{"chains":[{"id":"C1","label":"Short name","description":"Attack flow description",'
            '"finding_types":["Type A","Type B"],"severity":"HIGH"}]}\n'
        )
        raw = self._ask_llm(prompt)
        try:
            data   = json.loads(re.search(r'\{[\s\S]*\}', raw).group(0))
            chains = []
            for c in data.get("chains", []):
                chain = AttackChain(
                    chain_id=c.get("id","C?"),
                    label=c.get("label","Unknown Chain"),
                    description=c.get("description",""),
                    findings=c.get("finding_types",[]),
                    severity=c.get("severity","MEDIUM"),
                )
                # Score chain by max member score
                member_scores = [f.triage_score for f in findings
                                 if any(t.lower() in f.type.lower() for t in chain.findings)]
                chain.chain_score = round(max(member_scores) if member_scores else 0, 1)
                # Tag findings with chain membership
                for f in findings:
                    if any(t.lower() in f.type.lower() for t in chain.findings):
                        f.chain_id = chain.chain_id
                        f.chain_role = "entry_point" if not f.chain_id else "amplifier"
                chains.append(chain)
            return chains
        except Exception:
            return []

    def _ask_llm(self, prompt: str, system: str = "") -> str:
        try:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            payload = json.dumps({
                "model":   self.model,
                "messages": messages,
                "stream":  False,
                "options": {"temperature": 0.1, "num_predict": 2000},
            }).encode()
            req = urllib.request.Request(
                f"{OLLAMA_URL}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=90) as r:
                return json.loads(r.read()).get("message", {}).get("content", "").strip()
        except Exception as e:
            print(f"  ⚠️  LLM unavailable: {e}. Using heuristic scoring.")
            return ""


# ── Integration helper ─────────────────────────────────────────────────────────

def triage_findings(findings: List[Dict],
                    source: str = "nova",
                    save: bool  = True,
                    skip_llm: bool = False) -> List[TriagedFinding]:
    """
    One-liner for use from other Nova modules:

        from nova_triage import triage_findings
        prioritised = triage_findings(raw_findings)
    """
    t = NovaTriage(skip_llm=skip_llm)
    t.ingest(findings, source)
    results = t.run()
    if save and results:
        t.save()
    return results


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="🎯 Nova Triage — AI-powered findings prioritiser"
    )
    parser.add_argument("files",  nargs="*", help="Nova JSON report files to triage")
    parser.add_argument("--no-llm",   action="store_true", help="Use heuristic scoring (no Ollama)")
    parser.add_argument("--h1-only",  action="store_true", help="Show only H1-ready findings")
    parser.add_argument("--save",     default="", help="Output path (default: auto-timestamped)")
    parser.add_argument("--chains",   action="store_true", help="Show attack chains only")
    args = parser.parse_args()

    if not args.files:
        parser.print_help()
        print("\nExample:")
        print("  python3 nova_triage.py nova_sast_*.json nova_idor_*.json")
        sys.exit(0)

    t = NovaTriage(skip_llm=args.no_llm)
    for f in args.files:
        t.ingest_file(f)
    results = t.run()

    if args.chains:
        print(f"\n  Attack Chains ({len(t._chains)}):")
        for c in sorted(t._chains, key=lambda x: x.chain_score, reverse=True):
            print(f"    [{c.chain_score:.1f}] {c.label}: {c.description}")
            for ft in c.findings:
                print(f"       • {ft}")
    elif args.h1_only:
        h1 = t.h1_ready_findings()
        print(f"\n  {len(h1)} H1-ready findings:")
        for f in h1:
            print(f"    {f.priority_label} | {f.type} | {f.endpoint or f.file}")
    else:
        t.print_summary()

    out = t.save(args.save if args.save else None)
    print(f"\n  Done. {len(results)} triaged findings → {out}")
