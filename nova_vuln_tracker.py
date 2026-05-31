#!/usr/bin/env python3
"""
NOVA VULN TRACKER v1.0
Persistent SQLite vulnerability database.
Tracks findings across all runs — detects regressions, fixed issues,
new introductions, and provides trend analysis over time.
"""

import sqlite3
import json
import os
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

DB_PATH = os.path.expanduser(os.getenv("NOVA_DB", "~/nova_workspace/nova_vulns.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id           TEXT PRIMARY KEY,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    run_count    INTEGER DEFAULT 1,
    status       TEXT DEFAULT 'OPEN',
    vuln_type    TEXT,
    severity     TEXT,
    file         TEXT,
    line         INTEGER,
    endpoint     TEXT,
    snippet      TEXT,
    cve          TEXT,
    cvss         REAL,
    description  TEXT,
    patch        TEXT,
    source_module TEXT,
    target       TEXT,
    meta         TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    target      TEXT,
    mode        TEXT,
    total_found INTEGER DEFAULT 0,
    new_count   INTEGER DEFAULT 0,
    fixed_count INTEGER DEFAULT 0,
    regressed   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS timeline (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    event       TEXT NOT NULL,
    ts          TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_type     ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_file     ON findings(file);
CREATE INDEX IF NOT EXISTS idx_timeline_finding  ON timeline(finding_id);
"""


def _make_id(finding: Dict) -> str:
    key = "|".join([
        str(finding.get("type") or finding.get("vuln_type") or ""),
        str(finding.get("file") or ""),
        str(finding.get("line") or ""),
        str(finding.get("endpoint") or ""),
    ])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class NovaVulnTracker:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self.current_run_id: Optional[str] = None

    def start_run(self, target: str = "", mode: str = "scan") -> str:
        run_id = f"run_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self.conn.execute(
            "INSERT INTO runs (run_id, started_at, target, mode) VALUES (?,?,?,?)",
            (run_id, datetime.utcnow().isoformat(), target, mode)
        )
        self.conn.commit()
        self.current_run_id = run_id
        return run_id

    def finish_run(self, stats: Dict = None):
        if not self.current_run_id:
            return
        stats = stats or {}
        self.conn.execute("""
            UPDATE runs SET finished_at=?, total_found=?, new_count=?, fixed_count=?, regressed=?
            WHERE run_id=?
        """, (
            datetime.utcnow().isoformat(),
            stats.get("total", 0),
            stats.get("new", 0),
            stats.get("fixed", 0),
            stats.get("regressed", 0),
            self.current_run_id,
        ))
        self.conn.commit()

    def ingest_findings(self, findings: List[Dict], target: str = "", source_module: str = "") -> Dict:
        if not self.current_run_id:
            self.start_run(target)

        now = datetime.utcnow().isoformat()
        stats = {"total": len(findings), "new": 0, "seen_again": 0, "fixed": 0, "regressed": 0}
        current_ids = set()

        for finding in findings:
            fid = _make_id(finding)
            current_ids.add(fid)
            existing = self.conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
            vuln_type = finding.get("type") or finding.get("vuln_type") or finding.get("vulnerability_type") or "unknown"
            severity   = finding.get("severity", "MEDIUM")
            file_      = finding.get("file") or finding.get("filepath") or ""
            line       = finding.get("line") or finding.get("line_num") or 0
            endpoint   = finding.get("endpoint") or finding.get("url") or ""
            snippet    = (finding.get("snippet") or finding.get("sink_code") or "")[:300]
            cve        = finding.get("cve") or finding.get("cve_id") or ""
            cvss       = float(finding.get("cvss") or finding.get("cvss_score") or 0)
            description= finding.get("description") or finding.get("issue") or ""
            meta       = json.dumps({k: v for k, v in finding.items() if k not in (
                "type","vuln_type","severity","file","line","endpoint","snippet","cve","cvss","description")})

            if existing:
                prev_status = existing["status"]
                self.conn.execute("""
                    UPDATE findings SET last_seen=?, run_count=run_count+1, status='OPEN'
                    WHERE id=?
                """, (now, fid))
                if prev_status == "FIXED":
                    stats["regressed"] += 1
                    self._timeline(fid, "REGRESSED")
                else:
                    stats["seen_again"] += 1
                    self._timeline(fid, "SEEN_AGAIN")
            else:
                self.conn.execute("""
                    INSERT INTO findings
                      (id,first_seen,last_seen,status,vuln_type,severity,file,line,endpoint,
                       snippet,cve,cvss,description,source_module,target,meta)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (fid, now, now, "OPEN", vuln_type, severity, file_, line, endpoint,
                       snippet, cve, cvss, description, source_module, target, meta))
                stats["new"] += 1
                self._timeline(fid, "FIRST_SEEN")

        # Mark fixed: findings seen on this target before but not in this run
        if target:
            prev_open = self.conn.execute(
                "SELECT id FROM findings WHERE target=? AND status='OPEN'", (target,)
            ).fetchall()
            for row in prev_open:
                if row["id"] not in current_ids:
                    self.conn.execute(
                        "UPDATE findings SET status='FIXED',last_seen=? WHERE id=?",
                        (now, row["id"])
                    )
                    stats["fixed"] += 1
                    self._timeline(row["id"], "FIXED")

        self.conn.commit()
        self.finish_run(stats)
        self._print_summary(stats)
        return stats

    def _timeline(self, finding_id: str, event: str):
        if self.current_run_id:
            self.conn.execute(
                "INSERT INTO timeline (finding_id,run_id,event,ts) VALUES (?,?,?,?)",
                (finding_id, self.current_run_id, event, datetime.utcnow().isoformat())
            )

    def _print_summary(self, stats: Dict):
        print(f"\n  📊 Tracker Update:")
        print(f"     New findings  : {stats['new']}")
        print(f"     Seen again    : {stats['seen_again']}")
        print(f"     Fixed         : {stats['fixed']}")
        if stats['regressed']:
            print(f"     🔴 REGRESSIONS : {stats['regressed']} — previously fixed vulns have returned!")

    def get_open_findings(self, severity: str = None) -> List[Dict]:
        q = "SELECT * FROM findings WHERE status='OPEN'"
        params = []
        if severity:
            q += " AND severity=?"
            params.append(severity)
        q += " ORDER BY cvss DESC, first_seen DESC"
        rows = self.conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def get_regressions(self) -> List[Dict]:
        rows = self.conn.execute("""
            SELECT f.*, t.ts as regressed_at FROM findings f
            JOIN timeline t ON f.id = t.finding_id
            WHERE t.event = 'REGRESSED'
            ORDER BY t.ts DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_trend(self, days: int = 30) -> Dict:
        since = datetime.utcnow().replace(hour=0, minute=0, second=0).isoformat()
        runs = self.conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (days,)
        ).fetchall()
        return {
            "total_open":     self.conn.execute("SELECT COUNT(*) FROM findings WHERE status='OPEN'").fetchone()[0],
            "total_fixed":    self.conn.execute("SELECT COUNT(*) FROM findings WHERE status='FIXED'").fetchone()[0],
            "critical_open":  self.conn.execute("SELECT COUNT(*) FROM findings WHERE status='OPEN' AND severity='CRITICAL'").fetchone()[0],
            "high_open":      self.conn.execute("SELECT COUNT(*) FROM findings WHERE status='OPEN' AND severity='HIGH'").fetchone()[0],
            "regressions":    len(self.get_regressions()),
            "recent_runs":    [dict(r) for r in runs],
            "top_vuln_types": [dict(r) for r in self.conn.execute(
                "SELECT vuln_type, COUNT(*) as cnt FROM findings WHERE status='OPEN' GROUP BY vuln_type ORDER BY cnt DESC LIMIT 10"
            ).fetchall()],
        }

    def report(self, output_path: str = None) -> Dict:
        trend = self.get_trend()
        findings = self.get_open_findings()
        report = {
            "generated": datetime.utcnow().isoformat(),
            "db": self.db_path,
            "trend": trend,
            "open_findings": findings,
            "regressions": self.get_regressions(),
        }
        if output_path:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
            print(f"  💾 Tracker report → {output_path}")
        return report

    def markdown_dashboard(self) -> str:
        t = self.get_trend()
        lines = [
            "# Nova Vulnerability Tracker Dashboard\n",
            f"**Generated:** {datetime.utcnow().isoformat()}\n",
            f"## Status\n",
            f"| Metric | Count |",
            f"|---|---|",
            f"| 🔴 Critical Open | {t['critical_open']} |",
            f"| 🟠 High Open | {t['high_open']} |",
            f"| ✅ Total Fixed | {t['total_fixed']} |",
            f"| 🔄 Regressions | {t['regressions']} |\n",
            f"## Top Vulnerability Types\n",
        ]
        for vt in t.get("top_vuln_types", []):
            lines.append(f"- `{vt['vuln_type']}`: {vt['cnt']} open")
        regressions = self.get_regressions()
        if regressions:
            lines.append(f"\n## ⚠️ Regressions (previously-fixed vulns that returned)\n")
            for r in regressions[:5]:
                lines.append(f"- `{r['vuln_type']}` in `{r['file']}` — regressed at {r.get('regressed_at','?')}")
        return "\n".join(lines)

    def close(self):
        self.conn.close()


if __name__ == "__main__":
    import sys, glob
    finding_files = sys.argv[1:] if len(sys.argv) > 1 else glob.glob(os.path.expanduser("~/nova_workspace/nova_*_report.json"))
    tracker = NovaVulnTracker()
    tracker.start_run(target=".", mode="manual")
    all_findings = []
    for ff in finding_files:
        try:
            with open(ff) as f:
                d = json.load(f)
            items = d if isinstance(d, list) else (d.get("findings") or d.get("all") or [])
            all_findings.extend(items)
        except Exception as e:
            print(f"  ⚠️  {ff}: {e}")
    tracker.ingest_findings(all_findings, source_module="manual_import")
    report = tracker.report(os.path.expanduser("~/nova_workspace/nova_tracker_report.json"))
    md = tracker.markdown_dashboard()
    with open(os.path.expanduser("~/nova_workspace/nova_tracker_dashboard.md"), "w") as f:
        f.write(md)
    print(f"\n  📊 {report['trend']['total_open']} open | {report['trend']['total_fixed']} fixed")
    tracker.close()
