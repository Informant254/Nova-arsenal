"""
Nova Findings Database v1.0
============================
Dedicated storage and querying for security findings.

Features:
- Store findings from all sessions
- Query by severity, target, status, date
- Track remediation status
- Trend analysis over time
- Export findings
- Deduplication

Uses SQLite (offline, no server, works on Android/Termux)
"""

import sqlite3
import json
import logging
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import os

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.expanduser("~/.nova/findings.db")


class FindingStatus(Enum):
    """Status of a finding"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class FindingSeverity(Enum):
    """Severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A security finding"""

    # Identity
    id: str = ""
    fingerprint: str = ""

    # Basic info
    title: str = ""
    severity: str = "MEDIUM"
    description: str = ""
    impact: str = ""

    # Location
    target: str = ""
    url: str = ""
    parameter: str = ""
    endpoint: str = ""

    # Evidence
    evidence: str = ""
    request: str = ""
    response: str = ""
    payload: str = ""

    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    owasp: str = ""
    cve: str = ""
    cvss_score: float = 0.0

    # Tracking
    status: str = FindingStatus.OPEN.value
    session_id: str = ""
    tool: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    fixed_at: Optional[str] = None

    # Tags
    tags: List[str] = field(default_factory=list)

    def generate_fingerprint(self) -> str:
        """Generate unique fingerprint for deduplication"""

        raw = f"{self.target}{self.title}{self.endpoint}{self.parameter}"
        return hashlib.md5(raw.encode()).hexdigest()

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "impact": self.impact,
            "target": self.target,
            "url": self.url,
            "parameter": self.parameter,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "payload": self.payload,
            "remediation": self.remediation,
            "references": json.dumps(self.references),
            "owasp": self.owasp,
            "cve": self.cve,
            "cvss_score": self.cvss_score,
            "status": self.status,
            "session_id": self.session_id,
            "tool": self.tool,
            "discovered_at": self.discovered_at,
            "updated_at": self.updated_at,
            "fixed_at": self.fixed_at,
            "tags": json.dumps(self.tags)
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Finding":
        finding = cls()
        finding.id = row["id"]
        finding.fingerprint = row["fingerprint"]
        finding.title = row["title"]
        finding.severity = row["severity"]
        finding.description = row["description"]
        finding.impact = row["impact"]
        finding.target = row["target"]
        finding.url = row["url"]
        finding.parameter = row["parameter"]
        finding.endpoint = row["endpoint"]
        finding.evidence = row["evidence"]
        finding.request = row["request"]
        finding.response = row["response"]
        finding.payload = row["payload"]
        finding.remediation = row["remediation"]
        finding.references = json.loads(row["references"] or "[]")
        finding.owasp = row["owasp"]
        finding.cve = row["cve"]
        finding.cvss_score = row["cvss_score"]
        finding.status = row["status"]
        finding.session_id = row["session_id"]
        finding.tool = row["tool"]
        finding.discovered_at = row["discovered_at"]
        finding.updated_at = row["updated_at"]
        finding.fixed_at = row["fixed_at"]
        finding.tags = json.loads(row["tags"] or "[]")
        return finding


class NovaFindingsDB:
    """
    Dedicated database for security findings.

    Store, query, track, and analyze findings
    across all sessions and targets.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = self._connect()
        self._initialize_schema()
        logger.info(f"Findings DB initialized: {db_path}")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _initialize_schema(self):
        self.conn.executescript("""

        CREATE TABLE IF NOT EXISTS findings (
            id              TEXT PRIMARY KEY,
            fingerprint     TEXT UNIQUE,
            title           TEXT NOT NULL,
            severity        TEXT NOT NULL,
            description     TEXT DEFAULT '',
            impact          TEXT DEFAULT '',
            target          TEXT NOT NULL,
            url             TEXT DEFAULT '',
            parameter       TEXT DEFAULT '',
            endpoint        TEXT DEFAULT '',
            evidence        TEXT DEFAULT '',
            request         TEXT DEFAULT '',
            response        TEXT DEFAULT '',
            payload         TEXT DEFAULT '',
            remediation     TEXT DEFAULT '',
            references      TEXT DEFAULT '[]',
            owasp           TEXT DEFAULT '',
            cve             TEXT DEFAULT '',
            cvss_score      REAL DEFAULT 0.0,
            status          TEXT DEFAULT 'open',
            session_id      TEXT DEFAULT '',
            tool            TEXT DEFAULT '',
            discovered_at   TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            fixed_at        TEXT,
            tags            TEXT DEFAULT '[]'
        );

        CREATE INDEX IF NOT EXISTS idx_findings_target
            ON findings(target);
        CREATE INDEX IF NOT EXISTS idx_findings_severity
            ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_status
            ON findings(status);
        CREATE INDEX IF NOT EXISTS idx_findings_session
            ON findings(session_id);
        CREATE INDEX IF NOT EXISTS idx_findings_fingerprint
            ON findings(fingerprint);

        """)
        self.conn.commit()

    # ─────────────────────────────────────────
    # CREATE / UPDATE
    # ─────────────────────────────────────────

    def add_finding(self, finding: Finding) -> Tuple[bool, str]:
        """
        Add a finding to the database.

        Returns:
            (success, message)
        """

        # Generate ID and fingerprint
        if not finding.id:
            finding.id = self._generate_id()

        if not finding.fingerprint:
            finding.fingerprint = finding.generate_fingerprint()

        # Check for duplicates
        existing = self._find_by_fingerprint(finding.fingerprint)
        if existing:
            logger.info(f"Duplicate finding detected: {finding.title}")
            return False, f"Duplicate finding (ID: {existing.id})"

        try:
            self.conn.execute("""
                INSERT INTO findings
                (id, fingerprint, title, severity, description, impact,
                 target, url, parameter, endpoint, evidence, request,
                 response, payload, remediation, references, owasp, cve,
                 cvss_score, status, session_id, tool, discovered_at,
                 updated_at, fixed_at, tags)
                VALUES
                (:id, :fingerprint, :title, :severity, :description, :impact,
                 :target, :url, :parameter, :endpoint, :evidence, :request,
                 :response, :payload, :remediation, :references, :owasp, :cve,
                 :cvss_score, :status, :session_id, :tool, :discovered_at,
                 :updated_at, :fixed_at, :tags)
            """, finding.to_dict())

            self.conn.commit()
            logger.info(f"Finding added: {finding.title} [{finding.severity}]")
            return True, finding.id

        except Exception as e:
            logger.error(f"Failed to add finding: {e}")
            return False, str(e)

    def update_status(self, finding_id: str, status: FindingStatus, notes: str = "") -> bool:
        """Update finding status"""

        now = datetime.now().isoformat()
        fixed_at = now if status == FindingStatus.FIXED else None

        self.conn.execute("""
            UPDATE findings
            SET status = ?, updated_at = ?, fixed_at = ?
            WHERE id = ?
        """, (status.value, now, fixed_at, finding_id))

        self.conn.commit()
        logger.info(f"Finding {finding_id} status: {status.value}")
        return True

    def bulk_add(self, findings: List[Finding]) -> Dict[str, int]:
        """Add multiple findings at once"""

        added = 0
        duplicates = 0
        failed = 0

        for finding in findings:
            success, msg = self.add_finding(finding)
            if success:
                added += 1
            elif "Duplicate" in msg:
                duplicates += 1
            else:
                failed += 1

        return {
            "added": added,
            "duplicates": duplicates,
            "failed": failed,
            "total": len(findings)
        }

    # ─────────────────────────────────────────
    # QUERIES
    # ─────────────────────────────────────────

    def get_by_id(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID"""

        row = self.conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()

        return Finding.from_row(row) if row else None

    def get_by_target(
        self,
        target: str,
        severity: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[Finding]:
        """Get findings for a target"""

        query = "SELECT * FROM findings WHERE target = ?"
        params = [target]

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"

        rows = self.conn.execute(query, params).fetchall()
        return [Finding.from_row(r) for r in rows]

    def get_by_session(self, session_id: str) -> List[Finding]:
        """Get all findings from a session"""

        rows = self.conn.execute(
            "SELECT * FROM findings WHERE session_id = ?", (session_id,)
        ).fetchall()
        return [Finding.from_row(r) for r in rows]

    def get_open_findings(self, target: Optional[str] = None) -> List[Finding]:
        """Get all open findings"""

        if target:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE status = 'open' AND target = ?",
                (target,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE status = 'open'"
            ).fetchall()

        return [Finding.from_row(r) for r in rows]

    def get_critical_findings(self) -> List[Finding]:
        """Get all critical findings"""

        rows = self.conn.execute(
            "SELECT * FROM findings WHERE severity = 'CRITICAL' AND status = 'open'"
        ).fetchall()
        return [Finding.from_row(r) for r in rows]

    def search(self, query: str) -> List[Finding]:
        """Search findings by text"""

        rows = self.conn.execute("""
            SELECT * FROM findings
            WHERE title LIKE ?
            OR description LIKE ?
            OR target LIKE ?
            OR payload LIKE ?
        """, (f"%{query}%",) * 4).fetchall()

        return [Finding.from_row(r) for r in rows]

    # ─────────────────────────────────────────
    # ANALYTICS
    # ─────────────────────────────────────────

    def get_stats(self, target: Optional[str] = None) -> Dict[str, Any]:
        """Get finding statistics"""

        base_query = "FROM findings"
        params = []

        if target:
            base_query += " WHERE target = ?"
            params.append(target)

        total = self.conn.execute(
            f"SELECT COUNT(*) as c {base_query}", params
        ).fetchone()["c"]

        by_severity = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            where = f"WHERE severity = '{sev}'"
            if target:
                where += f" AND target = ?"
            count = self.conn.execute(
                f"SELECT COUNT(*) as c FROM findings {where}",
                params if target else []
            ).fetchone()["c"]
            by_severity[sev] = count

        by_status = {}
        for status in FindingStatus:
            where = f"WHERE status = '{status.value}'"
            if target:
                where += f" AND target = ?"
            count = self.conn.execute(
                f"SELECT COUNT(*) as c FROM findings {where}",
                params if target else []
            ).fetchone()["c"]
            by_status[status.value] = count

        open_critical = self.conn.execute(
            f"SELECT COUNT(*) as c FROM findings WHERE severity = 'CRITICAL' AND status = 'open'"
        ).fetchone()["c"]

        return {
            "total": total,
            "by_severity": by_severity,
            "by_status": by_status,
            "open_critical": open_critical,
            "remediation_rate": (
                f"{by_status.get('fixed', 0) / total * 100:.0f}%"
                if total > 0 else "0%"
            )
        }

    def get_trend(self, target: str, days: int = 30) -> List[Dict]:
        """Get finding trend over time"""

        rows = self.conn.execute("""
            SELECT
                substr(discovered_at, 1, 10) as date,
                COUNT(*) as count,
                severity
            FROM findings
            WHERE target = ?
            GROUP BY date, severity
            ORDER BY date
        """, (target,)).fetchall()

        return [{"date": r["date"], "count": r["count"], "severity": r["severity"]}
                for r in rows]

    def get_top_targets(self, limit: int = 10) -> List[Dict]:
        """Get targets with most findings"""

        rows = self.conn.execute("""
            SELECT
                target,
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_count
            FROM findings
            GROUP BY target
            ORDER BY critical DESC, total DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [
            {
                "target": r["target"],
                "total": r["total"],
                "critical": r["critical"],
                "open": r["open_count"]
            }
            for r in rows
        ]

    # ─────────────────────────────────────────
    # EXPORT
    # ─────────────────────────────────────────

    def export_json(
        self,
        target: Optional[str] = None,
        status: Optional[str] = None
    ) -> str:
        """Export findings as JSON"""

        if target:
            findings = self.get_by_target(target, status=status)
        else:
            findings = self.get_open_findings()

        data = {
            "exported_at": datetime.now().isoformat(),
            "total": len(findings),
            "findings": [f.to_dict() for f in findings]
        }

        return json.dumps(data, indent=2)

    def export_csv(self, target: Optional[str] = None) -> str:
        """Export findings as CSV"""

        if target:
            findings = self.get_by_target(target)
        else:
            findings = self.get_open_findings()

        lines = ["ID,Title,Severity,Target,Status,OWASP,CVE,Discovered"]

        for f in findings:
            lines.append(
                f'"{f.id}","{f.title}","{f.severity}","{f.target}",'
                f'"{f.status}","{f.owasp}","{f.cve}","{f.discovered_at[:10]}"'
            )

        return "\n".join(lines)

    # ─────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────

    def _find_by_fingerprint(self, fingerprint: str) -> Optional[Finding]:
        row = self.conn.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return Finding.from_row(row) if row else None

    def _generate_id(self) -> str:
        raw = f"NOVA-{datetime.now().isoformat()}"
        return "F" + hashlib.md5(raw.encode()).hexdigest()[:8].upper()

    def print_summary(self, target: Optional[str] = None):
        """Print findings summary"""

        stats = self.get_stats(target)

        title = f"Findings for {target}" if target else "All Findings"
        print(f"\n{'═'*50}")
        print(f" {title}")
        print(f"{'═'*50}")
        print(f" Total:     {stats['total']}")
        print(f" Critical:  {stats['by_severity']['CRITICAL']}")
        print(f" High:      {stats['by_severity']['HIGH']}")
        print(f" Medium:    {stats['by_severity']['MEDIUM']}")
        print(f" Low:       {stats['by_severity']['LOW']}")
        print(f"{'─'*50}")
        print(f" Open:      {stats['by_status']['open']}")
        print(f" Fixed:     {stats['by_status']['fixed']}")
        print(f" Fix Rate:  {stats['remediation_rate']}")
        print(f"{'═'*50}\n")

    def close(self):
        self.conn.close()


# ─────────────────────────────────────────
# EXAMPLE USAGE
# ─────────────────────────────────────────

if __name__ == "__main__":
    db = NovaFindingsDB()

    print("=== NOVA FINDINGS DATABASE ===\n")

    # Add a finding
    finding = Finding(
        title="SQL Injection in search",
        severity="CRITICAL",
        description="SQLi found in search parameter",
        target="target.com",
        endpoint="/api/search",
        parameter="q",
        payload="' OR '1'='1",
        evidence="HTTP 500 returned with SQL error",
        remediation="Use parameterized queries",
        owasp="A03:2021 Injection",
        cvss_score=9.8
    )

    success, msg = db.add_finding(finding)
    print(f"Finding added: {success} - {msg}")

    # Get stats
    db.print_summary("target.com")

    # Top targets
    print("Top targets:")
    for t in db.get_top_targets():
        print(f"  {t['target']}: {t['total']} findings ({t['critical']} critical)")

    db.close()
