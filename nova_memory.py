"""
Nova Memory System v1.0
========================
Gives Nova persistent memory across sessions.

Nova remembers:
- Targets you've tested before
- Findings from previous sessions
- Your preferences and patterns
- Conversation history
- Tools that worked/failed
- Successful techniques

Storage:
- SQLite database (lightweight, no server needed)
- Works fully offline
- Works on Android/Termux
- No external dependencies
"""

import sqlite3
import json
import logging
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.expanduser("~/.nova/memory.db")


# ─────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────

@dataclass
class TargetMemory:
    """What Nova remembers about a target"""
    target: str
    first_seen: str
    last_seen: str
    total_scans: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FindingMemory:
    """Stored finding from previous session"""
    id: str
    target: str
    title: str
    severity: str
    description: str
    timestamp: str
    status: str = "open"  # open, fixed, accepted_risk
    session_id: str = ""
    evidence: str = ""
    remediation: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class SessionMemory:
    """Complete session record"""
    session_id: str
    target: str
    started_at: str
    ended_at: Optional[str] = None
    findings_count: int = 0
    tools_used: List[str] = field(default_factory=list)
    notes: str = ""
    status: str = "active"  # active, completed, failed


@dataclass
class PreferenceMemory:
    """User preferences Nova remembers"""
    key: str
    value: str
    updated_at: str
    description: str = ""


@dataclass 
class TechniqueMemory:
    """Techniques that worked on targets"""
    technique: str
    target_type: str  # web, api, network, etc.
    success_count: int = 0
    fail_count: int = 0
    last_used: str = ""
    notes: str = ""


# ─────────────────────────────────────────
# MEMORY SYSTEM
# ─────────────────────────────────────────

class NovaMemory:
    """
    Nova's persistent memory system.

    Nova remembers everything across sessions:
    - Every target tested
    - Every finding discovered
    - What worked and what didn't
    - User preferences
    - Conversation context
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        """
        Initialize memory system.

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self._ensure_db_directory()
        self.conn = self._connect()
        self._initialize_schema()

        logger.info(f"Nova memory initialized: {db_path}")

    def _ensure_db_directory(self):
        """Create database directory if needed"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        """Connect to SQLite database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _initialize_schema(self):
        """Create database tables"""

        self.conn.executescript("""

        CREATE TABLE IF NOT EXISTS targets (
            target          TEXT PRIMARY KEY,
            first_seen      TEXT NOT NULL,
            last_seen       TEXT NOT NULL,
            total_scans     INTEGER DEFAULT 0,
            findings_count  INTEGER DEFAULT 0,
            critical_count  INTEGER DEFAULT 0,
            high_count      INTEGER DEFAULT 0,
            notes           TEXT DEFAULT '',
            tags            TEXT DEFAULT '[]',
            metadata        TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS findings (
            id              TEXT PRIMARY KEY,
            target          TEXT NOT NULL,
            title           TEXT NOT NULL,
            severity        TEXT NOT NULL,
            description     TEXT,
            timestamp       TEXT NOT NULL,
            status          TEXT DEFAULT 'open',
            session_id      TEXT,
            evidence        TEXT DEFAULT '',
            remediation     TEXT DEFAULT '',
            tags            TEXT DEFAULT '[]',
            FOREIGN KEY (target) REFERENCES targets(target)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            session_id      TEXT PRIMARY KEY,
            target          TEXT NOT NULL,
            started_at      TEXT NOT NULL,
            ended_at        TEXT,
            findings_count  INTEGER DEFAULT 0,
            tools_used      TEXT DEFAULT '[]',
            notes           TEXT DEFAULT '',
            status          TEXT DEFAULT 'active'
        );

        CREATE TABLE IF NOT EXISTS preferences (
            key             TEXT PRIMARY KEY,
            value           TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            description     TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS techniques (
            technique       TEXT NOT NULL,
            target_type     TEXT NOT NULL,
            success_count   INTEGER DEFAULT 0,
            fail_count      INTEGER DEFAULT 0,
            last_used       TEXT DEFAULT '',
            notes           TEXT DEFAULT '',
            PRIMARY KEY (technique, target_type)
        );

        CREATE TABLE IF NOT EXISTS conversations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT,
            role            TEXT NOT NULL,
            content         TEXT NOT NULL,
            timestamp       TEXT NOT NULL,
            intent          TEXT DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_findings_target 
            ON findings(target);
        CREATE INDEX IF NOT EXISTS idx_findings_severity 
            ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_sessions_target 
            ON sessions(target);
        CREATE INDEX IF NOT EXISTS idx_conversations_session 
            ON conversations(session_id);

        """)

        self.conn.commit()
        logger.info("Database schema initialized")

    # ─────────────────────────────────────────
    # TARGET MEMORY
    # ─────────────────────────────────────────

    def remember_target(self, target: str, notes: str = "", tags: List[str] = None) -> TargetMemory:
        """Remember a target"""

        now = datetime.now().isoformat()
        tags = tags or []

        existing = self.get_target(target)

        if existing:
            self.conn.execute("""
                UPDATE targets 
                SET last_seen = ?, total_scans = total_scans + 1, notes = ?
                WHERE target = ?
            """, (now, notes or existing.notes, target))
            self.conn.commit()
            logger.info(f"Updated target memory: {target}")
            return self.get_target(target)
        else:
            self.conn.execute("""
                INSERT INTO targets 
                (target, first_seen, last_seen, total_scans, notes, tags)
                VALUES (?, ?, ?, 1, ?, ?)
            """, (target, now, now, notes, json.dumps(tags)))
            self.conn.commit()
            logger.info(f"New target remembered: {target}")
            return self.get_target(target)

    def get_target(self, target: str) -> Optional[TargetMemory]:
        """Get target memory"""

        row = self.conn.execute(
            "SELECT * FROM targets WHERE target = ?", (target,)
        ).fetchone()

        if not row:
            return None

        return TargetMemory(
            target=row["target"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            total_scans=row["total_scans"],
            findings_count=row["findings_count"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            notes=row["notes"],
            tags=json.loads(row["tags"]),
            metadata=json.loads(row["metadata"])
        )

    def get_all_targets(self) -> List[TargetMemory]:
        """Get all remembered targets"""

        rows = self.conn.execute(
            "SELECT * FROM targets ORDER BY last_seen DESC"
        ).fetchall()

        return [
            TargetMemory(
                target=r["target"],
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                total_scans=r["total_scans"],
                findings_count=r["findings_count"],
                critical_count=r["critical_count"],
                high_count=r["high_count"],
                notes=r["notes"],
                tags=json.loads(r["tags"]),
                metadata=json.loads(r["metadata"])
            )
            for r in rows
        ]

    # ─────────────────────────────────────────
    # FINDINGS MEMORY
    # ─────────────────────────────────────────

    def remember_finding(self, finding: FindingMemory) -> bool:
        """Store a finding"""

        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO findings
                (id, target, title, severity, description, timestamp, 
                 status, session_id, evidence, remediation, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.id,
                finding.target,
                finding.title,
                finding.severity,
                finding.description,
                finding.timestamp,
                finding.status,
                finding.session_id,
                finding.evidence,
                finding.remediation,
                json.dumps(finding.tags)
            ))

            # Update target counts
            self.conn.execute("""
                UPDATE targets 
                SET findings_count = findings_count + 1,
                    critical_count = critical_count + CASE WHEN ? = 'CRITICAL' THEN 1 ELSE 0 END,
                    high_count = high_count + CASE WHEN ? = 'HIGH' THEN 1 ELSE 0 END
                WHERE target = ?
            """, (finding.severity, finding.severity, finding.target))

            self.conn.commit()
            logger.info(f"Finding remembered: {finding.title} on {finding.target}")
            return True

        except Exception as e:
            logger.error(f"Failed to store finding: {e}")
            return False

    def get_findings_for_target(self, target: str, severity: Optional[str] = None) -> List[FindingMemory]:
        """Get all findings for a target"""

        if severity:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE target = ? AND severity = ? ORDER BY timestamp DESC",
                (target, severity)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE target = ? ORDER BY timestamp DESC",
                (target,)
            ).fetchall()

        return [
            FindingMemory(
                id=r["id"],
                target=r["target"],
                title=r["title"],
                severity=r["severity"],
                description=r["description"],
                timestamp=r["timestamp"],
                status=r["status"],
                session_id=r["session_id"],
                evidence=r["evidence"],
                remediation=r["remediation"],
                tags=json.loads(r["tags"])
            )
            for r in rows
        ]

    def get_all_findings(self, status: Optional[str] = None) -> List[FindingMemory]:
        """Get all findings across all targets"""

        if status:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE status = ? ORDER BY timestamp DESC",
                (status,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings ORDER BY timestamp DESC"
            ).fetchall()

        return [
            FindingMemory(
                id=r["id"],
                target=r["target"],
                title=r["title"],
                severity=r["severity"],
                description=r["description"],
                timestamp=r["timestamp"],
                status=r["status"],
                session_id=r["session_id"],
                evidence=r["evidence"],
                remediation=r["remediation"],
                tags=json.loads(r["tags"])
            )
            for r in rows
        ]

    def update_finding_status(self, finding_id: str, status: str) -> bool:
        """Update finding status"""

        self.conn.execute(
            "UPDATE findings SET status = ? WHERE id = ?",
            (status, finding_id)
        )
        self.conn.commit()
        return True

    # ─────────────────────────────────────────
    # SESSION MEMORY
    # ─────────────────────────────────────────

    def start_session(self, target: str) -> SessionMemory:
        """Start a new session"""

        session_id = hashlib.md5(
            f"{target}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]

        now = datetime.now().isoformat()

        self.conn.execute("""
            INSERT INTO sessions (session_id, target, started_at, status)
            VALUES (?, ?, ?, 'active')
        """, (session_id, target, now))

        self.conn.commit()

        logger.info(f"Session started: {session_id} for {target}")

        return SessionMemory(
            session_id=session_id,
            target=target,
            started_at=now
        )

    def end_session(self, session_id: str, notes: str = "") -> bool:
        """End a session"""

        now = datetime.now().isoformat()

        self.conn.execute("""
            UPDATE sessions
            SET ended_at = ?, status = 'completed', notes = ?
            WHERE session_id = ?
        """, (now, notes, session_id))

        self.conn.commit()

        logger.info(f"Session ended: {session_id}")
        return True

    def get_sessions_for_target(self, target: str) -> List[SessionMemory]:
        """Get all sessions for a target"""

        rows = self.conn.execute(
            "SELECT * FROM sessions WHERE target = ? ORDER BY started_at DESC",
            (target,)
        ).fetchall()

        return [
            SessionMemory(
                session_id=r["session_id"],
                target=r["target"],
                started_at=r["started_at"],
                ended_at=r["ended_at"],
                findings_count=r["findings_count"],
                tools_used=json.loads(r["tools_used"]),
                notes=r["notes"],
                status=r["status"]
            )
            for r in rows
        ]

    # ─────────────────────────────────────────
    # CONVERSATION MEMORY
    # ─────────────────────────────────────────

    def remember_message(
        self,
        role: str,
        content: str,
        session_id: str = "",
        intent: str = ""
    ):
        """Remember a conversation message"""

        self.conn.execute("""
            INSERT INTO conversations (session_id, role, content, timestamp, intent)
            VALUES (?, ?, ?, ?, ?)
        """, (session_id, role, content, datetime.now().isoformat(), intent))

        self.conn.commit()

    def get_conversation_history(
        self,
        session_id: str,
        limit: int = 20
    ) -> List[Dict]:
        """Get conversation history"""

        rows = self.conn.execute("""
            SELECT role, content, timestamp, intent
            FROM conversations
            WHERE session_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (session_id, limit)).fetchall()

        return [
            {
                "role": r["role"],
                "content": r["content"],
                "timestamp": r["timestamp"],
                "intent": r["intent"]
            }
            for r in reversed(rows)
        ]

    # ─────────────────────────────────────────
    # PREFERENCES
    # ─────────────────────────────────────────

    def set_preference(self, key: str, value: str, description: str = ""):
        """Set a user preference"""

        self.conn.execute("""
            INSERT OR REPLACE INTO preferences (key, value, updated_at, description)
            VALUES (?, ?, ?, ?)
        """, (key, value, datetime.now().isoformat(), description))

        self.conn.commit()
        logger.info(f"Preference set: {key} = {value}")

    def get_preference(self, key: str, default: str = "") -> str:
        """Get a preference"""

        row = self.conn.execute(
            "SELECT value FROM preferences WHERE key = ?", (key,)
        ).fetchone()

        return row["value"] if row else default

    def get_all_preferences(self) -> Dict[str, str]:
        """Get all preferences"""

        rows = self.conn.execute("SELECT key, value FROM preferences").fetchall()
        return {r["key"]: r["value"] for r in rows}

    # ─────────────────────────────────────────
    # TECHNIQUE MEMORY
    # ─────────────────────────────────────────

    def record_technique(
        self,
        technique: str,
        target_type: str,
        success: bool,
        notes: str = ""
    ):
        """Record if a technique worked"""

        now = datetime.now().isoformat()

        existing = self.conn.execute(
            "SELECT * FROM techniques WHERE technique = ? AND target_type = ?",
            (technique, target_type)
        ).fetchone()

        if existing:
            if success:
                self.conn.execute("""
                    UPDATE techniques
                    SET success_count = success_count + 1, last_used = ?
                    WHERE technique = ? AND target_type = ?
                """, (now, technique, target_type))
            else:
                self.conn.execute("""
                    UPDATE techniques
                    SET fail_count = fail_count + 1, last_used = ?
                    WHERE technique = ? AND target_type = ?
                """, (now, technique, target_type))
        else:
            self.conn.execute("""
                INSERT INTO techniques
                (technique, target_type, success_count, fail_count, last_used, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                technique, target_type,
                1 if success else 0,
                0 if success else 1,
                now, notes
            ))

        self.conn.commit()

    def get_best_techniques(self, target_type: str, limit: int = 5) -> List[TechniqueMemory]:
        """Get most successful techniques for target type"""

        rows = self.conn.execute("""
            SELECT * FROM techniques
            WHERE target_type = ? AND success_count > 0
            ORDER BY success_count DESC
            LIMIT ?
        """, (target_type, limit)).fetchall()

        return [
            TechniqueMemory(
                technique=r["technique"],
                target_type=r["target_type"],
                success_count=r["success_count"],
                fail_count=r["fail_count"],
                last_used=r["last_used"],
                notes=r["notes"]
            )
            for r in rows
        ]

    # ─────────────────────────────────────────
    # SMART RECALL
    # ─────────────────────────────────────────

    def what_do_i_know_about(self, target: str) -> Dict[str, Any]:
        """
        Get everything Nova knows about a target.
        Called before starting a new session.
        """

        target_mem = self.get_target(target)
        findings = self.get_findings_for_target(target)
        sessions = self.get_sessions_for_target(target)

        if not target_mem:
            return {
                "known": False,
                "message": f"Never tested {target} before"
            }

        open_findings = [f for f in findings if f.status == "open"]
        critical = [f for f in findings if f.severity == "CRITICAL"]

        return {
            "known": True,
            "target": target,
            "first_seen": target_mem.first_seen,
            "last_seen": target_mem.last_seen,
            "total_scans": target_mem.total_scans,
            "total_findings": len(findings),
            "open_findings": len(open_findings),
            "critical_findings": len(critical),
            "previous_sessions": len(sessions),
            "summary": self._generate_target_summary(target_mem, findings, sessions)
        }

    def _generate_target_summary(
        self,
        target: TargetMemory,
        findings: List[FindingMemory],
        sessions: List[SessionMemory]
    ) -> str:
        """Generate natural language summary"""

        open_count = len([f for f in findings if f.status == "open"])
        critical = [f for f in findings if f.severity == "CRITICAL" and f.status == "open"]

        summary = f"I've tested {target.target} {target.total_scans} time(s). "

        if critical:
            summary += f"⚠️  There are {len(critical)} open CRITICAL findings. "

        if open_count > 0:
            summary += f"{open_count} findings are still open. "

        if sessions:
            last_session = sessions[0]
            summary += f"Last tested: {last_session.started_at[:10]}. "

        return summary

    # ─────────────────────────────────────────
    # STATS
    # ─────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Get overall memory statistics"""

        targets = self.conn.execute("SELECT COUNT(*) as c FROM targets").fetchone()["c"]
        findings = self.conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
        sessions = self.conn.execute("SELECT COUNT(*) as c FROM sessions").fetchone()["c"]
        critical = self.conn.execute(
            "SELECT COUNT(*) as c FROM findings WHERE severity = 'CRITICAL'"
        ).fetchone()["c"]
        open_findings = self.conn.execute(
            "SELECT COUNT(*) as c FROM findings WHERE status = 'open'"
        ).fetchone()["c"]

        return {
            "targets_remembered": targets,
            "total_findings": findings,
            "total_sessions": sessions,
            "critical_findings": critical,
            "open_findings": open_findings,
            "db_path": self.db_path,
            "db_size": f"{os.path.getsize(self.db_path) / 1024:.1f} KB" if os.path.exists(self.db_path) else "0 KB"
        }

    def close(self):
        """Close database connection"""
        self.conn.close()


# ─────────────────────────────────────────
# EXAMPLE USAGE
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("\n=== NOVA MEMORY SYSTEM ===\n")

    memory = NovaMemory()

    # Remember a target
    memory.remember_target("target.com", notes="Bug bounty target")

    # Start a session
    session = memory.start_session("target.com")
    print(f"Session started: {session.session_id}")

    # Store a finding
    finding = FindingMemory(
        id="F001",
        target="target.com",
        title="SQL Injection in search",
        severity="CRITICAL",
        description="SQLi found in search parameter",
        timestamp=datetime.now().isoformat(),
        session_id=session.session_id
    )
    memory.remember_finding(finding)

    # What do I know about this target?
    knowledge = memory.what_do_i_know_about("target.com")
    print(f"\nWhat I know about target.com:")
    print(f"  {knowledge['summary']}")

    # Get stats
    stats = memory.get_stats()
    print(f"\nMemory stats:")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    memory.close()
