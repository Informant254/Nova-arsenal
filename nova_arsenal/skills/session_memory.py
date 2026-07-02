"""
Nova Arsenal — Session Memory
================================

Persistent, per-user memory so people don't lose track of what Nova was
doing between sessions. Built on SQLite, consistent with the rest of
Nova's data layer (see nova_arsenal/db/ and the alembic migrations).

What gets remembered:
  - target_history   : targets Nova has reasoned about or worked (from the
                        skills marketplace's TargetReasoner output)
  - task_log          : discrete tasks Nova ran, their outcome, and a short
                        summary — this is the "what did we do yesterday" answer
  - findings          : vulnerabilities/flags found, linked to a target
  - preferences       : user-stated preferences Nova should keep applying
                        (e.g. "always draft H1 reports in formal tone")

Explicitly NOT stored here: credentials/API tokens (those stay in
nova_arsenal/credentials/, encrypted at rest — memory is not a secrets store).

Usage:
    memory = SessionMemory(user_id="informant254")
    memory.log_task("recon", target="webcorp.h1", outcome="success",
                     summary="Ran subdomain enum, found 12 hosts")
    memory.remember_target("webcorp.h1", platform="hackerone", status="in_progress")
    recent = memory.recap(days=7)
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional


DEFAULT_DB_PATH = Path("nova_memory.db")


SCHEMA = """
CREATE TABLE IF NOT EXISTS task_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    task_type TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL,          -- success | partial | failed | in_progress
    summary TEXT NOT NULL,
    detail_json TEXT,               -- optional structured detail
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS target_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    name TEXT,
    status TEXT NOT NULL,           -- reasoned_about | in_progress | completed | abandoned
    last_score REAL,                -- last TargetReasoner score, if any
    notes TEXT,
    first_seen_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, target_id, platform)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT,
    status TEXT NOT NULL DEFAULT 'draft',  -- draft | submitted | accepted | rejected
    detail_json TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS preferences (
    user_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, key)
);

CREATE INDEX IF NOT EXISTS idx_task_log_user_time ON task_log(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_target_history_user ON target_history(user_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_findings_user ON findings(user_id, created_at);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TaskEntry:
    id: int
    task_type: str
    target: Optional[str]
    outcome: str
    summary: str
    detail: dict[str, Any]
    created_at: str


@dataclass
class TargetEntry:
    target_id: str
    platform: str
    name: Optional[str]
    status: str
    last_score: Optional[float]
    notes: Optional[str]
    updated_at: str


class SessionMemory:
    """
    Per-user persistent memory. Each user_id gets its own logical namespace
    within a shared SQLite file (row-scoped, not separate files) — this
    keeps it consistent with how the rest of Nova's SQLite/alembic layer
    is structured, and makes a future migration to Postgres a schema-only
    change rather than a redesign.
    """

    def __init__(self, user_id: str, db_path: str | Path = DEFAULT_DB_PATH):
        if not user_id or not user_id.strip():
            raise ValueError("user_id is required — memory must be scoped to a user")
        self.user_id = user_id
        self.db_path = Path(db_path)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    # ── Task log ───────────────────────────────────────────────────

    def log_task(
        self,
        task_type: str,
        outcome: str,
        summary: str,
        target: Optional[str] = None,
        detail: Optional[dict[str, Any]] = None,
    ) -> int:
        """Record a completed (or in-progress) task. Returns the row id."""
        valid_outcomes = {"success", "partial", "failed", "in_progress"}
        if outcome not in valid_outcomes:
            raise ValueError(f"outcome must be one of {valid_outcomes}, got '{outcome}'")

        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO task_log
                   (user_id, task_type, target, outcome, summary, detail_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    self.user_id, task_type, target, outcome, summary,
                    json.dumps(detail or {}), _now(),
                ),
            )
            return cur.lastrowid

    def recent_tasks(self, limit: int = 20) -> list[TaskEntry]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM task_log WHERE user_id = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (self.user_id, limit),
            ).fetchall()
        return [
            TaskEntry(
                id=r["id"], task_type=r["task_type"], target=r["target"],
                outcome=r["outcome"], summary=r["summary"],
                detail=json.loads(r["detail_json"] or "{}"),
                created_at=r["created_at"],
            )
            for r in rows
        ]

    # ── Target history ───────────────────────────────────────────

    def remember_target(
        self,
        target_id: str,
        platform: str,
        status: str,
        name: Optional[str] = None,
        last_score: Optional[float] = None,
        notes: Optional[str] = None,
    ) -> None:
        """Upsert a target's tracking status — called whenever Nova reasons
        about, starts, or finishes work on a target from the skills
        marketplace connectors."""
        valid_statuses = {"reasoned_about", "in_progress", "completed", "abandoned"}
        if status not in valid_statuses:
            raise ValueError(f"status must be one of {valid_statuses}, got '{status}'")

        now = _now()
        with self._conn() as conn:
            existing = conn.execute(
                """SELECT id FROM target_history
                   WHERE user_id = ? AND target_id = ? AND platform = ?""",
                (self.user_id, target_id, platform),
            ).fetchone()

            if existing:
                conn.execute(
                    """UPDATE target_history
                       SET status = ?, name = COALESCE(?, name),
                           last_score = COALESCE(?, last_score),
                           notes = COALESCE(?, notes), updated_at = ?
                       WHERE id = ?""",
                    (status, name, last_score, notes, now, existing["id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO target_history
                       (user_id, target_id, platform, name, status, last_score,
                        notes, first_seen_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (self.user_id, target_id, platform, name, status,
                     last_score, notes, now, now),
                )

    def active_targets(self) -> list[TargetEntry]:
        """Targets currently in_progress — the 'what was I working on' answer."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM target_history
                   WHERE user_id = ? AND status = 'in_progress'
                   ORDER BY updated_at DESC""",
                (self.user_id,),
            ).fetchall()
        return [self._row_to_target(r) for r in rows]

    def target_history(self, limit: int = 50) -> list[TargetEntry]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM target_history WHERE user_id = ?
                   ORDER BY updated_at DESC LIMIT ?""",
                (self.user_id, limit),
            ).fetchall()
        return [self._row_to_target(r) for r in rows]

    @staticmethod
    def _row_to_target(r: sqlite3.Row) -> TargetEntry:
        return TargetEntry(
            target_id=r["target_id"], platform=r["platform"], name=r["name"],
            status=r["status"], last_score=r["last_score"], notes=r["notes"],
            updated_at=r["updated_at"],
        )

    # ── Findings ──────────────────────────────────────────────────

    def record_finding(
        self,
        target_id: str,
        platform: str,
        title: str,
        severity: Optional[str] = None,
        status: str = "draft",
        detail: Optional[dict[str, Any]] = None,
    ) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO findings
                   (user_id, target_id, platform, title, severity, status,
                    detail_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    self.user_id, target_id, platform, title, severity,
                    status, json.dumps(detail or {}), _now(),
                ),
            )
            return cur.lastrowid

    def findings_for_target(self, target_id: str, platform: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM findings
                   WHERE user_id = ? AND target_id = ? AND platform = ?
                   ORDER BY created_at DESC""",
                (self.user_id, target_id, platform),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Preferences ──────────────────────────────────────────────

    def set_preference(self, key: str, value: str) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO preferences (user_id, key, value, updated_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(user_id, key) DO UPDATE SET
                       value = excluded.value, updated_at = excluded.updated_at""",
                (self.user_id, key, value, _now()),
            )

    def get_preference(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM preferences WHERE user_id = ? AND key = ?",
                (self.user_id, key),
            ).fetchone()
        return row["value"] if row else default

    def all_preferences(self) -> dict[str, str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT key, value FROM preferences WHERE user_id = ?",
                (self.user_id,),
            ).fetchall()
        return {r["key"]: r["value"] for r in rows}

    # ── Recap — the "what have we been doing" summary ─────────────────

    def recap(self, days: int = 7) -> dict[str, Any]:
        """
        Returns a structured summary of recent activity — this is what
        powers Nova answering "what were we working on?" at the start of
        a new session, instead of starting cold every time.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        with self._conn() as conn:
            tasks = conn.execute(
                """SELECT * FROM task_log WHERE user_id = ? AND created_at >= ?
                   ORDER BY created_at DESC""",
                (self.user_id, cutoff),
            ).fetchall()
            targets = conn.execute(
                """SELECT * FROM target_history WHERE user_id = ? AND updated_at >= ?
                   ORDER BY updated_at DESC""",
                (self.user_id, cutoff),
            ).fetchall()
            findings = conn.execute(
                """SELECT * FROM findings WHERE user_id = ? AND created_at >= ?
                   ORDER BY created_at DESC""",
                (self.user_id, cutoff),
            ).fetchall()

        in_progress = [self._row_to_target(t) for t in targets if t["status"] == "in_progress"]

        return {
            "period_days": days,
            "task_count": len(tasks),
            "targets_touched": len(targets),
            "findings_recorded": len(findings),
            "active_targets": [
                {"target_id": t.target_id, "platform": t.platform, "name": t.name}
                for t in in_progress
            ],
            "recent_tasks": [
                {"type": r["task_type"], "outcome": r["outcome"], "summary": r["summary"]}
                for r in tasks[:10]
            ],
        }
