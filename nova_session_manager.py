"""
Nova Session Manager v1.0
==========================
Complete session lifecycle management.

Features:
- Create and resume sessions
- Save session state to disk
- Auto-save progress
- Session history
- Resume interrupted sessions
- Export session data
- Session comparison (track progress over time)

Works fully offline.
Works on Android/Termux.
SQLite based (no server needed).
"""

import os
import json
import logging
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

DEFAULT_SESSION_DIR = os.path.expanduser("~/.nova/sessions")


class SessionStatus(Enum):
    """Session lifecycle states"""
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    FAILED = "failed"


class SessionPhase(Enum):
    """Current phase of session"""
    INITIALIZING = "initializing"
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    COMPLETED = "completed"


@dataclass
class SessionState:
    """Complete state of a session"""

    # Identity
    session_id: str
    target: str
    name: str = ""

    # Lifecycle
    status: SessionStatus = SessionStatus.ACTIVE
    phase: SessionPhase = SessionPhase.INITIALIZING
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None

    # Progress
    progress_percent: int = 0
    steps_completed: List[str] = field(default_factory=list)
    steps_pending: List[str] = field(default_factory=list)
    steps_failed: List[str] = field(default_factory=list)

    # Findings
    findings: List[Dict] = field(default_factory=list)
    chains: List[Dict] = field(default_factory=list)
    notes: str = ""

    # Context
    scope: str = ""
    risk_level: str = "medium"
    tools_used: List[str] = field(default_factory=list)
    commands_run: List[Dict] = field(default_factory=list)

    # Conversation
    conversation: List[Dict] = field(default_factory=list)

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        d = asdict(self)
        d["status"] = self.status.value
        d["phase"] = self.phase.value
        return d

    @classmethod
    def from_dict(cls, data: Dict) -> "SessionState":
        """Create from dictionary"""
        data["status"] = SessionStatus(data.get("status", "active"))
        data["phase"] = SessionPhase(data.get("phase", "initializing"))
        return cls(**data)

    def summary(self) -> str:
        """Human readable summary"""
        return (
            f"Session: {self.session_id}\n"
            f"Target: {self.target}\n"
            f"Status: {self.status.value}\n"
            f"Phase: {self.phase.value}\n"
            f"Progress: {self.progress_percent}%\n"
            f"Findings: {len(self.findings)}\n"
            f"Started: {self.created_at[:19]}"
        )


class NovaSessionManager:
    """
    Manages Nova session lifecycle.

    Sessions persist to disk so you can:
    - Resume interrupted scans
    - Compare results over time
    - Never lose progress
    - Pick up where you left off
    """

    def __init__(self, session_dir: str = DEFAULT_SESSION_DIR):
        """
        Initialize session manager.

        Args:
            session_dir: Directory to store sessions
        """
        self.session_dir = session_dir
        self.active_session: Optional[SessionState] = None
        self._ensure_directory()

        logger.info(f"Session manager initialized: {session_dir}")

    def _ensure_directory(self):
        """Create session directory if needed"""
        os.makedirs(self.session_dir, exist_ok=True)

    def _session_path(self, session_id: str) -> str:
        """Get path to session file"""
        return os.path.join(self.session_dir, f"{session_id}.json")

    # ─────────────────────────────────────────
    # SESSION CREATION
    # ─────────────────────────────────────────

    def new_session(
        self,
        target: str,
        name: str = "",
        scope: str = "",
        risk_level: str = "medium"
    ) -> SessionState:
        """
        Create a new session.

        Args:
            target: Target being tested
            name: Optional friendly name
            scope: What's in scope
            risk_level: How aggressive

        Returns:
            New SessionState
        """

        # Generate unique session ID
        session_id = self._generate_session_id(target)

        # Create session
        session = SessionState(
            session_id=session_id,
            target=target,
            name=name or f"Session for {target}",
            scope=scope,
            risk_level=risk_level
        )

        # Save to disk
        self._save_session(session)

        # Set as active
        self.active_session = session

        logger.info(f"New session created: {session_id} for {target}")
        print(f"\n[Nova] Session started: {session_id}")
        print(f"[Nova] Target: {target}")
        print(f"[Nova] Saved to: {self._session_path(session_id)}\n")

        return session

    def resume_session(self, session_id: str) -> Optional[SessionState]:
        """
        Resume an existing session.

        Args:
            session_id: Session to resume

        Returns:
            SessionState or None if not found
        """

        path = self._session_path(session_id)

        if not os.path.exists(path):
            logger.warning(f"Session not found: {session_id}")
            print(f"[Nova] Session {session_id} not found.")
            return None

        # Load session
        session = self._load_session(session_id)

        if not session:
            return None

        # Mark as active again
        session.status = SessionStatus.ACTIVE
        session.updated_at = datetime.now().isoformat()
        self._save_session(session)

        self.active_session = session

        logger.info(f"Session resumed: {session_id}")
        print(f"\n[Nova] Resuming session: {session_id}")
        print(f"[Nova] Target: {session.target}")
        print(f"[Nova] Progress: {session.progress_percent}%")
        print(f"[Nova] Findings so far: {len(session.findings)}")

        if session.steps_pending:
            print(f"[Nova] Pending steps: {len(session.steps_pending)}")
            for step in session.steps_pending[:3]:
                print(f"         - {step}")

        print()
        return session

    def pause_session(self, session_id: Optional[str] = None) -> bool:
        """
        Pause a session (save state, can resume later).

        Args:
            session_id: Session to pause (defaults to active)
        """

        session = self._get_session(session_id)
        if not session:
            return False

        session.status = SessionStatus.PAUSED
        session.updated_at = datetime.now().isoformat()
        self._save_session(session)

        logger.info(f"Session paused: {session.session_id}")
        print(f"\n[Nova] Session paused: {session.session_id}")
        print(f"[Nova] Resume with: nova resume {session.session_id}\n")

        return True

    def complete_session(
        self,
        session_id: Optional[str] = None,
        notes: str = ""
    ) -> bool:
        """
        Mark session as completed.

        Args:
            session_id: Session to complete
            notes: Final notes
        """

        session = self._get_session(session_id)
        if not session:
            return False

        session.status = SessionStatus.COMPLETED
        session.phase = SessionPhase.COMPLETED
        session.progress_percent = 100
        session.completed_at = datetime.now().isoformat()
        session.updated_at = datetime.now().isoformat()

        if notes:
            session.notes = notes

        self._save_session(session)
        self.active_session = None

        logger.info(f"Session completed: {session.session_id}")
        print(f"\n[Nova] Session completed: {session.session_id}")
        print(f"[Nova] Total findings: {len(session.findings)}")
        print(f"[Nova] Duration: {self._calculate_duration(session)}\n")

        return True

    # ─────────────────────────────────────────
    # SESSION UPDATES
    # ─────────────────────────────────────────

    def update_phase(self, phase: SessionPhase) -> bool:
        """Update current phase"""

        if not self.active_session:
            return False

        self.active_session.phase = phase
        self.active_session.updated_at = datetime.now().isoformat()

        phase_progress = {
            SessionPhase.INITIALIZING: 5,
            SessionPhase.RECONNAISSANCE: 20,
            SessionPhase.SCANNING: 50,
            SessionPhase.ANALYSIS: 75,
            SessionPhase.REPORTING: 90,
            SessionPhase.COMPLETED: 100
        }

        self.active_session.progress_percent = phase_progress.get(phase, 0)

        self._auto_save()

        print(f"[Nova] Phase: {phase.value} ({self.active_session.progress_percent}%)")
        return True

    def add_finding(self, finding: Dict) -> bool:
        """Add a finding to current session"""

        if not self.active_session:
            return False

        self.active_session.findings.append(finding)
        self.active_session.updated_at = datetime.now().isoformat()
        self._auto_save()

        severity = finding.get("severity", "UNKNOWN")
        title = finding.get("title", "Unknown finding")

        print(f"[Nova] Finding added [{severity}]: {title}")
        return True

    def add_chain(self, chain: Dict) -> bool:
        """Add a vulnerability chain"""

        if not self.active_session:
            return False

        self.active_session.chains.append(chain)
        self._auto_save()
        return True

    def complete_step(self, step: str) -> bool:
        """Mark a step as completed"""

        if not self.active_session:
            return False

        if step in self.active_session.steps_pending:
            self.active_session.steps_pending.remove(step)

        self.active_session.steps_completed.append(step)
        self._auto_save()
        return True

    def add_step(self, step: str) -> bool:
        """Add a pending step"""

        if not self.active_session:
            return False

        self.active_session.steps_pending.append(step)
        self._auto_save()
        return True

    def log_command(self, command: str, output: str, tool: str = "") -> bool:
        """Log a command that was run"""

        if not self.active_session:
            return False

        entry = {
            "command": command,
            "output": output[:500],
            "tool": tool,
            "timestamp": datetime.now().isoformat()
        }

        self.active_session.commands_run.append(entry)

        if tool and tool not in self.active_session.tools_used:
            self.active_session.tools_used.append(tool)

        self._auto_save()
        return True

    def add_conversation_message(self, role: str, content: str) -> bool:
        """Add message to conversation history"""

        if not self.active_session:
            return False

        self.active_session.conversation.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        })

        self._auto_save()
        return True

    # ─────────────────────────────────────────
    # SESSION RETRIEVAL
    # ─────────────────────────────────────────

    def list_sessions(self, target: Optional[str] = None) -> List[SessionState]:
        """
        List all sessions.

        Args:
            target: Filter by target (optional)
        """

        sessions = []

        for filename in os.listdir(self.session_dir):
            if not filename.endswith(".json"):
                continue

            session_id = filename.replace(".json", "")
            session = self._load_session(session_id)

            if session:
                if target and session.target != target:
                    continue
                sessions.append(session)

        # Sort by created_at descending
        sessions.sort(key=lambda s: s.created_at, reverse=True)
        return sessions

    def get_recent_sessions(self, limit: int = 5) -> List[SessionState]:
        """Get most recent sessions"""
        return self.list_sessions()[:limit]

    def find_sessions_for_target(self, target: str) -> List[SessionState]:
        """Get all sessions for a target"""
        return self.list_sessions(target=target)

    def get_resumable_sessions(self) -> List[SessionState]:
        """Get sessions that can be resumed"""

        all_sessions = self.list_sessions()
        return [
            s for s in all_sessions
            if s.status in [SessionStatus.PAUSED, SessionStatus.INTERRUPTED]
        ]

    # ─────────────────────────────────────────
    # SESSION COMPARISON
    # ─────────────────────────────────────────

    def compare_sessions(
        self,
        session_id_1: str,
        session_id_2: str
    ) -> Dict[str, Any]:
        """
        Compare two sessions for same target.
        Tracks progress over time.
        """

        s1 = self._load_session(session_id_1)
        s2 = self._load_session(session_id_2)

        if not s1 or not s2:
            return {"error": "Session not found"}

        s1_findings = {f.get("id", ""): f for f in s1.findings}
        s2_findings = {f.get("id", ""): f for f in s2.findings}

        new_findings = [f for k, f in s2_findings.items() if k not in s1_findings]
        fixed_findings = [f for k, f in s1_findings.items() if k not in s2_findings]
        persisting = [f for k, f in s1_findings.items() if k in s2_findings]

        return {
            "session_1": {
                "id": s1.session_id,
                "date": s1.created_at[:10],
                "findings": len(s1.findings)
            },
            "session_2": {
                "id": s2.session_id,
                "date": s2.created_at[:10],
                "findings": len(s2.findings)
            },
            "comparison": {
                "new_findings": len(new_findings),
                "fixed_findings": len(fixed_findings),
                "persisting_findings": len(persisting),
                "improvement": len(fixed_findings) > 0
            },
            "new_findings_detail": new_findings,
            "fixed_findings_detail": fixed_findings
        }

    # ─────────────────────────────────────────
    # DISPLAY HELPERS
    # ─────────────────────────────────────────

    def print_session_list(self, sessions: List[SessionState] = None):
        """Print formatted session list"""

        if sessions is None:
            sessions = self.list_sessions()

        if not sessions:
            print("[Nova] No sessions found.")
            return

        print(f"\n{'─'*60}")
        print(f"{'SESSION ID':<15} {'TARGET':<25} {'STATUS':<12} {'FINDINGS'}")
        print(f"{'─'*60}")

        for s in sessions:
            print(
                f"{s.session_id:<15} "
                f"{s.target[:24]:<25} "
                f"{s.status.value:<12} "
                f"{len(s.findings)}"
            )

        print(f"{'─'*60}\n")

    def print_session_detail(self, session: SessionState):
        """Print detailed session info"""

        print(f"\n{'═'*50}")
        print(f" Session: {session.session_id}")
        print(f"{'═'*50}")
        print(f" Target:    {session.target}")
        print(f" Status:    {session.status.value}")
        print(f" Phase:     {session.phase.value}")
        print(f" Progress:  {session.progress_percent}%")
        print(f" Started:   {session.created_at[:19]}")
        print(f" Findings:  {len(session.findings)}")
        print(f" Tools:     {', '.join(session.tools_used) or 'None'}")

        if session.findings:
            print(f"\n Findings by severity:")
            by_sev = {}
            for f in session.findings:
                sev = f.get("severity", "UNKNOWN")
                by_sev[sev] = by_sev.get(sev, 0) + 1
            for sev, count in sorted(by_sev.items()):
                print(f"   {sev}: {count}")

        print(f"{'═'*50}\n")

    # ─────────────────────────────────────────
    # PERSISTENCE
    # ─────────────────────────────────────────

    def _save_session(self, session: SessionState) -> bool:
        """Save session to disk"""

        try:
            path = self._session_path(session.session_id)

            with open(path, 'w') as f:
                json.dump(session.to_dict(), f, indent=2, default=str)

            return True

        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            return False

    def _load_session(self, session_id: str) -> Optional[SessionState]:
        """Load session from disk"""

        path = self._session_path(session_id)

        if not os.path.exists(path):
            return None

        try:
            with open(path, 'r') as f:
                data = json.load(f)

            return SessionState.from_dict(data)

        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            return None

    def _auto_save(self):
        """Auto-save active session"""

        if self.active_session:
            self._save_session(self.active_session)

    def _get_session(self, session_id: Optional[str]) -> Optional[SessionState]:
        """Get session by ID or return active"""

        if session_id:
            return self._load_session(session_id)
        return self.active_session

    def _generate_session_id(self, target: str) -> str:
        """Generate unique session ID"""

        raw = f"{target}{datetime.now().isoformat()}"
        return hashlib.md5(raw.encode()).hexdigest()[:10]

    def _calculate_duration(self, session: SessionState) -> str:
        """Calculate session duration"""

        try:
            start = datetime.fromisoformat(session.created_at)
            end = datetime.fromisoformat(
                session.completed_at or datetime.now().isoformat()
            )
            delta = end - start
            minutes = int(delta.total_seconds() / 60)
            return f"{minutes} minutes"
        except:
            return "unknown"


# ─────────────────────────────────────────
# EXAMPLE USAGE
# ─────────────────────────────────────────

if __name__ == "__main__":
    manager = NovaSessionManager()

    print("=== NOVA SESSION MANAGER ===\n")

    # Create new session
    session = manager.new_session(
        target="target.com",
        name="Bug bounty test",
        scope="*.target.com",
        risk_level="medium"
    )

    # Update progress
    manager.update_phase(SessionPhase.RECONNAISSANCE)
    manager.add_step("DNS enumeration")
    manager.add_step("Port scanning")

    # Add finding
    manager.add_finding({
        "id": "F001",
        "title": "SQL Injection",
        "severity": "CRITICAL",
        "description": "SQLi in search parameter"
    })

    # Complete a step
    manager.complete_step("DNS enumeration")

    # Pause it
    manager.pause_session()

    # List sessions
    print("All sessions:")
    manager.print_session_list()

    # Resume
    resumed = manager.resume_session(session.session_id)
    if resumed:
        manager.print_session_detail(resumed)

    # Complete
    manager.complete_session(notes="All findings documented")
