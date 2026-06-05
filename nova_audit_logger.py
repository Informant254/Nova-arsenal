"""
Nova Audit Logger v1.0
======================
CRITICAL: Maintains complete audit trail of ALL actions.

Everything is logged:
- Plan generation
- Approval requests
- User approvals/rejections
- Command execution
- Output captured
- Errors
- User decisions
- Timestamps
- Who did what, when

Audit log is immutable (append-only).
Used for accountability, compliance, and investigation.
"""

import logging
import json
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
import uuid

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of events to audit"""
    PLAN_GENERATED = "plan_generated"
    PLAN_PRESENTED = "plan_presented"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    EXECUTION_STARTED = "execution_started"
    COMMAND_EXECUTED = "command_executed"
    CODE_EXECUTED = "code_executed"
    EXECUTION_COMPLETED = "execution_completed"
    EXECUTION_FAILED = "execution_failed"
    OUTPUT_CAPTURED = "output_captured"
    ERROR_OCCURRED = "error_occurred"
    AUTHORIZATION_CHECKED = "authorization_checked"
    USER_ACTION = "user_action"


@dataclass
class AuditEntry:
    """Single audit log entry"""
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    event_type: AuditEventType = AuditEventType.USER_ACTION
    
    # Who did it
    user: str = ""  # API key
    
    # What happened
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Context
    plan_id: Optional[str] = None
    task_id: Optional[str] = None
    target: Optional[str] = None
    
    # For integrity
    entry_hash: str = ""
    previous_entry_hash: str = ""
    
    # Severity
    severity: str = "INFO"  # INFO, WARNING, ERROR, CRITICAL


class AuditLogger:
    """
    Maintains immutable audit trail.
    Every action is logged with full context.
    """
    
    def __init__(self, log_file: str = "/var/log/nova/audit.log"):
        """
        Initialize audit logger.
        
        Args:
            log_file: Path to audit log file
        """
        self.log_file = log_file
        self.entries: List[AuditEntry] = []
        self.last_hash = "0"  # Genesis block
        
        # Ensure logging is strict
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def log_plan_generated(
        self,
        plan_id: str,
        task_id: str,
        objective: str,
        target: str,
        user: str,
        steps_count: int,
        risk_level: str
    ) -> AuditEntry:
        """Log plan generation"""
        
        entry = self._create_entry(
            event_type=AuditEventType.PLAN_GENERATED,
            user=user,
            description=f"Plan generated: {objective}",
            details={
                "objective": objective,
                "steps": steps_count,
                "risk_level": risk_level
            },
            plan_id=plan_id,
            task_id=task_id,
            target=target,
            severity="INFO"
        )
        
        self._append_entry(entry)
        
        logger.info(f"[PLAN_GENERATED] {plan_id} by {user} for {target}")
        
        return entry
    
    def log_approval_requested(
        self,
        plan_id: str,
        task_id: str,
        target: str,
        user: str,
        risk_level: str
    ) -> AuditEntry:
        """Log approval request"""
        
        entry = self._create_entry(
            event_type=AuditEventType.APPROVAL_REQUESTED,
            user=user,
            description=f"Approval requested for plan {plan_id}",
            details={
                "plan_id": plan_id,
                "risk_level": risk_level,
                "target": target
            },
            plan_id=plan_id,
            task_id=task_id,
            target=target,
            severity="WARNING"  # This is important
        )
        
        self._append_entry(entry)
        
        logger.warning(f"[APPROVAL_REQUESTED] {plan_id} - awaiting user approval")
        
        return entry
    
    def log_approval_granted(
        self,
        plan_id: str,
        task_id: str,
        target: str,
        approved_by: str,
        approval_notes: str = ""
    ) -> AuditEntry:
        """Log approval granted (USER RESPONSIBILITY POINT)"""
        
        entry = self._create_entry(
            event_type=AuditEventType.APPROVAL_GRANTED,
            user=approved_by,
            description=f"Plan {plan_id} APPROVED",
            details={
                "plan_id": plan_id,
                "target": target,
                "notes": approval_notes,
                "timestamp": datetime.now().isoformat()
            },
            plan_id=plan_id,
            task_id=task_id,
            target=target,
            severity="CRITICAL"  # User taking responsibility
        )
        
        self._append_entry(entry)
        
        logger.critical(
            f"[APPROVAL_GRANTED] {plan_id} APPROVED BY {approved_by} FOR {target}"
        )
        logger.critical(
            f"  USER ASSUMES FULL RESPONSIBILITY FOR THIS ACTION"
        )
        
        return entry
    
    def log_approval_denied(
        self,
        plan_id: str,
        task_id: str,
        target: str,
        denied_by: str,
        reason: str
    ) -> AuditEntry:
        """Log approval denied"""
        
        entry = self._create_entry(
            event_type=AuditEventType.APPROVAL_DENIED,
            user=denied_by,
            description=f"Plan {plan_id} REJECTED",
            details={
                "plan_id": plan_id,
                "target": target,
                "reason": reason
            },
            plan_id=plan_id,
            task_id=task_id,
            target=target,
            severity="INFO"
        )
        
        self._append_entry(entry)
        
        logger.info(f"[APPROVAL_DENIED] {plan_id} - {reason}")
        
        return entry
    
    def log_execution_started(
        self,
        plan_id: str,
        task_id: str,
        target: str,
        user: str,
        steps_count: int
    ) -> AuditEntry:
        """Log execution start"""
        
        entry = self._create_entry(
            event_type=AuditEventType.EXECUTION_STARTED,
            user=user,
            description=f"Plan {plan_id} execution started",
            details={
                "plan_id": plan_id,
                "target": target,
                "steps": steps_count,
                "started_at": datetime.now().isoformat()
            },
            plan_id=plan_id,
            task_id=task_id,
            target=target,
            severity="WARNING"
        )
        
        self._append_entry(entry)
        
        logger.warning(f"[EXECUTION_STARTED] {plan_id} - executing {steps_count} steps")
        
        return entry
    
    def log_command_executed(
        self,
        plan_id: str,
        step_number: int,
        command: str,
        output: str,
        error: str,
        return_code: int,
        user: str
    ) -> AuditEntry:
        """Log command execution"""
        
        entry = self._create_entry(
            event_type=AuditEventType.COMMAND_EXECUTED,
            user=user,
            description=f"Command executed in plan {plan_id}",
            details={
                "step": step_number,
                "command": command[:100],  # First 100 chars
                "return_code": return_code,
                "output_length": len(output),
                "error_length": len(error),
                "timestamp": datetime.now().isoformat()
            },
            plan_id=plan_id,
            severity="INFO"
        )
        
        self._append_entry(entry)
        
        logger.info(
            f"[COMMAND_EXECUTED] Plan {plan_id} Step {step_number} - "
            f"Return code: {return_code}"
        )
        
        return entry
    
    def log_execution_completed(
        self,
        plan_id: str,
        task_id: str,
        target: str,
        user: str,
        total_steps: int,
        successful_steps: int,
        failed_steps: int
    ) -> AuditEntry:
        """Log execution completion"""
        
        entry = self._create_entry(
            event_type=AuditEventType.EXECUTION_COMPLETED,
            user=user,
            description=f"Plan {plan_id} execution completed",
            details={
                "plan_id": plan_id,
                "target": target,
                "total_steps": total_steps,
                "successful": successful_steps,
                "failed": failed_steps,
                "completed_at": datetime.now().isoformat()
            },
            plan_id=plan_id,
            task_id=task_id,
            target=target,
            severity="WARNING"
        )
        
        self._append_entry(entry)
        
        logger.warning(
            f"[EXECUTION_COMPLETED] {plan_id} - "
            f"{successful_steps}/{total_steps} steps succeeded"
        )
        
        return entry
    
    def log_execution_failed(
        self,
        plan_id: str,
        task_id: str,
        target: str,
        user: str,
        error: str
    ) -> AuditEntry:
        """Log execution failure"""
        
        entry = self._create_entry(
            event_type=AuditEventType.EXECUTION_FAILED,
            user=user,
            description=f"Plan {plan_id} execution FAILED",
            details={
                "plan_id": plan_id,
                "target": target,
                "error": error,
                "failed_at": datetime.now().isoformat()
            },
            plan_id=plan_id,
            task_id=task_id,
            target=target,
            severity="ERROR"
        )
        
        self._append_entry(entry)
        
        logger.error(f"[EXECUTION_FAILED] {plan_id} - {error}")
        
        return entry
    
    def log_authorization_check(
        self,
        user: str,
        target: str,
        authorized: bool
    ) -> AuditEntry:
        """Log authorization check"""
        
        entry = self._create_entry(
            event_type=AuditEventType.AUTHORIZATION_CHECKED,
            user=user,
            description=f"Authorization check for {target}",
            details={
                "target": target,
                "authorized": authorized,
                "checked_at": datetime.now().isoformat()
            },
            target=target,
            severity="WARNING"
        )
        
        self._append_entry(entry)
        
        status = "AUTHORIZED" if authorized else "NOT AUTHORIZED"
        logger.warning(f"[AUTH_CHECK] {target} - {status}")
        
        return entry
    
    def _create_entry(
        self,
        event_type: AuditEventType,
        user: str,
        description: str,
        details: Dict[str, Any],
        plan_id: Optional[str] = None,
        task_id: Optional[str] = None,
        target: Optional[str] = None,
        severity: str = "INFO"
    ) -> AuditEntry:
        """Create audit entry with integrity hash"""
        
        entry = AuditEntry(
            event_type=event_type,
            user=user,
            description=description,
            details=details,
            plan_id=plan_id,
            task_id=task_id,
            target=target,
            severity=severity,
            previous_entry_hash=self.last_hash
        )
        
        # Calculate hash (without entry_hash field for integrity)
        entry_hash = self._calculate_hash(entry)
        entry.entry_hash = entry_hash
        
        return entry
    
    def _calculate_hash(self, entry: AuditEntry) -> str:
        """Calculate SHA256 hash of entry"""
        
        # Create dict without entry_hash for hashing
        entry_dict = asdict(entry)
        entry_dict.pop('entry_hash', None)
        
        entry_json = json.dumps(entry_dict, sort_keys=True, default=str)
        return hashlib.sha256(entry_json.encode()).hexdigest()
    
    def _append_entry(self, entry: AuditEntry):
        """Append entry to log (immutable)"""
        
        self.entries.append(entry)
        self.last_hash = entry.entry_hash
        
        # Write to file (append-only)
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(asdict(entry), default=str) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def get_entries_for_plan(self, plan_id: str) -> List[AuditEntry]:
        """Get all audit entries for a plan"""
        
        return [e for e in self.entries if e.plan_id == plan_id]
    
    def get_entries_for_user(self, user: str) -> List[AuditEntry]:
        """Get all audit entries for a user"""
        
        return [e for e in self.entries if e.user == user]
    
    def get_entries_for_target(self, target: str) -> List[AuditEntry]:
        """Get all audit entries for a target"""
        
        return [e for e in self.entries if e.target == target]
    
    def verify_integrity(self) -> Tuple[bool, str]:
        """
        Verify audit log integrity using hash chain.
        Detects if any entry was modified.
        """
        
        previous_hash = "0"
        
        for i, entry in enumerate(self.entries):
            if entry.previous_entry_hash != previous_hash:
                return False, f"Entry {i} broken hash chain"
            
            # Recalculate hash
            calculated_hash = self._calculate_hash(entry)
            if calculated_hash != entry.entry_hash:
                return False, f"Entry {i} hash mismatch"
            
            previous_hash = entry.entry_hash
        
        return True, "Audit log integrity verified"
    
    def export_audit_report(self) -> Dict[str, Any]:
        """Export audit report"""
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "total_entries": len(self.entries),
            "by_event_type": {},
            "by_severity": {},
            "by_user": {},
            "by_target": {},
            "entries": [asdict(e) for e in self.entries]
        }
        
        for entry in self.entries:
            # By event type
            evt = entry.event_type.value
            report["by_event_type"][evt] = report["by_event_type"].get(evt, 0) + 1
            
            # By severity
            sev = entry.severity
            report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1
            
            # By user
            user = entry.user
            report["by_user"][user] = report["by_user"].get(user, 0) + 1
            
            # By target
            if entry.target:
                tgt = entry.target
                report["by_target"][tgt] = report["by_target"].get(tgt, 0) + 1
        
        return report


# Example usage
if __name__ == "__main__":
    audit_logger = AuditLogger()
    
    print("\n=== NOVA AUDIT LOGGER ===\n")
    
    # Log various events
    audit_logger.log_plan_generated(
        plan_id="plan_123",
        task_id="task_456",
        objective="Reconnaissance",
        target="target.com",
        user="user_789",
        steps_count=5,
        risk_level="MEDIUM"
    )
    
    audit_logger.log_approval_requested(
        plan_id="plan_123",
        task_id="task_456",
        target="target.com",
        user="user_789",
        risk_level="MEDIUM"
    )
    
    audit_logger.log_approval_granted(
        plan_id="plan_123",
        task_id="task_456",
        target="target.com",
        approved_by="user_789",
        approval_notes="Target authorized"
    )
    
    audit_logger.log_execution_started(
        plan_id="plan_123",
        task_id="task_456",
        target="target.com",
        user="user_789",
        steps_count=5
    )
    
    # Verify integrity
    valid, msg = audit_logger.verify_integrity()
    print(f"\nIntegrity check: {msg}\n")
    
    # Export report
    report = audit_logger.export_audit_report()
    print(f"Total entries: {report['total_entries']}")
    print(f"By severity: {report['by_severity']}")
