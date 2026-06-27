"""
Safety Controls — Pentera-inspired emergency stop, stealth modes, and guardrails.

Every action must pass through the safety checker before execution.
Emergency stop halts ALL operations immediately.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class StealthMode(Enum):
    """Noise levels for testing operations."""
    LOUD = "loud"
    NORMAL = "normal"
    QUIET = "quiet"
    SILENT = "silent"


class OperationStatus(Enum):
    """Status of a tracked operation."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass
class OperationRequest:
    """A request to perform an operation that must pass safety checks."""
    operation_id: str
    operation_type: str
    target: str
    technique_id: str | None = None
    risk_level: int = 5
    reversible: bool = True
    requires_approval: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    approved: bool = False
    status: OperationStatus = OperationStatus.PENDING
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "target": self.target,
            "technique_id": self.technique_id,
            "risk_level": self.risk_level,
            "reversible": self.reversible,
            "requires_approval": self.requires_approval,
            "created_at": self.created_at.isoformat(),
            "approved": self.approved,
            "status": self.status.value,
        }


@dataclass
class SafetyRule:
    """A rule that gates operation execution."""
    rule_id: str
    description: str
    max_risk_level: int = 10
    allowed_types: set[str] = field(default_factory=set)
    blocked_targets: set[str] = field(default_factory=set)
    require_reversible: bool = False
    max_concurrent: int = 10
    require_approval_above: int = 7
    stealth_min: StealthMode = StealthMode.NORMAL


@dataclass
class SafetyAuditEntry:
    """An audit log entry for safety decisions."""
    entry_id: str
    operation_id: str
    decision: str
    reason: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "operation_id": self.operation_id,
            "decision": self.decision,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


class SafetyController:
    """
    Pentera-inspired safety controller.

    Every operation passes through safety checks before execution.
    Emergency stop halts all operations immediately.
    """

    def __init__(self, rule: SafetyRule | None = None):
        self.rule = rule or SafetyRule(
            rule_id="default",
            description="Default safety rule",
            max_risk_level=10,
            require_reversible=False,
            max_concurrent=10,
            require_approval_above=7,
        )
        self._active_operations: dict[str, OperationRequest] = {}
        self._audit_log: list[SafetyAuditEntry] = []
        self._emergency_stopped = False
        self._approval_callbacks: dict[str, callable] = {}
        self._lock = asyncio.Lock()

    @property
    def is_emergency_stopped(self) -> bool:
        return self._emergency_stopped

    @property
    def active_count(self) -> int:
        return len(self._active_operations)

    async def check_operation(self, request: OperationRequest) -> tuple[bool, str]:
        """Check if an operation passes all safety rules. Returns (allowed, reason)."""
        if self._emergency_stopped:
            self._audit(request.operation_id, "BLOCKED", "Emergency stop active")
            return False, "Emergency stop is active — all operations halted"

        if request.target in self.rule.blocked_targets:
            self._audit(request.operation_id, "BLOCKED", f"Target blocked: {request.target}")
            return False, f"Target {request.target} is blocked by safety rules"

        if request.risk_level > self.rule.max_risk_level:
            self._audit(
                request.operation_id, "BLOCKED",
                f"Risk {request.risk_level} exceeds max {self.rule.max_risk_level}",
            )
            return False, f"Risk level {request.risk_level} exceeds maximum {self.rule.max_risk_level}"

        if self.rule.require_reversible and not request.reversible:
            self._audit(request.operation_id, "BLOCKED", "Non-reversible operation blocked")
            return False, "Operation must be reversible per safety rules"

        if self.active_count >= self.rule.max_concurrent:
            self._audit(
                request.operation_id, "BLOCKED",
                f"Max concurrent {self.rule.max_concurrent} reached",
            )
            return False, f"Max concurrent operations ({self.rule.max_concurrent}) reached"

        if request.risk_level > self.rule.require_approval_above and not request.approved:
            self._audit(request.operation_id, "PENDING_APPROVAL", "High-risk operation")
            return False, f"Operation requires approval (risk {request.risk_level} > {self.rule.require_approval_above})"

        if request.operation_type in self.rule.allowed_types and self.rule.allowed_types:
            pass
        elif request.risk_level > 5:
            self._audit(request.operation_id, "WARNING", "High-risk operation allowed")
            logger.warning(f"High-risk operation {request.operation_id} allowed: risk={request.risk_level}")

        self._audit(request.operation_id, "ALLOWED", "All safety checks passed")
        return True, "All safety checks passed"

    async def request_operation(
        self,
        operation_type: str,
        target: str,
        risk_level: int = 5,
        reversible: bool = True,
        technique_id: str | None = None,
        metadata: dict | None = None,
    ) -> OperationRequest:
        """Request an operation, passing it through safety checks."""
        request = OperationRequest(
            operation_id=str(uuid.uuid4()),
            operation_type=operation_type,
            target=target,
            technique_id=technique_id,
            risk_level=risk_level,
            reversible=reversible,
            requires_approval=risk_level > self.rule.require_approval_above,
            metadata=metadata or {},
        )

        allowed, reason = await self.check_operation(request)
        if allowed:
            request.status = OperationStatus.RUNNING
            async with self._lock:
                self._active_operations[request.operation_id] = request
        else:
            request.status = OperationStatus.BLOCKED
            self._audit(request.operation_id, "DENIED", reason)

        return request

    async def complete_operation(self, operation_id: str, success: bool = True) -> None:
        """Mark an operation as completed."""
        async with self._lock:
            op = self._active_operations.pop(operation_id, None)
        if op:
            op.status = OperationStatus.COMPLETED if success else OperationStatus.FAILED
            self._audit(operation_id, "COMPLETED" if success else "FAILED", "Operation finished")

    async def cancel_operation(self, operation_id: str) -> None:
        """Cancel an active operation."""
        async with self._lock:
            op = self._active_operations.pop(operation_id, None)
        if op:
            op.status = OperationStatus.CANCELLED
            self._audit(operation_id, "CANCELLED", "Operation cancelled")

    async def emergency_stop(self) -> str:
        """Halt ALL operations immediately. Returns stop ID."""
        self._emergency_stopped = True
        stop_id = str(uuid.uuid4())

        async with self._lock:
            cancelled = list(self._active_operations.keys())
            for op_id in cancelled:
                op = self._active_operations.pop(op_id)
                op.status = OperationStatus.CANCELLED

        self._audit(stop_id, "EMERGENCY_STOP", f"Cancelled {len(cancelled)} active operations")
        logger.critical(f"EMERGENCY STOP {stop_id}: Cancelled {len(cancelled)} operations")
        return stop_id

    async def resume(self) -> None:
        """Resume operations after emergency stop."""
        self._emergency_stopped = False
        self._audit("system", "RESUMED", "Emergency stop lifted")
        logger.info("Emergency stop lifted — operations resumed")

    async def approve_operation(self, operation_id: str) -> bool:
        """Approve a pending high-risk operation."""
        async with self._lock:
            for op in self._active_operations.values():
                if op.operation_id == operation_id:
                    op.approved = True
                    self._audit(operation_id, "APPROVED", "High-risk operation approved")
                    return True
        return False

    async def block_target(self, target: str) -> None:
        """Add a target to the blocklist."""
        self.rule.blocked_targets.add(target)
        self._audit("system", "TARGET_BLOCKED", f"Target {target} added to blocklist")

    async def unblock_target(self, target: str) -> None:
        """Remove a target from the blocklist."""
        self.rule.blocked_targets.discard(target)
        self._audit("system", "TARGET_UNBLOCKED", f"Target {target} removed from blocklist")

    def get_audit_log(self, limit: int = 100) -> list[dict]:
        """Return recent audit log entries."""
        entries = self._audit_log[-limit:]
        return [e.to_dict() for e in entries]

    def get_active_operations(self) -> list[dict]:
        """Return all active operations."""
        return [op.to_dict() for op in self._active_operations.values()]

    def _audit(self, operation_id: str, decision: str, reason: str) -> None:
        entry = SafetyAuditEntry(
            entry_id=str(uuid.uuid4()),
            operation_id=operation_id,
            decision=decision,
            reason=reason,
        )
        self._audit_log.append(entry)
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-5000:]
