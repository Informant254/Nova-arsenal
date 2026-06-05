"""
Nova Approval Workflow v1.0
===========================
CRITICAL COMPONENT: Manages approval process.

This is where user responsibility begins.
Nova generates the plan, user approves execution.

Workflow:
1. Plan generated (Nova autonomous)
2. Presented to user
3. User reviews carefully
4. User approves or rejects (explicit decision)
5. Only then execution happens
6. Everything logged

IMPORTANT: User who approves is responsible for:
- Target authorization
- Legal compliance
- Scope adherence
- Consequences
"""

import logging
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import uuid

logger = logging.getLogger(__name__)


class ApprovalStatus(Enum):
    """Status of approval"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"
    EXECUTED = "executed"


class RiskLevel(Enum):
    """Risk level of plan"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ApprovalRequest:
    """Request for plan approval"""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    plan_id: str = ""
    task_id: str = ""
    
    # Who is requesting
    requested_by: str = ""  # API key
    request_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # What's being requested
    objective: str = ""
    target: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    
    # Plan details
    steps_count: int = 0
    commands_count: int = 0
    code_artifacts_count: int = 0
    
    # Approval details
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: Optional[str] = None  # User who approved
    approved_timestamp: Optional[str] = None
    approval_notes: str = ""
    
    # Rejection details (if rejected)
    rejected_reason: str = ""
    
    # Execution tracking
    executed_at: Optional[str] = None
    execution_result: str = ""


@dataclass
class ApprovalPolicy:
    """Policy for approvals"""
    requires_approval: bool = True
    auto_approve_if_low_risk: bool = False
    low_risk_threshold: RiskLevel = RiskLevel.LOW
    requires_written_authorization: bool = True
    max_approval_time_hours: int = 24
    log_all_approvals: bool = True


class ApprovalWorkflow:
    """
    Manages approval process.
    This is critical - user decision point.
    """
    
    def __init__(self, policy: Optional[ApprovalPolicy] = None):
        """
        Initialize approval workflow.
        
        Args:
            policy: Approval policy (defaults to strict)
        """
        self.policy = policy or ApprovalPolicy()
        self.pending_requests: Dict[str, ApprovalRequest] = {}
        self.approval_history: List[ApprovalRequest] = []
        self.authorization_db = AuthorizationDatabase()
    
    def create_approval_request(
        self,
        plan_id: str,
        task_id: str,
        objective: str,
        target: str,
        risk_level: RiskLevel,
        steps_count: int,
        commands_count: int,
        code_artifacts_count: int,
        requested_by: str
    ) -> ApprovalRequest:
        """
        Create approval request.
        
        Args:
            plan_id: ID of plan needing approval
            task_id: ID of task
            objective: What the plan does
            target: Target being tested
            risk_level: Risk level of plan
            steps_count: Number of steps
            commands_count: Number of commands
            code_artifacts_count: Number of code artifacts
            requested_by: API key requesting approval
            
        Returns:
            ApprovalRequest
        """
        
        request = ApprovalRequest(
            plan_id=plan_id,
            task_id=task_id,
            objective=objective,
            target=target,
            risk_level=risk_level,
            steps_count=steps_count,
            commands_count=commands_count,
            code_artifacts_count=code_artifacts_count,
            requested_by=requested_by
        )
        
        self.pending_requests[request.request_id] = request
        
        logger.info(f"Approval request created: {request.request_id}")
        logger.info(f"  Plan: {plan_id}")
        logger.info(f"  Target: {target}")
        logger.info(f"  Risk: {risk_level.value}")
        logger.info(f"  Status: AWAITING APPROVAL")
        
        return request
    
    def present_for_approval(self, request: ApprovalRequest) -> Dict[str, any]:
        """
        Present plan for user approval.
        
        Returns:
            Human-readable approval request
        """
        
        presentation = {
            "request_id": request.request_id,
            "plan_id": request.plan_id,
            
            "objective": request.objective,
            "target": request.target,
            
            "plan_details": {
                "steps": request.steps_count,
                "commands": request.commands_count,
                "code_artifacts": request.code_artifacts_count
            },
            
            "risk_assessment": {
                "level": request.risk_level.value.upper(),
                "requires_approval": self.policy.requires_approval
            },
            
            "what_will_happen": self._get_risk_description(request.risk_level),
            
            "authorization_check": self._check_authorization(
                request.requested_by,
                request.target
            ),
            
            "user_responsibility": {
                "required": [
                    "You are responsible for verifying target authorization",
                    "You accept legal liability for this action",
                    "You confirm the target is within authorized scope",
                    "You understand the potential impact",
                    "You are accountable for this decision"
                ]
            },
            
            "approval_required": True,
            "message": "EXPLICIT APPROVAL REQUIRED - Review above carefully. Do you approve? YES/NO"
        }
        
        return presentation
    
    def approve_request(
        self,
        request_id: str,
        approved_by: str,
        notes: str = ""
    ) -> Tuple[bool, str]:
        """
        Approve a request.
        
        CRITICAL: This is where user takes responsibility.
        
        Args:
            request_id: ID of request to approve
            approved_by: User approving (API key)
            notes: Approval notes/comments
            
        Returns:
            (success, message)
        """
        
        if request_id not in self.pending_requests:
            return False, f"Request {request_id} not found"
        
        request = self.pending_requests[request_id]
        
        # Log approval
        logger.warning(f"APPROVAL: User {approved_by} approved plan {request.plan_id}")
        logger.warning(f"  Target: {request.target}")
        logger.warning(f"  Risk: {request.risk_level.value}")
        logger.warning(f"  Timestamp: {datetime.now().isoformat()}")
        logger.warning(f"  Notes: {notes}")
        
        # Mark as approved
        request.approval_status = ApprovalStatus.APPROVED
        request.approved_by = approved_by
        request.approved_timestamp = datetime.now().isoformat()
        request.approval_notes = notes
        
        # Add to history
        self.approval_history.append(request)
        
        # Remove from pending
        del self.pending_requests[request_id]
        
        return True, f"Plan {request.plan_id} approved. Ready for execution."
    
    def reject_request(
        self,
        request_id: str,
        rejected_by: str,
        reason: str
    ) -> Tuple[bool, str]:
        """
        Reject a request.
        
        Args:
            request_id: ID of request to reject
            rejected_by: User rejecting
            reason: Why it was rejected
            
        Returns:
            (success, message)
        """
        
        if request_id not in self.pending_requests:
            return False, f"Request {request_id} not found"
        
        request = self.pending_requests[request_id]
        
        logger.info(f"REJECTION: User {rejected_by} rejected plan {request.plan_id}")
        logger.info(f"  Reason: {reason}")
        
        request.approval_status = ApprovalStatus.REJECTED
        request.rejected_reason = reason
        
        self.approval_history.append(request)
        del self.pending_requests[request_id]
        
        return True, f"Plan {request.plan_id} rejected. No execution will occur."
    
    def get_pending_requests(self, user: str) -> List[ApprovalRequest]:
        """Get pending requests for user"""
        
        return [
            req for req in self.pending_requests.values()
            if req.requested_by == user
        ]
    
    def get_approval_history(self, user: Optional[str] = None) -> List[ApprovalRequest]:
        """Get approval history"""
        
        if user:
            return [req for req in self.approval_history if req.requested_by == user]
        return self.approval_history
    
    def _check_authorization(self, api_key: str, target: str) -> Dict[str, any]:
        """Check if user is authorized for target"""
        
        is_authorized = self.authorization_db.check_authorization(api_key, target)
        
        return {
            "user": api_key[:10] + "...",
            "target": target,
            "authorized": is_authorized,
            "status": "AUTHORIZED" if is_authorized else "NOT AUTHORIZED"
        }
    
    def _get_risk_description(self, risk_level: RiskLevel) -> str:
        """Get human description of risk"""
        
        descriptions = {
            RiskLevel.LOW: "Low risk - basic information gathering",
            RiskLevel.MEDIUM: "Medium risk - active testing, some potential impact",
            RiskLevel.HIGH: "High risk - extensive active testing, significant potential impact",
            RiskLevel.CRITICAL: "CRITICAL RISK - Could cause service disruption, data loss, or major impact"
        }
        
        return descriptions.get(risk_level, "Unknown risk level")


class AuthorizationDatabase:
    """
    Manages authorization for targets.
    User must be explicitly authorized to test targets.
    """
    
    def __init__(self):
        self.authorizations: Dict[str, List[str]] = {}
    
    def add_authorization(self, api_key: str, target: str, expires_at: Optional[str] = None):
        """Grant authorization for target"""
        
        if api_key not in self.authorizations:
            self.authorizations[api_key] = []
        
        self.authorizations[api_key].append({
            "target": target,
            "authorized_at": datetime.now().isoformat(),
            "expires_at": expires_at
        })
        
        logger.info(f"Authorization granted: {api_key} → {target}")
    
    def check_authorization(self, api_key: str, target: str) -> bool:
        """Check if user authorized for target"""
        
        if api_key not in self.authorizations:
            logger.warning(f"No authorization found for {api_key}")
            return False
        
        for auth in self.authorizations[api_key]:
            if auth["target"] == target:
                # Check expiration
                if auth.get("expires_at"):
                    expires = datetime.fromisoformat(auth["expires_at"])
                    if datetime.now() > expires:
                        return False
                return True
        
        logger.warning(f"No authorization for {api_key} → {target}")
        return False
    
    def revoke_authorization(self, api_key: str, target: str) -> bool:
        """Revoke authorization"""
        
        if api_key in self.authorizations:
            self.authorizations[api_key] = [
                auth for auth in self.authorizations[api_key]
                if auth["target"] != target
            ]
            logger.info(f"Authorization revoked: {api_key} → {target}")
            return True
        
        return False


class ApprovalAuditor:
    """Audit all approval decisions"""
    
    def __init__(self):
        self.audit_log: List[Dict] = []
    
    def log_approval_decision(
        self,
        request_id: str,
        decision: str,  # "APPROVED" or "REJECTED"
        user: str,
        timestamp: str,
        notes: str = ""
    ):
        """Log approval decision"""
        
        entry = {
            "request_id": request_id,
            "decision": decision,
            "user": user,
            "timestamp": timestamp,
            "notes": notes,
            "recorded_at": datetime.now().isoformat()
        }
        
        self.audit_log.append(entry)
        
        logger.info(f"Audit: {decision} by {user} - {request_id}")
    
    def export_audit_log(self) -> List[Dict]:
        """Export audit log"""
        return self.audit_log


# Example usage
if __name__ == "__main__":
    workflow = ApprovalWorkflow()
    
    print("\n=== NOVA APPROVAL WORKFLOW ===\n")
    
    # Create request
    request = workflow.create_approval_request(
        plan_id="plan_123",
        task_id="task_456",
        objective="Perform reconnaissance on target.com",
        target="target.com",
        risk_level=RiskLevel.MEDIUM,
        steps_count=5,
        commands_count=8,
        code_artifacts_count=2,
        requested_by="user_789"
    )
    
    print(f"Request created: {request.request_id}")
    print(f"Status: {request.approval_status.value}")
    print()
    
    # Present for approval
    print("Presenting plan for approval...\n")
    presentation = workflow.present_for_approval(request)
    print(json.dumps(presentation, indent=2))
    print()
    
    # User approves
    print("User approves plan...")
    success, msg = workflow.approve_request(
        request.request_id,
        approved_by="user_789",
        notes="Target authorized. Proceeding with testing."
    )
    print(f"Result: {msg}\n")
    
    # Show history
    print("Approval history:")
    for req in workflow.get_approval_history():
        print(f"  {req.plan_id}: {req.approval_status.value}")
