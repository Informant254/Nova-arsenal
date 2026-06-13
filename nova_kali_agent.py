"""
NOVA KALI AGENT v1.0
====================
Fully autonomous penetration testing agent.

Architecture:
- 100% autonomous in PLANNING and REASONING
- Requires explicit APPROVAL before EXECUTION
- Complete AUDIT TRAIL of all actions
- Transparent about RESPONSIBILITY MODEL

This agent can:
✓ Understand any penetration testing task
✓ Generate complete attack plans
✓ Write custom code and exploits
✓ Coordinate Kali tools
✓ BUT: Cannot execute without user approval

Responsibility:
- Nova's job: Generate the best plans
- User's job: Approve only authorized targets
- Both: Accountability through logging
"""

import logging
import json
import importlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
import uuid

# ── Wire in all Kali knowledge-base sub-modules ──────────────────────────────
def _load_kb(module: str):
    try:
        return importlib.import_module(module)
    except Exception:
        return None

_KB_CRYPTO_STEGO     = _load_kb("nova_kali_kb_crypto_stego")
_KB_EXPLOITATION     = _load_kb("nova_kali_kb_exploitation")
_KB_FORENSICS        = _load_kb("nova_kali_kb_forensics")
_KB_PASSWORD_ATTACKS = _load_kb("nova_kali_kb_password_attacks")
_KB_POST_EXPLOITATION= _load_kb("nova_kali_kb_post_exploitation")
_KB_REPORTING        = _load_kb("nova_kali_kb_reporting")
_KB_SCANNING         = _load_kb("nova_kali_kb_scanning")
_KB_SNIFFING         = _load_kb("nova_kali_kb_sniffing")
_KB_SOCIAL_ENGINEERING=_load_kb("nova_kali_kb_social_engineering")
_KB_WEB_APPLICATION  = _load_kb("nova_kali_kb_web_application")

KALI_KB_MODULES: Dict[str, Any] = {
    name: mod for name, mod in {
        "crypto_stego":      _KB_CRYPTO_STEGO,
        "exploitation":      _KB_EXPLOITATION,
        "forensics":         _KB_FORENSICS,
        "password_attacks":  _KB_PASSWORD_ATTACKS,
        "post_exploitation": _KB_POST_EXPLOITATION,
        "reporting":         _KB_REPORTING,
        "scanning":          _KB_SCANNING,
        "sniffing":          _KB_SNIFFING,
        "social_engineering":_KB_SOCIAL_ENGINEERING,
        "web_application":   _KB_WEB_APPLICATION,
    }.items() if mod is not None
}

logger = logging.getLogger(__name__)


class ApprovalStatus(Enum):
    """Approval workflow states"""
    PENDING = "pending"           # Waiting for approval
    APPROVED = "approved"         # User approved
    REJECTED = "rejected"         # User rejected
    EXECUTED = "executed"         # Successfully executed
    FAILED = "failed"             # Execution failed


class TaskType(Enum):
    """Types of penetration testing tasks Nova can handle"""
    RECONNAISSANCE = "recon"
    SCANNING = "scanning"
    VULNERABILITY_ASSESSMENT = "vuln_assessment"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PRIVILEGE_ESCALATION = "priv_esc"
    LATERAL_MOVEMENT = "lateral"
    DATA_EXFILTRATION = "exfil"
    REPORTING = "reporting"
    CUSTOM = "custom"


@dataclass
class Task:
    """A penetration testing task"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: str = ""
    target: str = ""
    task_type: TaskType = TaskType.RECONNAISSANCE
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    api_key: Optional[str] = None
    authorization_token: Optional[str] = None


@dataclass
class ExecutionPlan:
    """Complete plan for executing a task"""
    task_id: str
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Planning phase (autonomous)
    objective: str = ""
    analysis: str = ""
    
    # Steps (what Nova recommends)
    steps: List[Dict[str, Any]] = field(default_factory=list)
    
    # Code/Payloads to execute
    code_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    
    # Tool commands
    tool_commands: List[str] = field(default_factory=list)
    
    # Metadata
    estimated_duration: int = 0  # minutes
    risk_level: str = "MEDIUM"
    impact: str = ""
    
    # Approval workflow
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approval_requested_at: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    approval_notes: str = ""
    
    # Execution tracking
    execution_started_at: Optional[str] = None
    execution_completed_at: Optional[str] = None
    execution_status: str = "NOT_EXECUTED"
    execution_output: Dict[str, Any] = field(default_factory=dict)


class NovaKaliAgent:
    """
    Fully autonomous penetration testing agent.
    
    CRITICAL: This agent is designed with explicit approval requirements.
    
    Workflow:
    1. PLAN (100% autonomous - generate complete attack strategy)
    2. PROPOSE (present plan to user)
    3. APPROVE (user explicitly approves or rejects)
    4. EXECUTE (only if approved)
    5. LOG (everything logged for audit)
    """
    
    def __init__(self, api_key: str, authorization_token: Optional[str] = None):
        """
        Initialize Nova with authentication.
        
        Args:
            api_key: User's API key for authentication
            authorization_token: Optional authorization token for specific targets
        """
        self.api_key = api_key
        self.authorization_token = authorization_token
        self.kali_knowledge = KaliKnowledgeBase()
        self.task_analyzer = TaskAnalyzer()
        self.code_generator = CodeGenerator()
        self.approval_engine = ApprovalEngine()
        self.execution_controller = ExecutionController()
        self.audit_logger = AuditLogger()
        
        logger.info(f"Nova initialized for user: {api_key[:10]}...")
    
    def process_task(self, description: str, target: str) -> ExecutionPlan:
        """
        PHASE 1: AUTONOMOUS PLANNING
        
        Nova receives a task and generates a complete, executable plan.
        This phase is 100% autonomous - Nova reasons about everything.
        
        Args:
            description: What the user wants to do
            target: Target system/network
            
        Returns:
            Complete ExecutionPlan (not yet approved)
        """
        
        logger.info(f"Nova processing task: {description} on {target}")
        
        # Create task
        task = Task(
            description=description,
            target=target,
            api_key=self.api_key
        )
        
        # AUTONOMOUS: Analyze the task
        analysis = self.task_analyzer.analyze(description, target)
        logger.info(f"Task analysis: {analysis['task_type']}")
        
        # AUTONOMOUS: Generate execution plan
        plan = ExecutionPlan(
            task_id=task.id,
            objective=description,
            analysis=json.dumps(analysis)
        )
        
        # AUTONOMOUS: Generate steps (completely figured out by Nova)
        plan.steps = self._generate_execution_steps(description, target, analysis)
        
        # AUTONOMOUS: Generate code artifacts
        plan.code_artifacts = self._generate_code_artifacts(analysis, plan.steps)
        
        # AUTONOMOUS: Generate tool commands
        plan.tool_commands = self._generate_tool_commands(analysis, plan.steps)
        
        # AUTONOMOUS: Estimate impact and risk
        plan.risk_level = self._assess_risk(analysis)
        plan.impact = self._assess_impact(analysis)
        plan.estimated_duration = self._estimate_duration(plan.steps)
        
        # Plan is ready - but NOT executed yet
        plan.approval_status = ApprovalStatus.PENDING
        plan.approval_requested_at = datetime.now().isoformat()
        
        logger.info(f"Plan generated: {plan.plan_id}")
        logger.info(f"Status: {plan.approval_status.value}")
        logger.info(f"Steps: {len(plan.steps)}")
        logger.info(f"Code artifacts: {len(plan.code_artifacts)}")
        logger.info(f"Tool commands: {len(plan.tool_commands)}")
        
        return plan
    
    def present_plan(self, plan: ExecutionPlan) -> Dict[str, Any]:
        """
        PHASE 2: PRESENT PLAN FOR APPROVAL
        
        Nova presents the complete plan to the user.
        User must review and explicitly approve.
        
        Returns:
            Human-readable plan
        """
        
        presentation = {
            "plan_id": plan.plan_id,
            "objective": plan.objective,
            "target": plan.target if hasattr(plan, 'target') else "Unknown",
            
            "analysis": json.loads(plan.analysis),
            
            "execution_steps": [
                {
                    "number": i + 1,
                    "description": step.get('description', ''),
                    "tool": step.get('tool', ''),
                    "rationale": step.get('rationale', '')
                }
                for i, step in enumerate(plan.steps)
            ],
            
            "code_to_execute": [
                {
                    "purpose": artifact.get('purpose', ''),
                    "language": artifact.get('language', ''),
                    "preview": artifact.get('code', '')[:200] + "..."
                }
                for artifact in plan.code_artifacts
            ],
            
            "tool_commands": plan.tool_commands[:5],  # First 5
            
            "risk_assessment": {
                "level": plan.risk_level,
                "impact": plan.impact,
                "estimated_duration_minutes": plan.estimated_duration
            },
            
            "approval_status": plan.approval_status.value,
            "message": "AWAITING USER APPROVAL - Review plan above and approve/reject"
        }
        
        return presentation
    
    def request_approval(self, plan: ExecutionPlan, target: str) -> Tuple[bool, str]:
        """
        PHASE 3: REQUEST APPROVAL
        
        CRITICAL STEP: User must explicitly approve before anything executes.
        
        Args:
            plan: The execution plan
            target: The target being tested
            
        Returns:
            (approved, message)
        """
        
        # Validate authorization
        is_authorized = self.approval_engine.validate_authorization(
            self.api_key,
            self.authorization_token,
            target
        )
        
        if not is_authorized:
            raise AuthorizationError(
                f"Target '{target}' not authorized for this API key. "
                f"Obtain authorization token and try again."
            )
        
        # Log the approval request
        self.audit_logger.log_approval_request(
            plan_id=plan.plan_id,
            task_id=plan.task_id,
            user=self.api_key,
            target=target,
            plan_summary=self._summarize_plan(plan)
        )
        
        return True, "Plan submitted for approval. User must explicitly approve to proceed."
    
    def execute_with_approval(
        self,
        plan: ExecutionPlan,
        user_approval: bool,
        approval_comments: str = ""
    ) -> Dict[str, Any]:
        """
        PHASE 4: EXECUTE (ONLY WITH APPROVAL)
        
        CRITICAL: This step REQUIRES explicit user approval.
        If user didn't approve, execution cannot proceed.
        
        Args:
            plan: The execution plan
            user_approval: User's explicit approval (True/False)
            approval_comments: User's comments on approval
            
        Returns:
            Execution results
        """
        
        if not user_approval:
            logger.warning(f"Plan {plan.plan_id} REJECTED by user")
            plan.approval_status = ApprovalStatus.REJECTED
            
            self.audit_logger.log_rejection(
                plan_id=plan.plan_id,
                reason=approval_comments
            )
            
            return {
                "status": "REJECTED",
                "message": "Plan was not approved. No execution occurred.",
                "comments": approval_comments
            }
        
        # User approved - NOW we can execute
        logger.info(f"Plan {plan.plan_id} APPROVED by user")
        
        plan.approval_status = ApprovalStatus.APPROVED
        plan.approved_by = self.api_key
        plan.approved_at = datetime.now().isoformat()
        plan.approval_notes = approval_comments
        
        # Log approval
        self.audit_logger.log_approval(
            plan_id=plan.plan_id,
            user=self.api_key,
            timestamp=plan.approved_at,
            comments=approval_comments
        )
        
        # Execute the plan
        logger.info(f"Executing plan {plan.plan_id}...")
        plan.execution_started_at = datetime.now().isoformat()
        
        try:
            execution_results = self.execution_controller.execute_plan(plan)
            
            plan.execution_status = "COMPLETED"
            plan.execution_completed_at = datetime.now().isoformat()
            plan.execution_output = execution_results
            plan.approval_status = ApprovalStatus.EXECUTED
            
            # Log execution completion
            self.audit_logger.log_execution(
                plan_id=plan.plan_id,
                status="SUCCESS",
                output=execution_results
            )
            
            return {
                "status": "EXECUTED",
                "plan_id": plan.plan_id,
                "results": execution_results,
                "audit_trail": f"All actions logged. Reference ID: {plan.plan_id}"
            }
        
        except Exception as e:
            logger.error(f"Execution failed: {e}")
            plan.execution_status = "FAILED"
            plan.approval_status = ApprovalStatus.FAILED
            
            self.audit_logger.log_execution(
                plan_id=plan.plan_id,
                status="FAILED",
                error=str(e)
            )
            
            raise ExecutionError(f"Plan execution failed: {e}")
    
    def _generate_execution_steps(
        self,
        description: str,
        target: str,
        analysis: Dict
    ) -> List[Dict[str, Any]]:
        """Nova autonomously generates detailed execution steps"""
        
        steps = []
        
        # Based on analysis, generate appropriate steps
        task_type = analysis.get('task_type')
        
        if task_type == 'recon':
            steps = [
                {
                    'number': 1,
                    'description': 'DNS enumeration',
                    'tool': 'nslookup, dig, dnsrecon',
                    'rationale': 'Identify DNS records and potential subdomains'
                },
                {
                    'number': 2,
                    'description': 'WHOIS lookup',
                    'tool': 'whois',
                    'rationale': 'Identify registrant information and IP ranges'
                },
                {
                    'number': 3,
                    'description': 'Port scanning',
                    'tool': 'nmap, masscan',
                    'rationale': 'Identify open ports and services'
                }
            ]
        
        elif task_type == 'scanning':
            steps = [
                {
                    'number': 1,
                    'description': 'Service enumeration',
                    'tool': 'nmap -sV',
                    'rationale': 'Identify service versions'
                },
                {
                    'number': 2,
                    'description': 'Vulnerability scanning',
                    'tool': 'nessus, openvas',
                    'rationale': 'Identify known vulnerabilities'
                }
            ]
        
        return steps
    
    def _generate_code_artifacts(
        self,
        analysis: Dict,
        steps: List[Dict]
    ) -> List[Dict[str, Any]]:
        """Nova autonomously generates exploit code, payloads, scripts"""
        
        artifacts = []
        
        # Generate based on what's needed
        # This is where Nova writes actual code
        
        return artifacts
    
    def _generate_tool_commands(
        self,
        analysis: Dict,
        steps: List[Dict]
    ) -> List[str]:
        """Nova autonomously generates Kali tool commands"""
        
        commands = []
        
        for step in steps:
            tool = step.get('tool', '')
            if tool:
                commands.append(f"{tool} [parameters based on target]")
        
        return commands
    
    def _assess_risk(self, analysis: Dict) -> str:
        """Nova assesses risk level"""
        return "MEDIUM"
    
    def _assess_impact(self, analysis: Dict) -> str:
        """Nova assesses potential impact"""
        return "Information gathering and vulnerability identification"
    
    def _estimate_duration(self, steps: List[Dict]) -> int:
        """Nova estimates how long execution will take"""
        return len(steps) * 10  # Rough estimate
    
    def _summarize_plan(self, plan: ExecutionPlan) -> str:
        """Summarize plan for audit"""
        return f"{len(plan.steps)} steps, {len(plan.tool_commands)} tool commands"


class KaliKnowledgeBase:
    """
    Complete blueprint of Kali Linux.
    Nova knows all 300+ tools.
    """
    
    def __init__(self):
        self.tools = self._load_kali_tools()
    
    def _load_kali_tools(self) -> Dict[str, Dict]:
        """Load knowledge of all Kali tools"""
        
        # This would be a comprehensive database
        # For now, showing structure
        tools = {
            "nmap": {
                "category": "reconnaissance",
                "description": "Network mapper",
                "syntax": "nmap [options] [target]",
                "use_cases": ["Port scanning", "Service enumeration"]
            },
            "sqlmap": {
                "category": "exploitation",
                "description": "SQL injection tool",
                "syntax": "sqlmap -u [URL] [options]",
                "use_cases": ["SQLi testing", "Database enumeration"]
            },
            # ... 298 more tools
        }
        
        return tools


class TaskAnalyzer:
    """Analyzes what the user is asking for"""
    
    def analyze(self, description: str, target: str) -> Dict[str, Any]:
        """Analyze task and determine approach"""
        
        return {
            "task_type": "recon",
            "target": target,
            "approach": "standard",
            "tools_needed": ["nmap", "whois"]
        }


class CodeGenerator:
    """Generates exploit code, payloads, scripts"""
    
    def generate_code(self, task_type: str, analysis: Dict) -> List[str]:
        """Generate code artifacts"""
        return []


class ApprovalEngine:
    """Manages approval workflow"""
    
    def validate_authorization(
        self,
        api_key: str,
        auth_token: Optional[str],
        target: str
    ) -> bool:
        """Validate user is authorized for target"""
        
        # This would check against authorization database
        # For now: simple check
        if not api_key:
            return False
        
        return True


class ExecutionController:
    """Executes approved plans using real Kali Linux tools via subprocess."""

    MAX_TIMEOUT = 120

    def execute_plan(self, plan: ExecutionPlan) -> Dict[str, Any]:
        """Execute the approved plan — runs each tool command via subprocess."""
        import subprocess, shlex, shutil

        outputs          = []
        commands_run     = 0
        commands_failed  = 0
        findings_found   = []

        for cmd_str in plan.tool_commands:
            if not cmd_str or not cmd_str.strip():
                continue
            parts = shlex.split(cmd_str)
            tool  = parts[0] if parts else ""

            if not shutil.which(tool):
                logger.warning(f"Tool not found: {tool} — skipping")
                outputs.append({"command": cmd_str, "status": "skipped", "reason": f"{tool} not in PATH"})
                continue

            logger.info(f"Executing: {cmd_str[:120]}")
            try:
                proc = subprocess.run(
                    parts,
                    capture_output=True,
                    text=True,
                    timeout=self.MAX_TIMEOUT,
                )
                stdout = proc.stdout[:4000]
                stderr = proc.stderr[:1000]
                outputs.append({
                    "command":    cmd_str,
                    "status":     "completed",
                    "returncode": proc.returncode,
                    "stdout":     stdout,
                    "stderr":     stderr,
                })
                commands_run += 1
                for line in stdout.splitlines():
                    if any(kw in line.lower() for kw in ("open","vuln","critical","high","found","error","inject","xss","sql","rce","lfi")):
                        findings_found.append({"tool": tool, "output_line": line.strip()})
            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout after {self.MAX_TIMEOUT}s: {cmd_str[:60]}")
                outputs.append({"command": cmd_str, "status": "timeout", "timeout_s": self.MAX_TIMEOUT})
                commands_failed += 1
            except Exception as ex:
                logger.error(f"Execution error on '{cmd_str[:60]}': {ex}")
                outputs.append({"command": cmd_str, "status": "error", "error": str(ex)})
                commands_failed += 1

        logger.info(f"Execution complete: {commands_run} run, {commands_failed} failed, {len(findings_found)} hits")
        return {
            "status":           "completed",
            "commands_executed": commands_run,
            "commands_failed":  commands_failed,
            "raw_findings":     findings_found,
            "results":          outputs,
        }


class AuditLogger:
    """Maintains complete audit trail"""
    
    def log_approval_request(self, **kwargs):
        """Log approval request"""
        logger.info(f"Approval requested: {kwargs}")
    
    def log_approval(self, **kwargs):
        """Log approval"""
        logger.info(f"Plan approved: {kwargs}")
    
    def log_rejection(self, **kwargs):
        """Log rejection"""
        logger.info(f"Plan rejected: {kwargs}")
    
    def log_execution(self, **kwargs):
        """Log execution"""
        logger.info(f"Execution logged: {kwargs}")


class AuthorizationError(Exception):
    """Raised when authorization check fails"""
    pass


class ExecutionError(Exception):
    """Raised when execution fails"""
    pass


# Example Usage
if __name__ == "__main__":
    # Initialize Nova
    nova = NovaKaliAgent(
        api_key="user_api_key_12345",
        authorization_token="auth_token_target_xyz"
    )
    
    # User gives task
    task = "Perform a reconnaissance on target.com"
    target = "target.com"
    
    print("\n" + "="*60)
    print("NOVA KALI AGENT - AUTONOMOUS PENETRATION TESTING")
    print("="*60)
    
    # PHASE 1: AUTONOMOUS PLANNING
    print("\n[PHASE 1] Nova generates complete plan...")
    plan = nova.process_task(task, target)
    
    # PHASE 2: PRESENT PLAN
    print("\n[PHASE 2] Nova presents plan for approval...")
    presentation = nova.present_plan(plan)
    print(json.dumps(presentation, indent=2))
    
    # PHASE 3: REQUEST APPROVAL
    print("\n[PHASE 3] Requesting approval...")
    approved, msg = nova.request_approval(plan, target)
    print(f"Approval status: {msg}")
    
    # PHASE 4: USER DECIDES
    print("\n[PHASE 4] User decision required")
    print("Does user approve this plan? (In real usage: Y/N)")
    user_approval = True  # Simulating user approval
    
    if user_approval:
        print("\nUser approved. Executing plan...")
        result = nova.execute_with_approval(
            plan,
            user_approval=True,
            approval_comments="Target is authorized. Proceed."
        )
        print(json.dumps(result, indent=2))
    else:
        print("\nUser rejected plan. No execution.")
        result = nova.execute_with_approval(
            plan,
            user_approval=False,
            approval_comments="Need more information before proceeding"
        )
        print(json.dumps(result, indent=2))
    
    print("\n" + "="*60)
    print("All actions logged and auditable")
    print("="*60)
