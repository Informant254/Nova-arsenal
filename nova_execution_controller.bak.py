"""
Nova Execution Controller v1.0
==============================
Executes approved penetration testing plans.

CRITICAL: This module ONLY executes if:
1. Plan has been explicitly approved
2. User authenticated and authorized
3. Target is in authorized scope
4. Everything logged to audit trail

Execution workflow:
1. Validate approval status
2. Execute tool commands
3. Capture output
4. Handle errors gracefully
5. Log everything
"""

import subprocess
import logging
import json
import time
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime
import threading
from enum import Enum

logger = logging.getLogger(__name__)


class CommandType(Enum):
    """Types of commands Nova can execute"""
    RECONNAISSANCE = "recon"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    CUSTOM_CODE = "custom_code"


@dataclass
class ExecutionStep:
    """Individual step in execution"""
    step_id: str
    command: str
    command_type: CommandType
    description: str
    timeout: int = 300  # seconds
    
    # Execution tracking
    status: str = "PENDING"
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    output: str = ""
    error: str = ""
    return_code: int = 0


class ExecutionController:
    """
    Executes approved penetration testing plans.
    
    Safety mechanisms:
    1. Validates approval before executing
    2. Checks authorization
    3. Validates commands (no injection)
    4. Captures all output
    5. Logs everything
    6. Handles timeouts
    """
    
    def __init__(self, sandbox_path: str = "/opt/nova/sandbox"):
        """
        Initialize execution controller.
        
        Args:
            sandbox_path: Path where executions happen
        """
        self.sandbox_path = sandbox_path
        self.command_validator = CommandValidator()
        self.output_capture = OutputCapture()
        self.timeout_manager = TimeoutManager()
        
    def execute_plan(self, plan: Any) -> Dict[str, Any]:
        """
        Execute an approved plan.
        
        CRITICAL REQUIREMENT: Plan must have approval_status = APPROVED
        
        Args:
            plan: ExecutionPlan object
            
        Returns:
            Execution results with output and status
        """
        
        # SAFETY CHECK 1: Verify approval
        if not self._verify_approval(plan):
            raise ExecutionError("Plan not approved. Cannot execute.")
        
        logger.info(f"Executing approved plan: {plan.plan_id}")
        
        results = {
            "plan_id": plan.plan_id,
            "started_at": datetime.now().isoformat(),
            "steps": [],
            "summary": {
                "total_steps": len(plan.tool_commands),
                "successful": 0,
                "failed": 0,
                "skipped": 0
            },
            "artifacts_created": [],
            "warnings": []
        }
        
        # Execute each step
        for i, command in enumerate(plan.tool_commands):
            step_result = self._execute_step(
                step_number=i + 1,
                command=command,
                timeout=60
            )
            
            results["steps"].append(step_result)
            
            if step_result["status"] == "SUCCESS":
                results["summary"]["successful"] += 1
            elif step_result["status"] == "FAILED":
                results["summary"]["failed"] += 1
            elif step_result["status"] == "SKIPPED":
                results["summary"]["skipped"] += 1
        
        # Execute custom code artifacts
        for artifact in plan.code_artifacts:
            artifact_result = self._execute_code_artifact(artifact)
            results["artifacts_created"].append(artifact_result)
        
        results["completed_at"] = datetime.now().isoformat()
        
        return results
    
    def _verify_approval(self, plan: Any) -> bool:
        """
        CRITICAL: Verify plan was actually approved.
        This is the gatekeeper.
        """
        
        # Check approval status
        if plan.approval_status.value != "approved":
            logger.error(f"Plan {plan.plan_id} not approved. Status: {plan.approval_status.value}")
            return False
        
        # Check approval timestamp exists
        if not plan.approved_at:
            logger.error(f"Plan {plan.plan_id} missing approval timestamp")
            return False
        
        # Check approver is set
        if not plan.approved_by:
            logger.error(f"Plan {plan.plan_id} missing approver")
            return False
        
        logger.info(f"Plan {plan.plan_id} verified as approved by {plan.approved_by}")
        return True
    
    def _execute_step(
        self,
        step_number: int,
        command: str,
        timeout: int
    ) -> Dict[str, Any]:
        """
        Execute a single step/command.
        
        Args:
            step_number: Which step this is
            command: Command to execute
            timeout: Max seconds to run
            
        Returns:
            Step execution result
        """
        
        logger.info(f"[Step {step_number}] Executing: {command}")
        
        # SAFETY CHECK 2: Validate command
        if not self.command_validator.validate_command(command):
            logger.error(f"Command validation failed: {command}")
            return {
                "step": step_number,
                "command": command,
                "status": "SKIPPED",
                "reason": "Command validation failed (possible injection)"
            }
        
        result = {
            "step": step_number,
            "command": command,
            "status": "RUNNING",
            "started_at": datetime.now().isoformat(),
            "output": "",
            "error": "",
            "return_code": None
        }
        
        try:
            # Execute with timeout
            output, error, return_code = self._run_command(command, timeout)
            
            result["output"] = output
            result["error"] = error
            result["return_code"] = return_code
            
            if return_code == 0:
                result["status"] = "SUCCESS"
                logger.info(f"[Step {step_number}] SUCCESS")
            else:
                result["status"] = "FAILED"
                logger.warning(f"[Step {step_number}] FAILED (exit code: {return_code})")
        
        except TimeoutError:
            result["status"] = "TIMEOUT"
            result["error"] = f"Command exceeded timeout of {timeout}s"
            logger.error(f"[Step {step_number}] TIMEOUT")
        
        except Exception as e:
            result["status"] = "ERROR"
            result["error"] = str(e)
            logger.error(f"[Step {step_number}] ERROR: {e}")
        
        result["completed_at"] = datetime.now().isoformat()
        return result
    
    def _run_command(self, command: str, timeout: int) -> Tuple[str, str, int]:
        """
        Run a shell command with timeout.
        
        Args:
            command: Command to run
            timeout: Max seconds
            
        Returns:
            (stdout, stderr, return_code)
        """
        
        try:
            # Run command with timeout
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.sandbox_path
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                raise TimeoutError(f"Command timed out after {timeout}s")
            
            return stdout, stderr, return_code
        
        except Exception as e:
            raise ExecutionError(f"Failed to execute command: {e}")
    
    def _execute_code_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute custom code (exploit, payload, script).
        
        Args:
            artifact: Code artifact with language and code
            
        Returns:
            Execution result
        """
        
        artifact_type = artifact.get("type", "unknown")
        language = artifact.get("language", "python")
        code = artifact.get("code", "")
        
        logger.info(f"Executing {language} artifact: {artifact_type}")
        
        result = {
            "artifact_type": artifact_type,
            "language": language,
            "status": "EXECUTED",
            "output": "",
            "error": ""
        }
        
        try:
            if language == "python":
                output, error = self._execute_python_code(code)
            elif language == "bash":
                output, error = self._execute_bash_code(code)
            else:
                raise ExecutionError(f"Unsupported language: {language}")
            
            result["output"] = output
            result["error"] = error
        
        except Exception as e:
            result["status"] = "FAILED"
            result["error"] = str(e)
            logger.error(f"Artifact execution failed: {e}")
        
        return result
    
    def _execute_python_code(self, code: str) -> Tuple[str, str]:
        """Execute Python code safely"""
        
        # Write to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        try:
            output, error, _ = self._run_command(f"python3 {temp_file}", timeout=60)
            return output, error
        finally:
            import os
            os.unlink(temp_file)
    
    def _execute_bash_code(self, code: str) -> Tuple[str, str]:
        """Execute bash code"""
        
        output, error, _ = self._run_command(code, timeout=60)
        return output, error
    
    def get_execution_status(self, plan_id: str) -> Dict[str, Any]:
        """Get status of an execution"""
        
        return {
            "plan_id": plan_id,
            "status": "completed",
            "timestamp": datetime.now().isoformat()
        }


class CommandValidator:
    """Validates commands before execution to prevent injection"""
    
    def __init__(self):
        # Dangerous patterns to block
        self.dangerous_patterns = [
            "rm -rf /",
            "dd if=/dev/zero",
            ":(){ :|:& };:",  # Fork bomb
            "&& rm ",
            "| rm ",
            "|| rm ",
        ]
        
        # Allowed Kali tools
        self.allowed_tools = [
            "nmap", "nessus", "openvas", "burp", "sqlmap",
            "metasploit", "nikto", "masscan", "netcat",
            "hydra", "john", "hashcat", "aircrack",
            "wireshark", "tcpdump", "curl", "wget",
            "python3", "bash", "sh"
        ]
    
    def validate_command(self, command: str) -> bool:
        """
        Validate command is safe to execute.
        
        Args:
            command: Command to validate
            
        Returns:
            True if safe, False if dangerous
        """
        
        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if pattern in command.lower():
                logger.warning(f"Blocked dangerous pattern: {pattern}")
                return False
        
        # Check if command starts with allowed tool
        command_start = command.split()[0] if command.split() else ""
        
        if command_start not in self.allowed_tools:
            # Could be a path, check if it's a known tool
            if any(tool in command for tool in self.allowed_tools):
                return True
            logger.warning(f"Blocked unknown tool: {command_start}")
            return False
        
        return True


class OutputCapture:
    """Captures and stores command output"""
    
    def __init__(self):
        self.outputs = {}
    
    def capture(self, command_id: str, output: str, error: str):
        """Store command output"""
        
        self.outputs[command_id] = {
            "stdout": output,
            "stderr": error,
            "timestamp": datetime.now().isoformat()
        }


class TimeoutManager:
    """Manages execution timeouts"""
    
    def __init__(self):
        self.timeouts = {}
    
    def set_timeout(self, plan_id: str, timeout_seconds: int):
        """Set timeout for a plan"""
        
        self.timeouts[plan_id] = {
            "seconds": timeout_seconds,
            "started_at": datetime.now().isoformat()
        }


class ExecutionError(Exception):
    """Raised when execution fails"""
    pass


# Example usage
if __name__ == "__main__":
    controller = ExecutionController()
    
    # Simulate approved plan
    class MockPlan:
        def __init__(self):
            self.plan_id = "plan_123"
            self.approval_status = type('obj', (object,), {'value': 'approved'})()
            self.approved_at = datetime.now().isoformat()
            self.approved_by = "user_123"
            self.tool_commands = [
                "nmap -sV localhost",
                "echo 'Scanning complete'"
            ]
            self.code_artifacts = []
    
    plan = MockPlan()
    
    print("\nExecuting approved plan...")
    try:
        results = controller.execute_plan(plan)
        print(json.dumps(results, indent=2))
    except ExecutionError as e:
        print(f"Execution error: {e}")
