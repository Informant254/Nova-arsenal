"""
Agent Runner - Full autonomous agent loop.

The brain of Nova-Arsenal. This module:
1. Takes a target and objective
2. Uses the LLM to plan and reason
3. Decides what tools/commands to use
4. Executes in the Kali sandbox
5. Parses results and feeds back to LLM
6. Writes custom code when needed
7. Iterates until objective is met or max steps reached
8. Stores findings in database
9. Emits WebSocket events for real-time updates
"""

import asyncio
import json
import logging
import traceback
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

from nova_arsenal.code_generator import CodeGenerator, CodeLanguage, GeneratedCode
from nova_arsenal.kali_blueprint import KaliBlueprint
from nova_arsenal.sandbox_executor import ExecResult, SandboxExecutor, create_executor
from nova_arsenal.secure_executor import SecureExecutor, SecurityPolicy, ValidationResult

logger = logging.getLogger(__name__)


class AgentPhase(Enum):
    """Current phase of the agent."""
    INIT = "init"
    PLANNING = "planning"
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class ActionType(Enum):
    """Types of actions the agent can take."""
    EXECUTE_COMMAND = "execute_command"
    EXECUTE_TOOL = "execute_tool"
    WRITE_AND_RUN_CODE = "write_and_run_code"
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    ANALYZE_RESULT = "analyze_result"
    REFLECT = "reflect"
    PLAN = "plan"
    REPORT_FINDING = "report_finding"


@dataclass
class AgentAction:
    """An action taken by the agent."""
    step: int
    phase: AgentPhase
    action_type: ActionType
    description: str
    command: str = ""
    result: Optional[ExecResult] = None
    analysis: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "phase": self.phase.value,
            "action_type": self.action_type.value,
            "description": self.description,
            "command": self.command,
            "exit_code": self.result.exit_code if self.result else None,
            "stdout": self.result.stdout[:500] if self.result else None,
            "analysis": self.analysis,
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
        }


@dataclass
class Finding:
    """A security finding discovered by the agent."""
    title: str
    severity: str
    description: str
    evidence: str = ""
    endpoint: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    remediation: str = ""
    tool_used: str = ""
    raw_output: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "endpoint": self.endpoint,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "tool_used": self.tool_used,
        }


# Type for event callbacks
EventCallback = Callable[[str, Dict[str, Any]], Coroutine[Any, Any, None]]


class AgentRunner:
    """
    Fully autonomous security research agent.
    
    Runs the complete loop:
    LLM reasoning → tool selection → command execution → result analysis → iteration
    """

    def __init__(
        self,
        target: str,
        objective: str = "Find and exploit all critical vulnerabilities",
        max_steps: int = 40,
        reflect_every: int = 5,
        scope: Optional[List[str]] = None,
        executor: Optional[SandboxExecutor] = None,
        llm_complete: Optional[Callable[..., Coroutine[Any, Any, str]]] = None,
        on_event: Optional[EventCallback] = None,
    ) -> None:
        self.target = target
        self.objective = objective
        self.max_steps = max_steps
        self.reflect_every = reflect_every
        self.scope = scope or [target]

        # Core components
        self.blueprint = KaliBlueprint()
        self.executor = executor or create_executor()
        self.secure = SecureExecutor(SecurityPolicy())
        self.code_gen = CodeGenerator()

        # LLM integration (injected)
        self._llm_complete = llm_complete

        # Event system
        self._on_event = on_event

        # State
        self._step = 0
        self._phase = AgentPhase.INIT
        self._actions: List[AgentAction] = []
        self._findings: List[Finding] = []
        self._context: List[Dict[str, str]] = []
        self._running = False
        self._error: Optional[str] = None

    # ── Public API ──────────────────────────────────────────────────────────

    async def run(self) -> Dict[str, Any]:
        """Execute the full autonomous agent loop."""
        self._running = True
        start_time = datetime.now(timezone.utc)

        try:
            await self._emit("agent_started", {
                "target": self.target,
                "objective": self.objective,
                "max_steps": self.max_steps,
            })

            # Phase 1: Initialize and plan
            await self._set_phase(AgentPhase.PLANNING)
            plan = await self._plan()
            await self._emit("plan_created", {"plan": plan})

            # Phase 2: Reconnaissance
            await self._set_phase(AgentPhase.RECONNAISSANCE)
            await self._execute_recon()

            # Phase 3: Scanning
            await self._set_phase(AgentPhase.SCANNING)
            await self._execute_scanning()

            # Phase 4: Exploitation
            await self._set_phase(AgentPhase.EXPLOITATION)
            await self._execute_exploitation()

            # Phase 5: Post-exploitation
            await self._set_phase(AgentPhase.POST_EXPLOITATION)
            await self._execute_post_exploitation()

            # Phase 6: Reporting
            await self._set_phase(AgentPhase.REPORTING)
            report = await self._generate_report()

            await self._set_phase(AgentPhase.COMPLETED)
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

            await self._emit("agent_completed", {
                "steps": self._step,
                "findings": len(self._findings),
                "elapsed_seconds": elapsed,
            })

            return {
                "status": "completed",
                "target": self.target,
                "objective": self.objective,
                "steps_taken": self._step,
                "findings_count": len(self._findings),
                "findings": [f.to_dict() for f in self._findings],
                "report": report,
                "elapsed_seconds": elapsed,
                "actions": [a.to_dict() for a in self._actions],
            }

        except Exception as e:
            self._error = str(e)
            logger.error(f"Agent error: {e}\n{traceback.format_exc()}")
            await self._set_phase(AgentPhase.FAILED)
            await self._emit("agent_error", {"error": str(e)})
            return {
                "status": "failed",
                "error": str(e),
                "steps_taken": self._step,
                "findings_count": len(self._findings),
                "findings": [f.to_dict() for f in self._findings],
            }
        finally:
            self._running = False

    async def step_once(self, instruction: str = "") -> AgentAction:
        """Execute a single agent step (for interactive mode)."""
        self._step += 1

        # Ask LLM what to do next
        prompt = self._build_step_prompt(instruction)
        response = await self._ask_llm(prompt)

        # Parse the response into an action
        action = self._parse_llm_action(response)

        # Validate the command
        if action.command:
            validation = self.secure.validate_command(action.command, self.scope)
            if not validation.allowed:
                action.result = ExecResult(
                    command=action.command,
                    stdout="",
                    stderr=f"BLOCKED: {validation.reason}",
                    exit_code=-1,
                )
                action.analysis = f"Command blocked by security policy: {validation.reason}"
                self._actions.append(action)
                return action

            # Execute
            start = datetime.now(timezone.utc)
            action.result = await self.executor.execute(action.command)
            action.duration_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000

            # Analyze result
            action.analysis = await self._analyze_result(action)

        self._actions.append(action)
        await self._emit("step_completed", action.to_dict())

        # Reflect periodically
        if self._step % self.reflect_every == 0:
            await self._reflect()

        return action

    def stop(self) -> None:
        """Stop the agent."""
        self._running = False

    def get_state(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "phase": self._phase.value,
            "step": self._step,
            "max_steps": self.max_steps,
            "findings": len(self._findings),
            "running": self._running,
            "error": self._error,
        }

    # ── Planning Phase ──────────────────────────────────────────────────────

    async def _plan(self) -> str:
        """Generate an attack plan using the LLM."""
        prompt = f"""You are an elite security researcher with full knowledge of Kali Linux.

TARGET: {self.target}
OBJECTIVE: {self.objective}
SCOPE: {', '.join(self.scope)}

KALI TOOLS AVAILABLE:
{self.blueprint.get_context_for_task(self.objective)}

Create a detailed step-by-step attack plan. Be specific about which tools to use and in what order.
Return the plan as a numbered list. Focus on the most impactful approach.

PLAN:"""

        plan = await self._ask_llm(prompt)
        self._context.append({"role": "system", "content": f"Attack plan:\n{plan}"})
        return plan

    # ── Reconnaissance Phase ────────────────────────────────────────────────

    async def _execute_recon(self) -> None:
        """Execute reconnaissance commands."""
        recon_tools = self.blueprint.get_tools_by_category("recon")

        # Start with DNS/subdomain enumeration
        recon_commands = [
            f"subfinder -d {self.target} -silent -o /workspace/subs.txt 2>/dev/null || echo 'subfinder not available'",
            f"cat /workspace/subs.txt 2>/dev/null | head -50 || echo 'No subdomains found yet'",
            f"nmap -sn {self.target} -oN /workspace/ping_scan.txt 2>/dev/null || echo 'nmap ping scan done'",
            f"nmap -sV -sC --top-ports 1000 {self.target} -oN /workspace/nmap_quick.txt 2>/dev/null || echo 'quick scan done'",
            f"httpx -l /workspace/subs.txt -silent -sc -title 2>/dev/null | head -30 || echo 'httpx probe done'",
        ]

        for cmd in recon_commands:
            if not self._running:
                break
            await self._execute_and_analyze(cmd, AgentPhase.RECONNAISSANCE)

    # ── Scanning Phase ──────────────────────────────────────────────────────

    async def _execute_scanning(self) -> None:
        """Execute vulnerability scanning."""
        scan_commands = [
            f"nmap -sV -sC -p- {self.target} -oN /workspace/nmap_full.txt 2>/dev/null || echo 'full scan done'",
            f"nuclei -u https://{self.target} -severity critical,high,medium -json 2>/dev/null | head -50 || echo 'nuclei scan done'",
            f"nikto -h {self.target} -o /workspace/nikto.txt 2>/dev/null || echo 'nikto scan done",
            f"whatweb {self.target} 2>/dev/null || echo 'whatweb done'",
        ]

        for cmd in scan_commands:
            if not self._running:
                break
            await self._execute_and_analyze(cmd, AgentPhase.SCANNING)

    # ── Exploitation Phase ──────────────────────────────────────────────────

    async def _execute_exploitation(self) -> None:
        """Attempt exploitation based on findings."""
        # Ask LLM what to exploit based on scan results
        scan_context = self._get_scan_results()
        prompt = f"""Based on these scan results for {self.target}, suggest specific exploitation commands:

{scan_context}

Available Kali tools for exploitation:
{chr(10).join(f'- {t.name}: {t.description}' for t in self.blueprint.get_tools_by_category('exploitation'))}
{chr(10).join(f'- {t.name}: {t.description}' for t in self.blueprint.get_tools_by_category('web_exploit'))}

Provide 3-5 specific commands to try. Return ONLY the commands, one per line:"""

        response = await self._ask_llm(prompt)
        commands = self._extract_commands(response)

        for cmd in commands:
            if not self._running:
                break
            await self._execute_and_analyze(cmd, AgentPhase.EXPLOITATION)

    # ── Post-Exploitation Phase ─────────────────────────────────────────────

    async def _execute_post_exploitation(self) -> None:
        """Post-exploitation: gather more info, pivot, extract data."""
        post_commands = [
            f"cat /workspace/nmap_full.txt 2>/dev/null | head -100 || echo 'reading scan results'",
            f"ls -la /workspace/ 2>/dev/null || echo 'listing workspace'",
            f"id && uname -a && whoami 2>/dev/null || echo 'system info'",
        ]

        for cmd in post_commands:
            if not self._running:
                break
            await self._execute_and_analyze(cmd, AgentPhase.POST_EXPLOITATION)

    # ── Core Execution ──────────────────────────────────────────────────────

    async def _execute_and_analyze(self, command: str, phase: AgentPhase) -> Optional[AgentAction]:
        """Execute a command and analyze the result."""
        self._step += 1
        await self._set_phase(phase)

        # Validate
        validation = self.secure.validate_command(command, self.scope)
        if not validation.allowed:
            action = AgentAction(
                step=self._step,
                phase=phase,
                action_type=ActionType.EXECUTE_COMMAND,
                description=f"Blocked: {command[:80]}",
                command=command,
                analysis=f"BLOCKED: {validation.reason}",
            )
            self._actions.append(action)
            return action

        # Execute
        action = AgentAction(
            step=self._step,
            phase=phase,
            action_type=ActionType.EXECUTE_COMMAND,
            description=command[:200],
            command=command,
        )

        start = datetime.now(timezone.utc)
        action.result = await self.executor.execute(command)
        action.duration_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000

        # Analyze with LLM
        action.analysis = await self._analyze_result(action)

        # Check for findings
        await self._check_for_findings(action)

        self._actions.append(action)
        await self._emit("step_completed", action.to_dict())

        # Reflect periodically
        if self._step % self.reflect_every == 0:
            await self._reflect()

        return action

    # ── LLM Integration ─────────────────────────────────────────────────────

    async def _ask_llm(self, prompt: str) -> str:
        """Ask the LLM a question."""
        if self._llm_complete:
            return await self._llm_complete(
                prompt=prompt,
                system_prompt=self._get_system_prompt(),
                temperature=0.3,
                max_tokens=4096,
            )

        # Fallback: return a simulated response for testing
        return self._simulate_llm_response(prompt)

    def _get_system_prompt(self) -> str:
        return f"""You are Nova, an elite autonomous security researcher operating in Kali Linux.

PERSONALITY:
- Methodical and thorough
- Follows the MITRE ATT&CK framework
- Always documents findings
- Respects scope boundaries
- Uses the right tool for each job

TARGET: {self.target}
SCOPE: {', '.join(self.scope)}

KALI LINUX KNOWLEDGE:
{self.blueprint.get_full_context()}

RULES:
1. Always validate commands before execution
2. Stay within the defined scope
3. Document all findings with evidence
4. Use native Kali tools when possible
5. Write custom code only when needed
6. Reflect on progress every {self.reflect_every} steps

CURRENT CONTEXT:
{self._format_context()}"""

    def _format_context(self) -> str:
        """Format recent context for the LLM."""
        recent = self._actions[-10:] if self._actions else []
        lines = []
        for a in recent:
            lines.append(f"Step {a.step}: {a.command}")
            if a.analysis:
                lines.append(f"  Analysis: {a.analysis[:200]}")
        return "\n".join(lines) if lines else "No actions taken yet."

    def _build_step_prompt(self, instruction: str = "") -> str:
        """Build a prompt for a single step."""
        return f"""Current state:
- Target: {self.target}
- Phase: {self._phase.value}
- Step: {self._step}/{self.max_steps}
- Findings so far: {len(self._findings)}

Recent actions:
{self._format_context()}

{f'Instruction: {instruction}' if instruction else 'Decide the next action to take toward the objective.'}

Respond with a JSON object:
{{
    "action": "execute_command" | "write_and_run_code" | "analyze" | "reflect",
    "command": "the command to run (if applicable)",
    "description": "what this action accomplishes",
    "code": "custom code (if action is write_and_run_code)",
    "language": "python" | "bash (if action is write_and_run_code)"
}}"""

    def _simulate_llm_response(self, prompt: str) -> str:
        """Simulated LLM response for testing."""
        if "plan" in prompt.lower():
            return """1. Run subfinder for subdomain enumeration
2. Run nmap for port scanning
3. Run nuclei for vulnerability scanning
4. Test discovered web services for vulnerabilities
5. Attempt exploitation of critical findings"""
        return '{"action": "execute_command", "command": "echo test", "description": "test step"}'

    def _parse_llm_action(self, response: str) -> AgentAction:
        """Parse LLM response into an AgentAction."""
        try:
            # Try to parse as JSON
            data = json.loads(response)
            action_type = ActionType.EXECUTE_COMMAND
            if data.get("action") == "write_and_run_code":
                action_type = ActionType.WRITE_AND_RUN_CODE
            elif data.get("action") == "analyze":
                action_type = ActionType.ANALYZE_RESULT
            elif data.get("action") == "reflect":
                action_type = ActionType.REFLECT

            return AgentAction(
                step=self._step,
                phase=self._phase,
                action_type=action_type,
                description=data.get("description", ""),
                command=data.get("command", ""),
            )
        except (json.JSONDecodeError, KeyError):
            # Fallback: extract command from text
            import re
            cmd_match = re.search(r'```(?:bash|sh)?\n(.*?)```', response, re.DOTALL)
            if cmd_match:
                return AgentAction(
                    step=self._step,
                    phase=self._phase,
                    action_type=ActionType.EXECUTE_COMMAND,
                    description="Extracted from LLM response",
                    command=cmd_match.group(1).strip(),
                )
            return AgentAction(
                step=self._step,
                phase=self._phase,
                action_type=ActionType.REFLECT,
                description=response[:200],
            )

    async def _analyze_result(self, action: AgentAction) -> str:
        """Analyze the result of an action using the LLM."""
        if not action.result:
            return "No result to analyze"

        result_text = action.result.output[:2000]
        prompt = f"""Analyze this command execution result:

Command: {action.command}
Exit code: {action.result.exit_code}
Output:
{result_text}

Provide a brief analysis:
1. Did it succeed?
2. What did we learn?
3. Are there any security findings?
4. What should we do next?

Analysis:"""

        return await self._ask_llm(prompt)

    # ── Finding Detection ───────────────────────────────────────────────────

    async def _check_for_findings(self, action: AgentAction) -> None:
        """Check action results for security findings."""
        if not action.result:
            return

        output = action.result.output.lower()

        # Simple heuristic-based finding detection
        finding_patterns = {
            "sql_injection": ["sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite3"],
            "xss": ["<script>", "alert(", "document.cookie", "onerror="],
            "rce": ["command injection", "os command", "/bin/sh", "/bin/bash"],
            "lfi": ["root:", "bin:", "passwd", "etc/passwd"],
            "info_disclosure": ["stack trace", "debug", "version", "internal server error"],
            "default_creds": ["default password", "admin/admin", "root/toor"],
        }

        for finding_type, patterns in finding_patterns.items():
            for pattern in patterns:
                if pattern in output:
                    finding = Finding(
                        title=f"Potential {finding_type.replace('_', ' ').title()} detected",
                        severity="high" if finding_type in ("rce", "sql_injection") else "medium",
                        description=f"Pattern '{pattern}' found in output of {action.command}",
                        evidence=action.result.stdout[:500],
                        tool_used=action.command.split()[0] if action.command else "",
                        raw_output=action.result.output[:1000],
                    )
                    self._findings.append(finding)
                    await self._emit("finding_discovered", finding.to_dict())
                    break

    # ── Reflection ──────────────────────────────────────────────────────────

    async def _reflect(self) -> str:
        """Reflect on progress and adjust strategy."""
        prompt = f"""Reflect on the current progress of the security assessment.

Target: {self.target}
Objective: {self.objective}
Phase: {self._phase.value}
Steps: {self._step}/{self.max_steps}
Findings: {len(self._findings)}

Recent actions:
{self._format_context()}

Findings so far:
{chr(10).join(f'- {f.title} ({f.severity})' for f in self._findings) if self._findings else 'None yet'}

Provide:
1. Assessment of progress
2. What's working well
3. What needs adjustment
4. Recommended next steps

Reflection:"""

        reflection = await self._ask_llm(prompt)
        await self._emit("reflection", {"reflection": reflection[:500]})
        return reflection

    # ── Reporting ───────────────────────────────────────────────────────────

    async def _generate_report(self) -> str:
        """Generate a final report."""
        prompt = f"""Generate a professional security assessment report for {self.target}.

Objective: {self.objective}
Steps taken: {self._step}
Findings: {len(self._findings)}

Findings detail:
{json.dumps([f.to_dict() for f in self._findings], indent=2) if self._findings else 'No findings discovered'}

Actions taken:
{chr(10).join(f'- {a.description}' for a in self._actions[:20])}

Generate a report with:
1. Executive Summary
2. Methodology
3. Findings (with severity and recommendations)
4. Conclusion

Report:"""

        return await self._ask_llm(prompt)

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _get_scan_results(self) -> str:
        """Get accumulated scan results."""
        lines = []
        for action in self._actions:
            if action.result and action.phase in (AgentPhase.RECONNAISSANCE, AgentPhase.SCANNING):
                lines.append(f"[{action.command[:60]}]")
                lines.append(action.result.stdout[:300])
                lines.append("")
        return "\n".join(lines[-50:]) if lines else "No scan results yet"

    def _extract_commands(self, text: str) -> List[str]:
        """Extract commands from LLM text response."""
        import re
        commands = []
        # Try code blocks first
        blocks = re.findall(r'```(?:bash|sh)?\n(.*?)```', text, re.DOTALL)
        for block in blocks:
            for line in block.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    commands.append(line)

        # Fallback: extract lines that look like commands
        if not commands:
            for line in text.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-") and " " in line:
                    if any(tool in line for tool in ["nmap", "nuclei", "sqlmap", "ffuf", "hydra", "nikto", "subfinder", "httpx", "cat", "ls", "echo", "curl", "wget"]):
                        commands.append(line)

        return commands[:5]  # Limit to 5 commands

    async def _set_phase(self, phase: AgentPhase) -> None:
        """Update the current phase."""
        if self._phase != phase:
            old = self._phase
            self._phase = phase
            await self._emit("phase_changed", {"from": old.value, "to": phase.value})

    async def _emit(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit an event to the callback."""
        if self._on_event:
            try:
                await self._on_event(event_type, data)
            except Exception as e:
                logger.warning(f"Event callback error: {e}")


def create_runner(
    target: str,
    objective: str = "Find and exploit all critical vulnerabilities",
    max_steps: int = 40,
    scope: Optional[List[str]] = None,
    llm_complete: Optional[Callable[..., Coroutine[Any, Any, str]]] = None,
    on_event: Optional[EventCallback] = None,
    sandbox_mode: Optional[str] = None,
) -> AgentRunner:
    """Factory to create a fully configured AgentRunner."""
    executor = create_executor(mode=sandbox_mode)

    return AgentRunner(
        target=target,
        objective=objective,
        max_steps=max_steps,
        scope=scope,
        executor=executor,
        llm_complete=llm_complete,
        on_event=on_event,
    )
