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

# API integrations (lazy-imported to avoid hard deps)
from nova_arsenal.integrations import MetasploitRPC, BurpAPI, NmapParser, SQLmapAPI
from nova_arsenal.intelligence import ToolSelector
from nova_arsenal.correlation import Correlator

logger = logging.getLogger(__name__)


class AgentPhase(Enum):
    """Current phase of the agent."""
    INIT = "init"
    PLANNING = "planning"
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    INTEGRATION = "integration"       # API-driven tool integrations (MSF, Burp, SQLmap)
    CORRELATION = "correlation"       # Cross-tool result correlation
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
        integrations: Optional[Dict[str, Dict[str, Any]]] = None,
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

        # Tool selection intelligence
        self.tool_selector = ToolSelector()

        # Result correlation
        self.correlator = Correlator()

        # API-driven integrations (configured via integrations dict)
        integrations = integrations or {}
        self.msf_rpc: Optional[MetasploitRPC] = None
        self.burp_api: Optional[BurpAPI] = None
        self.sqlmap_api: Optional[SQLmapAPI] = None
        self.nmap_parser = NmapParser()

        msf_config = integrations.get("metasploit", {})
        if msf_config.get("enabled", False):
            self.msf_rpc = MetasploitRPC(
                host=msf_config.get("host", "https://127.0.0.1:55553"),
                password=msf_config.get("password", ""),
            )

        burp_config = integrations.get("burp", {})
        if burp_config.get("enabled", False):
            self.burp_api = BurpAPI(
                base_url=burp_config.get("url", "http://127.0.0.1:1337"),
                api_key=burp_config.get("api_key", ""),
            )

        sqlmap_config = integrations.get("sqlmap", {})
        if sqlmap_config.get("enabled", False):
            self.sqlmap_api = SQLmapAPI(
                server_url=sqlmap_config.get("url", "http://127.0.0.1:8775"),
            )

        # State
        self._step = 0
        self._phase = AgentPhase.INIT
        self._actions: List[AgentAction] = []
        self._findings: List[Finding] = []
        self._context: List[Dict[str, str]] = []
        self._running = False
        self._error: Optional[str] = None

        # Detected services (populated during scanning)
        self._detected_services: Dict[str, List[int]] = {}

        # Integration artifacts
        self._burp_issues: List[Dict[str, Any]] = []
        self._msf_results: List[Dict[str, Any]] = []
        self._sqlmap_results: List[Dict[str, Any]] = []

        # Correlation result
        self._correlation_result: Optional[Any] = None

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

            # Phase 4: API-Driven Integrations (Metasploit, Burp, SQLmap)
            await self._set_phase(AgentPhase.INTEGRATION)
            await self._run_integrations()

            # Phase 5: Exploitation
            await self._set_phase(AgentPhase.EXPLOITATION)
            await self._execute_exploitation()

            # Phase 6: Post-exploitation
            await self._set_phase(AgentPhase.POST_EXPLOITATION)
            await self._execute_post_exploitation()

            # Phase 7: Cross-Tool Correlation
            await self._set_phase(AgentPhase.CORRELATION)
            await self._run_correlation()

            # Phase 8: Reporting
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
        """Generate an attack plan using blueprint attack chains + integration intelligence."""
        detected_services = self._detected_services or {}

        plan_sections = ["## Attack Plan\n"]
        plan_sections.append(f"Target: {self.target}")
        plan_sections.append(f"Objective: {self.objective}\n")

        # Phase 1: Reconnaissance
        plan_sections.append("### Phase 1: Reconnaissance")
        recon_tools = self.blueprint.get_tools_by_category("recon")[:3]
        plan_sections.append(f"Tools: {', '.join(t.name for t in recon_tools)}")
        plan_sections.append("- Subdomain enumeration via subfinder")
        plan_sections.append("- Ping sweep and port discovery via nmap")
        plan_sections.append("- Service fingerprinting via nmap -sV\n")

        # Phase 2: Scanning
        plan_sections.append("### Phase 2: Vulnerability Scanning")
        plan_sections.append("- Full port scan via nmap -p- with XML output")
        plan_sections.append("- Vulnerability scan via nuclei")
        plan_sections.append("- Web technology detection via whatweb\n")

        # Phase 3: API-Driven Integrations
        plan_sections.append("### Phase 3: API-Driven Integrations")
        has_msf = self.msf_rpc is not None
        has_burp = self.burp_api is not None
        has_sqlmap = self.sqlmap_api is not None
        if has_msf or has_burp or has_sqlmap:
            if has_msf:
                plan_sections.append("- Metasploit RPC: module execution based on detected services")
            if has_burp:
                plan_sections.append("- Burp Suite REST: active scanning + issue collection")
            if has_sqlmap:
                plan_sections.append("- SQLmap API: automated SQL injection testing")
        else:
            plan_sections.append("- No API integrations configured (use Nmap/Burp/SQLmap as CLI)")
        plan_sections.append("")

        # Phase 4: Exploitation
        plan_sections.append("### Phase 4: Exploitation")
        if detected_services:
            svcs = [f"{svc}:{','.join(map(str, ports))}" for svc, ports in detected_services.items()]
            plan_sections.append(f"Detected services: {', '.join(svcs)}")
            plan_sections.append("- Tool-selection intelligence picks optimal exploit tools")
            for svc in detected_services:
                if svc in ("http", "https"):
                    plan_sections.append(f"  - {svc}: nuclei (exploit/rce), sqlmap, hydra")
                elif svc == "smb":
                    plan_sections.append("  - SMB: Metasploit MS17-010, enum4linux, crackmapexec")
                elif svc == "ssh":
                    plan_sections.append("  - SSH: hydra brute force, key-based auth testing")
                elif svc in ("mysql", "postgresql", "mssql"):
                    plan_sections.append(f"  - {svc}: sqlmap, hydra, nmap NSE scripts")
                else:
                    plan_sections.append(f"  - {svc}: targeted exploitation")
        else:
            plan_sections.append("- Targeted exploitation based on scan findings")

        # Phase 5: Post-Exploitation
        plan_sections.append("\n### Phase 5: Post-Exploitation")
        plan_sections.append("- Data extraction and log collection")
        plan_sections.append("- Pivot potential assessment")
        plan_sections.append("- Credential harvesting\n")

        # Phase 6: Cross-Tool Correlation
        plan_sections.append("### Phase 6: Cross-Tool Correlation")
        plan_sections.append("- Correlate Nmap + Burp + Metasploit + SQLmap findings")
        plan_sections.append("- Boost severity for multi-source confirmed vulnerabilities")
        plan_sections.append("- Generate cross-tool insights\n")

        # Phase 7: Reporting
        plan_sections.append("### Phase 7: Reporting")
        plan_sections.append("- Compilation of all findings with correlation data")
        plan_sections.append("- Severity ratings and remediation recommendations")
        plan_sections.append("- Cross-tool confidence scoring")

        plan = "\n".join(plan_sections)
        await self._emit("plan_created", {"plan": plan})
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

        # Add theHarvester for passive recon
        recon_commands.append(
            f"theHarvester -d {self.target} -b google,yahoo,bing 2>/dev/null | head -50 || echo 'theHarvester done'"
        )

        for cmd in recon_commands:
            if not self._running:
                break
            await self._execute_and_analyze(cmd, AgentPhase.RECONNAISSANCE)

    # ── Scanning Phase ──────────────────────────────────────────────────────

    async def _execute_scanning(self) -> None:
        """Execute vulnerability scanning with proper structured output."""
        scan_commands = [
            f"nmap -sV -sC -p- {self.target} -oX /workspace/nmap_full.xml -oN /workspace/nmap_full.txt 2>/dev/null || echo 'full scan done'",
            f"nuclei -u https://{self.target} -severity critical,high,medium -json 2>/dev/null | head -50 || echo 'nuclei scan done'",
            f"nikto -h {self.target} -o /workspace/nikto.txt 2>/dev/null || echo 'nikto scan done",
            f"whatweb {self.target} -v 2>/dev/null | head -30 || echo 'whatweb done'",
        ]

        # Run initial scans and detect services
        for cmd in scan_commands:
            if not self._running:
                break
            await self._execute_and_analyze(cmd, AgentPhase.SCANNING)

        # Detect services from scan results
        self._detect_services()

        # Add service-specific scanning based on detected services
        if "http" in self._detected_services or "https" in self._detected_services:
            scan_commands.extend([
                f"dirsearch -u http://{self.target} -w /usr/share/wordlists/dirb/common.txt -t 10 2>/dev/null | head -40 || echo 'dirsearch done'",
                f"nuclei -u http://{self.target} -as -json 2>/dev/null | head -50 || echo 'nuclei automated done'",
            ])

        if "smb" in self._detected_services:
            scan_commands.extend([
                f"enum4linux -a {self.target} 2>/dev/null | head -80 || echo 'enum4linux done'",
                f"smbclient -L //{self.target} -N 2>/dev/null || echo 'smbclient done'",
            ])

        if "mysql" in self._detected_services:
            scan_commands.append(
                f"nmap --script mysql-* -p 3306 {self.target} 2>/dev/null | head -40 || echo 'mysql scan done'"
            )

        if "ssh" in self._detected_services:
            scan_commands.append(
                f"nmap --script ssh-* -p 22 {self.target} 2>/dev/null | head -40 || echo 'ssh scan done'"
            )

        # Parse nmap XML output for structured data
        if "nmap" in scan_commands[0]:
            try:
                parsed = self.nmap_parser.parse_file("/workspace/nmap_full.xml")
                if parsed.hosts:
                    nmap_findings = self.nmap_parser.extract_findings(parsed)
                    for nf in nmap_findings:
                        finding = Finding(
                            title=nf["title"],
                            severity=nf["severity"],
                            description=nf["description"],
                            tool_used="nmap",
                        )
                        self._findings.append(finding)
                        await self._emit("finding_discovered", finding.to_dict())
            except Exception as e:
                logger.warning(f"Failed to parse nmap XML: {e}")

        for cmd in scan_commands[4:]:  # Run additional scans
            if not self._running:
                break
            await self._execute_and_analyze(cmd, AgentPhase.SCANNING)

    # ── Exploitation Phase ──────────────────────────────────────────────────

    async def _execute_exploitation(self) -> None:
        """Attempt exploitation using tool-selection intelligence + attack chains."""
        scan_context = self._get_scan_results()

        # Use tool selection intelligence to decide strategy
        strategy = await self._generate_strategy()
        detected_services = set(self._detected_services.keys())

        # Map detected services to relevant attack chains
        chain_mapping = {
            "http": ["web_recon", "sql_injection"],
            "https": ["web_recon", "sql_injection"],
            "smb": ["smb_attack", "credential_attack"],
            "ssh": ["credential_attack"],
            "mysql": ["sql_injection"],
            "kerberos": ["kerberos_attack"],
        }

        exploit_commands = []

        # Phase 1: Commands from tool selection (priority-based)
        for suggestion in self.tool_selector.suggest(
            services=self._detected_services,
            findings=[f.to_dict() for f in self._findings],
            target=self.target,
        ):
            if suggestion.tool_type == "kali" and suggestion.command:
                exploit_commands.append(suggestion.command)

        # Phase 2: Commands from relevant attack chains
        for service in detected_services:
            for chain_name in chain_mapping.get(service, []):
                chain = self.blueprint.get_attack_chain(chain_name)
                if chain and isinstance(chain, list):
                    for step in chain:
                        cmd = step.replace("{target}", self.target)
                        if cmd not in exploit_commands:
                            exploit_commands.append(cmd)
                elif chain and isinstance(chain, dict):
                    for step in chain.get("steps", []):
                        cmd = step.replace("{target}", self.target)
                        if cmd not in exploit_commands:
                            exploit_commands.append(cmd)

        # Phase 3: Service-specific exploitation commands
        if "smb" in detected_services:
            exploit_commands.extend([
                f"crackmapexec smb {self.target} -u 'guest' -p '' --shares 2>/dev/null | head -30 || echo 'smb enumeration done'",
                f"nmap --script smb-vuln-* -p 445 {self.target} 2>/dev/null | head -30 || echo 'smb vuln scan done'",
            ])

        if "http" in detected_services or "https" in detected_services:
            exploit_commands.extend([
                f"nuclei -u http://{self.target} -tags exploit,rce -json 2>/dev/null | head -20 || echo 'exploit scan done'",
                f"sqlmap -u http://{self.target} --batch --random-agent 2>/dev/null | head -30 || echo 'sqlmap scan done'",
            ])

        if "ssh" in detected_services:
            exploit_commands.extend([
                f"hydra -l root -P /usr/share/wordlists/rockyou.txt {self.target} ssh -t 4 2>/dev/null | head -20 || echo 'ssh brute force done'",
            ])

        if not exploit_commands:
            # Fall back to LLM-based exploitation suggestions
            prompt = f"""Based on these scan results for {self.target}, suggest specific exploitation commands:

{scan_context}

Available Kali tools for exploitation:
{chr(10).join(f'- {t.name}: {t.description}' for t in self.blueprint.get_tools_by_category('exploitation'))}
{chr(10).join(f'- {t.name}: {t.description}' for t in self.blueprint.get_tools_by_category('web_exploit'))}

Provide 3-5 specific commands to try. Return ONLY the commands, one per line:"""

            response = await self._ask_llm(prompt)
            exploit_commands = self._extract_commands(response)

        # Deduplicate and limit
        seen: set = set()
        unique_commands = []
        for cmd in exploit_commands:
            if cmd not in seen:
                seen.add(cmd)
                unique_commands.append(cmd)

        for cmd in unique_commands[:10]:
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

- {instruction if instruction else 'Decide the next action to take toward the objective.'}

Respond with a JSON object:
{{
    "action": "execute_command" | "write_and_run_code" | "analyze" | "reflect",
    "command": "the command to run (if applicable)",
    "description": "what this action accomplishes",
    "code": "custom code (if action is write_and_run_code)",
    "language": "python" | "bash (if action is write_and_run_code)"
}}"""

    def _simulate_llm_response(self, prompt: str) -> str:
        """Intelligent local response using blueprint tool knowledge."""
        prompt_lower = prompt.lower()

        # Plan generation
        if "plan" in prompt_lower:
            chains = list(self.blueprint.attack_chains.items())[:5]
            plan_lines = []
            for name, chain in chains:
                description = chain.get("description", "") if isinstance(chain, dict) else ""
                tools = ", ".join(chain.get("tools", [])) if isinstance(chain, dict) else ""
                plan_lines.append(f"{name.replace('_', ' ').title()}: {description}")
                if tools:
                    plan_lines.append(f"  Tools: {tools}")
            if not plan_lines:
                plan_lines = [
                    "1. Run subfinder for subdomain enumeration",
                    "2. Run nmap for port scanning",
                    "3. Run nuclei for vulnerability scanning",
                    "4. Test discovered web services for vulnerabilities",
                    "5. Attempt exploitation of critical findings",
                ]
            return "\n".join(plan_lines)

        # Exploitation suggestions
        if "exploit" in prompt_lower or "suggest" in prompt_lower:
            tools = self.blueprint.suggest_tools(prompt)
            if tools:
                return "\n".join(tools[:5])

        # Finding analysis
        if "analyze" in prompt_lower:
            return "Analysis: Command executed successfully. No critical findings detected in output."

        # Default: suggest a tool from the blueprint
        tools = self.blueprint.suggest_tools(prompt)
        if tools:
            return (
                '{"action": "execute_command", '
                f'"command": "echo Running {tools[0]}", '
                f'"description": "Execute {tools[0]} for current phase"}}'
            )

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

    # ── Service Detection ──────────────────────────────────────────────────

    def _detect_services(self) -> None:
        """Parse findings to detect running services and populate _detected_services."""
        self._detected_services = {}

        for action in self._actions:
            if not action.result or not action.result.output:
                continue

            output = action.result.output.lower()

            # Parse nmap-style output for open ports
            import re

            # Match patterns like "80/tcp open http" or "445/tcp open microsoft-ds"
            port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)'
            for match in re.finditer(port_pattern, output):
                port = int(match.group(1))
                proto = match.group(2)
                service = match.group(3).lower()

                # Normalize service names
                svc_map = {
                    "http": "http", "https": "https", "http-proxy": "http",
                    "microsoft-ds": "smb", "netbios-ssn": "smb", "smb": "smb",
                    "ms-wbt-server": "rdp", "rdp": "rdp",
                    "kerberos-sec": "kerberos", "kpasswd": "kerberos",
                    "postgresql": "postgresql", "ms-sql-s": "mssql",
                }
                normalized = svc_map.get(service, service)

                if normalized not in self._detected_services:
                    self._detected_services[normalized] = []
                if port not in self._detected_services[normalized]:
                    self._detected_services[normalized].append(port)

            # Parse nuclei/nmap JSON output for additional services
            json_pattern = r'"port":\s*(\d+),\s*"protocol":\s*"([^"]+)"'
            for match in re.finditer(json_pattern, output):
                port = int(match.group(1))
                proto = match.group(2)
                normalized = proto.lower()
                if normalized not in self._detected_services:
                    self._detected_services[normalized] = []
                if port not in self._detected_services[normalized]:
                    self._detected_services[normalized].append(port)

        # Also check existing findings for service indicators
        for finding in self._findings:
            if "Detected" in finding.title:
                service = finding.title.split("Detected ")[1].split(" service")[0].lower()
                if service not in self._detected_services:
                    self._detected_services[service] = []
                if finding.endpoint:
                    try:
                        self._detected_services[service].append(int(finding.endpoint))
                    except ValueError:
                        pass

        if self._detected_services:
            logger.info(f"Detected services: {self._detected_services}")

    # ── API-Driven Integrations ────────────────────────────────────────────

    async def _run_integrations(self) -> None:
        """
        Run API-driven tool integrations (Metasploit, Burp, SQLmap).
        Uses tool selection intelligence to decide which integrations to fire.
        """
        # Detect services first
        self._detect_services()

        if not self._detected_services:
            logger.info("No services detected; skipping API integrations")
            return

        # Get tool suggestions from intelligence engine
        findings_dicts = [f.to_dict() for f in self._findings]
        suggestions = self.tool_selector.suggest(
            services=self._detected_services,
            findings=findings_dicts,
            target=self.target,
        )

        await self._emit("tool_suggestions", {
            "suggestions": [s.to_dict() for s in suggestions[:10]],
            "detected_services": self._detected_services,
        })

        # Execute integration in priority order
        for suggestion in suggestions:
            if not self._running:
                break

            tool_type = suggestion.tool_type

            if tool_type == "metasploit" and self.msf_rpc:
                await self._run_msf_integration(suggestion)
            elif tool_type == "burp" and self.burp_api:
                await self._run_burp_integration(suggestion)
            elif tool_type == "sqlmap" and self.sqlmap_api:
                await self._run_sqlmap_integration(suggestion)

    async def _run_msf_integration(self, suggestion: Any) -> None:
        """Run Metasploit integration based on tool suggestion."""
        if not self.msf_rpc:
            return

        await self._emit("integration_started", {
            "tool": "metasploit",
            "reasoning": suggestion.reasoning,
        })

        # Authenticate
        authed = await self.msf_rpc.login()
        if not authed:
            logger.warning("Metasploit RPC login failed; skipping MSF integration")
            return

        target = suggestion.params.get("target", self.target)

        # Determine which MSF modules to run based on detected services
        msf_tasks = []

        if "smb" in self._detected_services:
            msf_tasks = [
                ("auxiliary/scanner/smb/smb_version", {"RHOSTS": target}),
                ("auxiliary/scanner/smb/smb_ms17_010", {"RHOSTS": target}),
                ("auxiliary/scanner/smb/pipe_auditor", {"RHOSTS": target}),
            ]
        elif "http" in self._detected_services or "https" in self._detected_services:
            msf_tasks = [
                ("auxiliary/scanner/http/http_version", {"RHOSTS": target}),
                ("auxiliary/scanner/http/title", {"RHOSTS": target}),
            ]
        elif "ssh" in self._detected_services:
            msf_tasks = [
                ("auxiliary/scanner/ssh/ssh_version", {"RHOSTS": target}),
            ]

        for module, options in msf_tasks:
            if not self._running:
                break
            result = await self.msf_rpc.execute_module(
                module=module,
                options=options,
                timeout=60,
            )
            self._msf_results.append(result.to_dict())
            await self._emit("integration_result", {
                "tool": "metasploit",
                "module": module,
                "status": result.status,
                "findings": result.findings,
            })

        if self._msf_results:
            logger.info(f"MSF integration: {len(self._msf_results)} module results")

    async def _run_burp_integration(self, suggestion: Any) -> None:
        """Run Burp Suite integration based on tool suggestion."""
        if not self.burp_api:
            return

        await self._emit("integration_started", {
            "tool": "burp",
            "reasoning": suggestion.reasoning,
        })

        health = await self.burp_api.check_health()
        if not health:
            logger.warning("Burp API not accessible; skipping Burp integration")
            return

        # Determine target URLs
        urls = []
        if "http" in self._detected_services or "https" in self._detected_services:
            scheme = "https" if "https" in self._detected_services else "http"
            for port in self._detected_services.get("http", []) + self._detected_services.get("https", []):
                urls.append(f"{scheme}://{self.target}:{port}")
        if not urls:
            urls = [f"http://{self.target}"]
        if not urls:
            urls = [f"http://{self.target}"]

        # Start scans
        for url in urls[:2]:  # Limit to 2 URLs
            if not self._running:
                break
            job = await self.burp_api.start_scan(url)
            if job.status != "failed":
                await self._emit("integration_result", {
                    "tool": "burp",
                    "scan_id": job.scan_id,
                    "url": url,
                    "status": job.status,
                })

        # Collect existing issues
        self._burp_issues = await self.burp_api.get_issues()
        if self._burp_issues:
            logger.info(f"Burp integration: {len(self._burp_issues)} issues collected")

            # Create findings from Burp issues
            for issue in self._burp_issues[:10]:
                finding = Finding(
                    title=f"Burp: {issue.name}",
                    severity=issue.severity,
                    description=issue.description[:500],
                    evidence=issue.evidence[:500],
                    endpoint=issue.url,
                    remediation=issue.remediation[:500],
                    tool_used="burp",
                )
                self._findings.append(finding)

    async def _run_sqlmap_integration(self, suggestion: Any) -> None:
        """Run SQLmap integration based on tool suggestion."""
        if not self.sqlmap_api:
            return

        await self._emit("integration_started", {
            "tool": "sqlmap",
            "reasoning": suggestion.reasoning,
        })

        # Determine target URL
        url = suggestion.params.get("url", f"http://{self.target}")

        # Create and start SQLmap task
        task = await self.sqlmap_api.new_task(url)
        if task.status == "failed":
            logger.warning("SQLmap task creation failed")
            return

        # Wait for completion (with timeout)
        task = await self.sqlmap_api.wait_for_completion(
            task.task_id, max_time=120
        )

        if task.is_complete:
            self._sqlmap_results.append(task.to_dict())

            # Create findings from SQLmap results
            for finding in task.findings:
                f = Finding(
                    title=f"SQL Injection: {finding.title}",
                    severity="high",
                    description=f"Parameter '{finding.parameter}' is injectable via {finding.technique}",
                    evidence=f"Payload: {finding.payload[:300]}",
                    endpoint=url,
                    remediation="Use parameterized queries and input validation",
                    tool_used="sqlmap",
                )
                self._findings.append(f)

            await self._emit("integration_result", {
                "tool": "sqlmap",
                "task_id": task.task_id,
                "status": task.status,
                "findings_count": len(task.findings),
                "dbms": task.dbms,
            })

            logger.info(f"SQLmap integration: {len(task.findings)} injection points found")

    # ── Tool Selection Intelligence ────────────────────────────────────────

    async def _generate_strategy(self) -> Dict[str, Any]:
        """Generate exploitation strategy using tool-selection intelligence."""
        if not self._detected_services:
            self._detect_services()

        findings_dicts = [f.to_dict() for f in self._findings]
        strategy = self.tool_selector.decide_exploit_strategy(
            services=self._detected_services,
            findings=findings_dicts,
        )

        await self._emit("strategy_updated", strategy)
        return strategy

    # ── Cross-Tool Correlation ─────────────────────────────────────────────

    async def _run_correlation(self) -> None:
        """
        Correlate findings across all tool sources.

        Combines results from:
        - Nmap (from action results via NmapParser)
        - Burp Suite (from integration phase)
        - Metasploit (from integration phase)
        - SQLmap (from integration phase)
        - Built-in findings (heuristic/LM-based)
        """
        # Parse nmap XML output from action results
        nmap_data = None
        for action in self._actions:
            if action.command and "nmap" in action.command.lower() and action.result:
                if "-oX" in action.command or "-oA" in action.command:
                    # Try to parse as XML
                    parsed = self.nmap_parser.parse(action.result.output)
                    if parsed.hosts:
                        nmap_data = parsed.to_dict()
                        break
                else:
                    # Try parsing output directly
                    parsed = self.nmap_parser.parse(action.result.output)
                    if parsed.hosts:
                        nmap_data = parsed.to_dict()
                        break

        # Run correlation
        findings_dicts = [f.to_dict() for f in self._findings]

        self._correlation_result = await self.correlator.correlate(
            nmap_data=nmap_data,
            burp_issues=self._burp_issues,
            msf_results=self._msf_results,
            sqlmap_tasks=self._sqlmap_results,
            findings=findings_dicts,
        )

        # Boost findings that were correlated
        for cf in self._correlation_result.correlated_findings:
            if cf.source_count >= 2:
                # Only create high/critical correlated findings
                if cf.severity in ("critical", "high"):
                    finding = Finding(
                        title=cf.title,
                        severity=cf.severity,
                        description=cf.description[:500],
                        evidence=cf.evidence[:500],
                        endpoint=cf.endpoint,
                        remediation=cf.remediation,
                        tool_used="+".join(cf.source_tools),
                    )
                    self._findings.append(finding)

        await self._emit("correlation_complete", self._correlation_result.to_dict())

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
        """Generate a final report with correlation data."""
        correlation_section = ""
        if self._correlation_result:
            cr = self._correlation_result
            correlation_section = f"""
Cross-Tool Correlation:
- Correlated findings: {cr.total_correlated}
- Critical: {len(cr.critical_findings)}
- High: {len(cr.high_findings)}
- Tools used: {', '.join(f'{k}({v})' for k, v in cr.tool_coverage.items()) if cr.tool_coverage else 'None'}
- Confidence score: {cr.to_dict().get('confidence_score', 0)}

Top Correlated Findings:
{chr(10).join(f'  [{f.severity.upper()}] {f.title} (sources: {", ".join(f.source_tools)})' for f in cr.correlated_findings[:5]) if cr.correlated_findings else '  None'}

Insights:
{chr(10).join(f'  - {i}' for i in cr.cross_tool_insights) if cr.cross_tool_insights else '  No insights generated'}
"""

        integration_section = ""
        if self._msf_results or self._burp_issues or self._sqlmap_results:
            integration_section = """
API Integration Results:
"""
            if self._msf_results:
                integration_section += f"- Metasploit: {len(self._msf_results)} modules executed\n"
            if self._burp_issues:
                integration_section += f"- Burp Suite: {len(self._burp_issues)} issues found\n"
            if self._sqlmap_results:
                injection_count = sum(len(r.get("findings", [])) for r in self._sqlmap_results)
                integration_section += f"- SQLmap: {injection_count} injection points found\n"

        prompt = f"""Generate a professional security assessment report for {self.target}.

Objective: {self.objective}
Steps taken: {self._step}
Findings: {len(self._findings)}
Detected services: {json.dumps(self._detected_services) if self._detected_services else 'None detected'}
{integration_section}
{correlation_section}
Findings detail:
{json.dumps([f.to_dict() for f in self._findings], indent=2) if self._findings else 'No findings discovered'}

Actions taken:
{chr(10).join(f'- {a.description}' for a in self._actions[:20])}

Generate a report with:
1. Executive Summary
2. Methodology
3. Findings (with severity and recommendations)
4. Correlation Summary (cross-tool findings)
5. Conclusion

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
