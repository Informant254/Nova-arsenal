"""
Tool-Selection Intelligence Engine.

Maps detected services, ports, and findings to the optimal
security tool for the job. Nova uses this to decide:
- Port 445 open → Metasploit SMB modules + enum4linux
- Web app detected → Burp scan + nuclei + nikto
- Login form → SQLmap (POST injection) vs Hydra (brute force) vs custom payload
- SMB + outdated version → MSF exploit module
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolSuggestion:
    """A suggested tool with reasoning."""
    tool_name: str
    tool_type: str
    command: str
    reasoning: str
    priority: int  # 1-10, higher = more relevant
    phase: str = "exploitation"
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_type": self.tool_type,
            "command": self.command,
            "reasoning": self.reasoning,
            "priority": self.priority,
            "phase": self.phase,
        }


class ToolSelector:
    """
    Rule-based tool selection engine.

    Takes detected services, findings, and target context,
    returns ranked tool suggestions with reasoning.

    Usage:
        selector = ToolSelector()
        suggestions = selector.suggest(
            services={"http": [80, 443], "smb": [445]},
            findings=[...],
            target="10.0.0.1"
        )
        for s in suggestions:
            print(f"{s.tool_name} (p{s.priority}): {s.reasoning}")
    """

    def __init__(self) -> None:
        # Service → tool rules
        self._service_rules = self._build_service_rules()

        # Finding type → tool rules
        self._finding_rules = self._build_finding_rules()

        # Correlation rules (cross-service)
        self._correlation_rules = self._build_correlation_rules()

    def _build_service_rules(self) -> List[Dict[str, Any]]:
        """Build rules mapping services to recommended tools."""
        return [
            # ── Web Services ──
            {
                "services": ["http", "https", "http-proxy"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="burp_scan",
                        tool_type="burp",
                        command="",
                        reasoning="Web app detected; start Burp Suite active scan for comprehensive vuln detection",
                        priority=10,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="nuclei",
                        tool_type="kali",
                        command="nuclei -u {url} -severity critical,high,medium -json",
                        reasoning="Template-based vulnerability scanner for known CVEs",
                        priority=9,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="nikto",
                        tool_type="kali",
                        command="nikto -h {url} -ssl -Format txt",
                        reasoning="Classic web server scanner for misconfigurations and outdated software",
                        priority=7,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="whatweb",
                        tool_type="kali",
                        command="whatweb {url} --log-verbose=/workspace/whatweb.txt 2>/dev/null",
                        reasoning="Identify web technologies, frameworks, and CMS versions",
                        priority=6,
                        phase="reconnaissance",
                    ),
                    ToolSuggestion(
                        tool_name="dirsearch",
                        tool_type="kali",
                        command="dirsearch -u {url} -w /usr/share/wordlists/dirb/common.txt -t 20",
                        reasoning="Directory and file enumeration for hidden endpoints",
                        priority=8,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="sqlmap",
                        tool_type="sqlmap",
                        command="",
                        reasoning="If login form or URL params found: SQL injection detection",
                        priority=8,
                        phase="exploitation",
                    ),
                ],
            },
            # ── SMB Services ──
            {
                "services": ["smb", "microsoft-ds", "netbios-ssn"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="msf_smb",
                        tool_type="metasploit",
                        command="",
                        reasoning="Port 445 (SMB) → launch Metasploit SMB scanner modules for version + vuln detection",
                        priority=10,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="enum4linux",
                        tool_type="kali",
                        command="enum4linux -a {target}",
                        reasoning="Full SMB enumeration: users, shares, OS info, policies",
                        priority=9,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="crackmapexec",
                        tool_type="kali",
                        command="crackmapexec smb {target} -u 'guest' -p '' --shares",
                        reasoning="Quick SMB share enumeration and credential checking",
                        priority=8,
                        phase="exploitation",
                    ),
                    ToolSuggestion(
                        tool_name="smbclient",
                        tool_type="kali",
                        command="smbclient -L //{target} -N",
                        reasoning="List SMB shares with null session",
                        priority=7,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="nmap_smb_vuln",
                        tool_type="kali",
                        command="nmap --script smb-vuln-* -p 445 {target}",
                        reasoning="NSE scripts for known SMB vulnerabilities (EternalBlue, etc.)",
                        priority=9,
                        phase="exploitation",
                    ),
                ],
            },
            # ── SSH Services ──
            {
                "services": ["ssh"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="hydra_ssh",
                        tool_type="kali",
                        command="hydra -l root -P /usr/share/wordlists/rockyou.txt {target} ssh -t 4",
                        reasoning="SSH brute force with common credentials",
                        priority=7,
                        phase="exploitation",
                    ),
                    ToolSuggestion(
                        tool_name="nmap_ssh_scan",
                        tool_type="kali",
                        command="nmap --script ssh-* -p 22 {target}",
                        reasoning="NSE scripts for SSH hostkey, auth-methods, and vuln checks",
                        priority=8,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="msf_ssh_scan",
                        tool_type="metasploit",
                        command="",
                        reasoning="Check SSH version and known vulns via Metasploit auxiliary modules",
                        priority=6,
                        phase="scanning",
                    ),
                ],
            },
            # ── Database Services ──
            {
                "services": ["mysql", "postgresql", "ms-sql-s", "oracle-tns"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="sqlmap_db",
                        tool_type="sqlmap",
                        command="",
                        reasoning="Database service detected; use SQLmap for direct DB injection testing",
                        priority=9,
                        phase="exploitation",
                    ),
                    ToolSuggestion(
                        tool_name="nmap_db_scan",
                        tool_type="kali",
                        command="nmap --script mysql-* -p 3306 {target}",
                        reasoning="NSE scripts for database-specific vulnerabilities",
                        priority=8,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="msf_db_scan",
                        tool_type="metasploit",
                        command="",
                        reasoning="Metasploit auxiliary modules for database service enumeration",
                        priority=7,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="hydra_db",
                        tool_type="kali",
                        command="hydra -l root -P /usr/share/wordlists/rockyou.txt {target} mysql -t 4",
                        reasoning="Database credential brute forcing",
                        priority=6,
                        phase="exploitation",
                    ),
                ],
            },
            # ── RDP Services ──
            {
                "services": ["ms-wbt-server", "rdp"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="nmap_rdp_scan",
                        tool_type="kali",
                        command="nmap --script rdp-* -p 3389 {target}",
                        reasoning="NSE scripts for RDP vulnerabilities (BlueKeep, etc.)",
                        priority=9,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="crowbar_rdp",
                        tool_type="kali",
                        command="crowbar -b rdp -s {target}/32 -u admin -C /usr/share/wordlists/rockyou.txt",
                        reasoning="RDP brute forcing with crowbar",
                        priority=7,
                        phase="exploitation",
                    ),
                ],
            },
            # ── DNS Services ──
            {
                "services": ["dns", "domain"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="dnsrecon",
                        tool_type="kali",
                        command="dnsrecon -d {target} -t std",
                        reasoning="Standard DNS enumeration: records, subdomains, zone transfer",
                        priority=8,
                        phase="reconnaissance",
                    ),
                    ToolSuggestion(
                        tool_name="dnsenum",
                        tool_type="kali",
                        command="dnsenum {target}",
                        reasoning="Automated DNS enumeration with dictionary attacks",
                        priority=7,
                        phase="reconnaissance",
                    ),
                ],
            },
            # ── LDAP / Kerberos ──
            {
                "services": ["ldap", "kerberos-sec", "kpasswd"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="nmap_ldap_scan",
                        tool_type="kali",
                        command="nmap --script ldap-* -p 389,636 {target}",
                        reasoning="LDAP NSE scripts for directory enumeration",
                        priority=8,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="msf_kerberos",
                        tool_type="metasploit",
                        command="",
                        reasoning="Kerberos authentication testing with Metasploit auxiliary modules",
                        priority=9,
                        phase="exploitation",
                    ),
                    ToolSuggestion(
                        tool_name="kerbrute",
                        tool_type="kali",
                        command="kerbrute userenum -d {domain} --dc {target} /usr/share/wordlists/names.txt",
                        reasoning="Kerberos user enumeration",
                        priority=8,
                        phase="scanning",
                    ),
                ],
            },
            # ── FTP Services ──
            {
                "services": ["ftp"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="hydra_ftp",
                        tool_type="kali",
                        command="hydra -l anonymous -P /usr/share/wordlists/rockyou.txt {target} ftp -t 4",
                        reasoning="FTP brute force + anonymous access check",
                        priority=8,
                        phase="exploitation",
                    ),
                    ToolSuggestion(
                        tool_name="nmap_ftp_scan",
                        tool_type="kali",
                        command="nmap --script ftp-* -p 21 {target}",
                        reasoning="NSE scripts for FTP vulnerabilities and anonymous access",
                        priority=7,
                        phase="scanning",
                    ),
                ],
            },
        ]

    def _build_finding_rules(self) -> List[Dict[str, Any]]:
        """Build rules matching finding types to recommended tools."""
        return [
            {
                "finding_pattern": "sql_injection",
                "title_match": ["sql", "injection", "sqli"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="sqlmap",
                        tool_type="sqlmap",
                        command="",
                        reasoning="SQL injection pattern found; deploy SQLmap for automated extraction",
                        priority=10,
                        phase="exploitation",
                    ),
                    ToolSuggestion(
                        tool_name="msf_sqli",
                        tool_type="metasploit",
                        command="",
                        reasoning="Metasploit auxiliary for SQL injection exploitation",
                        priority=7,
                        phase="exploitation",
                    ),
                ],
            },
            {
                "finding_pattern": "xss",
                "title_match": ["xss", "cross-site", "script"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="dalfox",
                        tool_type="kali",
                        command="dalfox url {url}",
                        reasoning="XSS pattern found; automated XSS scanner for confirmation",
                        priority=9,
                        phase="exploitation",
                    ),
                    ToolSuggestion(
                        tool_name="burp_xss",
                        tool_type="burp",
                        command="",
                        reasoning="Deploy Burp Suite scan with XSS-focused checks",
                        priority=8,
                        phase="exploitation",
                    ),
                ],
            },
            {
                "finding_pattern": "rce",
                "title_match": ["rce", "exec", "command inj"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="msf_rce",
                        tool_type="metasploit",
                        command="",
                        reasoning="RCE pattern found; use Metasploit exploit modules for remote code execution",
                        priority=10,
                        phase="exploitation",
                    ),
                    ToolSuggestion(
                        tool_name="burp_rce",
                        tool_type="burp",
                        command="",
                        reasoning="Sub-Burp scan focus: RCE payload testing and verification",
                        priority=8,
                        phase="exploitation",
                    ),
                ],
            },
            {
                "finding_pattern": "default_creds",
                "title_match": ["default", "credential", "password"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="hydra",
                        tool_type="kali",
                        command="hydra -C /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt {target} {service}",
                        reasoning="Default credentials found; systematic brute force with common creds",
                        priority=9,
                        phase="exploitation",
                    ),
                    ToolSuggestion(
                        tool_name="crackmapexec",
                        tool_type="kali",
                        command="crackmapexec {service} {target} -u /usr/share/seclists/Usernames/Names/names.txt -p /usr/share/wordlists/rockyou.txt",
                        reasoning="Credential spraying across discovered services",
                        priority=8,
                        phase="exploitation",
                    ),
                ],
            },
            {
                "finding_pattern": "info_disclosure",
                "title_match": ["disclosure", "leak", "version", "debug"],
                "suggestions": [
                    ToolSuggestion(
                        tool_name="burp_info_leak",
                        tool_type="burp",
                        command="",
                        reasoning="Information disclosure found; Burp scan for additional leaks",
                        priority=7,
                        phase="scanning",
                    ),
                    ToolSuggestion(
                        tool_name="nuclei_leak",
                        tool_type="kali",
                        command="nuclei -u {url} -tags exposure,config -json",
                        reasoning="Nuclei template scan for known information exposure paths",
                        priority=8,
                        phase="scanning",
                    ),
                ],
            },
        ]

    def _build_correlation_rules(self) -> List[Dict[str, Any]]:
        """Build cross-service correlation rules."""
        return [
            {
                "name": "web_db_chain",
                "condition": "http AND (mysql OR postgresql)",
                "description": "Web server with database → SQLmap + Burp combined",
                "suggestions": [
                    ToolSuggestion(
                        tool_name="sqlmap_combined",
                        tool_type="sqlmap",
                        command="",
                        reasoning="Web app + database service: SQLmap for DB-focused injection, Burp for web-layer vulns",
                        priority=10,
                        phase="exploitation",
                    ),
                ],
            },
            {
                "name": "smb_outdated_chain",
                "condition": "smb AND outdated",
                "description": "Outdated SMB → immediate Metasploit EternalBlue check",
                "suggestions": [
                    ToolSuggestion(
                        tool_name="msf_eternalblue",
                        tool_type="metasploit",
                        command="",
                        reasoning="Outdated SMB detected: prioritize EternalBlue (MS17-010) check",
                        priority=10,
                        phase="exploitation",
                    ),
                ],
            },
            {
                "name": "web_login_chain",
                "condition": "http AND (login OR form OR auth)",
                "description": "Login form → SQLmap vs Hydra decision",
                "suggestions": [
                    ToolSuggestion(
                        tool_name="sqlmap_form",
                        tool_type="sqlmap",
                        command="",
                        reasoning="Login form detected: SQLmap for POST-based injection, Hydra for brute force",
                        priority=9,
                        phase="exploitation",
                    ),
                    ToolSuggestion(
                        tool_name="hydra_form",
                        tool_type="kali",
                        command="hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'",
                        reasoning="Login form brute force with admin credentials",
                        priority=8,
                        phase="exploitation",
                    ),
                ],
            },
        ]

    def suggest(
        self,
        services: Dict[str, List[int]],
        findings: Optional[List[Dict[str, Any]]] = None,
        target: str = "",
        domain: str = "",
    ) -> List[ToolSuggestion]:
        """
        Get tool suggestions based on detected services and findings.

        Args:
            services: Dict mapping service name → list of ports
            findings: List of existing findings
            target: Target IP/hostname
            domain: Domain name (if applicable)

        Returns:
            Ranked list of ToolSuggestion objects
        """
        suggestions: Dict[str, ToolSuggestion] = {}
        findings = findings or []

        # Phase 1: Service-based suggestions
        for rule in self._service_rules:
            matched_services = [s for s in rule["services"] if s in services]
            if matched_services:
                for suggestion in rule["suggestions"]:
                    key = suggestion.tool_name
                    if key not in suggestions or suggestion.priority > suggestions[key].priority:
                        suggestion.params["target"] = target
                        suggestion.params["domain"] = domain
                        suggestion.params["matched_services"] = matched_services

                        # Fill in URL for web tools
                        if any(s in ("http", "https") for s in matched_services):
                            scheme = "https" if "https" in services else "http"
                            suggestion.params["url"] = f"{scheme}://{target}"
                            suggestion.command = suggestion.command.replace(
                                "{url}", f"{scheme}://{target}"
                            )

                        suggestion.command = suggestion.command.replace("{target}", target)
                        suggestion.command = suggestion.command.replace("{domain}", domain if domain else target)
                        suggestions[key] = suggestion

        # Phase 2: Finding-based suggestions
        for finding in findings:
            title = (finding.get("title", "") + " " + finding.get("description", "")).lower()
            for rule in self._finding_rules:
                if any(match in title for match in rule["title_match"]):
                    for suggestion in rule["suggestions"]:
                        key = suggestion.tool_name
                        if key not in suggestions or suggestion.priority > suggestions[key].priority:
                            suggestion.params["target"] = target
                            suggestions[key] = suggestion

        # Phase 3: Correlation-based suggestions
        services_found = set(services.keys())
        for rule in self._correlation_rules:
            condition = rule["condition"]
            parts = condition.replace("(", "").replace(")", "").split(" AND ")
            if all(any(svc in services_found for svc in part.split(" OR ")) for part in parts):
                for suggestion in rule["suggestions"]:
                    key = suggestion.tool_name
                    if key not in suggestions or suggestion.priority > suggestions[key].priority:
                        suggestions[key] = suggestion

        # Sort by priority descending
        ranked = sorted(suggestions.values(), key=lambda s: s.priority, reverse=True)

        logger.info(
            f"ToolSelector: {len(ranked)} suggestions from "
            f"{len(services)} services + {len(findings)} findings"
        )
        return ranked

    def decide_exploit_strategy(
        self,
        services: Dict[str, List[int]],
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        High-level strategy decision based on full context.

        Returns structured strategy dict with:
        - primary_vector: the most promising attack vector
        - tools_to_run: list of tools in order
        - reasoning: explanation of decisions
        """
        findings = findings or []
        suggestions = self.suggest(services, findings)

        if not suggestions:
            return {
                "primary_vector": "none",
                "tools_to_run": [],
                "reasoning": "No attack vectors identified from available data",
                "confidence": 0,
            }

        # Group tools by type
        by_type: Dict[str, List[ToolSuggestion]] = {}
        for s in suggestions:
            by_type.setdefault(s.tool_type, []).append(s)

        # Determine primary vector
        top = suggestions[0]
        service_list = list(services.keys())

        strategy = {
            "primary_vector": top.tool_type,
            "primary_tool": top.tool_name,
            "reasoning": top.reasoning,
            "tools_to_run": [s.tool_name for s in suggestions[:5]],
            "confidence": min(100, len(suggestions) * 15),
            "service_count": len(service_list),
            "finding_count": len(findings),
        }

        # Add type-specific notes
        if "metasploit" in by_type:
            strategy["msf_modules"] = [
                {
                    "module": s.tool_name,
                    "reasoning": s.reasoning,
                    "priority": s.priority,
                }
                for s in by_type["metasploit"]
            ]

        if "sqlmap" in by_type:
            strategy["sqlmap_reason"] = by_type["sqlmap"][0].reasoning

        if "burp" in by_type:
            strategy["burp_targets"] = [
                s.params.get("url", "")
                for s in by_type["burp"]
                if s.params.get("url")
            ]

        return strategy
