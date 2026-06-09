"""
Nova Output Parser v1.0
========================
Parses raw tool output into structured findings.

Supported tools:
- nmap (XML, greppable, normal)
- nikto
- sqlmap
- gobuster / ffuf / dirb
- whatweb
- wafw00f
- whois
- dig / nslookup
- enum4linux
- theHarvester
- wfuzz

Instead of raw text, Nova gets structured data:
- Title
- Severity
- Description
- Evidence
- Remediation
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────

@dataclass
class ParsedFinding:
    """Structured finding from tool output"""
    tool: str
    title: str
    severity: str
    description: str
    evidence: str
    target: str = ""
    port: Optional[int] = None
    service: str = ""
    remediation: str = ""
    raw_output: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "tool": self.tool,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "remediation": self.remediation,
            "timestamp": self.timestamp
        }


@dataclass
class ParseResult:
    """Result of parsing tool output"""
    tool: str
    target: str
    success: bool
    findings: List[ParsedFinding] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    parse_errors: List[str] = field(default_factory=list)
    summary: str = ""

    @property
    def critical_count(self) -> int:
        return len([f for f in self.findings if f.severity == "CRITICAL"])

    @property
    def high_count(self) -> int:
        return len([f for f in self.findings if f.severity == "HIGH"])


# ─────────────────────────────────────────
# MAIN PARSER
# ─────────────────────────────────────────

class NovaOutputParser:
    """
    Parses raw tool output into structured findings.

    Instead of showing users walls of text,
    Nova extracts what matters and structures it cleanly.
    """

    def __init__(self):
        self.parsers = {
            "nmap": NmapParser(),
            "nikto": NiktoParser(),
            "sqlmap": SqlmapParser(),
            "gobuster": GobusterParser(),
            "ffuf": FfufParser(),
            "dirb": DirbParser(),
            "whatweb": WhatwebParser(),
            "whois": WhoisParser(),
            "dig": DigParser(),
            "theharvester": TheHarvesterParser(),
            "enum4linux": Enum4linuxParser(),
        }

    def parse(self, tool: str, output: str, target: str = "") -> ParseResult:
        """
        Parse output from any tool.

        Args:
            tool: Tool name (nmap, nikto, etc.)
            output: Raw tool output
            target: Target that was tested

        Returns:
            ParseResult with structured findings
        """

        tool_lower = tool.lower().strip()

        if tool_lower not in self.parsers:
            logger.warning(f"No parser for tool: {tool}")
            return self._fallback_parse(tool, output, target)

        try:
            parser = self.parsers[tool_lower]
            result = parser.parse(output, target)
            logger.info(f"Parsed {tool}: {len(result.findings)} findings")
            return result

        except Exception as e:
            logger.error(f"Parser error for {tool}: {e}")
            return self._fallback_parse(tool, output, target)

    def _fallback_parse(self, tool: str, output: str, target: str) -> ParseResult:
        """Fallback when no specific parser available"""

        finding = ParsedFinding(
            tool=tool,
            title=f"Output from {tool}",
            severity="INFO",
            description="Raw tool output (no structured parser available)",
            evidence=output[:500],
            target=target,
            raw_output=output
        )

        return ParseResult(
            tool=tool,
            target=target,
            success=True,
            findings=[finding],
            summary=f"Raw output from {tool} ({len(output)} chars)"
        )

    def parse_multiple(
        self,
        results: List[Tuple[str, str, str]]
    ) -> List[ParseResult]:
        """
        Parse multiple tool outputs at once.

        Args:
            results: List of (tool, output, target) tuples
        """
        return [self.parse(tool, output, target) for tool, output, target in results]

    def aggregate_findings(self, parse_results: List[ParseResult]) -> List[ParsedFinding]:
        """Combine findings from multiple tools"""

        all_findings = []
        for result in parse_results:
            all_findings.extend(result.findings)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        return all_findings


# ─────────────────────────────────────────
# INDIVIDUAL PARSERS
# ─────────────────────────────────────────

class NmapParser:
    """Parse nmap output"""

    def parse(self, output: str, target: str = "") -> ParseResult:
        """Parse nmap output"""

        findings = []
        raw_data = {"hosts": [], "open_ports": []}

        # Parse open ports
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?'
        for match in re.finditer(port_pattern, output):
            port = int(match.group(1))
            service = match.group(2)
            version = match.group(3) or ""

            severity = self._port_to_severity(port, service)

            finding = ParsedFinding(
                tool="nmap",
                title=f"Open Port {port}/{service}",
                severity=severity,
                description=f"Port {port} is open running {service}. {version}".strip(),
                evidence=f"{port}/tcp open {service} {version}".strip(),
                target=target,
                port=port,
                service=service,
                remediation=self._port_remediation(port, service),
                metadata={"version": version}
            )

            findings.append(finding)
            raw_data["open_ports"].append({
                "port": port,
                "service": service,
                "version": version
            })

        # Check for OS detection
        os_match = re.search(r'OS details: (.+)', output)
        if os_match:
            raw_data["os"] = os_match.group(1)

        summary = f"Found {len(findings)} open ports on {target}"

        return ParseResult(
            tool="nmap",
            target=target,
            success=True,
            findings=findings,
            raw_data=raw_data,
            summary=summary
        )

    def _port_to_severity(self, port: int, service: str) -> str:
        """Determine severity based on port/service"""

        critical_ports = [21, 23, 445, 3389, 5900]
        high_ports = [22, 25, 80, 443, 3306, 5432, 6379, 27017]

        if port in critical_ports:
            return "HIGH"
        elif port in high_ports:
            return "MEDIUM"
        elif "ssl" in service.lower() or "tls" in service.lower():
            return "LOW"
        return "INFO"

    def _port_remediation(self, port: int, service: str) -> str:
        """Suggest remediation for open port"""

        remediations = {
            21: "Disable FTP. Use SFTP instead.",
            22: "Restrict SSH access by IP. Use key-based auth.",
            23: "Disable Telnet immediately. Use SSH.",
            25: "Restrict SMTP relay. Authenticate outbound.",
            3389: "Disable RDP or restrict by IP.",
            445: "Restrict SMB. Disable if not needed.",
            3306: "Restrict MySQL to localhost only.",
            5432: "Restrict PostgreSQL to localhost only.",
            6379: "Add Redis authentication. Restrict access.",
            27017: "Add MongoDB authentication. Restrict access.",
            5900: "Disable VNC or restrict by IP."
        }

        return remediations.get(port, f"Review if port {port} needs to be publicly accessible.")


class NiktoParser:
    """Parse nikto output"""

    def parse(self, output: str, target: str = "") -> ParseResult:
        """Parse nikto output"""

        findings = []

        # Nikto finding pattern
        finding_pattern = r'\+ (.+)'
        osvdb_pattern = r'OSVDB-(\d+): (.+)'

        for line in output.split('\n'):
            line = line.strip()

            # Skip headers and empty lines
            if not line or line.startswith('-') or line.startswith('*'):
                continue

            if line.startswith('+'):
                content = line[2:]

                # Determine severity
                severity = self._nikto_severity(content)

                # OSVDB reference
                osvdb_match = re.search(osvdb_pattern, content)
                osvdb_id = osvdb_match.group(1) if osvdb_match else ""

                finding = ParsedFinding(
                    tool="nikto",
                    title=self._nikto_title(content),
                    severity=severity,
                    description=content,
                    evidence=line,
                    target=target,
                    remediation=self._nikto_remediation(content),
                    metadata={"osvdb": osvdb_id}
                )

                findings.append(finding)

        summary = f"Nikto found {len(findings)} issues on {target}"

        return ParseResult(
            tool="nikto",
            target=target,
            success=True,
            findings=findings,
            summary=summary
        )

    def _nikto_severity(self, content: str) -> str:
        """Determine severity from nikto output"""

        content_lower = content.lower()

        if any(w in content_lower for w in ["sql injection", "xss", "rce", "command"]):
            return "CRITICAL"
        elif any(w in content_lower for w in ["vulnerability", "vulnerable", "exploit"]):
            return "HIGH"
        elif any(w in content_lower for w in ["outdated", "old version", "deprecated"]):
            return "MEDIUM"
        elif any(w in content_lower for w in ["disclosure", "information", "header"]):
            return "LOW"
        return "INFO"

    def _nikto_title(self, content: str) -> str:
        """Extract title from nikto finding"""

        if ":" in content:
            return content.split(":")[0].strip()[:80]
        return content[:80]

    def _nikto_remediation(self, content: str) -> str:
        """Suggest remediation based on finding"""

        content_lower = content.lower()

        if "x-frame-options" in content_lower:
            return "Add header: X-Frame-Options: SAMEORIGIN"
        elif "x-xss-protection" in content_lower:
            return "Add header: X-XSS-Protection: 1; mode=block"
        elif "x-content-type" in content_lower:
            return "Add header: X-Content-Type-Options: nosniff"
        elif "server" in content_lower and "version" in content_lower:
            return "Hide server version in HTTP headers"
        elif "directory" in content_lower and "index" in content_lower:
            return "Disable directory listing"
        return "Review and address the identified issue"


class SqlmapParser:
    """Parse sqlmap output"""

    def parse(self, output: str, target: str = "") -> ParseResult:
        """Parse sqlmap output"""

        findings = []
        raw_data = {
            "injectable_parameters": [],
            "databases": [],
            "tables": []
        }

        # Check if injection found
        if "is vulnerable" in output or "injectable" in output.lower():
            # Extract parameter
            param_match = re.search(r"parameter '(.+?)' is vulnerable", output)
            param = param_match.group(1) if param_match else "unknown"

            # Extract injection type
            type_match = re.search(r"Type: (.+)", output)
            injection_type = type_match.group(1) if type_match else "Unknown"

            # Extract databases if found
            db_matches = re.findall(r'\[\*\] (.+)', output)
            databases = [d.strip() for d in db_matches if d.strip()]

            raw_data["injectable_parameters"].append(param)
            raw_data["databases"] = databases

            finding = ParsedFinding(
                tool="sqlmap",
                title=f"SQL Injection in parameter '{param}'",
                severity="CRITICAL",
                description=(
                    f"Parameter '{param}' is vulnerable to SQL injection. "
                    f"Type: {injection_type}"
                ),
                evidence=f"Injectable parameter: {param}\nType: {injection_type}",
                target=target,
                remediation=(
                    "Use parameterized queries / prepared statements. "
                    "Never concatenate user input into SQL queries."
                ),
                metadata={
                    "parameter": param,
                    "injection_type": injection_type,
                    "databases": databases
                }
            )

            findings.append(finding)

        # Check for WAF detection
        if "waf" in output.lower() or "firewall" in output.lower():
            finding = ParsedFinding(
                tool="sqlmap",
                title="WAF/Firewall Detected",
                severity="INFO",
                description="A web application firewall was detected",
                evidence="WAF detection by sqlmap",
                target=target
            )
            findings.append(finding)

        summary = (
            f"SQLmap: {'Found injectable parameters' if findings else 'No injection found'}"
        )

        return ParseResult(
            tool="sqlmap",
            target=target,
            success=True,
            findings=findings,
            raw_data=raw_data,
            summary=summary
        )


class GobusterParser:
    """Parse gobuster output"""

    def parse(self, output: str, target: str = "") -> ParseResult:
        """Parse gobuster directory/file discovery output"""

        findings = []
        discovered = []

        # Gobuster result pattern: /path (Status: 200) [Size: 1234]
        result_pattern = r'(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?'

        for match in re.finditer(result_pattern, output):
            path = match.group(1)
            status = int(match.group(2))
            size = match.group(3) or "unknown"

            discovered.append({"path": path, "status": status, "size": size})

            severity = self._path_severity(path, status)

            if severity != "INFO" or status == 200:
                finding = ParsedFinding(
                    tool="gobuster",
                    title=f"Discovered: {path} (HTTP {status})",
                    severity=severity,
                    description=f"Path {path} returned HTTP {status}",
                    evidence=f"GET {path} -> {status} (Size: {size})",
                    target=target,
                    remediation=self._path_remediation(path),
                    metadata={"status": status, "size": size}
                )
                findings.append(finding)

        summary = f"Gobuster discovered {len(discovered)} paths on {target}"

        return ParseResult(
            tool="gobuster",
            target=target,
            success=True,
            findings=findings,
            raw_data={"discovered_paths": discovered},
            summary=summary
        )

    def _path_severity(self, path: str, status: int) -> str:
        """Determine severity based on path"""

        path_lower = path.lower()

        if any(p in path_lower for p in ["/admin", "/login", "/wp-admin", "/phpmyadmin"]):
            return "HIGH"
        elif any(p in path_lower for p in ["/config", "/.env", "/backup", "/db"]):
            return "HIGH"
        elif any(p in path_lower for p in ["/api", "/v1", "/v2"]):
            return "MEDIUM"
        elif status == 403:
            return "LOW"
        return "INFO"

    def _path_remediation(self, path: str) -> str:
        """Suggest remediation for discovered path"""

        path_lower = path.lower()

        if "admin" in path_lower:
            return "Restrict admin access by IP or VPN"
        elif ".env" in path_lower:
            return "Remove .env file from web root immediately"
        elif "backup" in path_lower:
            return "Remove backup files from web root"
        elif "config" in path_lower:
            return "Restrict access to config files"
        return "Review if this path should be publicly accessible"


class FfufParser:
    """Parse ffuf output"""

    def parse(self, output: str, target: str = "") -> ParseResult:
        """Parse ffuf fuzzing output"""

        findings = []
        discovered = []

        # ffuf result pattern
        result_pattern = r'(\S+)\s+\[Status: (\d+), Size: (\d+)'

        for match in re.finditer(result_pattern, output):
            path = match.group(1)
            status = int(match.group(2))
            size = int(match.group(3))

            discovered.append({
                "path": path,
                "status": status,
                "size": size
            })

            if status in [200, 201, 301, 302, 403]:
                finding = ParsedFinding(
                    tool="ffuf",
                    title=f"Found: {path} [{status}]",
                    severity="MEDIUM" if status == 200 else "LOW",
                    description=f"FFUF discovered {path} (Status: {status}, Size: {size})",
                    evidence=f"{path} -> HTTP {status}",
                    target=target,
                    metadata={"status": status, "size": size}
                )
                findings.append(finding)

        return ParseResult(
            tool="ffuf",
            target=target,
            success=True,
            findings=findings,
            raw_data={"discovered": discovered},
            summary=f"FFUF found {len(discovered)} results"
        )


class DirbParser:
    """Parse dirb output"""

    def parse(self, output: str, target: str = "") -> ParseResult:
        findings = []

        url_pattern = r'\+\s+(https?://\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)'

        for match in re.finditer(url_pattern, output):
            url = match.group(1)
            code = int(match.group(2))
            size = match.group(3)

            finding = ParsedFinding(
                tool="dirb",
                title=f"Directory found: {url}",
                severity="MEDIUM" if code == 200 else "LOW",
                description=f"DIRB found accessible URL: {url}",
                evidence=f"{url} (HTTP {code})",
                target=target,
                metadata={"status": code, "size": size}
            )
            findings.append(finding)

        return ParseResult(
            tool="dirb",
            target=target,
            success=True,
            findings=findings,
            summary=f"DIRB found {len(findings)} URLs"
        )


class WhatwebParser:
    """Parse whatweb output"""

    def parse(self, output: str, target: str = "") -> ParseResult:
        findings = []
        technologies = []

        tech_pattern = r'(\w[\w\-\.]+)\[([^\]]+)\]'

        for match in re.finditer(tech_pattern, output):
            tech = match.group(1)
            version = match.group(2)
            technologies.append({"tech": tech, "version": version})

            if any(v in version.lower() for v in ["1.", "2.", "3."]):
                finding = ParsedFinding(
                    tool="whatweb",
                    title=f"Technology detected: {tech} {version}",
                    severity="INFO",
                    description=f"Target uses {tech} version {version}",
                    evidence=f"{tech}[{version}]",
                    target=target,
                    remediation="Ensure this technology is up to date",
                    metadata={"tech": tech, "version": version}
                )
                findings.append(finding)

        return ParseResult(
            tool="whatweb",
            target=target,
            success=True,
            findings=findings,
            raw_data={"technologies": technologies},
            summary=f"WhatWeb detected {len(technologies)} technologies"
        )


class WhoisParser:
    """Parse whois output"""

    def parse(self, output: str, target: str = "") -> ParseResult:
        raw_data = {}

        patterns = {
            "registrar": r'Registrar:\s*(.+)',
            "creation_date": r'Creation Date:\s*(.+)',
            "expiry_date": r'Registry Expiry Date:\s*(.+)',
            "registrant": r'Registrant Organization:\s*(.+)',
            "name_servers": r'Name Server:\s*(.+)'
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                raw_data[key] = match.group(1).strip()

        finding = ParsedFinding(
            tool="whois",
            title=f"WHOIS data for {target}",
            severity="INFO",
            description=f"Domain registration information",
            evidence=json.dumps(raw_data, indent=2),
            target=target,
            metadata=raw_data
        )

        return ParseResult(
            tool="whois",
            target=target,
            success=True,
            findings=[finding],
            raw_data=raw_data,
            summary=f"WHOIS: {raw_data.get('registrar', 'Unknown registrar')}"
        )


class DigParser:
    """Parse dig output"""

    def parse(self, output: str, target: str = "") -> ParseResult:
        findings = []
        records = {}

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

        for record_type in record_types:
            pattern = rf'\S+\s+\d+\s+IN\s+{record_type}\s+(\S+)'
            matches = re.findall(pattern, output)

            if matches:
                records[record_type] = matches

                finding = ParsedFinding(
                    tool="dig",
                    title=f"DNS {record_type} records for {target}",
                    severity="INFO",
                    description=f"Found {len(matches)} {record_type} record(s)",
                    evidence="\n".join(matches),
                    target=target,
                    metadata={"record_type": record_type, "values": matches}
                )
                findings.append(finding)

        return ParseResult(
            tool="dig",
            target=target,
            success=True,
            findings=findings,
            raw_data=records,
            summary=f"DNS records: {', '.join(records.keys())}"
        )


class TheHarvesterParser:
    """Parse theHarvester output"""

    def parse(self, output: str, target: str = "") -> ParseResult:
        findings = []
        emails = []
        hosts = []
        ips = []

        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = list(set(re.findall(email_pattern, output)))

        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = list(set(re.findall(ip_pattern, output)))

        if emails:
            finding = ParsedFinding(
                tool="theharvester",
                title=f"Email addresses discovered ({len(emails)})",
                severity="MEDIUM",
                description="Email addresses found through OSINT",
                evidence="\n".join(emails[:10]),
                target=target,
                remediation="Remove email addresses from public sources where possible",
                metadata={"emails": emails}
            )
            findings.append(finding)

        if ips:
            finding = ParsedFinding(
                tool="theharvester",
                title=f"IP addresses discovered ({len(ips)})",
                severity="INFO",
                description="IP addresses associated with target",
                evidence="\n".join(ips[:10]),
                target=target,
                metadata={"ips": ips}
            )
            findings.append(finding)

        return ParseResult(
            tool="theharvester",
            target=target,
            success=True,
            findings=findings,
            raw_data={"emails": emails, "ips": ips},
            summary=f"theHarvester: {len(emails)} emails, {len(ips)} IPs"
        )


class Enum4linuxParser:
    """Parse enum4linux output"""

    def parse(self, output: str, target: str = "") -> ParseResult:
        findings = []

        user_pattern = r'user:\[(.+?)\]\s+rid:\[(.+?)\]'
        users = re.findall(user_pattern, output)

        share_pattern = r'Sharename\s+Type\s+Comment.+?(?:\n.+)+'
        shares = re.findall(r'\\\\\S+\\(\S+)\s+(\S+)', output)

        if users:
            finding = ParsedFinding(
                tool="enum4linux",
                title=f"Windows users enumerated ({len(users)})",
                severity="HIGH",
                description="User accounts discovered via SMB",
                evidence="\n".join([f"{u[0]} (RID: {u[1]})" for u in users[:5]]),
                target=target,
                remediation="Disable null sessions. Require authentication for SMB",
                metadata={"users": [u[0] for u in users]}
            )
            findings.append(finding)

        if shares:
            finding = ParsedFinding(
                tool="enum4linux",
                title=f"SMB shares discovered ({len(shares)})",
                severity="MEDIUM",
                description="Accessible SMB shares found",
                evidence="\n".join([f"{s[0]} ({s[1]})" for s in shares[:5]]),
                target=target,
                remediation="Review SMB share permissions. Remove unnecessary shares",
                metadata={"shares": shares}
            )
            findings.append(finding)

        return ParseResult(
            tool="enum4linux",
            target=target,
            success=True,
            findings=findings,
            summary=f"enum4linux: {len(users)} users, {len(shares)} shares"
        )


# ─────────────────────────────────────────
# EXAMPLE USAGE
# ─────────────────────────────────────────

if __name__ == "__main__":
    parser = NovaOutputParser()

    print("=== NOVA OUTPUT PARSER ===\n")

    nmap_output = """
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 7.4
    80/tcp   open  http    Apache 2.4.6
    443/tcp  open  https   Apache 2.4.6
    3306/tcp open  mysql   MySQL 5.7.32
    """

    result = parser.parse("nmap", nmap_output, "target.com")

    print(f"Tool: {result.tool}")
    print(f"Target: {result.target}")
    print(f"Findings: {len(result.findings)}")
    print(f"Summary: {result.summary}\n")

    for finding in result.findings:
        print(f"  [{finding.severity}] {finding.title}")
        print(f"  Remediation: {finding.remediation}\n")
