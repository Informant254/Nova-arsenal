"""
NOVA RESULT PARSER
==================
Parses output from Kali tools into structured vulnerability data.

Supported tools:
- nmap  (XML, JSON, raw text)
- sqlmap (text/log output)
- nikto  (text, CSV, XML)

Features:
- Aggregate all findings into a FindingsDatabase
- Structured vulnerability data (CVE, severity, port, service)
- Export to JSON / summary report

Usage:
    from nova_result_parser import NovaResultParser

    parser = NovaResultParser()

    # Parse individual tool output
    findings = parser.parse("nmap", output_text, fmt="xml")
    findings = parser.parse("sqlmap", output_text)
    findings = parser.parse("nikto", output_text)

    # Or parse a ToolResult from nova_performance_optimizer
    findings = parser.parse_tool_result(tool_result)

    # Get aggregated database
    db = parser.database
    print(db.summary())
    db.export_json("findings.json")
"""

import re
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum


# ──────────────────────────────────────────────
# SEVERITY LEVELS
# ──────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH:     4,
    Severity.MEDIUM:   3,
    Severity.LOW:      2,
    Severity.INFO:     1,
}


# ──────────────────────────────────────────────
# FINDING DATA MODEL
# ──────────────────────────────────────────────

@dataclass
class Finding:
    """A single vulnerability or information finding"""
    id: str = ""
    tool: str = ""
    target: str = ""
    severity: Severity = Severity.INFO

    # What was found
    title: str = ""
    description: str = ""

    # Location
    port: Optional[int] = None
    protocol: str = ""
    service: str = ""
    path: str = ""

    # Technical detail
    cve: Optional[str] = None
    evidence: str = ""
    recommendation: str = ""

    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    raw: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ──────────────────────────────────────────────
# FINDINGS DATABASE
# ──────────────────────────────────────────────

class FindingsDatabase:
    """
    Aggregates all parsed findings across tools.
    Deduplicates, sorts by severity, and exports.
    """

    def __init__(self):
        self._findings: List[Finding] = []

    def add(self, finding: Finding):
        if not self._is_duplicate(finding):
            self._findings.append(finding)

    def add_many(self, findings: List[Finding]):
        for f in findings:
            self.add(f)

    def _is_duplicate(self, new: Finding) -> bool:
        for existing in self._findings:
            if (existing.tool == new.tool and
                existing.target == new.target and
                existing.title == new.title and
                existing.port == new.port):
                return True
        return False

    @property
    def all(self) -> List[Finding]:
        return sorted(
            self._findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
            reverse=True
        )

    def by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self._findings if f.severity == severity]

    def by_tool(self, tool: str) -> List[Finding]:
        return [f for f in self._findings if f.tool == tool]

    def by_target(self, target: str) -> List[Finding]:
        return [f for f in self._findings if f.target == target]

    def critical_and_high(self) -> List[Finding]:
        return [
            f for f in self.all
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

    def summary(self) -> Dict[str, Any]:
        counts = {s.value: 0 for s in Severity}
        for f in self._findings:
            counts[f.severity.value] += 1
        tools_used = list({f.tool for f in self._findings})
        targets = list({f.target for f in self._findings})
        return {
            "total_findings": len(self._findings),
            "by_severity": counts,
            "tools": tools_used,
            "targets": targets,
            "critical_and_high": len(self.critical_and_high())
        }

    def export_json(self, path: str = "nova_findings.json"):
        data = {
            "generated_at": datetime.now().isoformat(),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.all]
        }
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        print(f"[+] Findings exported to {path}")
        return path

    def print_report(self):
        summary = self.summary()
        print("\n" + "=" * 60)
        print("NOVA FINDINGS REPORT")
        print("=" * 60)
        print(f"Total findings : {summary['total_findings']}")
        print(f"Critical       : {summary['by_severity']['CRITICAL']}")
        print(f"High           : {summary['by_severity']['HIGH']}")
        print(f"Medium         : {summary['by_severity']['MEDIUM']}")
        print(f"Low            : {summary['by_severity']['LOW']}")
        print(f"Info           : {summary['by_severity']['INFO']}")
        print(f"Tools used     : {', '.join(summary['tools'])}")
        print(f"Targets        : {', '.join(summary['targets'])}")
        print("-" * 60)

        for f in self.all:
            port_str = f":{f.port}" if f.port else ""
            cve_str  = f" [{f.cve}]" if f.cve else ""
            print(f"[{f.severity.value:<8}] {f.title}{cve_str}")
            print(f"           Target : {f.target}{port_str}  Service: {f.service or 'N/A'}")
            if f.description:
                print(f"           Detail : {f.description[:100]}")
            if f.recommendation:
                print(f"           Fix    : {f.recommendation}")
            print()


# ──────────────────────────────────────────────
# NMAP PARSER
# ──────────────────────────────────────────────

class NmapParser:
    """Parse nmap output: XML (preferred), JSON, or raw text"""

    def parse(self, output: str, target: str = "", fmt: str = "auto") -> List[Finding]:
        fmt = self._detect_format(output) if fmt == "auto" else fmt
        if fmt == "xml":
            return self._parse_xml(output, target)
        elif fmt == "json":
            return self._parse_json(output, target)
        else:
            return self._parse_text(output, target)

    def _detect_format(self, output: str) -> str:
        stripped = output.strip()
        if stripped.startswith("<"):
            return "xml"
        try:
            json.loads(stripped)
            return "json"
        except Exception:
            return "text"

    def _parse_xml(self, output: str, target: str) -> List[Finding]:
        findings = []
        try:
            root = ET.fromstring(output)
        except ET.ParseError as e:
            return [Finding(
                tool="nmap", target=target, severity=Severity.INFO,
                title="nmap XML parse error", description=str(e)
            )]

        for host in root.findall("host"):
            # Get IP
            addr_el = host.find("address[@addrtype='ipv4']")
            host_ip = addr_el.get("addr", target) if addr_el is not None else target

            # Host status
            status_el = host.find("status")
            if status_el is not None and status_el.get("state") != "up":
                continue

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                portid   = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")

                state_el   = port_el.find("state")
                service_el = port_el.find("service")

                if state_el is None or state_el.get("state") != "open":
                    continue

                service_name    = service_el.get("name", "")    if service_el is not None else ""
                service_version = service_el.get("version", "") if service_el is not None else ""
                service_product = service_el.get("product", "") if service_el is not None else ""

                # Base finding for open port
                findings.append(Finding(
                    tool="nmap",
                    target=host_ip,
                    severity=Severity.INFO,
                    title=f"Open port {portid}/{protocol} — {service_name}",
                    description=f"{service_product} {service_version}".strip(),
                    port=portid,
                    protocol=protocol,
                    service=service_name,
                    raw=ET.tostring(port_el, encoding="unicode")
                ))

                # Flag risky services
                findings += self._flag_risky_service(
                    host_ip, portid, protocol, service_name, service_version
                )

                # Parse NSE scripts
                for script in port_el.findall("script"):
                    script_finding = self._parse_nse_script(
                        script, host_ip, portid, protocol, service_name
                    )
                    if script_finding:
                        findings.append(script_finding)

        return findings

    def _parse_json(self, output: str, target: str) -> List[Finding]:
        """Parse nmap JSON output (nmap -oJ)"""
        findings = []
        try:
            data = json.loads(output)
            hosts = data.get("nmaprun", {}).get("host", [])
            if isinstance(hosts, dict):
                hosts = [hosts]
            for host in hosts:
                host_ip = host.get("address", {}).get("addr", target)
                ports = host.get("ports", {}).get("port", [])
                if isinstance(ports, dict):
                    ports = [ports]
                for port in ports:
                    if port.get("state", {}).get("state") != "open":
                        continue
                    portid   = int(port.get("portid", 0))
                    protocol = port.get("protocol", "tcp")
                    service  = port.get("service", {})
                    svc_name = service.get("name", "")
                    findings.append(Finding(
                        tool="nmap",
                        target=host_ip,
                        severity=Severity.INFO,
                        title=f"Open port {portid}/{protocol} — {svc_name}",
                        port=portid,
                        protocol=protocol,
                        service=svc_name,
                        raw=json.dumps(port)
                    ))
                    findings += self._flag_risky_service(
                        host_ip, portid, protocol, svc_name, ""
                    )
        except Exception as e:
            findings.append(Finding(
                tool="nmap", target=target, severity=Severity.INFO,
                title="nmap JSON parse error", description=str(e)
            ))
        return findings

    def _parse_text(self, output: str, target: str) -> List[Finding]:
        """Fallback: parse nmap raw text output"""
        findings = []
        current_host = target

        host_pattern    = re.compile(r"Nmap scan report for (.+)")
        port_pattern    = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?")
        version_pattern = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)")

        for line in output.splitlines():
            host_match = host_pattern.search(line)
            if host_match:
                current_host = host_match.group(1).strip()
                continue

            port_match = port_pattern.search(line)
            if port_match:
                portid   = int(port_match.group(1))
                protocol = port_match.group(2)
                service  = port_match.group(3)
                version  = port_match.group(4) or ""

                findings.append(Finding(
                    tool="nmap",
                    target=current_host,
                    severity=Severity.INFO,
                    title=f"Open port {portid}/{protocol} — {service}",
                    description=version.strip(),
                    port=portid,
                    protocol=protocol,
                    service=service,
                    raw=line
                ))
                findings += self._flag_risky_service(
                    current_host, portid, protocol, service, version
                )

        return findings

    def _flag_risky_service(
        self,
        host: str,
        port: int,
        protocol: str,
        service: str,
        version: str
    ) -> List[Finding]:
        """Flag well-known risky services/ports"""
        findings = []
        risky = {
            21:   ("FTP open — credentials transmitted in cleartext",    Severity.MEDIUM, "Replace FTP with SFTP"),
            23:   ("Telnet open — unencrypted remote access",            Severity.HIGH,   "Disable Telnet, use SSH"),
            445:  ("SMB open — potential EternalBlue / ransomware risk", Severity.HIGH,   "Patch and restrict SMB"),
            3389: ("RDP open — brute force / BlueKeep risk",             Severity.HIGH,   "Restrict RDP access, use VPN"),
            1433: ("MSSQL exposed",                                      Severity.MEDIUM, "Restrict DB port access"),
            3306: ("MySQL exposed",                                      Severity.MEDIUM, "Restrict DB port access"),
            5432: ("PostgreSQL exposed",                                 Severity.MEDIUM, "Restrict DB port access"),
            6379: ("Redis exposed — often unauthenticated",              Severity.HIGH,   "Add Redis auth, bind to localhost"),
            27017:("MongoDB exposed — often unauthenticated",            Severity.HIGH,   "Add auth, restrict access"),
            2375: ("Docker daemon exposed (unencrypted)",                Severity.CRITICAL,"Never expose Docker API publicly"),
        }
        if port in risky:
            title, severity, rec = risky[port]
            findings.append(Finding(
                tool="nmap",
                target=host,
                severity=severity,
                title=title,
                port=port,
                protocol=protocol,
                service=service,
                description=version,
                recommendation=rec,
                raw=f"{port}/{protocol} {service} {version}"
            ))
        return findings

    def _parse_nse_script(
        self,
        script_el,
        host: str,
        port: int,
        protocol: str,
        service: str
    ) -> Optional[Finding]:
        """Parse NSE script results for vulns"""
        script_id     = script_el.get("id", "")
        script_output = script_el.get("output", "")

        severity = Severity.INFO
        cve = None

        # Extract CVE if present
        cve_match = re.search(r"CVE-\d{4}-\d+", script_output)
        if cve_match:
            cve = cve_match.group(0)
            severity = Severity.HIGH

        if "VULNERABLE" in script_output.upper():
            severity = Severity.HIGH
        if "CRITICAL" in script_output.upper():
            severity = Severity.CRITICAL

        if severity == Severity.INFO and not cve:
            return None  # Skip non-interesting scripts

        return Finding(
            tool="nmap",
            target=host,
            severity=severity,
            title=f"NSE: {script_id}",
            description=script_output[:300],
            port=port,
            protocol=protocol,
            service=service,
            cve=cve,
            raw=script_output
        )


# ──────────────────────────────────────────────
# SQLMAP PARSER
# ──────────────────────────────────────────────

class SqlmapParser:
    """Parse sqlmap console output"""

    # Patterns for key sqlmap findings
    PATTERNS = {
        "injectable":    (re.compile(r"Parameter: (.+?) \((.+?)\).*?is vulnerable", re.I | re.S), Severity.CRITICAL),
        "dbms":          (re.compile(r"back-end DBMS:\s*(.+)",                        re.I),       Severity.INFO),
        "database":      (re.compile(r"\[\*\] (.+?) \(current\)",                     re.I),       Severity.HIGH),
        "table":         (re.compile(r"Database: (.+?)\nTable: (.+?)\n",               re.I | re.S),Severity.HIGH),
        "credentials":   (re.compile(r"(?:username|user|password|pass).*?:\s*(.+)",   re.I),       Severity.CRITICAL),
        "os_shell":      (re.compile(r"os-shell",                                      re.I),       Severity.CRITICAL),
        "file_read":     (re.compile(r"file read",                                     re.I),       Severity.HIGH),
        "technique":     (re.compile(r"Type: (.+?)\n.*?Title: (.+?)\n",               re.I | re.S),Severity.HIGH),
    }

    def parse(self, output: str, target: str = "") -> List[Finding]:
        findings = []

        # Extract URL/target from output if not provided
        if not target:
            url_match = re.search(r"testing URL '(.+?)'", output)
            if url_match:
                target = url_match.group(1)

        # Injectable parameter
        inj_match = re.search(
            r"Parameter: (.+?) \((.+?)\)", output, re.I
        )
        if inj_match and "vulnerable" in output.lower():
            param  = inj_match.group(1)
            method = inj_match.group(2)
            findings.append(Finding(
                tool="sqlmap",
                target=target,
                severity=Severity.CRITICAL,
                title=f"SQL Injection — parameter '{param}' ({method})",
                description="sqlmap confirmed SQL injection vulnerability",
                service="http",
                recommendation="Use parameterized queries / prepared statements",
                raw=output[:500]
            ))

        # Injection techniques
        for tech_match in re.finditer(
            r"Type: (.+?)\n\s*Title: (.+?)\n\s*Payload: (.+?)\n",
            output, re.I | re.S
        ):
            findings.append(Finding(
                tool="sqlmap",
                target=target,
                severity=Severity.HIGH,
                title=f"SQLi technique: {tech_match.group(2).strip()}",
                description=f"Type: {tech_match.group(1).strip()}",
                evidence=tech_match.group(3).strip()[:200],
                service="http",
                raw=tech_match.group(0)
            ))

        # DBMS fingerprint
        dbms_match = re.search(r"back-end DBMS:\s*(.+)", output, re.I)
        if dbms_match:
            findings.append(Finding(
                tool="sqlmap",
                target=target,
                severity=Severity.INFO,
                title=f"DBMS identified: {dbms_match.group(1).strip()}",
                service="database",
                raw=dbms_match.group(0)
            ))

        # Current database
        for db_match in re.finditer(r"current database:\s*'?(.+?)'?\s*$", output, re.I | re.M):
            findings.append(Finding(
                tool="sqlmap",
                target=target,
                severity=Severity.HIGH,
                title=f"Database accessible: {db_match.group(1).strip()}",
                description="sqlmap was able to retrieve the current database name",
                service="database",
                raw=db_match.group(0)
            ))

        # Tables dumped
        for tbl_match in re.finditer(r"\| (.+?) \|", output):
            val = tbl_match.group(1).strip()
            if val and val not in ("Table", "Column", "Type"):
                findings.append(Finding(
                    tool="sqlmap",
                    target=target,
                    severity=Severity.HIGH,
                    title=f"Data extracted: {val}",
                    description="sqlmap extracted table/column data",
                    service="database",
                    raw=tbl_match.group(0)
                ))

        # OS shell / file read
        if re.search(r"os-shell", output, re.I):
            findings.append(Finding(
                tool="sqlmap",
                target=target,
                severity=Severity.CRITICAL,
                title="OS Shell obtained via SQL injection",
                description="sqlmap achieved OS-level command execution",
                recommendation="Immediately patch SQL injection and restrict DB privileges",
                raw=""
            ))

        if re.search(r"file read", output, re.I):
            findings.append(Finding(
                tool="sqlmap",
                target=target,
                severity=Severity.HIGH,
                title="File read via SQL injection",
                description="sqlmap was able to read files from the server filesystem",
                recommendation="Restrict FILE privilege on DB user",
                raw=""
            ))

        return findings


# ──────────────────────────────────────────────
# NIKTO PARSER
# ──────────────────────────────────────────────

class NiktoParser:
    """Parse nikto output: text, CSV, or XML"""

    def parse(self, output: str, target: str = "", fmt: str = "auto") -> List[Finding]:
        fmt = self._detect_format(output) if fmt == "auto" else fmt
        if fmt == "xml":
            return self._parse_xml(output, target)
        elif fmt == "csv":
            return self._parse_csv(output, target)
        else:
            return self._parse_text(output, target)

    def _detect_format(self, output: str) -> str:
        stripped = output.strip()
        if stripped.startswith("<"):
            return "xml"
        if stripped.startswith('"') or re.match(r"[\w.]+,\d+,", stripped):
            return "csv"
        return "text"

    def _parse_text(self, output: str, target: str) -> List[Finding]:
        findings = []

        # Extract target from output
        target_match = re.search(r"Target IP:\s*(\S+)", output)
        if target_match and not target:
            target = target_match.group(1)

        port_match = re.search(r"Target Port:\s*(\d+)", output)
        port = int(port_match.group(1)) if port_match else 80

        # Each finding line starts with + or -
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            if "Target IP" in line or "Target Port" in line or "Server" in line:
                continue
            if "Nikto" in line or "items checked" in line:
                continue

            severity = self._classify_nikto_line(line)
            cve = None
            cve_match = re.search(r"CVE-\d{4}-\d+", line)
            if cve_match:
                cve = cve_match.group(0)

            path = ""
            path_match = re.search(r"(/[\w./\-?=&%]+)", line)
            if path_match:
                path = path_match.group(1)

            findings.append(Finding(
                tool="nikto",
                target=target,
                severity=severity,
                title=line[:120],
                description=line,
                port=port,
                protocol="tcp",
                service="http",
                path=path,
                cve=cve,
                raw=line
            ))

        return findings

    def _parse_csv(self, output: str, target: str) -> List[Finding]:
        """Parse nikto CSV output (-Format csv)"""
        findings = []
        for line in output.splitlines():
            parts = line.split(",")
            if len(parts) < 7:
                continue
            host    = parts[0].strip('"') or target
            port    = int(parts[1]) if parts[1].isdigit() else 80
            uri     = parts[3].strip('"')
            method  = parts[4].strip('"')
            desc    = parts[6].strip('"') if len(parts) > 6 else ""

            cve = None
            cve_match = re.search(r"CVE-\d{4}-\d+", desc)
            if cve_match:
                cve = cve_match.group(0)

            findings.append(Finding(
                tool="nikto",
                target=host,
                severity=self._classify_nikto_line(desc),
                title=desc[:120],
                description=desc,
                port=port,
                protocol="tcp",
                service="http",
                path=uri,
                cve=cve,
                raw=line
            ))
        return findings

    def _parse_xml(self, output: str, target: str) -> List[Finding]:
        """Parse nikto XML output (-Format xml)"""
        findings = []
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            return findings

        for scan in root.findall(".//scandetails"):
            host = scan.get("targetip", target)
            port = int(scan.get("targetport", 80))

            for item in scan.findall("item"):
                desc     = item.findtext("description", "")
                uri      = item.findtext("uri", "")
                method   = item.findtext("method", "")

                cve = None
                cve_match = re.search(r"CVE-\d{4}-\d+", desc)
                if cve_match:
                    cve = cve_match.group(0)

                findings.append(Finding(
                    tool="nikto",
                    target=host,
                    severity=self._classify_nikto_line(desc),
                    title=desc[:120],
                    description=desc,
                    port=port,
                    protocol="tcp",
                    service="http",
                    path=uri,
                    cve=cve,
                    raw=ET.tostring(item, encoding="unicode")
                ))
        return findings

    def _classify_nikto_line(self, line: str) -> Severity:
        line_lower = line.lower()
        if any(k in line_lower for k in ["remote code", "rce", "command execution", "os-shell"]):
            return Severity.CRITICAL
        if any(k in line_lower for k in ["sql injection", "xss", "cve-", "outdated", "vulnerable",
                                          "shellshock", "heartbleed", "directory traversal"]):
            return Severity.HIGH
        if any(k in line_lower for k in ["password", "credential", "authentication", "sensitive",
                                          "misconfigur", "debug", "admin"]):
            return Severity.MEDIUM
        if any(k in line_lower for k in ["header", "cookie", "allowed method", "options"]):
            return Severity.LOW
        return Severity.INFO


# ──────────────────────────────────────────────
# MAIN PARSER
# ──────────────────────────────────────────────

class NovaResultParser:
    """
    Main result parser for NovaKaliAgent.

    Parses output from nmap, sqlmap, nikto into structured Finding objects
    and aggregates them into a FindingsDatabase.

    Usage:
        parser = NovaResultParser()

        # Parse raw output
        parser.parse("nmap", nmap_xml_output, target="192.168.1.1", fmt="xml")
        parser.parse("sqlmap", sqlmap_output, target="http://target.com")
        parser.parse("nikto", nikto_output, target="192.168.1.1")

        # Get all findings
        parser.database.print_report()
        parser.database.export_json("findings.json")
    """

    def __init__(self):
        self.database   = FindingsDatabase()
        self._nmap      = NmapParser()
        self._sqlmap    = SqlmapParser()
        self._nikto     = NiktoParser()
        self._parsers   = {
            "nmap":   self._nmap,
            "sqlmap": self._sqlmap,
            "nikto":  self._nikto,
        }

    def parse(
        self,
        tool: str,
        output: str,
        target: str = "",
        fmt: str = "auto"
    ) -> List[Finding]:
        """
        Parse output from a specific tool.

        Args:
            tool:   "nmap", "sqlmap", or "nikto"
            output: raw tool output string
            target: target IP or URL
            fmt:    output format hint ("auto", "xml", "json", "text", "csv")

        Returns:
            List of Finding objects (also added to self.database)
        """
        tool = tool.lower()
        parser = self._parsers.get(tool)

        if parser is None:
            # Unknown tool — store raw output as INFO finding
            findings = [Finding(
                tool=tool,
                target=target,
                severity=Severity.INFO,
                title=f"Raw output from {tool}",
                description=output[:500],
                raw=output
            )]
        elif tool == "nmap":
            findings = parser.parse(output, target, fmt)
        elif tool == "nikto":
            findings = parser.parse(output, target, fmt)
        else:
            findings = parser.parse(output, target)

        self.database.add_many(findings)
        return findings

    def parse_tool_result(self, tool_result) -> List[Finding]:
        """
        Parse a ToolResult object from nova_performance_optimizer directly.

        Args:
            tool_result: ToolResult instance

        Returns:
            List of Finding objects
        """
        return self.parse(
            tool=tool_result.tool,
            output=tool_result.output,
            target=tool_result.target
        )

    def parse_many(self, tool_results: list) -> List[Finding]:
        """Parse a list of ToolResult objects"""
        all_findings = []
        for tr in tool_results:
            all_findings.extend(self.parse_tool_result(tr))
        return all_findings

    def summary(self) -> Dict[str, Any]:
        return self.database.summary()


# ──────────────────────────────────────────────
# DEMO
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("NOVA RESULT PARSER — DEMO")
    print("=" * 60)

    parser = NovaResultParser()

    # ── Demo 1: nmap text output ──
    nmap_text = """
Starting Nmap 7.94 at 2026-06-06 03:00
Nmap scan report for 192.168.1.1
Host is up (0.001s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4
80/tcp   open  http       Apache httpd 2.4.6
443/tcp  open  https      Apache httpd 2.4.6
3306/tcp open  mysql      MySQL 5.7.34
3389/tcp open  ms-wbt-server Microsoft Terminal Services
21/tcp   open  ftp        vsftpd 3.0.3
"""
    print("\n[1] Parsing nmap text output...")
    nmap_findings = parser.parse("nmap", nmap_text, target="192.168.1.1")
    print(f"    Found {len(nmap_findings)} findings")

    # ── Demo 2: sqlmap output ──
    sqlmap_text = """
[*] testing URL 'http://192.168.1.1/login.php?id=1'
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND SLEEP(5)

back-end DBMS: MySQL >= 5.0.12
current database: 'webapp_db'
[+] Parameter: id (GET) is vulnerable

| users   |
| admin   |
| password|
"""
    print("\n[2] Parsing sqlmap output...")
    sql_findings = parser.parse("sqlmap", sqlmap_text, target="http://192.168.1.1/login.php")
    print(f"    Found {len(sql_findings)} findings")

    # ── Demo 3: nikto output ──
    nikto_text = """
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.1
+ Target Port:        80
+ Server: Apache/2.4.6
+ /: Server may leak inodes via ETags. CVE-2003-1418.
+ /: OSVDB-3092: /admin/: This might be interesting...
+ /: HTTP TRACE method is active; vulnerable to XSS.
+ /config.php: PHP config file found - may contain credentials.
+ /phpMyAdmin/: phpMyAdmin directory found - remote code execution possible.
"""
    print("\n[3] Parsing nikto output...")
    nikto_findings = parser.parse("nikto", nikto_text, target="192.168.1.1")
    print(f"    Found {len(nikto_findings)} findings")

    # ── Full report ──
    print("\n[4] Aggregated findings report:")
    parser.database.print_report()

    # ── Export ──
    parser.database.export_json("/tmp/nova_findings_demo.json")

    print("\nIntegrate with optimizer:")
    print("  results = optimizer.run_parallel(commands, target)")
    print("  findings = parser.parse_many(results)")
    print("  parser.database.print_report()")
