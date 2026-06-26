"""
Nmap XML Output Parser.

Parses nmap XML output (-oX) into structured, actionable data.

Converts raw scan data into:
- Open ports with service details
- OS detection results
- Script scan results (NSE)
- Host discovery status
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class NmapPort:
    """A discovered open port."""
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""
    product: str = ""
    extra_info: str = ""
    cpe: str = ""

    @property
    def key(self) -> str:
        return f"{self.protocol}/{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "product": self.product,
            "extra_info": self.extra_info,
            "cpe": self.cpe,
        }


@dataclass
class NmapHost:
    """A discovered host."""
    ip: str
    hostname: str = ""
    state: str = "up"
    os: str = ""
    os_accuracy: int = 0
    mac: str = ""
    ports: List[NmapPort] = field(default_factory=list)
    scripts: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "os": self.os,
            "os_accuracy": self.os_accuracy,
            "mac": self.mac,
            "ports": [p.to_dict() for p in self.ports],
            "scripts": self.scripts,
            "port_count": len(self.ports),
            "services": list(set(p.service for p in self.ports if p.state == "open")),
        }


@dataclass
class NmapScanResult:
    """Complete parsed nmap scan."""
    cmdline: str = ""
    start_time: str = ""
    runtime: str = ""
    hosts: List[NmapHost] = field(default_factory=list)
    raw_xml: str = ""

    @property
    def all_ports(self) -> List[NmapPort]:
        ports = []
        for host in self.hosts:
            ports.extend(host.ports)
        return ports

    @property
    def total_open_ports(self) -> int:
        return sum(1 for p in self.all_ports if p.state == "open")

    @property
    def services(self) -> Dict[str, List[int]]:
        services: Dict[str, List[int]] = {}
        for port in self.all_ports:
            if port.state == "open":
                svc = port.service.lower()
                if svc not in services:
                    services[svc] = []
                services[svc].append(port.port)
        return services

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cmdline": self.cmdline,
            "start_time": self.start_time,
            "runtime": self.runtime,
            "hosts": [h.to_dict() for h in self.hosts],
            "total_hosts": len(self.hosts),
            "total_open_ports": self.total_open_ports,
            "services": self.services,
        }


class NmapParser:
    """
    Parse nmap XML output into structured data.

    Usage:
        parser = NmapParser()
        result = parser.parse(xml_content)
        for port in result.all_ports:
            print(f"{port.port}/{port.service} - {port.version}")
    """

    @staticmethod
    def parse(xml_content: str) -> NmapScanResult:
        """Parse nmap XML output string."""
        result = NmapScanResult(raw_xml=xml_content[:500])
        if not xml_content or not xml_content.strip():
            return result

        # Extract scan metadata
        result.cmdline = NmapParser._extract(xml_content, r'<nmaprun[^>]* args="([^"]*)"')
        result.start_time = NmapParser._extract(
            xml_content, r'<nmaprun[^>]* start="(\d+)"'
        )
        if result.start_time:
            try:
                ts = int(result.start_time)
                result.start_time = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            except (ValueError, OSError):
                pass

        result.runtime = NmapParser._extract(xml_content, r'<finished[^>]* elapsed="([^"]*)"')

        # Parse each host
        host_sections = NmapParser._find_sections(xml_content, "host")

        for host_xml in host_sections:
            host = NmapParser._parse_host(host_xml)
            if host:
                result.hosts.append(host)

        logger.info(
            f"Parsed nmap scan: {len(result.hosts)} hosts, "
            f"{result.total_open_ports} open ports"
        )
        return result

    @staticmethod
    def parse_file(filepath: str) -> NmapScanResult:
        """Read and parse an nmap XML file."""
        try:
            with open(filepath, "r", errors="replace") as f:
                content = f.read()
            return NmapParser.parse(content)
        except FileNotFoundError:
            logger.warning(f"Nmap XML file not found: {filepath}")
            return NmapScanResult()
        except Exception as e:
            logger.error(f"Error reading nmap XML file {filepath}: {e}")
            return NmapScanResult()

    @staticmethod
    def _extract(text: str, pattern: str, group: int = 1) -> str:
        """Extract a regex group from text."""
        m = re.search(pattern, text, re.DOTALL)
        return m.group(group) if m else ""

    @staticmethod
    def _find_sections(text: str, tag: str) -> List[str]:
        """Find all top-level XML sections with given tag."""
        sections = []
        pattern = rf"<{tag}[^>]*>.*?</{tag}>"
        for m in re.finditer(pattern, text, re.DOTALL):
            sections.append(m.group())
        return sections

    @staticmethod
    def _parse_host(host_xml: str) -> Optional[NmapHost]:
        """Parse a single host section."""
        # Extract IP address
        ip = NmapParser._extract(
            host_xml,
            r'<address[^>]* addr="(\d+\.\d+\.\d+\.\d+)"[^>]* addrtype="ipv4"'
        )
        if not ip:
            ip = NmapParser._extract(
                host_xml,
                r'<address[^>]* addr="([^"]*)"[^>]* addrtype="ipv[46]"'
            )
        if not ip:
            return None

        host = NmapHost(ip=ip)

        # Hostname
        host.hostname = NmapParser._extract(host_xml, r'<hostname[^>]* name="([^"]*)"')

        # Host state
        state = NmapParser._extract(host_xml, r'<status[^>]* state="([^"]*)"')
        host.state = state if state else "up"

        # MAC address
        host.mac = NmapParser._extract(
            host_xml, r'<address[^>]* addr="([^"]*)"[^>]* addrtype="mac"'
        )

        # OS detection
        os_match = re.search(
            r'<osmatch[^>]* name="([^"]*)"[^>]* accuracy="(\d+)"',
            host_xml
        )
        if os_match:
            host.os = os_match.group(1)
            host.os_accuracy = int(os_match.group(2))

        # Ports
        port_sections = NmapParser._find_sections(host_xml, "port")
        for port_xml in port_sections:
            port = NmapParser._parse_port(port_xml)
            if port:
                host.ports.append(port)

        # Script results (NSE)
        script_sections = NmapParser._find_sections(host_xml, "script")
        for script_xml in script_sections:
            script_id = NmapParser._extract(script_xml, r'id="([^"]*)"')
            script_output = NmapParser._extract(script_xml, r'output="([^"]*)"')
            if script_id:
                host.scripts.append({
                    "id": script_id,
                    "output": script_output,
                })

        return host

    @staticmethod
    def _parse_port(port_xml: str) -> Optional[NmapPort]:
        """Parse a single port section."""
        port_id = NmapParser._extract(port_xml, r'portid="(\d+)"')
        protocol = NmapParser._extract(port_xml, r'protocol="([^"]*)"')
        state = NmapParser._extract(port_xml, r'<state[^>]* state="([^"]*)"')

        if not port_id:
            return None

        try:
            port_num = int(port_id)
        except ValueError:
            return None

        port = NmapPort(
            port=port_num,
            protocol=protocol or "tcp",
            state=state or "filtered",
            service="unknown",
        )

        # Service details
        service_section = NmapParser._extract(
            port_xml, r'(<service[^>]*/>|<service[^>]*>.*?</service>)'
        )
        if service_section:
            port.service = NmapParser._extract(service_section, r'name="([^"]*)"')
            port.product = NmapParser._extract(service_section, r'product="([^"]*)"')
            port.version = NmapParser._extract(service_section, r'version="([^"]*)"')
            port.extra_info = NmapParser._extract(service_section, r'extrainfo="([^"]*)"')
            port.cpe = NmapParser._extract(service_section, r'<cpe>[^<]*</cpe>')

        return port

    @staticmethod
    def extract_findings(result: NmapScanResult) -> List[Dict[str, Any]]:
        """Extract security-relevant findings from parsed scan data."""
        findings = []

        # Map service names to port numbers
        for svc, ports in result.services.items():
            if svc in ("http", "https", "http-proxy"):
                findings.append({
                    "title": f"Web Service Detected ({svc.upper()})",
                    "severity": "info",
                    "description": f"Web service running on port(s): {', '.join(map(str, ports))}",
                    "ports": ports,
                    "service": svc,
                })
            elif svc in ("smb", "microsoft-ds", "netbios-ssn"):
                findings.append({
                    "title": "SMB Service Detected",
                    "severity": "medium",
                    "description": f"SMB service on port(s): {', '.join(map(str, ports))}",
                    "ports": ports,
                    "service": svc,
                })
            elif svc in ("mysql", "postgresql", "ms-sql-s", "oracle-tns"):
                findings.append({
                    "title": f"Database Service Detected ({svc})",
                    "severity": "medium",
                    "description": f"Database service on port(s): {', '.join(map(str, ports))}",
                    "ports": ports,
                    "service": svc,
                })
            elif svc in ("ssh",):
                findings.append({
                    "title": "SSH Service Detected",
                    "severity": "low",
                    "description": f"SSH service on port(s): {', '.join(map(str, ports))}",
                    "ports": ports,
                    "service": svc,
                })

        # Check for outdated versions
        for port in result.all_ports:
            if port.version:
                version_str = f"{port.product} {port.version}".lower()
                outdated = ["2.4.", "1.0.", "0.9.", "old", "deprecated"]
                if any(x in version_str for x in outdated):
                    findings.append({
                        "title": f"Potentially Outdated Service: {port.service}",
                        "severity": "medium",
                        "description": f"{port.product} {port.version} on port {port.port}",
                        "ports": [port.port],
                        "service": port.service,
                    })

        return findings
