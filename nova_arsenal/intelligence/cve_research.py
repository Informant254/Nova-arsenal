"""
Live CVE / Exploit Research Module.

Takes detected services and their versions, then searches
public databases for known vulnerabilities and exploits.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CveResult:
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    exploit_available: bool
    exploit_source: str = ""
    affected_versions: str = ""
    published_date: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description[:200],
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "exploit_available": self.exploit_available,
            "exploit_source": self.exploit_source,
            "affected_versions": self.affected_versions,
            "published_date": self.published_date,
            "remediation": self.remediation,
        }


@dataclass
class ServiceCveResult:
    service: str
    port: int
    version: str
    cves: List[CveResult] = field(default_factory=list)
    has_exploit: bool = False
    risk_score: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "service": self.service,
            "port": self.port,
            "version": self.version,
            "cve_count": len(self.cves),
            "has_exploit": self.has_exploit,
            "risk_score": self.risk_score,
            "cves": [c.to_dict() for c in self.cves],
        }


SERVICE_CVE_MAP: Dict[str, List[Tuple[str, str, str, str, float, str]]] = {
    "http": [
        (r"apache httpd (\d+\.\d+\.\d+)", "Apache HTTPD {version} vulnerable to path traversal",
         "CVE-2021-41773", "high", 7.5, "Exploit available: curl http://target/cgi-bin/.%2e/%2e%2e/..."),
        (r"apache httpd (\d+\.\d+\.\d+)", "Apache HTTPD {version} vulnerable to SSRF",
         "CVE-2021-40438", "medium", 6.4, "Metasploit auxiliary/server/http_ssrf"),
    ],
    "smb": [
        (r"samba (\d+\.\d+\.\d+)", "Samba {version} vulnerable to remote code execution",
         "CVE-2021-44142", "critical", 9.9, "Metasploit exploit/linux/samba/is_known_pipename"),
        (r"microsoft-ds", "SMB vulnerable to EternalBlue",
         "CVE-2017-0144", "critical", 9.3, "Metasploit exploit/windows/smb/ms17_010_eternalblue"),
    ],
    "ssh": [
        (r"openssh (\d+\.\d+)", "OpenSSH {version} - potential vulnerabilities",
         "", "medium", 5.0, "Check for CVE-2024-6387 (regreSSHion) if version 8.5p1-9.7p1"),
        (r"libssh (\d+\.\d+\.\d+)", "libSSH {version} vulnerable to authentication bypass",
         "CVE-2018-10933", "critical", 9.1, "Metasploit auxiliary/scanner/ssh/libssh_auth_bypass"),
    ],
    "mysql": [
        (r"mysql (\d+\.\d+\.\d+)", "MySQL {version} - check for known vulnerabilities",
         "", "medium", 5.0, "Run nmap --script mysql-* for comprehensive checks"),
    ],
    "postgresql": [
        (r"postgresql (\d+\.\d+\.\d+)", "PostgreSQL {version} - check for known vulnerabilities",
         "", "medium", 5.0, "Run nmap --script pgsql-* for comprehensive checks"),
    ],
    "rdp": [
        (r"rdp", "RDP vulnerable to BlueKeep",
         "CVE-2019-0708", "critical", 9.8, "Metasploit exploit/windows/rdp/cve_2019_0708_bluekeep_rce"),
    ],
    "kerberos": [
        (r"kerberos", "Kerberos - check for MS14-068",
         "CVE-2014-068", "high", 8.0, "Metasploit auxiliary/admin/kerberos/ms14_068_kerberos_checksum"),
    ],
}


KNOWN_EXPLOIT_PATTERNS: Dict[str, List[str]] = {
    "eternalblue": ["MS17-010", "eternalblue", "CVE-2017-0144"],
    "bluekeep": ["bluekeep", "CVE-2019-0708"],
    "log4j": ["log4j", "log4shell", "CVE-2021-44228"],
    "shellshock": ["shellshock", "CVE-2014-6271"],
    "heartbleed": ["heartbleed", "CVE-2014-0160"],
    "printnightmare": ["printnightmare", "CVE-2021-34527"],
    "zerologon": ["zerologon", "CVE-2020-1472"],
    "proxyshell": ["proxyshell", "CVE-2021-34473"],
    "proxyLogon": ["proxylogon", "CVE-2021-26855"],
    "regresshion": ["regresshion", "CVE-2024-6387"],
}


class CveResearch:
    """
    Researches CVEs and exploits for detected services.

    Uses a combination of:
    - Built-in service→CVE mapping (offline, fast)
    - Pattern matching for known exploits
    - Version comparison heuristics
    """

    def __init__(self) -> None:
        self._cache: Dict[str, ServiceCveResult] = {}

    async def research(self, service: str, version: str, port: int) -> ServiceCveResult:
        cache_key = f"{service}:{version}:{port}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = ServiceCveResult(
            service=service,
            port=port,
            version=version,
        )

        cves = self._lookup_cves(service, version)
        exploit_flags = self._check_known_exploit(service, version)

        seen: set = set()
        for cve in cves + exploit_flags:
            dedup_key = (cve.cve_id, cve.severity)
            if dedup_key not in seen:
                seen.add(dedup_key)
                result.cves.append(cve)
                if cve.exploit_available:
                    result.has_exploit = True

        result.risk_score = self._calculate_risk(result.cves)
        self._cache[cache_key] = result
        return result

    def _lookup_cves(self, service: str, version: str) -> List[CveResult]:
        results: List[CveResult] = []
        service_key = service.lower()

        if service_key not in SERVICE_CVE_MAP:
            return results

        for pattern, desc_template, cve_id, severity, cvss, remediation in SERVICE_CVE_MAP[service_key]:
            match = re.search(pattern, version, re.IGNORECASE)
            if match or (not pattern.startswith(r"\d") and pattern == service_key):
                ver_str = match.group(1) if match else version
                description = desc_template.format(version=ver_str)
                has_exploit = bool(remediation and ("Metasploit" in remediation or "Exploit available" in remediation))
                exploit_source = ""
                if "Metasploit" in remediation:
                    exploit_source = remediation.split("Metasploit")[1].strip().split()[0] if "Metasploit" in remediation else ""
                elif "Exploit available" in remediation:
                    exploit_source = remediation

                results.append(CveResult(
                    cve_id=cve_id if cve_id else "N/A",
                    description=description,
                    severity=severity,
                    cvss_score=cvss,
                    exploit_available=has_exploit,
                    exploit_source=exploit_source,
                    affected_versions=ver_str,
                    remediation=remediation,
                ))

        return results

    def _check_known_exploit(self, service: str, version: str) -> List[CveResult]:
        results: List[CveResult] = []
        combined = f"{service} {version}".lower()

        for exploit_name, indicators in KNOWN_EXPLOIT_PATTERNS.items():
            if any(ind in combined for ind in indicators):
                cve_id = next((i for i in indicators if i.startswith("CVE-")), f"{exploit_name.title()}")

                severity_map = {
                    "eternalblue": ("critical", 9.3, "Metasploit: exploit/windows/smb/ms17_010_eternalblue"),
                    "bluekeep": ("critical", 9.8, "Metasploit: exploit/windows/rdp/ms17_010_eternalblue"),
                    "log4j": ("critical", 10.0, "Log4Shell - multiple exploit vectors available"),
                    "zerologon": ("critical", 10.0, "Metasploit: exploit/windows/domain/ms17_010_eternalblue"),
                    "printnightmare": ("critical", 9.0, "Multiple PoCs available"),
                    "regresshion": ("high", 8.1, "Check OpenSSH version 8.5p1-9.7p1 - signal handler race condition"),
                }

                severity, cvss, exploit = severity_map.get(exploit_name, ("high", 7.0, "Check exploit-db"))

                results.append(CveResult(
                    cve_id=cve_id,
                    description=f"Known exploit pattern detected: {exploit_name}",
                    severity=severity,
                    cvss_score=cvss,
                    exploit_available=True,
                    exploit_source=exploit,
                    affected_versions=version,
                    remediation=f"Research {cve_id} on exploit-db and apply vendor patch",
                ))

        return results

    def _calculate_risk(self, cves: List[CveResult]) -> float:
        if not cves:
            return 0.0

        max_cvss = max(c.cvss_score for c in cves)
        exploit_bonus = 0.3 if any(c.exploit_available for c in cves) else 0
        count_factor = min(len(cves) * 0.1, 0.5)

        return min(max_cvss / 10.0 + exploit_bonus + count_factor, 1.0)

    def clear_cache(self) -> None:
        self._cache.clear()
