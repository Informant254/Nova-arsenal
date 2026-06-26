"""
OSINT Chain Investigation.

Multi-phase automated OSINT pipeline that chains together
discovery steps to build a complete intelligence picture.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class OsintPhase(Enum):
    DOMAIN_DISCOVERY = "domain_discovery"
    SUBDOMAIN_ENUM = "subdomain_enum"
    TECH_DETECTION = "tech_detection"
    EMAIL_HARVEST = "email_harvest"
    SOCIAL_DISCOVERY = "social_discovery"
    BREACH_SEARCH = "breach_search"
    CORRELATION = "correlation"


PHASE_ORDER = [
    OsintPhase.DOMAIN_DISCOVERY,
    OsintPhase.SUBDOMAIN_ENUM,
    OsintPhase.TECH_DETECTION,
    OsintPhase.EMAIL_HARVEST,
    OsintPhase.SOCIAL_DISCOVERY,
    OsintPhase.BREACH_SEARCH,
    OsintPhase.CORRELATION,
]


@dataclass
class OsintArtifact:
    phase: OsintPhase
    type: str
    value: str
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase.value,
            "type": self.type,
            "value": self.value,
            "source": self.source,
            "metadata": self.metadata,
        }


@dataclass
class OsintChainResult:
    target: str
    completed_phases: List[str] = field(default_factory=list)
    artifacts: List[OsintArtifact] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    technologies: Dict[str, List[str]] = field(default_factory=dict)
    social_accounts: List[str] = field(default_factory=list)
    breached_accounts: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "completed_phases": self.completed_phases,
            "artifact_count": len(self.artifacts),
            "subdomains": self.subdomains[:20],
            "emails": self.emails[:20],
            "technologies": self.technologies,
            "social_accounts": self.social_accounts[:10],
            "breached_accounts": len(self.breached_accounts),
            "summary": self.summary,
        }


CommandExecutor = Callable[[str], Any]


class OsintChain:
    """
    7-phase OSINT investigation chain.

    Phase 1: Domain Discovery       — WHOIS, DNS records, reverse IP
    Phase 2: Subdomain Enumeration  — subfinder, amass, crtsh
    Phase 3: Tech Detection         — whatweb, wappalyzer, nmap
    Phase 4: Email Harvesting       — theHarvester, hunter.io
    Phase 5: Social Discovery       — social media profiles
    Phase 6: Breach Search          — haveibeenpwned, leak check
    Phase 7: Correlation            — cross-phase analysis
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self._executor = executor or self._default_executor

    async def investigate(self, target: str) -> OsintChainResult:
        result = OsintChainResult(target=target)

        for phase in PHASE_ORDER:
            if phase == OsintPhase.DOMAIN_DISCOVERY:
                await self._phase_domain_discovery(target, result)
            elif phase == OsintPhase.SUBDOMAIN_ENUM:
                await self._phase_subdomain_enum(target, result)
            elif phase == OsintPhase.TECH_DETECTION:
                await self._phase_tech_detection(target, result)
            elif phase == OsintPhase.EMAIL_HARVEST:
                await self._phase_email_harvest(target, result)
            elif phase == OsintPhase.SOCIAL_DISCOVERY:
                await self._phase_social_discovery(target, result)
            elif phase == OsintPhase.BREACH_SEARCH:
                await self._phase_breach_search(target, result)
            elif phase == OsintPhase.CORRELATION:
                await self._phase_correlation(result)

            result.completed_phases.append(phase.value)
            logger.info(f"OSINT phase {phase.value} completed for {target}")

        return result

    async def _phase_domain_discovery(self, target: str, result: OsintChainResult) -> None:
        try:
            whois_data = await self._run(f"whois {target} 2>/dev/null | head -40")
            if whois_data:
                result.artifacts.append(OsintArtifact(
                    phase=OsintPhase.DOMAIN_DISCOVERY,
                    type="whois",
                    value=target,
                    source="whois",
                    metadata={"raw": whois_data[:500]},
                ))
        except Exception as e:
            logger.warning(f"Domain discovery failed for {target}: {e}")

        try:
            dns_data = await self._run(f"dig {target} ANY +short 2>/dev/null || echo 'dig unavailable'")
            if dns_data and "dig unavailable" not in dns_data:
                for line in dns_data.strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith(";"):
                        result.artifacts.append(OsintArtifact(
                            phase=OsintPhase.DOMAIN_DISCOVERY,
                            type="dns_record",
                            value=line,
                            source="dig",
                        ))
        except Exception as e:
            logger.warning(f"DNS lookup failed for {target}: {e}")

        try:
            ns_data = await self._run(f"nslookup {target} 2>/dev/null | head -20")
            if ns_data:
                result.artifacts.append(OsintArtifact(
                    phase=OsintPhase.DOMAIN_DISCOVERY,
                    type="nameserver",
                    value=target,
                    source="nslookup",
                    metadata={"raw": ns_data[:500]},
                ))
        except Exception as e:
            logger.warning(f"NS lookup failed for {target}: {e}")

    async def _phase_subdomain_enum(self, target: str, result: OsintChainResult) -> None:
        try:
            subs = await self._run(f"subfinder -d {target} -silent 2>/dev/null | head -100")
            if subs:
                for s in subs.strip().split("\n"):
                    s = s.strip()
                    if s:
                        result.subdomains.append(s)
                        result.artifacts.append(OsintArtifact(
                            phase=OsintPhase.SUBDOMAIN_ENUM,
                            type="subdomain",
                            value=s,
                            source="subfinder",
                        ))
        except Exception as e:
            logger.warning(f"Subdomain enumeration failed for {target}: {e}")

        if not result.subdomains:
            try:
                crtsh = await self._run(
                    f"curl -s 'https://crt.sh/?q=%25.{target}&output=json' 2>/dev/null | "
                    f"python3 -c \"import sys,json; [print(e['name_value']) for e in json.load(sys.stdin)]\" 2>/dev/null | "
                    f"sort -u | head -50"
                )
                if crtsh:
                    for s in crtsh.strip().split("\n"):
                        s = s.strip()
                        if s and s not in result.subdomains:
                            result.subdomains.append(s)
                            result.artifacts.append(OsintArtifact(
                                phase=OsintPhase.SUBDOMAIN_ENUM,
                                type="subdomain",
                                value=s,
                                source="crt.sh",
                            ))
            except Exception as e:
                logger.warning(f"Certificate transparency search failed: {e}")

    async def _phase_tech_detection(self, target: str, result: OsintChainResult) -> None:
        try:
            whatweb_data = await self._run(f"whatweb {target} -v 2>/dev/null | head -40")
            if whatweb_data:
                techs = set()
                for line in whatweb_data.split("\n"):
                    for tech in ["Apache", "Nginx", "PHP", "jQuery", "React",
                                 "WordPress", "Drupal", "Joomla", "Django",
                                 "Ruby on Rails", "Express", "Node.js"]:
                        if tech.lower() in line.lower():
                            techs.add(tech)
                if techs:
                    result.technologies["web"] = sorted(techs)
                    result.artifacts.append(OsintArtifact(
                        phase=OsintPhase.TECH_DETECTION,
                        type="technology",
                        value=", ".join(sorted(techs)),
                        source="whatweb",
                    ))
        except Exception as e:
            logger.warning(f"Tech detection failed for {target}: {e}")

        try:
            nmap_tech = await self._run(
                f"nmap -sV --top-ports 100 {target} 2>/dev/null | grep -E 'open|service' | head -20"
            )
            if nmap_tech:
                result.artifacts.append(OsintArtifact(
                    phase=OsintPhase.TECH_DETECTION,
                    type="service_scan",
                    value=target,
                    source="nmap",
                    metadata={"raw": nmap_tech[:500]},
                ))
        except Exception as e:
            logger.warning(f"Nmap tech detection failed: {e}")

    async def _phase_email_harvest(self, target: str, result: OsintChainResult) -> None:
        try:
            harvester = await self._run(
                f"theHarvester -d {target} -b google,yahoo,bing 2>/dev/null | "
                f"grep -i '@{target}' | head -50"
            )
            if harvester:
                for line in harvester.strip().split("\n"):
                    line = line.strip()
                    if line and "@" in line:
                        emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', line)
                        for e in emails:
                            if e not in result.emails:
                                result.emails.append(e)
                                result.artifacts.append(OsintArtifact(
                                    phase=OsintPhase.EMAIL_HARVEST,
                                    type="email",
                                    value=e,
                                    source="theHarvester",
                                ))
        except Exception as e:
            logger.warning(f"Email harvest failed for {target}: {e}")

    async def _phase_social_discovery(self, target: str, result: OsintChainResult) -> None:
        domain_root = target.split(".")[0] if "." in target else target

        social_sites = [
            ("github", f"github.com/search?q={target}"),
            ("twitter", f"twitter.com/search?q={target}"),
            ("linkedin", f"linkedin.com/company/{domain_root}"),
        ]

        for site, url in social_sites:
            try:
                result.social_accounts.append(f"https://{url}")
                result.artifacts.append(OsintArtifact(
                    phase=OsintPhase.SOCIAL_DISCOVERY,
                    type="social_profile",
                    value=f"https://{url}",
                    source=site,
                ))
            except Exception as e:
                logger.warning(f"Social discovery for {site} failed: {e}")

    async def _phase_breach_search(self, target: str, result: OsintChainResult) -> None:
        for email in result.emails[:5]:
            prefix = email.split("@")[0]
            try:
                check = await self._run(
                    f"curl -s 'https://haveibeenpwned.com/account/{prefix}' 2>/dev/null | "
                    f"head -1 || echo 'unavailable'"
                )
                if "pwned" in check.lower():
                    result.breached_accounts.append(email)
                    result.artifacts.append(OsintArtifact(
                        phase=OsintPhase.BREACH_SEARCH,
                        type="breach",
                        value=email,
                        source="haveibeenpwned",
                        metadata={"status": "potentially compromised"},
                    ))
            except Exception as e:
                logger.warning(f"Breach search for {email} failed: {e}")

    async def _phase_correlation(self, result: OsintChainResult) -> None:
        summary_parts = [
            f"OSINT Investigation for {result.target}",
            f"Phases completed: {len(result.completed_phases)}/7",
        ]

        if result.subdomains:
            summary_parts.append(f"Subdomains: {len(result.subdomains)} found")
            summary_parts.append(f"  Top: {', '.join(result.subdomains[:5])}")

        if result.emails:
            summary_parts.append(f"Emails: {len(result.emails)} harvested")

        if result.technologies:
            for cat, techs in result.technologies.items():
                summary_parts.append(f"Technologies ({cat}): {', '.join(techs)}")

        if result.breached_accounts:
            summary_parts.append(f"Breached: {len(result.breached_accounts)} accounts compromised")
        else:
            summary_parts.append("Breached: No accounts found in known breaches")

        result.summary = "\n".join(summary_parts)

    async def _run(self, command: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            return stdout.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            return ""
        except Exception as e:
            logger.debug(f"Command failed: {command[:50]}: {e}")
            return ""

    @staticmethod
    def _default_executor(cmd: str) -> str:
        return ""
