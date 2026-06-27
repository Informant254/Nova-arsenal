"""
MITRE ATT&CK Mapping — technique identification and attack path mapping.

Maps observed behaviors to ATT&CK techniques, builds kill chains,
and provides coverage analysis.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class Tactic(Enum):
    """MITRE ATT&CK Tactic identifiers."""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


TACTIC_ORDER = [
    Tactic.RECONNAISSANCE,
    Tactic.RESOURCE_DEVELOPMENT,
    Tactic.INITIAL_ACCESS,
    Tactic.EXECUTION,
    Tactic.PERSISTENCE,
    Tactic.PRIVILEGE_ESCALATION,
    Tactic.DEFENSE_EVASION,
    Tactic.CREDENTIAL_ACCESS,
    Tactic.DISCOVERY,
    Tactic.LATERAL_MOVEMENT,
    Tactic.COLLECTION,
    Tactic.COMMAND_AND_CONTROL,
    Tactic.EXFILTRATION,
    Tactic.IMPACT,
]


@dataclass
class Technique:
    """A MITRE ATT&CK technique."""
    technique_id: str
    name: str
    tactic: Tactic
    description: str = ""
    detection: str = ""
    mitigation: str = ""
    platforms: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    sub_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic.value,
            "tactic_name": self.tactic.name,
            "description": self.description,
            "detection": self.detection,
            "mitigation": self.mitigation,
            "platforms": self.platforms,
            "data_sources": self.data_sources,
            "sub_techniques": self.sub_techniques,
        }


@dataclass
class ObservedBehavior:
    """A behavior observed during testing."""
    behavior_id: str
    description: str
    technique_id: str | None = None
    evidence: str = ""
    target: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = field(default_factory=dict)


@dataclass
class KillChain:
    """An attack kill chain built from observed techniques."""
    chain_id: str
    stages: list[dict]
    coverage: float
    total_techniques: int
    mapped_techniques: int

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "stages": self.stages,
            "coverage": self.coverage,
            "total_techniques": self.total_techniques,
            "mapped_techniques": self.mapped_techniques,
        }


# Common techniques database
TECHNIQUES: dict[str, Technique] = {
    "T1078": Technique(
        "T1078", "Valid Accounts", Tactic.INITIAL_ACCESS,
        description="Adversaries may obtain and abuse credentials of existing accounts.",
        platforms=["Linux", "Windows", "macOS", "SaaS"],
    ),
    "T1059": Technique(
        "T1059", "Command and Scripting Interpreter", Tactic.EXECUTION,
        description="Adversaries may abuse command and script interpreters to execute commands.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1053": Technique(
        "T1053", "Scheduled Task/Job", Tactic.PERSISTENCE,
        description="Adversaries may abuse task scheduling functionality.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1055": Technique(
        "T1055", "Process Injection", Tactic.DEFENSE_EVASION,
        description="Adversaries may inject code into processes in order to evade process-based defenses.",
        platforms=["Windows", "macOS"],
    ),
    "T1003": Technique(
        "T1003", "OS Credential Dumping", Tactic.CREDENTIAL_ACCESS,
        description="Adversaries may attempt to dump credentials to obtain account login and credential material.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1087": Technique(
        "T1087", "Account Discovery", Tactic.DISCOVERY,
        description="Adversaries may attempt to get a listing of accounts.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1021": Technique(
        "T1021", "Remote Services", Tactic.LATERAL_MOVEMENT,
        description="Adversaries may use Valid Accounts to log into a service for remote access.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1566": Technique(
        "T1566", "Phishing", Tactic.INITIAL_ACCESS,
        description="Adversaries may send phishing messages to gain access to victim systems.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1190": Technique(
        "T1190", "Exploit Public-Facing Application", Tactic.INITIAL_ACCESS,
        description="Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1068": Technique(
        "T1068", "Exploitation for Privilege Escalation", Tactic.PRIVILEGE_ESCALATION,
        description="Adversaries may exploit software vulnerabilities to escalate privileges.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1110": Technique(
        "T1110", "Brute Force", Tactic.CREDENTIAL_ACCESS,
        description="Adversaries may use brute force techniques to gain access to accounts.",
        platforms=["Linux", "Windows", "macOS", "SaaS"],
    ),
    "T1046": Technique(
        "T1046", "Network Service Discovery", Tactic.DISCOVERY,
        description="Adversaries may attempt to get a listing of services running on remote hosts.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1048": Technique(
        "T1048", "Exfiltration Over Alternative Protocol", Tactic.EXFILTRATION,
        description="Adversaries may steal data by exfiltrating it over a different protocol.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1486": Technique(
        "T1486", "Data Encrypted for Impact", Tactic.IMPACT,
        description="Adversaries may encrypt data on target systems to interrupt availability.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1027": Technique(
        "T1027", "Obfuscated Files or Information", Tactic.DEFENSE_EVASION,
        description="Adversaries may attempt to make an executable or file difficult to discover or analyze.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1547": Technique(
        "T1547", "Boot or Logon Autostart Execution", Tactic.PERSISTENCE,
        description="Adversaries may configure system settings to automatically execute a program during system boot or logon.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1070": Technique(
        "T1070", "Indicator Removal", Tactic.DEFENSE_EVASION,
        description="Adversaries may delete or modify artifacts generated within systems to remove evidence.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1018": Technique(
        "T1018", "Remote System Discovery", Tactic.DISCOVERY,
        description="Adversaries may attempt to get a listing of other systems by IP address or hostname.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1082": Technique(
        "T1082", "System Information Discovery", Tactic.DISCOVERY,
        description="An adversary may attempt to get detailed information about the operating system and hardware.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1083": Technique(
        "T1083", "File and Directory Discovery", Tactic.DISCOVERY,
        description="Adversaries may enumerate files and directories to find specific information.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1057": Technique(
        "T1057", "Process Discovery", Tactic.DISCOVERY,
        description="Adversaries may attempt to get information about running processes on a system.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1518": Technique(
        "T1518", "Software Discovery", Tactic.DISCOVERY,
        description="Adversaries may attempt to get information about installed software.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1049": Technique(
        "T1049", "System Network Connections Discovery", Tactic.DISCOVERY,
        description="Adversaries may attempt to get a listing of network connections to or from the compromised system.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1016": Technique(
        "T1016", "System Network Configuration Discovery", Tactic.DISCOVERY,
        description="Adversaries may look for details about the network configuration and settings.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1135": Technique(
        "T1135", "Network Share Discovery", Tactic.DISCOVERY,
        description="Adversaries may look for folders and drives shared on remote systems.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1069": Technique(
        "T1069", "Permission Groups Discovery", Tactic.DISCOVERY,
        description="Adversaries may attempt to discover security groups and permissions.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1497": Technique(
        "T1497", "Virtualization/Sandbox Evasion", Tactic.DEFENSE_EVASION,
        description="Adversaries may employ means to detect and avoid virtualization and analysis environments.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1071": Technique(
        "T1071", "Application Layer Protocol", Tactic.COMMAND_AND_CONTROL,
        description="Adversaries may communicate using OSI application layer protocols to avoid detection.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1573": Technique(
        "T1573", "Encrypted Channel", Tactic.COMMAND_AND_CONTROL,
        description="Adversaries may employ a known encryption algorithm to conceal command and control traffic.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1105": Technique(
        "T1105", "Ingress Tool Transfer", Tactic.COMMAND_AND_CONTROL,
        description="Adversaries may transfer tools or other files from an external system into a compromised environment.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1560": Technique(
        "T1560", "Archive Collected Data", Tactic.COLLECTION,
        description="An adversary may compress and/or encrypt data that is collected prior to exfiltration.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1005": Technique(
        "T1005", "Data from Local System", Tactic.COLLECTION,
        description="Adversaries may search local system sources to find files of interest.",
        platforms=["Linux", "Windows", "macOS"],
    ),
    "T1039": Technique(
        "T1039", "Data from Network Shared Drive", Tactic.COLLECTION,
        description="Adversaries may search network shares on computers they have compromised.",
        platforms=["Linux", "Windows", "macOS"],
    ),
}


class MITREMapper:
    """Maps observed behaviors to MITRE ATT&CK techniques."""

    def __init__(self):
        self.techniques = dict(TECHNIQUES)
        self._observations: list[ObservedBehavior] = []

    def add_behavior(self, behavior: ObservedBehavior) -> str | None:
        """Add an observed behavior and return matched technique ID."""
        self._observations.append(behavior)
        if behavior.technique_id and behavior.technique_id in self.techniques:
            return behavior.technique_id
        matched = self._match_behavior(behavior)
        if matched:
            behavior.technique_id = matched.technique_id
            return matched.technique_id
        return None

    def _match_behavior(self, behavior: ObservedBehavior) -> Technique | None:
        """Match a behavior description to a technique."""
        desc = behavior.description.lower()
        keyword_map = {
            "brute force": "T1110",
            "password spray": "T1110",
            "credential dump": "T1003",
            "mimikatz": "T1003",
            "sam dump": "T1003",
            "ntlm": "T1003",
            "hash": "T1003",
            "kerberoast": "T1003",
            "as-rep": "T1003",
            "lateral movement": "T1021",
            "psexec": "T1021",
            "remote desktop": "T1021",
            "ssh": "T1021",
            "wmi": "T1047",
            "scheduled task": "T1053",
            "cron": "T1053",
            "privilege escalation": "T1068",
            "exploit": "T1068",
            "sql injection": "T1190",
            "xss": "T1190",
            "rce": "T1190",
            "remote code execution": "T1190",
            "phishing": "T1566",
            "valid accounts": "T1078",
            "default password": "T1078",
            "discovery": "T1082",
            "enum": "T1082",
            "system info": "T1082",
            "process": "T1057",
            "service discovery": "T1046",
            "port scan": "T1046",
            "nmap": "T1046",
            "exfiltrat": "T1048",
            "data theft": "T1048",
            "encrypt": "T1486",
            "ransomware": "T1486",
            "obfuscat": "T1027",
            "encoded": "T1027",
            "packed": "T1027",
            "persistence": "T1547",
            "autostart": "T1547",
            "registry": "T1547",
            "clean": "T1070",
            "delete log": "T1070",
            "clear history": "T1070",
            "c2": "T1071",
            "command and control": "T1071",
            "beacon": "T1071",
            "reverse shell": "T1059",
            "powershell": "T1059",
            "cmd": "T1059",
            "script": "T1059",
            "virtualization": "T1497",
            "sandbox": "T1497",
            "vm detect": "T1497",
        }
        for keyword, tech_id in keyword_map.items():
            if keyword in desc:
                return self.techniques.get(tech_id)
        return None

    def build_kill_chain(self) -> KillChain:
        """Build a kill chain from all observations."""
        stages: dict[str, list[dict]] = {}
        for tactic in TACTIC_ORDER:
            stages[tactic.value] = []

        mapped = set()
        for obs in self._observations:
            if obs.technique_id and obs.technique_id in self.techniques:
                tech = self.techniques[obs.technique_id]
                mapped.add(obs.technique_id)
                stages[tech.tactic.value].append({
                    "technique_id": obs.technique_id,
                    "name": tech.name,
                    "behavior": obs.description,
                    "evidence": obs.evidence[:200],
                })

        chain_stages = []
        for tactic in TACTIC_ORDER:
            stage_techniques = stages[tactic.value]
            chain_stages.append({
                "tactic": tactic.value,
                "tactic_name": tactic.name,
                "techniques": stage_techniques,
                "covered": len(stage_techniques) > 0,
            })

        total = len(self.techniques)
        coverage = len(mapped) / total if total > 0 else 0.0

        return KillChain(
            chain_id=str(__import__("uuid").uuid4()),
            stages=chain_stages,
            coverage=coverage,
            total_techniques=total,
            mapped_techniques=len(mapped),
        )

    def get_coverage_report(self) -> dict:
        """Report on ATT&CK technique coverage."""
        kill_chain = self.build_kill_chain()
        tactic_coverage = {}
        for stage in kill_chain.stages:
            tactic_coverage[stage["tactic_name"]] = {
                "covered": stage["covered"],
                "technique_count": len(stage["techniques"]),
            }
        uncovered = []
        covered_ids = set()
        for obs in self._observations:
            if obs.technique_id:
                covered_ids.add(obs.technique_id)
        for tid, tech in self.techniques.items():
            if tid not in covered_ids:
                uncovered.append({"technique_id": tid, "name": tech.name, "tactic": tech.tactic.value})

        return {
            "total_techniques": kill_chain.total_techniques,
            "mapped_techniques": kill_chain.mapped_techniques,
            "coverage_percent": round(kill_chain.coverage * 100, 2),
            "tactic_coverage": tactic_coverage,
            "uncovered_techniques": uncovered,
            "kill_chain": kill_chain.to_dict(),
        }

    def get_technique(self, technique_id: str) -> Technique | None:
        """Look up a technique by ID."""
        return self.techniques.get(technique_id)

    def get_techniques_by_tactic(self, tactic: Tactic) -> list[Technique]:
        """Return all techniques for a given tactic."""
        return [t for t in self.techniques.values() if t.tactic == tactic]

    def get_all_observations(self) -> list[dict]:
        """Return all observations as dicts."""
        return [{
            "behavior_id": obs.behavior_id,
            "description": obs.description,
            "technique_id": obs.technique_id,
            "evidence": obs.evidence,
            "target": obs.target,
            "timestamp": obs.timestamp.isoformat(),
        } for obs in self._observations]
