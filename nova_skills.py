"""
Nova Skills Module - Prompt templates and skill library for security research.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Skill:
    """A security research skill with prompt templates."""

    name: str
    category: str
    description: str
    system: str
    template: str
    params: List[str]
    tags: List[str] = field(default_factory=list)

    def render(self, **kwargs: Any) -> Dict[str, str]:
        """Render the skill with given parameters."""
        missing = [p for p in self.params if p not in kwargs]
        if missing:
            raise ValueError(f"Missing required parameters: {', '.join(missing)}")
        return {
            "system": self.system.format(**kwargs),
            "user": self.template.format(**kwargs),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize skill to dictionary."""
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "params": list(self.params),
            "tags": list(self.tags),
        }


BUILTIN_SKILLS: Dict[str, Skill] = {
    "sqli_analysis": Skill(
        name="sqli_analysis",
        category="attack",
        description="Analyze and test for SQL injection vulnerabilities",
        system="You are a SQL injection specialist analyzing {target}. "
        "Follow safe testing practices and never modify production data.",
        template="Test {target} {endpoint} parameter {param} ({method}) for SQL injection.\n"
        "Request sample: {request_sample}\n"
        "Identify injection type, craft payloads, and verify findings.",
        params=["target", "endpoint", "param", "method", "request_sample"],
        tags=["sqli", "web", "injection"],
    ),
    "xss_analysis": Skill(
        name="xss_analysis",
        category="attack",
        description="Analyze and test for cross-site scripting vulnerabilities",
        system="You are an XSS specialist analyzing {target}. "
        "Focus on reflected, stored, and DOM-based XSS.",
        template="Test {endpoint} in {context} context for XSS.\n"
        "Current filters: {filters}\n"
        "Craft bypass payloads and verify injection points.",
        params=["target", "endpoint", "context", "filters"],
        tags=["xss", "web", "injection"],
    ),
    "subdomain_recon": Skill(
        name="subdomain_recon",
        category="recon",
        description="Discover subdomains for a target domain",
        system="You are a reconnaissance specialist mapping the attack surface of {target}.",
        template="Enumerate subdomains for {target} using passive and active techniques.\n"
        "Include DNS enumeration, certificate transparency, and web scraping.",
        params=["target"],
        tags=["recon", "subdomain", "dns"],
    ),
    "port_scan_analysis": Skill(
        name="port_scan_analysis",
        category="recon",
        description="Analyze port scan results and identify services",
        system="You are a network analyst interpreting scan data for {target}.",
        template="Analyze port scan results for {target}.\n"
        "Identify open ports, services, versions, and potential attack vectors.",
        params=["target"],
        tags=["recon", "network", "ports"],
    ),
    "vuln_analysis": Skill(
        name="vuln_analysis",
        category="analysis",
        description="Analyze discovered vulnerabilities and assess risk",
        system="You are a vulnerability analyst assessing findings for {target}.",
        template="Analyze the following vulnerability findings for {target}:\n"
        "{findings}\n"
        "Provide CVSS scoring, exploitation difficulty, and remediation advice.",
        params=["target", "findings"],
        tags=["analysis", "vulnerability", "risk"],
    ),
    "report_generation": Skill(
        name="report_generation",
        category="report",
        description="Generate a professional security assessment report",
        system="You are a senior security consultant writing a report for {target}.",
        template="Generate a security assessment report for {target}.\n"
        "Scope: {scope}\n"
        "Findings: {findings}\n"
        "Include executive summary, methodology, findings, and recommendations.",
        params=["target", "scope", "findings"],
        tags=["report", "documentation"],
    ),
    "xxe_analysis": Skill(
        name="xxe_analysis",
        category="attack",
        description="Analyze and test for XML external entity vulnerabilities",
        system="You are an XXE specialist analyzing {target}.",
        template="Test {endpoint} for XXE vulnerabilities.\n"
        "Analyze XML input handling and test for entity expansion attacks.",
        params=["target", "endpoint"],
        tags=["xxe", "web", "injection"],
    ),
    "ssrf_analysis": Skill(
        name="ssrf_analysis",
        category="attack",
        description="Analyze and test for server-side request forgery",
        system="You are an SSRF specialist analyzing {target}.",
        template="Test {endpoint} for SSRF vulnerabilities.\n"
        "Identify URL input points and test internal network access.",
        params=["target", "endpoint"],
        tags=["ssrf", "web", "injection"],
    ),
    "auth_analysis": Skill(
        name="auth_analysis",
        category="analysis",
        description="Analyze authentication and authorization mechanisms",
        system="You are an authentication specialist analyzing {target}.",
        template="Analyze authentication mechanisms for {target}.\n"
        "Review {auth_type} implementation for weaknesses.",
        params=["target", "auth_type"],
        tags=["auth", "analysis", "security"],
    ),
    "cloud_audit": Skill(
        name="cloud_audit",
        category="analysis",
        description="Audit cloud infrastructure configuration",
        system="You are a cloud security auditor reviewing {target}'s {cloud_provider} infrastructure.",
        template="Audit {cloud_provider} configuration for {target}.\n"
        "Check for misconfigurations, exposed services, and compliance issues.",
        params=["target", "cloud_provider"],
        tags=["cloud", "audit", "aws", "azure", "gcp"],
    ),
}


class SkillLibrary:
    """Library of security research skills."""

    def __init__(self, extra_skills: Optional[Dict[str, Skill]] = None) -> None:
        self._skills: Dict[str, Skill] = dict(BUILTIN_SKILLS)
        if extra_skills:
            self._skills.update(extra_skills)

    def list_skills(self, category: Optional[str] = None, tag: Optional[str] = None) -> List[Dict[str, Any]]:
        """List available skills, optionally filtered by category or tag."""
        results = []
        for skill in self._skills.values():
            if category and skill.category != category:
                continue
            if tag and tag not in skill.tags:
                continue
            results.append(skill.to_dict())
        return results

    def categories(self) -> List[str]:
        """Return list of unique skill categories."""
        return sorted({s.category for s in self._skills.values()})

    def get(self, name: str) -> Skill:
        """Get a skill by name."""
        if name not in self._skills:
            raise KeyError(f"Unknown skill: {name}")
        return self._skills[name]

    def render(self, name: str, **kwargs: Any) -> Dict[str, str]:
        """Render a skill by name with given parameters."""
        skill = self.get(name)
        return skill.render(**kwargs)

    def add_skill(self, skill: Skill) -> None:
        """Add a custom skill to the library."""
        self._skills[skill.name] = skill
