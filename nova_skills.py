#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🎯 NOVA SKILLS v1.0 — Reusable Prompt Template System                     ║
║                                                                              ║
║  Skills are reusable, parameterised attack + analysis prompt templates.     ║
║  Mirrors the Anthropic Claude Agent SDK Skills system.                      ║
║                                                                              ║
║  Built-in skills cover the full security research lifecycle:                ║
║    • Recon skills  — subdomain, endpoint, JS analysis prompts               ║
║    • Attack skills — SQLi, XSS, IDOR, SSRF, JWT, CSRF, business logic      ║
║    • Analysis skills — SAST, SCA, threat model, patch generation           ║
║    • Report skills — H1-ready report, executive summary, CVSS scoring      ║
║                                                                              ║
║  Usage:                                                                      ║
║    from nova_skills import SkillLibrary                                     ║
║    lib = SkillLibrary()                                                     ║
║    prompt = lib.render("sqli_analysis", target="example.com",              ║
║                        endpoint="/api/search", param="q")                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Skill definition ───────────────────────────────────────────────────────────

@dataclass
class Skill:
    name:        str
    category:    str
    description: str
    system:      str                    # system prompt template
    template:    str                    # user message template
    params:      List[str] = field(default_factory=list)  # required parameters
    tags:        List[str] = field(default_factory=list)
    version:     str = "1.0"

    def render(self, **kwargs) -> Dict[str, str]:
        """Render system + user prompt with the given parameters."""
        missing = [p for p in self.params if p not in kwargs]
        if missing:
            raise ValueError(f"Skill '{self.name}' missing parameters: {missing}")
        system = self.system
        user   = self.template
        for k, v in kwargs.items():
            placeholder = "{" + k + "}"
            system = system.replace(placeholder, str(v))
            user   = user.replace(placeholder, str(v))
        return {"system": system, "user": user}

    def to_dict(self) -> Dict:
        return {"name": self.name, "category": self.category,
                "description": self.description, "params": self.params, "tags": self.tags}


# ── Built-in skills ────────────────────────────────────────────────────────────

BUILTIN_SKILLS: List[Skill] = [

    # ── Recon ─────────────────────────────────────────────────────
    Skill(
        name="subdomain_analysis",
        category="recon",
        description="Analyse a list of subdomains to identify high-value attack targets.",
        system=(
            "You are an elite bug bounty recon specialist. Your job is to analyse "
            "discovered subdomains and identify which ones are most likely to yield "
            "critical security vulnerabilities. Focus on: staging/dev environments, "
            "admin panels, API gateways, internal tooling exposed externally, and "
            "services with weak authentication. Be concise and actionable."
        ),
        template=(
            "Target: {target}\n"
            "Discovered subdomains:\n{subdomains}\n\n"
            "Rank these subdomains by attack potential. For the top 10, explain:\n"
            "1. Why it's interesting\n"
            "2. What vulnerabilities to look for first\n"
            "3. Recommended first probe\n"
            "Output JSON: {{\"ranked\": [{{\"domain\": str, \"reason\": str, "
            "\"first_probe\": str, \"priority\": 1-10}}]}}"
        ),
        params=["target", "subdomains"],
        tags=["recon", "subdomain"],
    ),

    Skill(
        name="js_secret_analysis",
        category="recon",
        description="Analyse JavaScript files for leaked secrets, API keys, and internal endpoints.",
        system=(
            "You are a security researcher specialising in JavaScript analysis. "
            "Find: hardcoded API keys, tokens, secrets, internal API endpoints, "
            "GraphQL schemas, authentication bypass patterns, and business logic flaws "
            "exposed in client-side code. Be specific — quote the exact code."
        ),
        template=(
            "URL: {js_url}\nContent:\n{js_content}\n\n"
            "Find all: secrets/keys, internal endpoints, auth logic, dangerous functions. "
            "Output JSON: {{\"findings\": [{{\"type\": str, \"severity\": str, "
            "\"line\": int, \"snippet\": str, \"description\": str}}]}}"
        ),
        params=["js_url", "js_content"],
        tags=["recon", "javascript", "secrets"],
    ),

    # ── Attack ────────────────────────────────────────────────────
    Skill(
        name="sqli_analysis",
        category="attack",
        description="Analyse an endpoint for SQL injection opportunities.",
        system=(
            "You are an expert in SQL injection. Given an endpoint and parameter, "
            "generate a targeted test plan. Consider: error-based, blind boolean, "
            "time-based, union-based, and second-order SQLi. Account for WAF bypass "
            "techniques. Be surgical — high signal, low noise."
        ),
        template=(
            "Target: {target}\nEndpoint: {endpoint}\nParameter: {param}\n"
            "HTTP Method: {method}\nExample Request:\n{request_sample}\n\n"
            "Generate 10 targeted SQLi payloads. Explain what each tests. "
            "Output JSON: {{\"payloads\": [{{\"payload\": str, \"type\": str, "
            "\"reason\": str, \"waf_bypass\": bool}}]}}"
        ),
        params=["target", "endpoint", "param", "method", "request_sample"],
        tags=["attack", "sqli", "injection"],
    ),

    Skill(
        name="idor_analysis",
        category="attack",
        description="Analyse API endpoints for IDOR / BOLA vulnerabilities.",
        system=(
            "You are an IDOR specialist. Analyse API endpoints for broken object-level "
            "authorisation. Focus on: predictable IDs, missing ownership checks, "
            "horizontal vs vertical privilege escalation, mass assignment, and "
            "parameter pollution. Map every object reference to a test case."
        ),
        template=(
            "Target: {target}\nEndpoints:\n{endpoints}\n"
            "Auth Token (user A): {token_a}\nAuth Token (user B): {token_b}\n\n"
            "For each endpoint with an object ID, generate a test plan. "
            "Output JSON: {{\"tests\": [{{\"endpoint\": str, \"id_param\": str, "
            "\"test\": str, \"expected_vuln\": str, \"severity\": str}}]}}"
        ),
        params=["target", "endpoints", "token_a", "token_b"],
        tags=["attack", "idor", "bola"],
    ),

    Skill(
        name="xss_analysis",
        category="attack",
        description="Generate XSS payloads tailored to context.",
        system=(
            "You are an XSS specialist. Generate targeted payloads for: reflected, "
            "stored, DOM-based, and blind XSS. Account for HTML entity encoding, "
            "JavaScript string escaping, attribute injection, template injection, "
            "and CSP bypass. Tailor payloads to the context provided."
        ),
        template=(
            "Target: {target}\nEndpoint: {endpoint}\nInput context: {context}\n"
            "Existing filters observed: {filters}\n\n"
            "Generate 10 XSS payloads for this context. "
            "Output JSON: {{\"payloads\": [{{\"payload\": str, \"type\": str, "
            "\"bypasses\": str, \"notes\": str}}]}}"
        ),
        params=["target", "endpoint", "context", "filters"],
        tags=["attack", "xss"],
    ),

    Skill(
        name="jwt_attack",
        category="attack",
        description="Generate JWT attack vectors for a given token.",
        system=(
            "You are a JWT security expert. Test for: alg:none attack, RS256→HS256 "
            "key confusion, weak secrets (bruteforce), claim tampering (sub, role, exp), "
            "kid injection, jku/x5u header injection, and embedded JWK attacks."
        ),
        template=(
            "Target: {target}\nJWT Token: {token}\nDecoded Header: {header}\n"
            "Decoded Payload: {payload}\n\n"
            "List every applicable JWT attack with forged token examples. "
            "Output JSON: {{\"attacks\": [{{\"type\": str, \"forged_token\": str, "
            "\"description\": str, \"severity\": str}}]}}"
        ),
        params=["target", "token", "header", "payload"],
        tags=["attack", "jwt", "auth"],
    ),

    Skill(
        name="ssrf_analysis",
        category="attack",
        description="Identify and exploit SSRF vulnerabilities.",
        system=(
            "You are an SSRF specialist. Identify parameters that make server-side "
            "requests. Test for: cloud metadata endpoints (AWS/GCP/Azure), internal "
            "network scanning, protocol smuggling (gopher, file, dict), blind SSRF "
            "with out-of-band confirmation, and SSRF-to-RCE chains."
        ),
        template=(
            "Target: {target}\nEndpoints with URL parameters:\n{url_params}\n"
            "Cloud provider (if known): {cloud}\n\n"
            "Generate SSRF payloads for each parameter. "
            "Output JSON: {{\"tests\": [{{\"endpoint\": str, \"param\": str, "
            "\"payload\": str, \"target_url\": str, \"type\": str}}]}}"
        ),
        params=["target", "url_params", "cloud"],
        tags=["attack", "ssrf"],
    ),

    Skill(
        name="business_logic_analysis",
        category="attack",
        description="Find business logic flaws in application workflows.",
        system=(
            "You are a business logic security specialist. Find flaws in: payment flows "
            "(negative prices, coupon stacking, race conditions on credits), access control "
            "logic (skipping workflow steps, parameter tampering), state machine abuse, "
            "and trust boundary violations."
        ),
        template=(
            "Target: {target}\nApplication type: {app_type}\n"
            "Key workflows:\n{workflows}\n\n"
            "Identify the most likely business logic flaws for each workflow. "
            "Output JSON: {{\"flaws\": [{{\"workflow\": str, \"flaw\": str, "
            "\"test_steps\": [str], \"severity\": str}}]}}"
        ),
        params=["target", "app_type", "workflows"],
        tags=["attack", "business_logic"],
    ),

    # ── Analysis ──────────────────────────────────────────────────
    Skill(
        name="sast_triage",
        category="analysis",
        description="Triage SAST findings and rank by exploitability.",
        system=(
            "You are a senior application security engineer. Triage SAST findings: "
            "eliminate false positives, rank by real-world exploitability (not just "
            "CVSS), identify attack chains, and suggest the minimal fix for each real finding."
        ),
        template=(
            "Application: {app_name}\nLanguage: {language}\n"
            "Raw SAST findings:\n{findings}\n\n"
            "Triage these findings. Output JSON: {{\"triaged\": [{{\"id\": str, "
            "\"type\": str, \"real_vuln\": bool, \"exploitability\": 1-10, "
            "\"fix\": str, \"chain_with\": [str]}}]}}"
        ),
        params=["app_name", "language", "findings"],
        tags=["analysis", "sast"],
    ),

    Skill(
        name="threat_model_stride",
        category="analysis",
        description="Generate a STRIDE threat model for an application.",
        system=(
            "You are a threat modeling expert. Apply STRIDE methodology (Spoofing, "
            "Tampering, Repudiation, Information Disclosure, Denial of Service, "
            "Elevation of Privilege) to the described system. For each threat, "
            "provide: description, attack vector, impact, likelihood, and mitigation."
        ),
        template=(
            "Application: {app_name}\nArchitecture:\n{architecture}\n"
            "Data flows:\n{data_flows}\nTrust boundaries:\n{trust_boundaries}\n\n"
            "Generate complete STRIDE model. "
            "Output JSON: {{\"threats\": [{{\"category\": str, \"threat\": str, "
            "\"vector\": str, \"impact\": str, \"likelihood\": str, "
            "\"mitigation\": str, \"severity\": str}}]}}"
        ),
        params=["app_name", "architecture", "data_flows", "trust_boundaries"],
        tags=["analysis", "threat_model", "stride"],
    ),

    Skill(
        name="patch_generation",
        category="analysis",
        description="Generate code patches for confirmed vulnerabilities.",
        system=(
            "You are a senior security engineer who writes clear, minimal, correct patches. "
            "For each vulnerability: explain the root cause, show the vulnerable code, "
            "provide a patched version, add a unit test that would catch regression, "
            "and note any follow-up hardening to apply."
        ),
        template=(
            "Language: {language}\nFramework: {framework}\n"
            "Vulnerability: {vuln_type}\nDescription: {description}\n"
            "Vulnerable code:\n{code}\n\n"
            "Provide a complete, production-ready fix. "
            "Output JSON: {{\"root_cause\": str, \"patched_code\": str, "
            "\"test_case\": str, \"hardening\": [str]}}"
        ),
        params=["language", "framework", "vuln_type", "description", "code"],
        tags=["analysis", "patch", "remediation"],
    ),

    # ── Reporting ─────────────────────────────────────────────────
    Skill(
        name="h1_report",
        category="report",
        description="Generate a HackerOne-ready vulnerability report.",
        system=(
            "You are a bug bounty hunter writing a HackerOne report. The report must be: "
            "clear, reproducible step-by-step, include impact analysis showing business risk, "
            "provide CVSS score with justification, and suggest remediation. "
            "Avoid speculation — only report confirmed, reproducible issues."
        ),
        template=(
            "Vulnerability type: {vuln_type}\nTarget: {target}\nEndpoint: {endpoint}\n"
            "Severity: {severity}\nEvidence:\n{evidence}\n\n"
            "Write a complete HackerOne report. Include: Summary, Steps to Reproduce "
            "(numbered), Impact, CVSS Score + vector, Recommended Fix, References."
        ),
        params=["vuln_type", "target", "endpoint", "severity", "evidence"],
        tags=["report", "hackerone", "h1"],
    ),

    Skill(
        name="executive_summary",
        category="report",
        description="Generate an executive security summary for non-technical stakeholders.",
        system=(
            "You are a CISO-level communicator. Translate technical security findings into "
            "clear business risk language. Focus on: business impact, risk to data/customers, "
            "regulatory implications (GDPR, PCI-DSS), and prioritised remediation roadmap. "
            "Avoid jargon. Use quantified risk where possible."
        ),
        template=(
            "Organisation: {org}\nAssessment scope: {scope}\n"
            "Findings summary:\n{findings}\nTotal critical: {critical_count}\n"
            "Total high: {high_count}\n\n"
            "Write a 1-page executive summary with: Risk Overview, Top 3 Risks "
            "(business language), Remediation Priorities, and Recommended Next Steps."
        ),
        params=["org", "scope", "findings", "critical_count", "high_count"],
        tags=["report", "executive"],
    ),
]


# ── Skill library ──────────────────────────────────────────────────────────────

class SkillLibrary:
    """Registry and renderer for Nova skills."""

    def __init__(self, custom_dir: Optional[str] = None):
        self._skills: Dict[str, Skill] = {}
        for skill in BUILTIN_SKILLS:
            self._skills[skill.name] = skill
        if custom_dir:
            self._load_custom(Path(custom_dir))

    def _load_custom(self, path: Path):
        if not path.exists():
            return
        for f in path.glob("*.json"):
            try:
                d = json.loads(f.read_text())
                s = Skill(**d)
                self._skills[s.name] = s
                print(f"  📚 Loaded custom skill: {s.name}")
            except Exception as e:
                print(f"  ⚠️  Failed to load skill {f}: {e}")

    def get(self, name: str) -> Skill:
        if name not in self._skills:
            raise KeyError(f"Skill '{name}' not found. Available: {list(self._skills)}")
        return self._skills[name]

    def render(self, name: str, **kwargs) -> Dict[str, str]:
        """Render a skill's prompts with the given parameters."""
        return self.get(name).render(**kwargs)

    def list_skills(self, category: Optional[str] = None,
                    tag: Optional[str] = None) -> List[Dict]:
        skills = list(self._skills.values())
        if category:
            skills = [s for s in skills if s.category == category]
        if tag:
            skills = [s for s in skills if tag in s.tags]
        return [s.to_dict() for s in skills]

    def categories(self) -> List[str]:
        return sorted(set(s.category for s in self._skills.values()))

    def register(self, skill: Skill):
        self._skills[skill.name] = skill

    def save_custom(self, skill: Skill, directory: str):
        Path(directory).mkdir(parents=True, exist_ok=True)
        path = Path(directory) / f"{skill.name}.json"
        path.write_text(json.dumps({
            "name": skill.name, "category": skill.category,
            "description": skill.description, "system": skill.system,
            "template": skill.template, "params": skill.params,
            "tags": skill.tags, "version": skill.version
        }, indent=2))
        print(f"  💾 Saved skill to {path}")


# ── Global singleton ───────────────────────────────────────────────────────────
_library: Optional[SkillLibrary] = None

def get_library() -> SkillLibrary:
    global _library
    if _library is None:
        _library = SkillLibrary()
    return _library


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    lib = SkillLibrary()

    if len(sys.argv) < 2 or sys.argv[1] == "list":
        print(f"Nova Skills Library — {len(lib._skills)} skills\n")
        for cat in lib.categories():
            skills = lib.list_skills(category=cat)
            print(f"  [{cat.upper()}]")
            for s in skills:
                print(f"    • {s['name']:<30} — {s['description'][:60]}")
    else:
        name = sys.argv[1]
        skill = lib.get(name)
        print(f"Skill: {skill.name}\nCategory: {skill.category}")
        print(f"Required params: {skill.params}")
        print(f"\nSystem prompt preview:\n{skill.system[:300]}...")
