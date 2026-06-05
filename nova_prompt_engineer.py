"""
Nova Prompt Engineer v1.0
=========================
Optimizes prompts to the LLM for better chain reasoning.

Reality: 
Bad prompt → Bad chains
Good prompt → Great chains

This module crafts sophisticated prompts that make Claude/GPT-4/Llama 
reason like expert security researchers.
"""

import logging
from typing import List, Dict, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ReasoningMode(Enum):
    """Different types of reasoning to request"""
    CHAIN_DISCOVERY = "discovery"     # Find chains we missed
    EXPLOITATION = "exploitation"     # How to exploit a chain
    IMPACT = "impact"                 # What damage can it do
    VERIFICATION = "verification"     # Is this chain real?
    REMEDIATION = "remediation"       # How to fix it


class PromptEngineer:
    """
    Crafts sophisticated prompts for LLM-based chain reasoning.
    The difference between good and bad reasoning is the prompt.
    """
    
    def __init__(self):
        self.reasoning_mode = ReasoningMode.CHAIN_DISCOVERY
    
    def build_chain_discovery_prompt(
        self,
        findings: List[Dict],
        context: Optional[Dict] = None,
        constraint: Optional[str] = None
    ) -> str:
        """
        Build a prompt to discover chains.
        
        This is the core prompt that makes LLMs find interesting chains.
        """
        
        findings_text = self._format_findings(findings)
        context_text = self._format_context(context)
        
        prompt = f"""You are an expert security researcher analyzing a vulnerability assessment.

APPLICATION CONTEXT:
{context_text}

VULNERABILITIES DISCOVERED:
{findings_text}

TASK: Identify the most dangerous and realistic vulnerability chains.

For each chain:
1. **Chain Name**: Clear, specific name (e.g., "JWT Forgery → Admin Access")
2. **Severity**: CRITICAL, HIGH, MEDIUM, LOW
3. **Attack Steps**: Numbered, detailed steps an attacker would follow
4. **Why It Works**: Technical explanation of the vulnerability chain
5. **Impact**: What an attacker can do (e.g., "steal all user data")
6. **CVSS Score**: Estimate v3.1 score (0-10)
7. **Exploitation Difficulty**: TRIVIAL, EASY, MODERATE, DIFFICULT
8. **Proof of Concept**: A code snippet or command to exploit

ANALYSIS GUIDELINES:
- Focus on chains that actually work (not theoretical)
- Prioritize exploitability over CVSS score alone
- Consider the application architecture and defenses
- Chains should be realistic for 1-2 person team to exploit

{constraint if constraint else ''}

Output as JSON array with keys:
[{{
  "name": "...",
  "severity": "...",
  "steps": [...],
  "reasoning": "...",
  "impact": "...",
  "cvss_score": X.X,
  "difficulty": "...",
  "poc": "..."
}}]

Find 3-5 of the most dangerous and realistic chains. Be specific.
"""
        
        return prompt
    
    def build_chain_verification_prompt(self, chain: Dict) -> str:
        """
        Build a prompt to verify if a chain is real.
        
        This helps filter out hallucinated chains.
        """
        
        prompt = f"""You are an expert penetration tester reviewing a vulnerability chain.

CHAIN: {chain.get('name', 'Unknown')}

Steps:
{chr(10).join(f"  {i+1}. {step}" for i, step in enumerate(chain.get('steps', [])))}

Impact: {chain.get('impact', 'Unknown')}

QUESTIONS:
1. Is this chain technically realistic? (0-100%)
2. Would a real attacker actually use this? (0-100%)
3. Are there any logical flaws? List them.
4. Is each step actually possible given standard web app security?
5. What assumptions does this chain make?

Be critical. False positives waste time. Only report if you're confident this chain works.

Output as JSON:
{{
  "realistic": 0-100,
  "attacker_would_use": 0-100,
  "flaws": ["flaw1", "flaw2"],
  "technically_possible": true/false,
  "assumptions": ["assumption1", "assumption2"],
  "verdict": "VERIFIED" or "REJECTED",
  "reasoning": "explanation"
}}
"""
        
        return prompt
    
    def build_impact_assessment_prompt(
        self,
        chain: Dict,
        application_type: str = "Web Application"
    ) -> str:
        """
        Build a prompt to assess real-world impact.
        
        Not just "data leak" but "affects X users, costs $Y, impacts Z business function"
        """
        
        prompt = f"""You are a security risk analyst assessing business impact.

VULNERABILITY CHAIN: {chain.get('name', 'Unknown')}

{application_type} with:
- Impact described as: {chain.get('impact', 'Unknown')}
- Difficulty to exploit: {chain.get('difficulty', 'Unknown')}
- CVSS Score: {chain.get('cvss_score', 'Unknown')}/10

ASSESS:
1. **User Impact**: What percentage of users are affected? Why?
2. **Data Impact**: What types of data are exposed? (PII, secrets, financial)
3. **Business Impact**: 
   - Revenue loss potential: estimate $/day
   - Reputation damage: estimate severity (1-10)
   - Compliance violations: GDPR, PCI, HIPAA, etc
4. **Recovery Effort**: How long to fix and recover? (hours/days)
5. **Real-World Likelihood**: Is this chain likely in actual deployments?

Output as JSON:
{{
  "users_affected_percent": 0-100,
  "data_types": ["PII", "Secrets", etc],
  "revenue_loss_per_day": "amount",
  "reputation_damage": 1-10,
  "compliance_violations": ["GDPR", "PCI"],
  "recovery_hours": 1-168,
  "real_world_likelihood": "RARE/UNCOMMON/COMMON/VERY_COMMON",
  "business_severity": "LOW/MEDIUM/HIGH/CRITICAL",
  "explanation": "..."
}}
"""
        
        return prompt
    
    def build_exploitation_guide_prompt(self, chain: Dict) -> str:
        """
        Build a prompt to create detailed exploitation guide.
        
        This is for report generation - detailed steps to exploit.
        """
        
        prompt = f"""You are a penetration tester writing an exploitation guide.

VULNERABILITY CHAIN: {chain.get('name', 'Unknown')}

Create a detailed exploitation guide that a junior pentester could follow.

INCLUDE:
1. **Tools Needed**: Specific tools (curl, Burp, custom script)
2. **Step-by-Step Instructions**: 
   - Exact commands/payloads
   - Expected results
   - How to verify success
3. **Common Pitfalls**: What goes wrong and how to fix it
4. **Troubleshooting**: If it doesn't work, try this...
5. **Variation/Bypass Techniques**: How to adapt if first approach fails

FORMAT AS NUMBERED STEPS WITH EXAMPLES.

Be practical. Include actual curl commands, payload examples, etc.
Not theoretical, but actionable.

Output as detailed markdown guide.
"""
        
        return prompt
    
    def build_remediation_prompt(self, chain: Dict) -> str:
        """
        Build a prompt to suggest specific remediation.
        
        Not just "use parameterized queries" but specific code changes.
        """
        
        prompt = f"""You are a security engineer recommending fixes.

VULNERABILITY CHAIN: {chain.get('name', 'Unknown')}

Attack Steps:
{chr(10).join(f"  {i+1}. {step}" for i, step in enumerate(chain.get('steps', [])))}

For EACH vulnerability in this chain, suggest:

1. **Specific Fix**: Exact code change or configuration
2. **Why It Works**: Why this prevents the vulnerability
3. **Implementation**: How to deploy (code, library, config)
4. **Testing**: How to verify the fix works
5. **Other Chains Prevented**: What else this fixes

Example format:
**Vulnerability: SQLi on /api/search**
- Fix: Use parameterized queries
- Code: `db.query("SELECT * FROM users WHERE name = ?", [user_input])`
- Verify: Test with: `' OR '1'='1`

Output complete remediation plan for the entire chain.
"""
        
        return prompt
    
    def build_comparative_prompt(
        self,
        findings: List[Dict],
        known_cves: Optional[List[str]] = None
    ) -> str:
        """
        Compare findings to known CVEs and attack patterns.
        
        This helps find novel chains inspired by public exploits.
        """
        
        prompt = f"""You are a threat intelligence analyst.

FINDINGS:
{self._format_findings(findings)}

KNOWN ATTACK PATTERNS YOU'RE FAMILIAR WITH:
- SQLi to RCE (UDF loading, stacked queries)
- SSRF to internal service compromise
- IDOR to privilege escalation
- XSS to session theft
- JWT forging via weak secrets
- Race conditions in business logic
- Prototype pollution in Node.js
- Deserialization attacks
- GraphQL enumeration attacks

YOUR TASK:
Find chains in these vulnerabilities inspired by known attack patterns.
Even if the app doesn't have that exact CVE, could these vulns combine 
in a similar way?

{"KNOWN CVEs TO CONSIDER: " + ", ".join(known_cves) if known_cves else ""}

Output chains that match known attack patterns but adapted to this app.

Output as JSON array of chains.
"""
        
        return prompt
    
    def build_novel_chain_discovery_prompt(
        self,
        findings: List[Dict],
        architecture_description: str
    ) -> str:
        """
        Push LLM to find NOVEL chains, not just known patterns.
        
        This is where you find the real security research opportunities.
        """
        
        prompt = f"""You are a security researcher at a top firm finding novel vulnerabilities.

APPLICATION ARCHITECTURE:
{architecture_description}

KNOWN VULNERABILITIES:
{self._format_findings(findings)}

CHALLENGE: These vulnerabilities individually are known. 
But their COMBINATION might be novel.

THINK ABOUT:
1. **Data Flow**: How does data flow from endpoint to endpoint?
2. **State Changes**: What application state changes allow new attacks?
3. **Timing**: Can race conditions or timing attacks enable new chains?
4. **Context**: What business logic assumptions does the app make?
5. **Unexploited Interactions**: Which findings have never been chained together?

Find 2-3 NOVEL chains that aren't obvious standard combinations.

Examples of novel chains:
- GraphQL introspection + IDOR on admin endpoint = full schema theft
- Race condition + IDOR + business logic = duplicate transactions
- Multiple SSRF endpoints + confused deputy = internal network compromise

NOVEL = Not a standard "SQLi→RCE" but something security researchers would write papers about.

Output as JSON with: name, reasoning, steps, impact, why_its_novel.
"""
        
        return prompt
    
    def optimize_for_model(self, prompt: str, model: str) -> str:
        """
        Optimize prompt for specific LLM model.
        
        Different models respond better to different prompt styles.
        """
        
        if "claude" in model.lower():
            # Claude loves structured thinking
            prompt = prompt.replace(
                "Output as",
                "Think through this step-by-step. Output as"
            )
            # Claude responds well to explicit constraints
            prompt += "\n\nConstraint: Be precise and specific. Avoid vague generalities."
        
        elif "gpt" in model.lower():
            # GPT likes clear examples
            prompt += "\n\nProvide concrete examples for each point."
        
        elif "llama" in model.lower() or "ollama" in model.lower():
            # Llama needs simpler, more direct prompts
            prompt = prompt.replace("JSON", "JSON (simple format)")
            prompt += "\n\nBe concise. Llama performs better with shorter prompts."
        
        return prompt
    
    def _format_findings(self, findings: List[Dict]) -> str:
        """Format findings for inclusion in prompt"""
        
        text = ""
        for i, finding in enumerate(findings, 1):
            text += f"\n{i}. **{finding.get('type', 'Unknown').upper()}**\n"
            text += f"   - Endpoint: {finding.get('endpoint', 'Unknown')}\n"
            text += f"   - Parameter: {finding.get('parameter', 'Unknown')}\n"
            text += f"   - Severity: {finding.get('severity', 'Unknown')}\n"
            text += f"   - Confidence: {finding.get('confidence', 0.5):.0%}\n"
            if finding.get('payload'):
                text += f"   - Example Payload: {finding.get('payload')}\n"
        
        return text
    
    def _format_context(self, context: Optional[Dict]) -> str:
        """Format application context for prompt"""
        
        if not context:
            return "No context provided."
        
        text = ""
        if context.get('app_name'):
            text += f"- App: {context['app_name']}\n"
        if context.get('frameworks'):
            text += f"- Frameworks: {', '.join(context['frameworks'])}\n"
        if context.get('auth_model'):
            text += f"- Authentication: {context['auth_model']}\n"
        if context.get('databases'):
            text += f"- Databases: {', '.join(context['databases'])}\n"
        if context.get('security_features'):
            features = context['security_features']
            has_features = [k.replace('_', ' ').title() for k, v in features.items() if v]
            if has_features:
                text += f"- Security Features: {', '.join(has_features)}\n"
        
        return text
    
    def build_system_prompt(self, mode: ReasoningMode = ReasoningMode.CHAIN_DISCOVERY) -> str:
        """
        Build system prompt for LLM.
        
        This sets the LLM's role and expertise level.
        """
        
        if mode == ReasoningMode.CHAIN_DISCOVERY:
            return """You are an elite security researcher who specializes in vulnerability chaining.
You have 15+ years of experience finding real exploitable chains in production systems.
Your task is to find chains that actually work, not theoretical ones.
Be specific, technical, and practical."""
        
        elif mode == ReasoningMode.VERIFICATION:
            return """You are a critical security auditor who verifies vulnerability chains.
You are skeptical of claims and require proof.
Your job is to separate real vulnerabilities from false positives."""
        
        elif mode == ReasoningMode.IMPACT:
            return """You are a security risk analyst who assesses business impact.
You understand both technical severity and real-world business consequences."""
        
        elif mode == ReasoningMode.EXPLOITATION:
            return """You are a penetration tester who writes detailed exploitation guides.
Your guides are so clear that a junior pentester can follow them step-by-step."""
        
        elif mode == ReasoningMode.REMEDIATION:
            return """You are a security engineer who recommends specific, actionable fixes.
Your recommendations include exact code changes and configuration."""
        
        return "You are a security expert."


# Example usage
if __name__ == "__main__":
    engineer = PromptEngineer()
    
    # Example findings
    findings = [
        {
            "type": "sql_injection",
            "endpoint": "/api/search",
            "parameter": "q",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "payload": "1' UNION SELECT username, password FROM users--"
        },
        {
            "type": "idor",
            "endpoint": "/api/user/{id}",
            "parameter": "id",
            "severity": "HIGH",
            "confidence": 0.85
        }
    ]
    
    # Build discovery prompt
    prompt = engineer.build_chain_discovery_prompt(findings)
    print("Chain Discovery Prompt:")
    print("=" * 50)
    print(prompt)
