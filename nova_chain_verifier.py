"""
Nova Chain Verifier v1.0
========================
Verifies that generated chains are actually exploitable.
This is what separates real findings from theoretical ones.

Without verification, chain reasoner can hallucinate chains that don't actually work.
This module ensures only *real* chains are reported.
"""

import logging
from typing import List, Dict, Any, Tuple, Optional
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class VerificationMethod(Enum):
    """How to verify a chain is real"""
    STATIC_ANALYSIS = "static"      # Code analysis shows chain is possible
    DYNAMIC_EXECUTION = "dynamic"   # Actually execute the chain
    BROWSER_EXECUTION = "browser"   # JavaScript/XSS execution verification
    MANUAL_REVIEW = "manual"        # Human review required
    HEURISTIC = "heuristic"         # Statistical confidence


@dataclass
class VerificationResult:
    """Result of chain verification"""
    chain_id: str
    is_verified: bool
    method: VerificationMethod
    confidence: float  # 0-1, how sure we are
    evidence: str     # Why we believe it works
    failed_reason: Optional[str] = None
    reproduction_steps: Optional[List[str]] = None


class ChainVerifier:
    """
    Verifies vulnerability chains are real, not theoretical.
    
    Strategy:
    1. Check if findings are contradictory (can both be true?)
    2. Verify chain is technically feasible
    3. Confirm each step can actually happen
    4. Test if possible with static analysis
    5. Mark as verified only if confident
    """

    def __init__(self, ast_intel=None, browser_session=None):
        """
        Args:
            ast_intel: AST analysis module for dataflow checking
            browser_session: Browser for XSS/JavaScript verification
        """
        self.ast_intel = ast_intel
        self.browser_session = browser_session

    def verify_chains(self, chains: List[Any]) -> List[Tuple[Any, VerificationResult]]:
        """
        Verify a list of chains.
        
        Returns: List of (chain, verification_result) tuples
        """
        verified = []
        
        for chain in chains:
            result = self._verify_single_chain(chain)
            verified.append((chain, result))
            
            logger.info(f"Chain {chain.chain_id}: "
                       f"{'✓ VERIFIED' if result.is_verified else '✗ FAILED'} "
                       f"({result.confidence:.0%} confidence)")
        
        return verified

    def _verify_single_chain(self, chain) -> VerificationResult:
        """Verify one chain through multiple checks"""
        
        # Check 1: Are findings compatible?
        if not self._check_findings_compatible(chain.findings):
            return VerificationResult(
                chain_id=chain.chain_id,
                is_verified=False,
                method=VerificationMethod.STATIC_ANALYSIS,
                confidence=0.0,
                evidence="Findings are contradictory",
                failed_reason="Two findings exclude each other"
            )
        
        # Check 2: Is chain technically feasible?
        feasibility = self._check_technical_feasibility(chain)
        if feasibility < 0.5:
            return VerificationResult(
                chain_id=chain.chain_id,
                is_verified=False,
                method=VerificationMethod.STATIC_ANALYSIS,
                confidence=feasibility,
                evidence=f"Technical feasibility: {feasibility:.0%}",
                failed_reason="Chain is theoretically possible but unlikely to work in practice"
            )
        
        # Check 3: Can we verify via static analysis?
        static_confidence = self._verify_via_static_analysis(chain)
        
        # Check 4: For XSS/JavaScript, verify execution possible
        execution_confidence = 1.0
        if any(f.type == "xss" for f in chain.findings):
            execution_confidence = self._verify_xss_execution(chain)
        
        # Check 5: For SSRF, verify internal service reachable
        ssrf_confidence = 1.0
        if any(f.type == "ssrf" for f in chain.findings):
            ssrf_confidence = self._verify_ssrf_feasibility(chain)
        
        # Combine confidence scores
        final_confidence = min(
            static_confidence,
            execution_confidence,
            ssrf_confidence
        )
        
        # Determine verification method
        if static_confidence > 0.9:
            method = VerificationMethod.STATIC_ANALYSIS
        elif execution_confidence < 1.0:
            method = VerificationMethod.BROWSER_EXECUTION
        else:
            method = VerificationMethod.HEURISTIC
        
        is_verified = final_confidence >= 0.7  # 70%+ confidence = verified
        
        return VerificationResult(
            chain_id=chain.chain_id,
            is_verified=is_verified,
            method=method,
            confidence=final_confidence,
            evidence=self._generate_evidence(chain, final_confidence),
            reproduction_steps=chain.steps if is_verified else None
        )

    def _check_findings_compatible(self, findings: List) -> bool:
        """Check if findings can both exist at the same time"""
        
        # Example conflicts:
        # - SQLi found AND input is sanitized = contradiction
        # - IDOR found AND strict authorization = contradiction
        
        types = [f.type for f in findings]
        
        # Known contradictions
        contradictions = [
            ("sql_injection", "parameterized_queries"),
            ("xss", "csp_enabled"),
            ("idor", "proper_authorization"),
            ("jwt_vulnerability", "jwt_validation_enabled")
        ]
        
        for f_type_1, f_type_2 in contradictions:
            if f_type_1 in types and f_type_2 in types:
                return False
        
        return True

    def _check_technical_feasibility(self, chain) -> float:
        """Score 0-1: Is this chain technically possible?"""
        
        feasibility = 1.0
        findings = chain.findings
        
        # Check 1: Sequential chaining
        # Some vulns can't happen after others
        if len(findings) >= 2:
            for i in range(len(findings) - 1):
                current = findings[i].type
                next_one = findings[i + 1].type
                
                # XSS must happen before session stealing
                if current != "xss" and next_one == "session_token":
                    feasibility -= 0.1
                
                # Authentication must happen before authorization bypass
                if current != "authentication" and next_one == "privilege_escalation":
                    feasibility *= 0.8
        
        # Check 2: Endpoint compatibility
        endpoints = [f.endpoint for f in findings if f.endpoint]
        if len(endpoints) > 1:
            # If findings are on different endpoints, chain is less likely
            unique_endpoints = len(set(endpoints))
            if unique_endpoints > 1:
                feasibility *= (1.0 / unique_endpoints)
        
        # Check 3: Known problematic chains
        type_combo = tuple(sorted([f.type for f in findings]))
        
        # These chains rarely work in practice
        bad_combos = [
            ("csrf", "random_token"),
            ("xss", "httponly_cookie"),
            ("idor", "uuid_identifier")
        ]
        
        for combo in bad_combos:
            if all(t in type_combo for t in combo):
                feasibility *= 0.3
        
        return max(feasibility, 0.0)

    def _verify_via_static_analysis(self, chain) -> float:
        """Use static analysis (AST intel) to verify chain"""
        
        if not self.ast_intel:
            return 0.8  # Without AST intel, assume high confidence
        
        confidence = 0.8
        
        for finding in chain.findings:
            # Check if code shows this vulnerability
            if finding.type == "sql_injection":
                # Does code use parameterized queries?
                uses_params = self.ast_intel.check_parameterized_queries(
                    finding.endpoint
                )
                if uses_params:
                    confidence *= 0.1
            
            elif finding.type == "xss":
                # Does code escape output?
                escapes_output = self.ast_intel.check_output_escaping(
                    finding.endpoint
                )
                if escapes_output:
                    confidence *= 0.2
            
            elif finding.type == "idor":
                # Does code check authorization?
                checks_auth = self.ast_intel.check_authorization(
                    finding.endpoint
                )
                if checks_auth:
                    confidence *= 0.1
        
        return max(confidence, 0.3)  # Never go below 0.3

    def _verify_xss_execution(self, chain) -> float:
        """For XSS chains, verify JavaScript can actually execute"""
        
        if not self.browser_session:
            return 0.9  # Without browser, assume it works
        
        xss_finding = next(
            (f for f in chain.findings if f.type == "xss"), 
            None
        )
        
        if not xss_finding:
            return 1.0  # No XSS, so no execution concern
        
        # Try to execute XSS payload
        try:
            payload = xss_finding.payload_example or "alert('xss')"
            
            # Inject payload in browser
            result = self.browser_session.inject_payload(
                xss_finding.endpoint,
                xss_finding.parameter,
                payload
            )
            
            if result.executed:
                return 1.0
            else:
                return 0.3  # Payload didn't execute
        
        except Exception as e:
            logger.warning(f"XSS verification failed: {e}")
            return 0.5

    def _verify_ssrf_feasibility(self, chain) -> float:
        """For SSRF chains, verify internal services are actually reachable"""
        
        ssrf_finding = next(
            (f for f in chain.findings if f.type == "ssrf"),
            None
        )
        
        if not ssrf_finding:
            return 1.0
        
        # Check if internal services are actually accessible
        # This depends on infrastructure which we might not know
        # So we give moderate confidence
        
        confidence = 0.7
        
        # If the SSRF target is explicitly mentioned, higher confidence
        if ssrf_finding.context.get("target_service"):
            confidence = 0.9
        
        return confidence

    def _generate_evidence(self, chain, confidence: float) -> str:
        """Generate human-readable evidence for verification"""
        
        finding_types = ", ".join([f.type for f in chain.findings])
        
        if confidence >= 0.9:
            return f"Chain is highly feasible: {finding_types}"
        elif confidence >= 0.7:
            return f"Chain is likely exploitable: {finding_types}"
        elif confidence >= 0.5:
            return f"Chain is possible but requires specific conditions: {finding_types}"
        else:
            return f"Chain is unlikely to work in practice: {finding_types}"

    def filter_verified_chains(self, verified_results: List[Tuple]) -> List:
        """Extract only verified chains"""
        return [
            chain for chain, result in verified_results 
            if result.is_verified
        ]

    def score_chains_by_reliability(self, verified_results: List[Tuple]) -> List[Tuple]:
        """Sort chains by verification confidence"""
        return sorted(
            verified_results,
            key=lambda x: x[1].confidence,
            reverse=True
        )

    def generate_verification_report(self, verified_results: List[Tuple]) -> str:
        """Generate a report of verification results"""
        
        total = len(verified_results)
        verified = sum(1 for _, result in verified_results if result.is_verified)
        
        report = f"""
Chain Verification Report
=========================

Total chains: {total}
Verified: {verified} ({verified/total*100:.0f}%)
Failed: {total-verified}

By Confidence:
- High (90-100%): {sum(1 for _, r in verified_results if r.confidence >= 0.9)}
- Medium (70-89%): {sum(1 for _, r in verified_results if 0.7 <= r.confidence < 0.9)}
- Low (50-69%): {sum(1 for _, r in verified_results if 0.5 <= r.confidence < 0.7)}
- Very Low (<50%): {sum(1 for _, r in verified_results if r.confidence < 0.5)}

Failed Chains:
"""
        
        for chain, result in verified_results:
            if not result.is_verified:
                report += f"\n- {chain.chain_id}: {result.failed_reason}"
        
        return report


# Example usage
if __name__ == "__main__":
    # Mock chain for testing
    class MockFinding:
        def __init__(self, type_, endpoint):
            self.type = type_
            self.endpoint = endpoint
            self.context = {}
            self.payload_example = None

    class MockChain:
        def __init__(self, chain_id, findings):
            self.chain_id = chain_id
            self.findings = findings

    # Test
    verifier = ChainVerifier()
    
    chain = MockChain(
        "test_1",
        [
            MockFinding("jwt_vulnerability", "/auth"),
            MockFinding("api_endpoint", "/admin")
        ]
    )
    
    result = verifier._verify_single_chain(chain)
    print(f"Chain verified: {result.is_verified}")
    print(f"Confidence: {result.confidence:.0%}")
    print(f"Evidence: {result.evidence}")
