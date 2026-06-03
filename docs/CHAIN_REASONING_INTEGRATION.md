"""
NOVA CHAIN REASONER - Integration Guide
========================================

This module adds sophisticated vulnerability chain reasoning to Nova Arsenal.
It's the "Claude-level" component that understands how vulnerabilities compound.

ARCHITECTURE
============

1. INPUT: Raw findings from all scanners (SQLi, XSS, IDOR, etc.)
2. PROCESSING: 
   - Template-based chains (known patterns)
   - Similarity-based chains (same endpoint, related vulns)
   - LLM reasoning chains (sophisticated multi-step attacks)
3. OUTPUT: Ranked vulnerability chains with PoCs and mitigations

KEY COMPONENTS
==============

ChainReasoner
- analyze_findings() → List[VulnerabilityChain]
- export_chains_json() → JSON report
- export_chains_html() → Interactive HTML report

VulnerabilityChain
- findings: List of chained vulnerabilities
- narrative: Human-readable description
- steps: Step-by-step attack instructions
- proof_of_concept: Working PoC code
- cvss_score: Impact estimation
- mitigations: How to fix

ChainType (enum)
- AUTHENTICATION_BYPASS (e.g., forged JWT → admin access)
- DATA_EXFILTRATION (e.g., SQLi → database dump)
- REMOTE_CODE_EXECUTION (e.g., SSRF + RCE service)
- PRIVILEGE_ESCALATION
- LATERAL_MOVEMENT
- DENIAL_OF_SERVICE
- SUPPLY_CHAIN_ATTACK
- ZERO_DAY_CORRELATOR (novel combinations)

INTEGRATION WITH NOVA ARSENAL
==============================

1. In nova_orchestrator.py or nova.py:

```python
from nova_chain_reasoner import ChainReasoner

class NovaOrchestrator:
    def __init__(self, llm_router, verify_engine):
        self.chain_reasoner = ChainReasoner(
            llm_router=llm_router,
            verify_engine=verify_engine
        )
    
    def hunt(self, target):
        # Run all scanners (Phase 1-4)
        findings = self._run_all_scanners(target)
        
        # NEW: Analyze chains
        chains = self.chain_reasoner.analyze_findings(findings)
        
        # Verify chains (optional)
        if self.verify_engine:
            chains = self._verify_chains(chains)
        
        # Generate reports
        self._export_findings(findings, chains)
        return findings, chains
```

2. In nova_audit_reporter.py:

```python
def generate_report(findings, chains):
    # Existing findings report
    report = generate_findings_report(findings)
    
    # NEW: Add chain section
    chains_section = f"""
## VULNERABILITY CHAINS (CRITICAL)

High-risk combinations discovered:

{format_chains(chains)}

Each chain represents a complete attack path with real impact.
"""
    
    report += chains_section
    return report
```

3. Hook into existing pipeline:

```python
# In nova.py main execution:
findings = phase1_sast() + phase2_sca() + phase3_active_scanning()
chains = ChainReasoner().analyze_findings(findings)

# Seeds for next hunt:
context.add_finding_chains(chains)
context.update_attack_surface(chains)
```

USAGE EXAMPLES
==============

Basic Usage:
```python
from nova_chain_reasoner import ChainReasoner

reasoner = ChainReasoner()
chains = reasoner.analyze_findings(raw_findings)

for chain in chains:
    print(f"{chain.severity} - {chain.narrative}")
    print(f"CVSS: {chain.cvss_score}")
    print(f"Steps: {chain.steps}")
```

With LLM Reasoning:
```python
from nova_llm_router import LLMRouter
from nova_chain_reasoner import ChainReasoner

llm = LLMRouter(provider='openai')  # or 'ollama', 'anthropic'
reasoner = ChainReasoner(llm_router=llm)

chains = reasoner.analyze_findings(findings)
# Now includes sophisticated LLM-generated chains
```

Export Options:
```python
# JSON (for parsing/integration)
json_report = reasoner.export_chains_json()

# HTML (for HackerOne/Bugcrowd reports)
html_report = reasoner.export_chains_html()

# For CLI output
for chain in reasoner.chains:
    print(chain.narrative)
    print(f"PoC: {chain.proof_of_concept}")
```

REASONING STRATEGIES
====================

1. TEMPLATE-BASED (Fast, Reliable)
   - Hardcoded patterns for common chains
   - Examples: SQLi→RCE, IDOR+Secret→Takeover, XSS+Session→Theft
   - Works offline, no LLM needed

2. SIMILARITY-BASED (Fast, Flexible)
   - Same endpoint + related vulnerability types = likely chain
   - Examples: Multiple findings on /api/user + IDOR = enumeration
   - Uses semantic understanding of vulnerability types

3. LLM REASONING (Slow, Sophisticated)
   - Sends all findings to LLM with reasoning prompt
   - Discovers novel chains human researchers might miss
   - Requires API key or local LLM
   - Can find: zero-days, complex multi-step chains, business logic combinations

CHAIN TYPES & IMPACT
====================

AUTHENTICATION_BYPASS
- Forged JWT → Admin access
- XSS steals session → Account takeover
- IDOR + leaked credentials → Any user
Impact: Full access as other users

DATA_EXFILTRATION
- SQLi → Database dump
- IDOR → Enumerate all records
- GraphQL introspection → Schema extraction
Impact: All data stolen

REMOTE_CODE_EXECUTION
- SSRF to internal RCE service
- SQLi + stacked queries + file write
- CVE dependency + known exploit
Impact: Full server compromise

PRIVILEGE_ESCALATION
- IDOR on admin endpoint
- JWT + weak secret + admin claim
Impact: User → Admin

LATERAL_MOVEMENT
- SSRF to internal database/Redis/Elasticsearch
- Initial compromise → reach internal systems
Impact: Expand from one service to entire network

DENIAL_OF_SERVICE
- Race condition in inventory
- Price manipulation in checkout
- Resource exhaustion via API
Impact: Service disruption, financial loss

SUPPLY_CHAIN_ATTACK
- CVE in dependency + vulnerable function call
- Dependency update → remote compromise
Impact: All users affected

ZERO_DAY_CORRELATOR
- Rare: Novel combination of known vulns
- Example: GraphQL + SSRF + IDOR + LLM injection = data theft
Impact: Unknown/unpredictable

CUSTOMIZATION
==============

Add custom chain patterns:
```python
CHAIN_PATTERNS = {
    ("your_vuln_type", "related_type"): {
        "name": "Your Chain Name",
        "chain_type": ChainType.YOUR_TYPE,
        "severity": "CRITICAL",
        "reasoning": "Why this chain works..."
    }
}
```

Add custom impact assessment:
```python
def _estimate_impact(self, chain_type, findings):
    # Override this for domain-specific reasoning
    impacts = {
        ChainType.YOUR_TYPE: "Your custom impact description"
    }
    return impacts.get(chain_type, "...")
```

TESTING
=======

Unit test example:
```python
def test_chain_reasoning():
    reasoner = ChainReasoner()
    
    findings = [
        {"type": "sql_injection", "severity": "CRITICAL", "endpoint": "/search"},
        {"type": "idor", "severity": "HIGH", "endpoint": "/api/user/{id}"}
    ]
    
    chains = reasoner.analyze_findings(findings)
    
    assert len(chains) > 0
    assert chains[0].severity == "CRITICAL"
    assert "SQLi" in chains[0].narrative or "IDOR" in chains[0].narrative
```

PERFORMANCE
===========

- Template-based chains: < 100ms (1000 findings)
- Similarity-based chains: < 500ms (1000 findings)
- LLM reasoning chains: 5-30s (depends on model)

Optimize by:
1. Filter low-confidence findings before chaining
2. Cache LLM responses for repeated findings
3. Run template + similarity offline, LLM async

EDGE CASES
==========

1. No chains found
   - Scanner found only low-severity vulns
   - No obvious combinations
   - This is GOOD - means defense-in-depth works

2. Too many chains
   - Reduce threshold for finding inclusion
   - Limit to top N chains by CVSS
   - Focus on CRITICAL severity only

3. False positive chains
   - Verify each chain before reporting
   - Use verify_engine to confirm feasibility
   - Manual review recommended for novel chains

FUTURE ENHANCEMENTS
====================

1. Machine learning: Learn chains from successful pentests
2. Dataflow analysis: Track data through application
3. Temporal analysis: Consider timing-based chains
4. Environment awareness: Chain feasibility depends on infrastructure
5. Remediation verification: Confirm fixes actually block chains
6. Industry-specific chains: Banking, healthcare, IoT, etc.

COMPATIBILITY
=============

Works with:
- nova_llm_router.py (OpenAI, Anthropic, Ollama)
- nova_verify_engine.py (confirmation of chains)
- nova_audit_reporter.py (report generation)
- nova_triage.py (HackerOne-ready scoring)

Requires:
- Python 3.10+
- Finding objects with: type, severity, endpoint, parameter, confidence

Optional:
- LLM API key (OpenAI, Anthropic) for advanced reasoning
- Verify engine for chain confirmation

ROADMAP
=======

v1.0 (Current)
- Template-based chains
- Similarity reasoning
- LLM integration
- HTML/JSON export

v2.0 (Planned)
- Dataflow analysis integration
- Remediation verification
- Machine learning ranking
- Interactive chain builder

v3.0 (Future)
- Real-time chain adaptation
- Fuzzy matching for novel findings
- Supply chain attack modeling
- Zero-day correlation engine

"""

# Integration example: How to use in nova_orchestrator.py
"""
EXAMPLE ORCHESTRATOR INTEGRATION
==================================

```python
# nova_orchestrator.py

import logging
from nova_chain_reasoner import ChainReasoner, ChainType
from nova_context import RunContext

logger = logging.getLogger(__name__)

class NovaOrchestrator:
    def __init__(self, llm_router, verify_engine=None, context=None):
        self.llm_router = llm_router
        self.verify_engine = verify_engine
        self.context = context or RunContext()
        self.chain_reasoner = ChainReasoner(
            llm_router=llm_router,
            verify_engine=verify_engine
        )
    
    def hunt(self, target_url: str, full_pipeline=True) -> Dict:
        '''
        Complete hunt with chain reasoning
        '''
        logger.info(f"Starting hunt on {target_url}")
        
        # Phase 0: Codebase mapping
        codebase_map = self._run_codebase_mapper(target_url)
        
        # Phase 1-4: All vulnerability scanners
        findings = self._run_all_scanners(target_url, codebase_map)
        logger.info(f"Found {len(findings)} vulnerabilities")
        
        # NEW: Phase 5 - Chain reasoning
        chains = self.chain_reasoner.analyze_findings(findings)
        logger.info(f"Identified {len(chains)} vulnerability chains")
        
        # Verify chains if possible
        if self.verify_engine:
            chains = self._verify_chains(chains)
            logger.info(f"Verified {sum(1 for c in chains if c.confidence > 0.8)} chains")
        
        # Emit findings with context
        for finding in findings:
            self.context.add_finding(finding)
        
        for chain in chains:
            self.context.add_chain(chain)
        
        # Generate comprehensive report
        report = self._generate_report(findings, chains, codebase_map)
        
        return {
            "target": target_url,
            "findings": findings,
            "chains": chains,
            "report": report,
            "summary": {
                "critical_vulns": len([f for f in findings if f['severity'] == 'CRITICAL']),
                "critical_chains": len([c for c in chains if c.severity == 'CRITICAL']),
                "total_cvss": sum(f.get('cvss', 0) for f in findings)
            }
        }
    
    def _verify_chains(self, chains):
        '''Verify each chain's feasibility'''
        verified = []
        for chain in chains:
            # Quick verification: are all findings real?
            if all(f.confidence > 0.5 for f in chain.findings):
                chain.confidence = min(chain.confidence, 0.95)
                verified.append(chain)
        return verified
    
    def _generate_report(self, findings, chains, codebase_map):
        '''Generate final report with chains'''
        return {
            "findings_summary": len(findings),
            "chains_summary": len(chains),
            "critical_chains": [c for c in chains if c.severity == 'CRITICAL'],
            "high_chains": [c for c in chains if c.severity == 'HIGH']
        }
```

This shows how Nova Arsenal v4.2+ includes chain reasoning as a core Phase 5 component.
"""
