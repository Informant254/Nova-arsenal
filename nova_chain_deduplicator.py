"""
Nova Chain Deduplicator & Ranker v1.0
======================================
Deduplicates chains and ranks by real impact.

Problem: 
- Template reasoner generates chain A
- Similarity reasoner generates almost identical chain A
- LLM reasoner generates same chain with different wording
Result: User sees same chain 3 times = noise

Solution:
- Detect duplicate/near-duplicate chains
- Keep only the highest confidence version
- Rank by real-world impact (not just CVSS)
"""

import logging
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import hashlib
import json

logger = logging.getLogger(__name__)


@dataclass
class ChainRanking:
    """How to rank chains by impact"""
    chain_id: str
    
    # Scores
    cvss_score: float              # 0-10 (CVSS v3.1)
    exploitability: float          # 0-1, how easy to exploit
    impact_score: float            # 0-1, how much damage
    business_impact: float         # 0-1, financial/reputational damage
    confidence: float              # 0-1, how sure we are
    
    # Metadata
    affected_users: int = 0        # How many users affected
    data_at_risk: str = ""         # PII, secrets, etc
    recovery_time: int = 0         # Minutes to fix
    
    # Final score
    final_score: float = 0.0
    
    def calculate_final_score(self) -> float:
        """Calculate weighted final score"""
        
        # Weights (tunable based on priorities)
        weights = {
            "cvss": 0.25,           # Technical severity
            "exploitability": 0.20, # How easy to exploit
            "impact": 0.20,         # Amount of damage
            "business": 0.15,       # Business risk
            "confidence": 0.20      # How sure we are
        }
        
        final = (
            self.cvss_score / 10 * weights["cvss"] +
            self.exploitability * weights["exploitability"] +
            self.impact_score * weights["impact"] +
            self.business_impact * weights["business"] +
            self.confidence * weights["confidence"]
        )
        
        self.final_score = final
        return final


class ChainDeduplicator:
    """Detects and removes duplicate/similar chains"""
    
    def __init__(self, similarity_threshold: float = 0.85):
        """
        Args:
            similarity_threshold: 0-1, how similar chains need to be to be considered duplicates
        """
        self.similarity_threshold = similarity_threshold
    
    def deduplicate_chains(self, chains: List) -> List:
        """
        Remove duplicate chains, keeping the highest confidence version.
        
        Returns:
            Deduplicated list of chains
        """
        
        if not chains:
            return []
        
        # Create signatures for each chain
        signatures = {}
        for chain in chains:
            sig = self._create_signature(chain)
            if sig not in signatures:
                signatures[sig] = []
            signatures[sig].append(chain)
        
        # For each signature, keep the best chain
        deduplicated = []
        for sig, chain_group in signatures.items():
            best_chain = max(chain_group, key=lambda c: c.confidence)
            deduplicated.append(best_chain)
            
            if len(chain_group) > 1:
                logger.info(f"Deduplicated {len(chain_group)-1} duplicate chains")
        
        return deduplicated
    
    def _create_signature(self, chain) -> str:
        """
        Create a signature of a chain.
        Same chains get same signature, different chains get different.
        """
        
        # Key elements that make a chain unique
        elements = {
            "chain_type": chain.chain_type.value if hasattr(chain.chain_type, 'value') else str(chain.chain_type),
            "finding_types": tuple(sorted([f.type for f in chain.findings])),
            "severity": chain.severity,
            "impact_class": self._classify_impact(chain.impact)
        }
        
        # Create hash
        sig_str = json.dumps(elements, sort_keys=True, default=str)
        return hashlib.md5(sig_str.encode()).hexdigest()
    
    def _classify_impact(self, impact_str: str) -> str:
        """Classify impact into buckets"""
        impact_lower = impact_str.lower()
        
        if any(word in impact_lower for word in ["code", "rce", "execute", "command"]):
            return "RCE"
        elif any(word in impact_lower for word in ["admin", "privilege", "access"]):
            return "PRIVILEGE_ESCALATION"
        elif any(word in impact_lower for word in ["data", "steal", "exfiltrate", "leak"]):
            return "DATA_THEFT"
        elif any(word in impact_lower for word in ["bypass", "authentication", "auth"]):
            return "AUTH_BYPASS"
        elif any(word in impact_lower for word in ["denial", "dos", "service"]):
            return "DENIAL_OF_SERVICE"
        else:
            return "OTHER"
    
    def find_similar_chains(self, chains: List, threshold: float = 0.9) -> List[Tuple[int, int, float]]:
        """
        Find similar chains above threshold.
        
        Returns:
            List of (index1, index2, similarity) tuples
        """
        
        similar = []
        
        for i, chain1 in enumerate(chains):
            for j, chain2 in enumerate(chains[i+1:], start=i+1):
                similarity = self._chain_similarity(chain1, chain2)
                if similarity >= threshold:
                    similar.append((i, j, similarity))
        
        return similar
    
    def _chain_similarity(self, chain1, chain2) -> float:
        """Calculate similarity between two chains (0-1)"""
        
        score = 0.0
        
        # Same chain type?
        if chain1.chain_type == chain2.chain_type:
            score += 0.3
        
        # Same finding types?
        types1 = set(f.type for f in chain1.findings)
        types2 = set(f.type for f in chain2.findings)
        overlap = len(types1 & types2) / max(len(types1 | types2), 1)
        score += overlap * 0.4
        
        # Same severity?
        if chain1.severity == chain2.severity:
            score += 0.2
        
        # Similar impact?
        if self._classify_impact(chain1.impact) == self._classify_impact(chain2.impact):
            score += 0.1
        
        return min(score, 1.0)


class ChainRanker:
    """
    Ranks chains by real-world impact, not just CVSS.
    
    CVSS is technical severity. Real impact considers:
    - How easy to exploit
    - How much damage
    - Business risk
    - Confidence in the chain
    """
    
    def rank_chains(self, chains: List) -> List[Tuple[ChainRanking, object]]:
        """
        Rank chains by impact.
        
        Returns:
            List of (ChainRanking, chain) tuples sorted by final score
        """
        
        rankings = []
        
        for chain in chains:
            ranking = self._create_ranking(chain)
            ranking.calculate_final_score()
            rankings.append((ranking, chain))
        
        # Sort by final score descending
        rankings.sort(key=lambda x: x[0].final_score, reverse=True)
        
        return rankings
    
    def _create_ranking(self, chain) -> ChainRanking:
        """Create a ranking for one chain"""
        
        # Start with CVSS as baseline
        cvss = chain.cvss_score if hasattr(chain, 'cvss_score') else 5.0
        
        # Exploitability: how easy?
        exploitability = self._estimate_exploitability(chain)
        
        # Impact: how much damage?
        impact = self._estimate_impact(chain)
        
        # Business impact: financial/reputational risk
        business_impact = self._estimate_business_impact(chain)
        
        # Confidence: how sure are we?
        confidence = chain.confidence if hasattr(chain, 'confidence') else 0.5
        
        # Count affected users (estimate)
        affected_users = self._estimate_affected_users(chain)
        
        # Data at risk
        data_at_risk = self._identify_data_at_risk(chain)
        
        # Recovery time
        recovery_time = self._estimate_recovery_time(chain)
        
        return ChainRanking(
            chain_id=chain.chain_id if hasattr(chain, 'chain_id') else "unknown",
            cvss_score=cvss,
            exploitability=exploitability,
            impact_score=impact,
            business_impact=business_impact,
            confidence=confidence,
            affected_users=affected_users,
            data_at_risk=data_at_risk,
            recovery_time=recovery_time
        )
    
    def _estimate_exploitability(self, chain) -> float:
        """0-1: How easy is this to exploit?"""
        
        exploitability = 0.5
        
        # More steps = harder
        num_steps = len(chain.steps) if hasattr(chain, 'steps') else 2
        exploitability *= (1.0 / (1 + num_steps * 0.1))
        
        # Certain vulnerability types are easier
        if hasattr(chain, 'findings'):
            finding_types = [f.type for f in chain.findings]
            
            # Easy to exploit
            if "sql_injection" in finding_types:
                exploitability = max(exploitability, 0.8)
            if "idor" in finding_types:
                exploitability = max(exploitability, 0.9)
            
            # Moderate
            if "xss" in finding_types:
                exploitability = max(exploitability, 0.6)
            
            # Harder
            if "jwt_vulnerability" in finding_types:
                exploitability = max(exploitability, 0.5)
        
        return min(exploitability, 1.0)
    
    def _estimate_impact(self, chain) -> float:
        """0-1: How much damage can this cause?"""
        
        impact = 0.5
        
        if hasattr(chain, 'chain_type'):
            chain_type = str(chain.chain_type).lower()
            
            # Maximum impact
            if "rce" in chain_type or "remote_code_execution" in chain_type:
                return 1.0
            
            # Very high
            if "data_exfiltration" in chain_type:
                return 0.95
            
            # High
            if "privilege_escalation" in chain_type:
                return 0.85
            if "authentication_bypass" in chain_type:
                return 0.80
            
            # Medium
            if "lateral_movement" in chain_type:
                return 0.65
            
            # Lower
            if "denial" in chain_type or "dos" in chain_type:
                return 0.50
        
        return impact
    
    def _estimate_business_impact(self, chain) -> float:
        """0-1: What's the business/financial impact?"""
        
        impact = 0.5
        
        # RCE = total business compromise
        if hasattr(chain, 'chain_type'):
            chain_type = str(chain.chain_type).lower()
            if "rce" in chain_type:
                return 1.0
            if "data_exfiltration" in chain_type:
                return 0.95
            if "authentication" in chain_type:
                return 0.85
        
        # Data at risk increases business impact
        if hasattr(chain, 'impact') and 'pii' in chain.impact.lower():
            impact = 0.95
        if hasattr(chain, 'impact') and 'secret' in chain.impact.lower():
            impact = 0.90
        
        return min(impact, 1.0)
    
    def _estimate_affected_users(self, chain) -> int:
        """Estimate how many users affected"""
        
        # Default: assume 80% of users affected
        users = 0.80
        
        # RCE = all users
        if hasattr(chain, 'chain_type') and "rce" in str(chain.chain_type).lower():
            return 1
        
        # Authentication bypass = all users
        if hasattr(chain, 'chain_type') and "auth" in str(chain.chain_type).lower():
            return 1
        
        # IDOR = only other users
        if hasattr(chain, 'chain_type') and "idor" in str(chain.chain_type).lower():
            return 0.95
        
        return users
    
    def _identify_data_at_risk(self, chain) -> str:
        """What data is at risk?"""
        
        if not hasattr(chain, 'impact'):
            return "Unknown"
        
        impact_lower = chain.impact.lower()
        data_types = []
        
        if any(word in impact_lower for word in ["pii", "personal", "email", "phone", "address"]):
            data_types.append("PII")
        if any(word in impact_lower for word in ["password", "hash", "credential", "token", "secret", "key"]):
            data_types.append("Credentials/Secrets")
        if any(word in impact_lower for word in ["payment", "credit", "card", "financial"]):
            data_types.append("Payment Data")
        if any(word in impact_lower for word in ["database", "data", "records"]):
            data_types.append("Database Records")
        if any(word in impact_lower for word in ["code", "source", "proprietary"]):
            data_types.append("Source Code")
        
        return ", ".join(data_types) if data_types else "Sensitive Data"
    
    def _estimate_recovery_time(self, chain) -> int:
        """Estimate minutes needed to fix"""
        
        # RCE = hours to recover from
        recovery = 60  # 1 hour default
        
        if hasattr(chain, 'chain_type'):
            chain_type = str(chain.chain_type).lower()
            
            if "rce" in chain_type:
                recovery = 480  # 8 hours
            elif "data_exfiltration" in chain_type:
                recovery = 240  # 4 hours
            elif "authentication" in chain_type:
                recovery = 120  # 2 hours
            elif "privilege_escalation" in chain_type:
                recovery = 90
            else:
                recovery = 30
        
        return recovery
    
    def generate_ranking_report(self, rankings: List[Tuple[ChainRanking, object]]) -> str:
        """Generate a ranking report"""
        
        report = "Chain Impact Ranking Report\n"
        report += "=" * 50 + "\n\n"
        
        for i, (ranking, chain) in enumerate(rankings, 1):
            report += f"{i}. {chain.chain_type.value if hasattr(chain.chain_type, 'value') else chain.chain_type}\n"
            report += f"   Final Score: {ranking.final_score:.2f}/1.0\n"
            report += f"   - CVSS: {ranking.cvss_score:.1f}/10\n"
            report += f"   - Exploitability: {ranking.exploitability:.0%}\n"
            report += f"   - Impact: {ranking.impact_score:.0%}\n"
            report += f"   - Business Risk: {ranking.business_impact:.0%}\n"
            report += f"   - Confidence: {ranking.confidence:.0%}\n"
            report += f"   Data at Risk: {ranking.data_at_risk}\n"
            report += f"   Recovery Time: ~{ranking.recovery_time} mins\n\n"
        
        return report


# Example usage
if __name__ == "__main__":
    class MockChain:
        def __init__(self, chain_id, chain_type, findings):
            self.chain_id = chain_id
            self.chain_type = chain_type
            self.findings = findings
            self.severity = "CRITICAL"
            self.cvss_score = 8.5
            self.confidence = 0.85
            self.impact = "Allows RCE"
            self.steps = ["Step 1", "Step 2", "Step 3"]
    
    class MockFinding:
        def __init__(self, type_):
            self.type = type_
    
    from enum import Enum
    class ChainType(Enum):
        RCE = "remote_code_execution"
    
    # Test deduplication
    chain1 = MockChain("c1", ChainType.RCE, [MockFinding("sqli")])
    chain2 = MockChain("c2", ChainType.RCE, [MockFinding("sqli")])
    chain3 = MockChain("c3", ChainType.RCE, [MockFinding("xss")])
    
    dedup = ChainDeduplicator()
    result = dedup.deduplicate_chains([chain1, chain2, chain3])
    print(f"Deduplicated {3} chains to {len(result)}")
    
    # Test ranking
    ranker = ChainRanker()
    rankings = ranker.rank_chains([chain1, chain3])
    for ranking, chain in rankings:
        print(f"{chain.chain_id}: {ranking.final_score:.2f}")
