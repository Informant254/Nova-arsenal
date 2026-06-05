"""
Nova Context Enricher v1.0
==========================
Enriches findings with application context.
This makes chain reasoning much smarter by understanding the app structure.

Example:
- Without context: "IDOR found on /api/user/{id}"
- With context: "IDOR on /api/user/{id} + app uses sequential IDs + no rate limiting"
  → Much smarter chain reasoning

Context comes from:
1. Codebase mapper (framework, auth model, endpoints)
2. Active scanning (what's actually deployed)
3. Configuration files (.env, config.yml)
4. Manual analysis
"""

import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AuthModel(Enum):
    """How the app authenticates users"""
    NONE = "none"
    BASIC = "basic"
    JWT = "jwt"
    SESSION_COOKIE = "session"
    OAUTH = "oauth"
    API_KEY = "api_key"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class IDScheme(Enum):
    """How app identifies resources"""
    SEQUENTIAL = "sequential"  # 1, 2, 3... easy to enumerate
    UUID = "uuid"              # Hard to guess
    HASH = "hash"              # Hard to guess
    ENCODED = "encoded"        # Base64, etc
    UNKNOWN = "unknown"


@dataclass
class ApplicationContext:
    """Rich context about the application"""
    
    # Basic info
    name: str
    url: str
    
    # Architecture
    frameworks: List[str] = field(default_factory=list)  # Express, Angular, Django, etc
    backend_language: Optional[str] = None               # Python, Node, Java, etc
    frontend_language: Optional[str] = None              # JavaScript, TypeScript, etc
    databases: List[str] = field(default_factory=list)   # PostgreSQL, MongoDB, Redis, etc
    
    # Security model
    auth_model: AuthModel = AuthModel.UNKNOWN
    auth_endpoints: List[str] = field(default_factory=list)
    protected_endpoints: List[str] = field(default_factory=list)
    public_endpoints: List[str] = field(default_factory=list)
    
    # Data model
    id_scheme: IDScheme = IDScheme.UNKNOWN
    multi_tenant: bool = False
    user_roles: List[str] = field(default_factory=list)
    
    # Infrastructure
    uses_cdn: bool = False
    uses_waf: bool = False
    uses_api_gateway: bool = False
    rate_limiting: bool = False
    
    # Security features
    has_csp: bool = False
    has_https: bool = False
    sanitizes_input: bool = False
    escapes_output: bool = False
    uses_parameterized_queries: bool = False
    
    # Known vulns/configs
    known_issues: List[str] = field(default_factory=list)
    misconfigurations: List[str] = field(default_factory=list)
    
    # Custom data
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContextEnricher:
    """
    Enriches findings with application context.
    Makes chain reasoning context-aware.
    """
    
    def __init__(self):
        self.context: Optional[ApplicationContext] = None
    
    def set_context(self, context: ApplicationContext):
        """Set the application context"""
        self.context = context
        logger.info(f"Context set for {context.name}")
    
    def build_context_from_codebase_map(self, codebase_map: Dict) -> ApplicationContext:
        """
        Build application context from codebase mapper output.
        
        Args:
            codebase_map: Output from nova_codebase_mapper.py
            
        Returns:
            Rich ApplicationContext
        """
        
        context = ApplicationContext(
            name=codebase_map.get("name", "Unknown"),
            url=codebase_map.get("url", ""),
            frameworks=codebase_map.get("frameworks", []),
            backend_language=codebase_map.get("backend_language"),
            frontend_language=codebase_map.get("frontend_language"),
            databases=codebase_map.get("databases", [])
        )
        
        # Detect auth model
        if "jwt" in str(codebase_map).lower():
            context.auth_model = AuthModel.JWT
        elif "session" in str(codebase_map).lower():
            context.auth_model = AuthModel.SESSION_COOKIE
        elif "oauth" in str(codebase_map).lower():
            context.auth_model = AuthModel.OAUTH
        
        # Detect endpoints
        context.auth_endpoints = codebase_map.get("auth_endpoints", [])
        context.protected_endpoints = codebase_map.get("protected_endpoints", [])
        context.public_endpoints = codebase_map.get("public_endpoints", [])
        
        # Detect ID scheme from code patterns
        if codebase_map.get("uses_uuid"):
            context.id_scheme = IDScheme.UUID
        elif codebase_map.get("uses_sequential_ids"):
            context.id_scheme = IDScheme.SEQUENTIAL
        
        # Detect security features
        context.has_csp = "csp" in str(codebase_map).lower()
        context.has_https = "https" in str(codebase_map).lower()
        context.sanitizes_input = codebase_map.get("sanitizes_input", False)
        context.escapes_output = codebase_map.get("escapes_output", False)
        context.uses_parameterized_queries = codebase_map.get("uses_parameterized_queries", False)
        
        # Detect infrastructure
        context.uses_cdn = codebase_map.get("uses_cdn", False)
        context.uses_waf = codebase_map.get("uses_waf", False)
        context.uses_api_gateway = codebase_map.get("uses_api_gateway", False)
        context.rate_limiting = codebase_map.get("rate_limiting", False)
        
        self.context = context
        return context
    
    def build_context_from_env(self, env_file: str) -> ApplicationContext:
        """
        Build context from .env or config file.
        
        Args:
            env_file: Path to .env or config file
        """
        
        context = ApplicationContext(name="From Config", url="")
        
        try:
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    key, value = line.split('=', 1)
                    key = key.lower()
                    
                    # Extract info from env vars
                    if "jwt_secret" in key or "jwt_key" in key:
                        context.auth_model = AuthModel.JWT
                    
                    if "session" in key:
                        context.auth_model = AuthModel.SESSION_COOKIE
                    
                    if "database_url" in key or "db_" in key:
                        # Extract database type
                        if "postgres" in value:
                            context.databases.append("PostgreSQL")
                        elif "mongo" in value:
                            context.databases.append("MongoDB")
                        elif "mysql" in value:
                            context.databases.append("MySQL")
                    
                    if "rate_limit" in key:
                        context.rate_limiting = "true" in value.lower()
                    
                    if "csp" in key:
                        context.has_csp = "true" in value.lower()
                    
                    if "waf" in key:
                        context.uses_waf = "true" in value.lower()
        
        except Exception as e:
            logger.warning(f"Failed to parse env file: {e}")
        
        self.context = context
        return context
    
    def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Add application context to findings.
        
        Args:
            findings: Raw findings from scanners
            
        Returns:
            Findings enriched with context
        """
        
        if not self.context:
            logger.warning("No context set, skipping enrichment")
            return findings
        
        enriched = []
        
        for finding in findings:
            finding_copy = finding.copy()
            finding_copy["context"] = finding_copy.get("context", {})
            
            # Add app-wide context
            finding_copy["context"]["app_name"] = self.context.name
            finding_copy["context"]["auth_model"] = self.context.auth_model.value
            finding_copy["context"]["id_scheme"] = self.context.id_scheme.value
            finding_copy["context"]["has_waf"] = self.context.uses_waf
            finding_copy["context"]["has_rate_limiting"] = self.context.rate_limiting
            
            # Type-specific enrichment
            if finding["type"] == "idor":
                finding_copy["context"]["id_scheme_matters"] = (
                    self.context.id_scheme == IDScheme.SEQUENTIAL
                )
                finding_copy["context"]["endpoint_is_protected"] = (
                    finding["endpoint"] in self.context.protected_endpoints
                )
            
            elif finding["type"] == "xss":
                finding_copy["context"]["has_csp"] = self.context.has_csp
                finding_copy["context"]["escapes_output"] = self.context.escapes_output
            
            elif finding["type"] == "sql_injection":
                finding_copy["context"]["uses_parameterized_queries"] = (
                    self.context.uses_parameterized_queries
                )
            
            elif finding["type"] == "authentication_bypass":
                finding_copy["context"]["auth_model"] = self.context.auth_model.value
                finding_copy["context"]["auth_endpoints"] = self.context.auth_endpoints
            
            elif finding["type"] == "ssrf":
                finding_copy["context"]["has_internal_services"] = (
                    len(self.context.databases) > 0 or
                    self.context.uses_api_gateway
                )
            
            enriched.append(finding_copy)
        
        logger.info(f"Enriched {len(enriched)} findings with context")
        return enriched
    
    def get_chain_reasoning_hints(self) -> str:
        """
        Generate hints for chain reasoner based on context.
        This helps the LLM know what chains are likely.
        """
        
        if not self.context:
            return ""
        
        hints = []
        
        # Auth model hints
        if self.context.auth_model == AuthModel.JWT:
            hints.append("- App uses JWT authentication (look for forging/bypass chains)")
        elif self.context.auth_model == AuthModel.SESSION_COOKIE:
            hints.append("- App uses session cookies (look for session stealing/fixation chains)")
        
        # ID scheme hints
        if self.context.id_scheme == IDScheme.SEQUENTIAL:
            hints.append("- App uses sequential IDs (IDOR enumeration is likely easy)")
        elif self.context.id_scheme == IDScheme.UUID:
            hints.append("- App uses UUIDs (IDOR enumeration is harder)")
        
        # Security feature hints
        if not self.context.has_csp:
            hints.append("- No Content Security Policy (XSS + session theft chains are likely)")
        
        if not self.context.uses_parameterized_queries:
            hints.append("- May not use parameterized queries (SQLi chains possible)")
        
        if not self.context.has_waf:
            hints.append("- No Web Application Firewall (injection attacks less filtered)")
        
        if not self.context.rate_limiting:
            hints.append("- No rate limiting (brute force chains possible)")
        
        # Database hints
        if self.context.databases:
            hints.append(f"- Uses {', '.join(self.context.databases)}")
        
        # Multi-tenancy hints
        if self.context.multi_tenant:
            hints.append("- Multi-tenant app (IDOR + data exfiltration is high impact)")
        
        return "\n".join(hints)
    
    def estimate_chain_difficulty(self, chain_type: str) -> str:
        """
        Estimate how hard a chain is to exploit given the context.
        
        Returns: "EASY", "MODERATE", "DIFFICULT", or "IMPOSSIBLE"
        """
        
        if not self.context:
            return "UNKNOWN"
        
        # JWT forgery
        if "jwt" in chain_type.lower():
            if self.context.auth_model != AuthModel.JWT:
                return "IMPOSSIBLE"
            return "MODERATE"
        
        # IDOR chains
        if "idor" in chain_type.lower():
            if self.context.id_scheme == IDScheme.UUID:
                return "DIFFICULT"
            elif self.context.id_scheme == IDScheme.SEQUENTIAL:
                return "EASY"
            return "MODERATE"
        
        # XSS chains
        if "xss" in chain_type.lower():
            if self.context.has_csp:
                return "DIFFICULT"
            return "MODERATE"
        
        # SQLi chains
        if "sql" in chain_type.lower():
            if self.context.uses_parameterized_queries:
                return "IMPOSSIBLE"
            return "MODERATE"
        
        return "MODERATE"
    
    def export_context(self) -> Dict:
        """Export context as JSON"""
        if not self.context:
            return {}
        
        return {
            "name": self.context.name,
            "url": self.context.url,
            "frameworks": self.context.frameworks,
            "databases": self.context.databases,
            "auth_model": self.context.auth_model.value,
            "id_scheme": self.context.id_scheme.value,
            "security_features": {
                "has_csp": self.context.has_csp,
                "has_https": self.context.has_https,
                "sanitizes_input": self.context.sanitizes_input,
                "escapes_output": self.context.escapes_output,
                "uses_parameterized_queries": self.context.uses_parameterized_queries,
            },
            "infrastructure": {
                "uses_cdn": self.context.uses_cdn,
                "uses_waf": self.context.uses_waf,
                "uses_api_gateway": self.context.uses_api_gateway,
                "rate_limiting": self.context.rate_limiting,
            }
        }


# Example usage
if __name__ == "__main__":
    # Create context
    enricher = ContextEnricher()
    
    context = ApplicationContext(
        name="TestApp",
        url="https://testapp.com",
        frameworks=["Express", "React"],
        auth_model=AuthModel.JWT,
        id_scheme=IDScheme.SEQUENTIAL,
        has_csp=False,
        rate_limiting=False
    )
    
    enricher.set_context(context)
    
    # Generate hints
    hints = enricher.get_chain_reasoning_hints()
    print("Chain Reasoning Hints:")
    print(hints)
    
    # Estimate chain difficulty
    print("\nChain Difficulty Estimates:")
    print(f"IDOR chains: {enricher.estimate_chain_difficulty('idor')}")
    print(f"XSS chains: {enricher.estimate_chain_difficulty('xss')}")
    print(f"JWT chains: {enricher.estimate_chain_difficulty('jwt')}")
