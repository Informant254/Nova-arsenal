"""
CVE variant / patch-gap analysis.

Given known CVEs and a target's services, hypothesizes *sibling* bugs:
same class, adjacent components, incomplete patches, or shared parsers.
This is a primary industrial technique for finding 0-days adjacent to N-days.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


# Bug-class templates used to expand a known CVE into nearby research angles.
_VARIANT_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
    "path_traversal": [
        {
            "title": "Alternate encoding path traversal",
            "hypothesis": "Incomplete normalization may allow %2e%2e / UTF-8 overlong / mixed-separator traversal",
            "tests": ["..%2f", "..%5c", "%2e%2e%2f", "....//", "..;/", "%c0%ae%c0%ae/"],
            "severity": "high",
            "class": "path_traversal",
        },
        {
            "title": "Symlink / junction follow after path check",
            "hypothesis": "TOCTOU between path validation and open may follow symlinks outside root",
            "tests": ["symlink-race", "hardlink-alias"],
            "severity": "high",
            "class": "path_traversal",
        },
    ],
    "rce": [
        {
            "title": "Secondary injection after partial fix",
            "hypothesis": "Patch may block one sink but leave adjacent command/template sinks open",
            "tests": ["command-chaining", "template-injection", "argument-injection"],
            "severity": "critical",
            "class": "rce",
        },
        {
            "title": "Deserialization gadget chain residual",
            "hypothesis": "Blocklist-based deserialization fixes often miss new gadget chains",
            "tests": ["gadget-enum", "type-confusion"],
            "severity": "critical",
            "class": "rce",
        },
    ],
    "auth_bypass": [
        {
            "title": "Alternate auth path bypass",
            "hypothesis": "Fix on primary login may not cover SSO, API keys, or legacy endpoints",
            "tests": ["alt-login", "header-spoof", "verb-tamper", "path-normalization"],
            "severity": "critical",
            "class": "auth_bypass",
        },
    ],
    "ssrf": [
        {
            "title": "SSRF via redirect / DNS rebinding",
            "hypothesis": "URL allowlists often fail on redirects, IPv6, or DNS rebinding",
            "tests": ["redirect-chain", "dns-rebind", "ipv6-mapped", "decimal-ip"],
            "severity": "high",
            "class": "ssrf",
        },
    ],
    "sqli": [
        {
            "title": "Second-order / ORM-edge SQL injection",
            "hypothesis": "Parameterized primary queries may still concatenate in reports/exports",
            "tests": ["second-order", "order-by", "limit-offset", "json-extract"],
            "severity": "high",
            "class": "sqli",
        },
    ],
    "xss": [
        {
            "title": "Mutation / DOM XSS residual",
            "hypothesis": "Server-side encoding fixes often leave client-side sinks or mXSS paths",
            "tests": ["dom-sink", "mutation-xss", "svg-script", "template-literal"],
            "severity": "medium",
            "class": "xss",
        },
    ],
    "memory_corruption": [
        {
            "title": "Adjacent parser overflow / UAF",
            "hypothesis": "A fixed buffer issue often coexists with related integer/overflow bugs in same parser",
            "tests": ["length-field-overflow", "chunked-truncation", "uaf-after-error"],
            "severity": "critical",
            "class": "memory_corruption",
        },
    ],
    "privilege_escalation": [
        {
            "title": "Incomplete privilege boundary",
            "hypothesis": "Patch may close one privileged RPC while sibling methods remain under-checked",
            "tests": ["method-enum", "id-oracle", "role-confusion"],
            "severity": "high",
            "class": "privilege_escalation",
        },
    ],
}

_CLASS_KEYWORDS: List[tuple[str, tuple[str, ...]]] = [
    ("path_traversal", ("path traversal", "directory traversal", "lfi", "arbitrary file")),
    ("rce", ("remote code", "rce", "command injection", "code execution", "os command")),
    ("auth_bypass", ("authentication bypass", "auth bypass", "broken auth", "improper auth")),
    ("ssrf", ("ssrf", "server-side request")),
    ("sqli", ("sql injection", "sqli")),
    ("xss", ("cross-site scripting", "xss")),
    ("memory_corruption", ("buffer overflow", "use after free", "uaf", "heap overflow", "out-of-bounds")),
    ("privilege_escalation", ("privilege escalation", "privesc", "elevation of privilege")),
]


@dataclass
class VariantHypothesis:
    """A research hypothesis derived from a known CVE or bug class."""

    source_cve: str
    bug_class: str
    title: str
    hypothesis: str
    target_service: str
    severity: str
    test_ideas: List[str] = field(default_factory=list)
    confidence: float = 0.5
    related_components: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_cve": self.source_cve,
            "bug_class": self.bug_class,
            "title": self.title,
            "hypothesis": self.hypothesis,
            "target_service": self.target_service,
            "severity": self.severity,
            "test_ideas": self.test_ideas,
            "confidence": round(self.confidence, 3),
            "related_components": self.related_components,
            "notes": self.notes,
        }


class VariantAnalyzer:
    """Expand known CVEs into variant / patch-gap research plans."""

    def classify(self, text: str) -> List[str]:
        text_l = (text or "").lower()
        classes: List[str] = []
        for cls, kws in _CLASS_KEYWORDS:
            if any(k in text_l for k in kws):
                classes.append(cls)
        return classes or ["unknown"]

    def analyze(
        self,
        cves: Sequence[Dict[str, Any]],
        services: Optional[Dict[str, Any]] = None,
        max_hypotheses: int = 50,
    ) -> List[VariantHypothesis]:
        services = services or {}
        service_names = {str(k).lower() for k in services.keys()} or {"generic"}
        hypotheses: List[VariantHypothesis] = []

        for cve in cves:
            cve_id = str(cve.get("cve_id") or cve.get("id") or "UNKNOWN")
            desc = str(cve.get("description") or cve.get("title") or "")
            sev = str(cve.get("severity") or "medium").lower()
            classes = self.classify(desc + " " + str(cve.get("title") or ""))
            affected = str(cve.get("affected_versions") or cve.get("service") or "")

            for cls in classes:
                templates = _VARIANT_TEMPLATES.get(cls, [])
                if not templates and cls == "unknown":
                    templates = [
                        {
                            "title": "General incomplete-patch residual",
                            "hypothesis": "Re-test original sink and sibling code paths after vendor patch",
                            "tests": ["regression-suite", "diff-review"],
                            "severity": sev,
                            "class": "unknown",
                        }
                    ]
                for tmpl in templates:
                    for svc in list(service_names)[:5]:
                        conf = 0.45
                        if svc in desc.lower() or svc in affected.lower():
                            conf += 0.25
                        if sev in {"critical", "high"}:
                            conf += 0.1
                        if cls != "unknown":
                            conf += 0.1
                        hypotheses.append(
                            VariantHypothesis(
                                source_cve=cve_id,
                                bug_class=tmpl.get("class", cls),
                                title=tmpl["title"],
                                hypothesis=tmpl["hypothesis"],
                                target_service=svc,
                                severity=tmpl.get("severity", sev),
                                test_ideas=list(tmpl.get("tests") or []),
                                confidence=min(0.95, conf),
                                related_components=self._extract_components(desc),
                                notes=f"Derived from {cve_id} class={cls}",
                            )
                        )

        # Dedup by (source, title, service)
        seen: set = set()
        unique: List[VariantHypothesis] = []
        for h in sorted(hypotheses, key=lambda x: x.confidence, reverse=True):
            key = (h.source_cve, h.title, h.target_service)
            if key in seen:
                continue
            seen.add(key)
            unique.append(h)
            if len(unique) >= max_hypotheses:
                break

        logger.info("Variant analysis produced %d hypotheses from %d CVEs", len(unique), len(cves))
        return unique

    async def analyze_async(self, *args: Any, **kwargs: Any) -> List[VariantHypothesis]:
        return self.analyze(*args, **kwargs)

    def _extract_components(self, text: str) -> List[str]:
        # Lightweight: product-like tokens and module paths
        comps = re.findall(r"\b(?:mod_|lib|module|plugin|handler|parser|servlet)[\w.-]+\b", text, re.I)
        products = re.findall(r"\b[A-Z][A-Za-z0-9.+-]{2,20}\b", text)
        return list(dict.fromkeys([*comps, *products]))[:10]
