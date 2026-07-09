"""
Novelty scoring: separate known-CVE noise from candidate novel findings.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set

logger = logging.getLogger(__name__)


# Well-known CVE / exploit keywords that reduce novelty if they dominate the finding.
_KNOWN_BUG_MARKERS = {
    "eternalblue": "CVE-2017-0144",
    "ms17-010": "CVE-2017-0144",
    "bluekeep": "CVE-2019-0708",
    "log4shell": "CVE-2021-44228",
    "log4j": "CVE-2021-44228",
    "heartbleed": "CVE-2014-0160",
    "shellshock": "CVE-2014-6271",
    "zerologon": "CVE-2020-1472",
    "printnightmare": "CVE-2021-34527",
    "proxyshell": "CVE-2021-34473",
    "proxylogon": "CVE-2021-26855",
    "regresshion": "CVE-2024-6387",
    "spring4shell": "CVE-2022-22965",
    "ghostcat": "CVE-2020-1938",
}

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


@dataclass
class NoveltyAssessment:
    """How novel a candidate appears relative to public knowledge."""

    score: float  # 0..1 (1 = highly novel / unknown)
    label: str
    matched_known: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 3),
            "label": self.label,
            "matched_known": self.matched_known,
            "reasons": self.reasons,
        }


class NoveltyScorer:
    """
    Score whether a finding looks like a known issue vs a novel candidate.

    High novelty does NOT prove a zero-day — it only means public fingerprint
    match is weak and the item deserves deeper validation.
    """

    def __init__(self, known_cve_ids: Optional[Set[str]] = None) -> None:
        self.known_cve_ids = {c.upper() for c in (known_cve_ids or set())}

    def assess(
        self,
        title: str = "",
        description: str = "",
        evidence: str = "",
        bug_class: str = "",
        extra_cves: Optional[Sequence[str]] = None,
    ) -> NoveltyAssessment:
        text = f"{title}\n{description}\n{evidence}\n{bug_class}".lower()
        matched: List[str] = []
        reasons: List[str] = []
        score = 0.75  # start leaning novel until known markers found

        for marker, cve in _KNOWN_BUG_MARKERS.items():
            if marker in text:
                matched.append(cve)
                score -= 0.25
                reasons.append(f"Matched known exploit family '{marker}' → {cve}")

        for cve in _CVE_ID_RE.findall(f"{title} {description} {evidence}"):
            cve_u = cve.upper()
            matched.append(cve_u)
            score -= 0.2
            reasons.append(f"Explicit CVE reference {cve_u}")
            if cve_u in self.known_cve_ids:
                score -= 0.1

        for cve in extra_cves or []:
            matched.append(str(cve).upper())
            score -= 0.15

        # Boost novelty for sanitizer crashes / variant language without CVE ids
        if any(k in text for k in ("use-after-free", "heap-buffer", "asan", "variant", "patch gap")):
            if not matched:
                score += 0.1
                reasons.append("Crash/variant language without known CVE fingerprint")

        if "nuclei" in text and matched:
            score -= 0.1
            reasons.append("Template scanner hit usually indicates known issue")

        score = max(0.0, min(1.0, score))
        if score >= 0.75:
            label = "likely_novel_candidate"
        elif score >= 0.45:
            label = "possibly_novel_or_variant"
        elif score >= 0.25:
            label = "likely_known_issue"
        else:
            label = "known_public_issue"

        if not reasons:
            reasons.append("No strong public fingerprint match")

        return NoveltyAssessment(
            score=score,
            label=label,
            matched_known=list(dict.fromkeys(matched)),
            reasons=reasons,
        )
