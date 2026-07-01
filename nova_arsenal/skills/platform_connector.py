"""
Nova Arsenal — Platform Connector Base Interface
===================================================

Every platform skill (HackerOne, Bugcrowd, HackTheBox, TryHackMe, ...)
implements PlatformConnector so Nova's reasoning layer can treat them
uniformly — list available targets, get details, and (where applicable)
submit findings — regardless of which platform they came from.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class PlatformKind(str, Enum):
    BUG_BOUNTY = "bug_bounty"
    CTF = "ctf"
    LAB = "lab"  # HackTheBox/TryHackMe style ongoing machines/rooms


@dataclass
class Target:
    """
    Unified representation of something Nova could choose to work on,
    regardless of which platform it came from.
    """
    id: str
    platform: str                 # "hackerone" | "bugcrowd" | "hackthebox" | "tryhackme"
    kind: PlatformKind
    name: str
    url: str
    scope_summary: str = ""
    tags: list[str] = field(default_factory=list)
    difficulty: Optional[str] = None          # easy/medium/hard/insane (labs/ctf)
    max_reward_usd: Optional[float] = None    # bug bounty only
    asset_types: list[str] = field(default_factory=list)  # web, api, mobile, network...
    last_updated: Optional[datetime] = None
    raw: dict[str, Any] = field(default_factory=dict)  # original platform payload


@dataclass
class TargetScore:
    """Nova's reasoning output for why a target is/isn't worth pursuing."""
    target: Target
    score: float                 # 0.0 - 1.0, higher = more worth pursuing
    reasoning: str
    matched_strengths: list[str] = field(default_factory=list)  # Nova modules that fit
    estimated_effort: str = "unknown"  # low/medium/high


class PlatformConnector(ABC):
    """
    Base class every platform skill must implement.

    credentials: dict supplied at load time from the skill's
    requires_credentials list in skill.json.
    """

    platform_name: str = "unknown"
    platform_kind: PlatformKind = PlatformKind.BUG_BOUNTY

    def __init__(self, credentials: dict[str, str]):
        self.credentials = credentials

    @abstractmethod
    def list_targets(self, limit: int = 50) -> list[Target]:
        """Return available targets/programs/rooms from this platform."""
        raise NotImplementedError

    @abstractmethod
    def get_target_detail(self, target_id: str) -> Target:
        """Fetch full detail (scope, rules, rewards) for a single target."""
        raise NotImplementedError

    def submit_finding(self, target_id: str, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Optional — not all platforms support programmatic submission.
        Override where the platform API allows it.
        """
        raise NotImplementedError(
            f"{self.platform_name} connector does not support automated submission. "
            "Submit manually via the platform UI."
        )

    def health_check(self) -> bool:
        """Override to do a lightweight auth check. Default assumes OK."""
        return True


class TargetReasoner:
    """
    Nova's "which target is worth my time" reasoning layer.

    This is intentionally simple/heuristic by default — in production this
    scoring is handed to the LLM router (multi_router.py) with the
    candidate targets + Nova's known module strengths as context, and the
    LLM produces the TargetScore.reasoning text. The heuristic version
    here is the deterministic fallback when no LLM is available.
    """

    # Maps asset/tag keywords to Nova's strongest module categories
    STRENGTH_MAP = {
        "web": ["nova_attack.py", "burp_api.py", "sqlmap_api.py"],
        "api": ["sqlmap_api.py", "burp_api.py"],
        "network": ["nova_recon.py", "msf_rpc.py"],
        "smb": ["msf_rpc.py", "nova_idor_scanner.py"],
        "active_directory": ["msf_rpc.py"],
        "mobile": [],  # honest gap — Nova has no dedicated mobile module yet
        "cloud": [],   # honest gap
    }

    def score(self, target: Target) -> TargetScore:
        matched = []
        score = 0.3  # baseline

        haystack = " ".join([target.name, target.scope_summary, *target.tags, *target.asset_types]).lower()

        for keyword, modules in self.STRENGTH_MAP.items():
            if keyword in haystack:
                if modules:
                    score += 0.15
                    matched.extend(modules)
                else:
                    score -= 0.1  # known gap area, be honest about lower confidence

        if target.max_reward_usd:
            if target.max_reward_usd >= 5000:
                score += 0.2
            elif target.max_reward_usd >= 1000:
                score += 0.1

        if target.difficulty in ("easy", "medium"):
            score += 0.1
        elif target.difficulty == "insane":
            score -= 0.1

        score = max(0.0, min(1.0, score))

        if matched:
            reasoning = (
                f"Target touches {', '.join(sorted(set(matched)))} — "
                f"strong match for Nova's existing toolset."
            )
        else:
            reasoning = (
                "No strong module match detected for this target's asset types. "
                "Nova would need broader recon before committing effort here."
            )

        effort = "low" if score >= 0.7 else "medium" if score >= 0.4 else "high"

        return TargetScore(
            target=target,
            score=round(score, 2),
            reasoning=reasoning,
            matched_strengths=sorted(set(matched)),
            estimated_effort=effort,
        )

    def rank(self, targets: list[Target]) -> list[TargetScore]:
        scored = [self.score(t) for t in targets]
        return sorted(scored, key=lambda s: s.score, reverse=True)
