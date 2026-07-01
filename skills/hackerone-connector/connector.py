"""
HackerOne Platform Connector
==============================

Implements PlatformConnector against HackerOne's public Hacker API v1.

Auth: HackerOne uses HTTP Basic Auth with your API username + API token,
both generated from your HackerOne account settings under
"API Token" (https://hackerone.com/settings/api_token/edit).

Docs: https://api.hackerone.com/docs/v1
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Allow importing the shared base interface when run inside Nova's skill loader
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from platform_connector import PlatformConnector, PlatformKind, Target  # noqa: E402

try:
    import httpx
except ImportError:
    httpx = None  # validated at instantiation time


H1_API_BASE = "https://api.hackerone.com/v1"


class HackerOneConnector(PlatformConnector):
    platform_name = "hackerone"
    platform_kind = PlatformKind.BUG_BOUNTY

    def __init__(self, credentials: dict[str, str]):
        super().__init__(credentials)
        if httpx is None:
            raise RuntimeError(
                "httpx is required for the HackerOne connector. "
                "Install it with: pip install httpx"
            )
        self._username = credentials.get("api_username", "")
        self._token = credentials.get("api_token", "")
        self._client = httpx.Client(
            base_url=H1_API_BASE,
            auth=(self._username, self._token),
            timeout=20.0,
            headers={"Accept": "application/json"},
        )

    def health_check(self) -> bool:
        try:
            r = self._client.get("/me")
            return r.status_code == 200
        except Exception:
            return False

    def list_targets(self, limit: int = 50) -> list[Target]:
        """
        Lists publicly disclosed/active bug bounty programs.
        Note: HackerOne's API exposes structured program data primarily
        for programs you're invited to or that are fully public — for
        broader discovery, combine this with the public directory at
        hackerone.com/directory (not API-accessible without scraping,
        which Nova does not do).
        """
        targets: list[Target] = []
        try:
            r = self._client.get("/hackers/programs", params={"page[size]": min(limit, 100)})
            r.raise_for_status()
            data = r.json().get("data", [])
        except Exception as e:
            print(f"  [!] HackerOne list_targets failed: {e}")
            return targets

        for item in data:
            attrs = item.get("attributes", {})
            handle = attrs.get("handle", item.get("id", "unknown"))
            offers_bounties = attrs.get("offers_bounties", False)

            targets.append(
                Target(
                    id=str(item.get("id", handle)),
                    platform=self.platform_name,
                    kind=PlatformKind.BUG_BOUNTY,
                    name=attrs.get("name", handle),
                    url=f"https://hackerone.com/{handle}",
                    scope_summary=attrs.get("profile_picture", ""),  # populated fully in get_target_detail
                    tags=["bounty"] if offers_bounties else ["vdp"],
                    max_reward_usd=None,  # requires detail call — H1 doesn't expose this on list
                    raw=item,
                )
            )
        return targets

    def get_target_detail(self, target_id: str) -> Target:
        try:
            r = self._client.get(f"/hackers/programs/{target_id}")
            r.raise_for_status()
            item = r.json().get("data", {})
        except Exception as e:
            raise RuntimeError(f"HackerOne get_target_detail failed for {target_id}: {e}") from e

        attrs = item.get("attributes", {})
        handle = attrs.get("handle", target_id)

        structured_scopes = item.get("relationships", {}).get(
            "structured_scopes", {}
        ).get("data", [])
        asset_types = sorted({
            s.get("attributes", {}).get("asset_type", "unknown")
            for s in structured_scopes
        })
        scope_lines = [
            s.get("attributes", {}).get("asset_identifier", "")
            for s in structured_scopes
        ]

        return Target(
            id=str(item.get("id", target_id)),
            platform=self.platform_name,
            kind=PlatformKind.BUG_BOUNTY,
            name=attrs.get("name", handle),
            url=f"https://hackerone.com/{handle}",
            scope_summary="; ".join(scope_lines[:10]),
            tags=["bounty"] if attrs.get("offers_bounties") else ["vdp"],
            asset_types=asset_types,
            raw=item,
        )

    def submit_finding(self, target_id: str, finding: dict[str, Any]) -> dict[str, Any]:
        """
        HackerOne supports report submission via API but it requires
        program-specific permission and a fully-formed report payload
        (title, vulnerability_information, severity, impact, weakness_id).
        Left intentionally unimplemented here — submitting reports
        autonomously without human review is a deliberate safety boundary,
        not a missing feature.
        """
        raise NotImplementedError(
            "Automated report submission is disabled by design. "
            "Nova drafts the report; a human reviews and submits it via "
            "https://hackerone.com to keep a person accountable for every disclosure."
        )
