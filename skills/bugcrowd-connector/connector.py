"""
Bugcrowd Platform Connector
==============================

Implements PlatformConnector against Bugcrowd's public API.

Auth: Bugcrowd uses a Bearer API token generated from
Account Settings -> API Credentials (https://bugcrowd.com/user/edit).

Docs: https://docs.bugcrowd.com/api/getting-started/
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from platform_connector import PlatformConnector, PlatformKind, Target  # noqa: E402

try:
    import httpx
except ImportError:
    httpx = None


BUGCROWD_API_BASE = "https://api.bugcrowd.com"
BUGCROWD_API_VERSION = "application/vnd.bugcrowd+json"


class BugcrowdConnector(PlatformConnector):
    platform_name = "bugcrowd"
    platform_kind = PlatformKind.BUG_BOUNTY

    def __init__(self, credentials: dict[str, str]):
        super().__init__(credentials)
        if httpx is None:
            raise RuntimeError(
                "httpx is required for the Bugcrowd connector. "
                "Install it with: pip install httpx"
            )
        self._token = credentials.get("api_token", "")
        self._client = httpx.Client(
            base_url=BUGCROWD_API_BASE,
            timeout=20.0,
            headers={
                "Authorization": f"Token {self._token}",
                "Accept": BUGCROWD_API_VERSION,
            },
        )

    def health_check(self) -> bool:
        try:
            r = self._client.get("/user")
            return r.status_code == 200
        except Exception:
            return False

    def list_targets(self, limit: int = 50) -> list[Target]:
        """
        Lists engagements (Bugcrowd's term for programs) visible to the
        authenticated researcher. Private programs only show up once
        you've been invited — same limitation as HackerOne's connector.
        """
        targets: list[Target] = []
        try:
            r = self._client.get("/engagements", params={"page[limit]": min(limit, 100)})
            r.raise_for_status()
            data = r.json().get("data", [])
        except Exception as e:
            print(f"  [!] Bugcrowd list_targets failed: {e}")
            return targets

        for item in data:
            attrs = item.get("attributes", {})
            code = attrs.get("code", item.get("id", "unknown"))
            reward_range = attrs.get("reward_range", {}) or {}

            targets.append(
                Target(
                    id=str(item.get("id", code)),
                    platform=self.platform_name,
                    kind=PlatformKind.BUG_BOUNTY,
                    name=attrs.get("name", code),
                    url=f"https://bugcrowd.com/{code}",
                    scope_summary=attrs.get("summary", ""),
                    tags=["bounty"] if reward_range.get("max") else ["vdp"],
                    max_reward_usd=reward_range.get("max"),
                    raw=item,
                )
            )
        return targets

    def get_target_detail(self, target_id: str) -> Target:
        try:
            r = self._client.get(f"/engagements/{target_id}")
            r.raise_for_status()
            item = r.json().get("data", {})
        except Exception as e:
            raise RuntimeError(f"Bugcrowd get_target_detail failed for {target_id}: {e}") from e

        attrs = item.get("attributes", {})
        code = attrs.get("code", target_id)
        reward_range = attrs.get("reward_range", {}) or {}

        # Bugcrowd exposes scope via a separate /engagements/{id}/scopes call
        asset_types: list[str] = []
        scope_lines: list[str] = []
        try:
            scope_r = self._client.get(f"/engagements/{target_id}/scopes")
            scope_r.raise_for_status()
            scope_data = scope_r.json().get("data", [])
            for s in scope_data:
                s_attrs = s.get("attributes", {})
                asset_types.append(s_attrs.get("target_type", "unknown"))
                scope_lines.append(s_attrs.get("name", ""))
        except Exception:
            pass  # scope endpoint is best-effort; don't fail the whole detail call

        return Target(
            id=str(item.get("id", target_id)),
            platform=self.platform_name,
            kind=PlatformKind.BUG_BOUNTY,
            name=attrs.get("name", code),
            url=f"https://bugcrowd.com/{code}",
            scope_summary="; ".join(scope_lines[:10]),
            tags=["bounty"] if reward_range.get("max") else ["vdp"],
            max_reward_usd=reward_range.get("max"),
            asset_types=sorted(set(asset_types)),
            raw=item,
        )

    def submit_finding(self, target_id: str, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Same boundary as every other bug bounty connector in this repo:
        Nova drafts, a human submits. Bugcrowd's submission API requires a
        fully-formed report (title, description, vrt_id, severity) and
        program-specific submission permissions — left unimplemented on
        purpose, not because it's technically hard.
        """
        raise NotImplementedError(
            "Automated report submission is disabled by design. "
            "Nova drafts the report; a human reviews and submits it via "
            "https://bugcrowd.com to keep a person accountable for every disclosure."
        )
