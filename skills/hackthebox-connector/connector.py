"""
HackTheBox Platform Connector
================================

Implements PlatformConnector against the HackTheBox public API.

Auth: HTB uses an "App Token" generated from
Account Settings -> App Tokens (https://app.hackthebox.com/profile/settings).

Docs: https://documenter.getpostman.com/view/13129365/TVeqbmgw
(community-documented; HTB does not publish an official OpenAPI spec)
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


HTB_API_BASE = "https://www.hackthebox.com/api/v4"


class HackTheBoxConnector(PlatformConnector):
    platform_name = "hackthebox"
    platform_kind = PlatformKind.LAB

    def __init__(self, credentials: dict[str, str]):
        super().__init__(credentials)
        if httpx is None:
            raise RuntimeError(
                "httpx is required for the HackTheBox connector. "
                "Install it with: pip install httpx"
            )
        self._token = credentials.get("app_token", "")
        self._client = httpx.Client(
            base_url=HTB_API_BASE,
            timeout=20.0,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json",
            },
        )

    def health_check(self) -> bool:
        try:
            r = self._client.get("/user/info")
            return r.status_code == 200
        except Exception:
            return False

    def list_targets(self, limit: int = 50) -> list[Target]:
        """Lists currently active machines. Retired machines are excluded by
        default since they require VIP and aren't meaningful 'next target'
        candidates for an autonomous agent deciding what's worth attempting."""
        targets: list[Target] = []
        try:
            r = self._client.get("/machine/list")
            r.raise_for_status()
            machines = r.json().get("info", [])
        except Exception as e:
            print(f"  [!] HackTheBox list_targets failed: {e}")
            return targets

        for m in machines[:limit]:
            difficulty = self._normalize_difficulty(m.get("difficultyText", ""))
            targets.append(
                Target(
                    id=str(m.get("id")),
                    platform=self.platform_name,
                    kind=PlatformKind.LAB,
                    name=m.get("name", "unknown"),
                    url=f"https://app.hackthebox.com/machines/{m.get('id')}",
                    scope_summary=f"OS: {m.get('os', 'unknown')}",
                    tags=[m.get("os", "unknown").lower()],
                    difficulty=difficulty,
                    asset_types=["network", m.get("os", "").lower()],
                    raw=m,
                )
            )
        return targets

    def get_target_detail(self, target_id: str) -> Target:
        try:
            r = self._client.get(f"/machine/profile/{target_id}")
            r.raise_for_status()
            m = r.json().get("info", {})
        except Exception as e:
            raise RuntimeError(f"HackTheBox get_target_detail failed for {target_id}: {e}") from e

        difficulty = self._normalize_difficulty(m.get("difficultyText", ""))
        return Target(
            id=str(m.get("id", target_id)),
            platform=self.platform_name,
            kind=PlatformKind.LAB,
            name=m.get("name", "unknown"),
            url=f"https://app.hackthebox.com/machines/{m.get('id', target_id)}",
            scope_summary=f"OS: {m.get('os', 'unknown')} | Points: {m.get('points', '?')}",
            tags=[m.get("os", "unknown").lower()],
            difficulty=difficulty,
            asset_types=["network", m.get("os", "").lower()],
            raw=m,
        )

    def submit_finding(self, target_id: str, finding: dict[str, Any]) -> dict[str, Any]:
        """HTB findings are flag submissions, not vulnerability reports."""
        flag = finding.get("flag")
        if not flag:
            raise ValueError("finding dict must include a 'flag' key for HTB submission")
        try:
            r = self._client.post(
                "/machine/own",
                json={"id": int(target_id), "flag": flag, "difficulty": finding.get("difficulty", 50)},
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def _normalize_difficulty(text: str) -> str:
        t = text.lower()
        if "easy" in t:
            return "easy"
        if "medium" in t:
            return "medium"
        if "hard" in t:
            return "hard"
        if "insane" in t:
            return "insane"
        return "unknown"
