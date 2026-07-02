"""
TryHackMe Platform Connector
==============================

Implements PlatformConnector against TryHackMe.

HONEST LIMITATION: unlike HackerOne, Bugcrowd, and HackTheBox, TryHackMe
does not publish an official public API. This connector uses their
internal web endpoints (the same ones the site's own frontend calls),
authenticated via your browser session cookie.

This means:
  - It can break without notice if TryHackMe changes their frontend.
  - It requires a session cookie (from your logged-in browser), not a
    clean API token — copy the "connect.sid" cookie value from your
    browser's dev tools after logging in.
  - This is inherently less stable than the other three connectors.
    If TryHackMe ships an official API in the future, this connector
    should be rewritten against it.

We're shipping it anyway because the value (reasoning about THM rooms
alongside HTB/bounty targets) outweighs the fragility, but this comment
block is here so nobody is surprised when it needs maintenance.
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


THM_BASE = "https://tryhackme.com/api/v2"


class TryHackMeConnector(PlatformConnector):
    platform_name = "tryhackme"
    platform_kind = PlatformKind.LAB

    def __init__(self, credentials: dict[str, str]):
        super().__init__(credentials)
        if httpx is None:
            raise RuntimeError(
                "httpx is required for the TryHackMe connector. "
                "Install it with: pip install httpx"
            )
        self._cookie = credentials.get("session_cookie", "")
        self._client = httpx.Client(
            base_url=THM_BASE,
            timeout=20.0,
            headers={"Accept": "application/json"},
            cookies={"connect.sid": self._cookie},
        )

    def health_check(self) -> bool:
        try:
            r = self._client.get("/user/me")
            return r.status_code == 200
        except Exception:
            return False

    def list_targets(self, limit: int = 50) -> list[Target]:
        """
        Lists active/popular rooms. Uses the same unofficial endpoint the
        TryHackMe web app calls to populate its room browser — see module
        docstring for why this is more fragile than the other connectors.
        """
        targets: list[Target] = []
        try:
            r = self._client.get(
                "/rooms",
                params={"limit": min(limit, 100), "sort": "trending"},
            )
            r.raise_for_status()
            rooms = r.json().get("rooms", r.json().get("data", []))
        except Exception as e:
            print(f"  [!] TryHackMe list_targets failed: {e}")
            print("      (this connector relies on an unofficial endpoint — see connector.py docstring)")
            return targets

        for room in rooms[:limit]:
            difficulty = self._normalize_difficulty(room.get("difficulty", ""))
            code = room.get("code", room.get("id", "unknown"))
            targets.append(
                Target(
                    id=str(code),
                    platform=self.platform_name,
                    kind=PlatformKind.LAB,
                    name=room.get("title", room.get("name", "unknown")),
                    url=f"https://tryhackme.com/room/{code}",
                    scope_summary=room.get("description", "")[:200],
                    tags=room.get("tags", []),
                    difficulty=difficulty,
                    asset_types=["network"],
                    raw=room,
                )
            )
        return targets

    def get_target_detail(self, target_id: str) -> Target:
        try:
            r = self._client.get(f"/rooms/{target_id}")
            r.raise_for_status()
            room = r.json().get("room", r.json())
        except Exception as e:
            raise RuntimeError(f"TryHackMe get_target_detail failed for {target_id}: {e}") from e

        difficulty = self._normalize_difficulty(room.get("difficulty", ""))
        return Target(
            id=str(room.get("code", target_id)),
            platform=self.platform_name,
            kind=PlatformKind.LAB,
            name=room.get("title", room.get("name", "unknown")),
            url=f"https://tryhackme.com/room/{room.get('code', target_id)}",
            scope_summary=room.get("description", "")[:500],
            tags=room.get("tags", []),
            difficulty=difficulty,
            asset_types=["network"],
            raw=room,
        )

    def submit_finding(self, target_id: str, finding: dict[str, Any]) -> dict[str, Any]:
        """THM findings are flag submissions, same category as HTB."""
        flag = finding.get("flag")
        if not flag:
            raise ValueError("finding dict must include a 'flag' key for TryHackMe submission")
        try:
            r = self._client.post(
                f"/rooms/{target_id}/answer",
                json={"answer": flag, "questionNo": finding.get("question_no", 1)},
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def _normalize_difficulty(text: str) -> str:
        t = str(text).lower()
        if "easy" in t or t == "1":
            return "easy"
        if "medium" in t or t == "2":
            return "medium"
        if "hard" in t or t == "3":
            return "hard"
        if "insane" in t:
            return "insane"
        return "unknown"
