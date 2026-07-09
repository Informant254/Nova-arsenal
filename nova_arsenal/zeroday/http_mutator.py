"""
Lightweight HTTP protocol mutator for parser / edge-case research.

Sends constrained mutations against an authorized target. Default is dry-run
(plan only) unless --execute is passed. Not an exploit generator.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class MutationResult:
    mutation: str
    status: str
    detail: str = ""
    elapsed_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mutation": self.mutation,
            "status": self.status,
            "detail": self.detail[:300],
            "elapsed_ms": round(self.elapsed_ms, 2),
        }


# Research-oriented mutation *descriptions* and request shapes (not weaponized payloads).
_MUTATIONS: List[Dict[str, Any]] = [
    {"name": "duplicate_content_length", "headers": {"Content-Length": "0", "Content-Length ": "5"}},
    {"name": "tab_in_header_name", "headers": {"X-Test\tName": "1"}},
    {"name": "obs_fold_hint", "headers": {"X-Fold": "start\r\n folded"}},
    {"name": "absolute_form_path", "path_suffix": ""},
    {"name": "double_slash_path", "path_suffix": "//"},
    {"name": "encoded_slash", "path_suffix": "/%2e%2e/"},
    {"name": "long_method", "method": "A" * 64},
    {"name": "chunked_and_cl", "headers": {"Transfer-Encoding": "chunked", "Content-Length": "4"}},
    {"name": "unicode_path", "path_suffix": "/%c0%ae%c0%ae/"},
    {"name": "null_in_query", "query": "a=1%00b=2"},
]


class HttpMutator:
    """Plan or execute HTTP edge-case mutations for parser research."""

    def __init__(self, max_requests: int = 100) -> None:
        self.max_requests = max_requests

    def plan(self, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        base_path = parsed.path or "/"
        plans = []
        for i, mut in enumerate(_MUTATIONS):
            if i >= self.max_requests:
                break
            plans.append(
                {
                    "name": mut["name"],
                    "url": url,
                    "method": mut.get("method", "GET"),
                    "path": base_path + mut.get("path_suffix", ""),
                    "headers": mut.get("headers", {}),
                    "query": mut.get("query", ""),
                }
            )
        return plans

    async def run(
        self,
        url: str,
        execute: bool = False,
        timeout: float = 3.0,
    ) -> List[MutationResult]:
        plans = self.plan(url)
        if not execute:
            return [
                MutationResult(mutation=p["name"], status="planned", detail=json.dumps(p)[:200])
                for p in plans
            ]

        try:
            import httpx
        except ImportError:
            return [
                MutationResult(
                    mutation="all",
                    status="error",
                    detail="httpx not installed; run with execute=False for plan-only",
                )
            ]

        results: List[MutationResult] = []
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
            for p in plans:
                t0 = time.perf_counter()
                try:
                    # Only send relatively safe GET-like probes; skip grotesque methods on execute
                    method = p["method"] if len(p["method"]) <= 16 else "GET"
                    headers = {k: v for k, v in p.get("headers", {}).items() if "\r" not in k and "\n" not in k}
                    r = await client.request(method, url, headers=headers)
                    results.append(
                        MutationResult(
                            mutation=p["name"],
                            status=f"http_{r.status_code}",
                            detail=f"len={len(r.content)}",
                            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    results.append(
                        MutationResult(
                            mutation=p["name"],
                            status="error",
                            detail=str(exc),
                            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
                        )
                    )
        return results


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Nova HTTP mutator (authorized testing only)")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--out", default="./fuzz_out", help="Output directory (reserved)")
    parser.add_argument("--max-requests", type=int, default=50)
    parser.add_argument("--execute", action="store_true", help="Actually send requests")
    parser.add_argument("--authorized", action="store_true", help="Confirm authorization")
    args = parser.parse_args(argv)

    if args.execute and not args.authorized:
        print(json.dumps({"error": "Refusing to execute without --authorized"}))
        return 2

    mutator = HttpMutator(max_requests=args.max_requests)
    results = asyncio.run(mutator.run(args.url, execute=args.execute and args.authorized))
    print(json.dumps([r.to_dict() for r in results], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
