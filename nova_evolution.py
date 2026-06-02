#!/usr/bin/env python3
"""Safe self-improvement entrypoint for Nova.

Self-evolution is disabled unless NOVA_ALLOW_EVOLUTION=true. When enabled it
routes the requested improvement through NovaCodeAgent so patches are validated
with git before they are applied and verification commands are recorded.
"""

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict

from nova_code_agent import NovaCodeAgent


def run(goal: str, repo: str = ".", test_command: str = "", allow: bool = False) -> Dict[str, Any]:
    enabled = allow or os.getenv("NOVA_ALLOW_EVOLUTION", "false").lower() == "true"
    if not enabled:
        return {
            "status": "blocked",
            "reason": "Set NOVA_ALLOW_EVOLUTION=true to allow self-improvement patches.",
            "goal": goal,
            "repo": str(Path(repo).resolve()),
        }
    task = f"Improve Nova safely: {goal}. Keep the patch minimal, tested, and reversible."
    return NovaCodeAgent(repo=repo, task=task, test_command=test_command, max_retries=1, allow_edits=True).run()


def main() -> int:
    parser = argparse.ArgumentParser(description="Nova safe self-improvement")
    parser.add_argument("--goal", required=True, help="Improvement goal")
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--test-command", default="", help="Verification command")
    parser.add_argument("--allow", action="store_true", help="Allow without NOVA_ALLOW_EVOLUTION=true")
    args = parser.parse_args()
    result = run(args.goal, args.repo, args.test_command, args.allow)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("status") != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
