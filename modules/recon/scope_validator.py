"""
Nova Arsenal — Scope Validator Module
Validates targets against the structured scope map (targets_scope_map.json).
Prevents accidental out-of-scope testing.
"""

import fnmatch
import json
from typing import Optional
from pathlib import Path


class ScopeValidator:
    def __init__(self, scope_map: dict):
        self.programs = scope_map.get("programs", {})

    @classmethod
    def from_file(cls, path: str = "targets_scope_map.json"):
        with open(path) as f:
            return cls(json.load(f))

    def check(self, target: str, program: Optional[str] = None) -> dict:
        """
        Returns {"in_scope": bool, "reason": str, "program": str|None}
        """
        programs_to_check = (
            {program: self.programs[program]}
            if program and program in self.programs
            else self.programs
        )

        for prog_name, prog in programs_to_check.items():
            if not prog.get("authorized", True):
                continue

            # Check out-of-scope first
            for pattern in prog.get("out_of_scope", []):
                if fnmatch.fnmatch(target, pattern) or target == pattern:
                    return {
                        "in_scope": False,
                        "reason": f"explicitly out-of-scope for {prog_name}",
                        "program": prog_name,
                    }

            # Check wildcards
            for pattern in prog.get("in_scope_wildcards", []):
                if fnmatch.fnmatch(target, pattern):
                    return {
                        "in_scope": True,
                        "reason": f"matches wildcard {pattern} in {prog_name}",
                        "program": prog_name,
                    }

            # Check explicit
            for explicit in prog.get("in_scope_explicit", []):
                if target == explicit or target.endswith("." + explicit):
                    return {
                        "in_scope": True,
                        "reason": f"explicit scope match in {prog_name}",
                        "program": prog_name,
                    }

        return {
            "in_scope": False,
            "reason": "no matching program scope found",
            "program": None,
        }

    def list_programs(self):
        for name, prog in self.programs.items():
            status = "✓ bounty" if prog.get("bounty") else "— no bounty"
            auth = "" if prog.get("authorized", True) else " [NO AUTH]"
            print(f"  • {name} ({prog['platform']}) {status}{auth}")
            print(f"    {prog['url']}")
