"""
Nova Arsenal — CKA-Agent Adapter
Wraps CKA-Agent (ICML+ICLR 2026) trojan knowledge jailbreak framework.
CKA-Agent bypasses LLM safety guardrails by weaving harmless context
around adversarial goals — achieving >90% ASR on GPT-4, Claude, Gemini.

Source: cloned_repos/CKA-Agent/
Paper:  https://arxiv.org/abs/... (ICML 2026 / ICLR 2026)
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Optional


CKA_REPO = Path(__file__).parents[3] / "cloned_repos" / "CKA-Agent"
DEFAULT_CONFIG = CKA_REPO / "config" / "method" / "cka-agent.yml"

METHODS = {
    "cka-agent":           "CKA-Agent (flagship — trojan knowledge bypass)",
    "pair":                "PAIR (iterative refinement with judge model)",
    "autodan":             "AutoDAN (genetic algorithm token-level jailbreak)",
    "pap":                 "PAP (persuasion-based adversarial prompting)",
    "multi_agent":         "Multi-Agent Jailbreak (attacker + judge + target)",
    "actor_attack":        "Actor Attack (role-based indirect injection)",
    "x_teaming":           "X-Teaming (cross-model team jailbreak)",
}


class CKAAdapter:
    def __init__(self, cka_root: Optional[Path] = None):
        self.root = cka_root or CKA_REPO
        self.config_dir = self.root / "config"
        self.available = self.root.exists()

    def list_methods(self):
        print("\n[*] Available Jailbreak Methods:\n")
        for key, desc in METHODS.items():
            cfg = self.config_dir / "method" / f"{key}.yml"
            status = "✓" if cfg.exists() else "✗"
            print(f"  [{status}] {key:<20} — {desc}")

    def load_config(self, method: str = "cka-agent") -> dict:
        cfg_path = self.config_dir / "method" / f"{method}.yml"
        if not cfg_path.exists():
            raise FileNotFoundError(f"Config not found: {cfg_path}")
        import yaml
        with open(cfg_path) as f:
            return yaml.safe_load(f)

    def run(self, goal: str, method: str = "cka-agent", target_model: str = "gpt-4o", **kwargs):
        """
        Launch CKA-Agent against a target LLM with a specified goal.
        Requires the CKA-Agent repo to be present in cloned_repos/.
        """
        if not self.available:
            print(f"[!] CKA-Agent not found at {self.root}")
            print("    Run: git clone https://github.com/Graph-COM/CKA-Agent cloned_repos/CKA-Agent")
            return

        print(f"\n[*] CKA-Agent Jailbreak")
        print(f"    Method:  {method}")
        print(f"    Target:  {target_model}")
        print(f"    Goal:    {goal[:80]}{'...' if len(goal)>80 else ''}\n")

        # Build the command using CKA-Agent's main.py
        cmd = [
            sys.executable,
            str(self.root / "main.py"),
            "--method", method,
            "--target-model", target_model,
            "--goal", goal,
        ]
        for k, v in kwargs.items():
            cmd += [f"--{k}", str(v)]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                cwd=str(self.root), timeout=120
            )
            if result.returncode == 0:
                print("[+] Attack complete:")
                print(result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout)
            else:
                print("[!] Attack failed:")
                print(result.stderr[-500:])
            return result
        except subprocess.TimeoutExpired:
            print("[!] Timeout — CKA-Agent ran for >120s")
        except FileNotFoundError:
            print("[!] CKA-Agent main.py not found — check cloned_repos/CKA-Agent/")

    def run_interactive(self):
        print("\n[*] CKA-Agent Interactive Mode\n")
        self.list_methods()
        print()
        method = input("Method [cka-agent]: ").strip() or "cka-agent"
        model  = input("Target model [gpt-4o-mini]: ").strip() or "gpt-4o-mini"
        goal   = input("Attack goal: ").strip()
        if goal:
            self.run(goal=goal, method=method, target_model=model)
        else:
            print("[!] No goal provided.")
