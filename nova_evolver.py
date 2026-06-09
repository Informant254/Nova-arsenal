#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🧬 NOVA EVOLVER v1.0 — Self-Improvement Engine                ║
║                                                                  ║
║  Allows Nova to propose and apply incremental improvements to   ║
║  her own source code using LLM-generated patches.               ║
║                                                                  ║
║  Safety controls:                                                ║
║    • dry_run=True by default — never writes without explicit OK  ║
║    • forbidden_files list from nova_config.json                 ║
║    • Backup created before every write                           ║
║    • Only modifies files that exist and are writable            ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    from nova_evolver import NovaEvolver

    evolver = NovaEvolver(reasoning=reasoning_core, repo_path=".", dry_run=True)
    result  = evolver.evolve(max_patches=2, improvement_goal="reliability")
    print(result)
"""

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

FORBIDDEN_FILES = {
    "nova_evolver.py",
    "nova_memory_system.py",
    "nova_config.json",
    ".env",
}


class NovaEvolver:
    """
    LLM-driven self-improvement engine.
    Proposes patches to Nova modules and optionally applies them.
    """

    def __init__(
        self,
        reasoning: Any = None,
        repo_path: str = ".",
        dry_run: bool = True,
    ):
        self._reasoning = reasoning
        self._repo      = Path(repo_path).resolve()
        self._dry_run   = dry_run

        # Load forbidden list from config (extend defaults)
        config_path = self._repo / "nova_config.json"
        if config_path.exists():
            try:
                cfg = json.loads(config_path.read_text())
                FORBIDDEN_FILES.update(
                    cfg.get("evolution", {}).get("forbidden_files", [])
                )
            except Exception:
                pass

    def _backup(self, filepath: Path) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        bak = filepath.with_suffix(f".{ts}.bak")
        shutil.copy2(filepath, bak)
        return bak

    def _safe_to_modify(self, filepath: Path) -> bool:
        if filepath.name in FORBIDDEN_FILES:
            return False
        if not filepath.exists():
            return False
        if not os.access(filepath, os.W_OK):
            return False
        return True

    def propose_patches(self, improvement_goal: str,
                        max_patches: int = 3) -> List[Dict]:
        """
        Ask the LLM to propose code improvements.
        Returns a list of patch dicts: {file, description, old_code, new_code}
        """
        if not self._reasoning:
            return []

        nova_files = sorted(self._repo.glob("nova_*.py"))[:20]
        file_list  = "\n".join(f.name for f in nova_files)

        prompt = (
            f"Goal: {improvement_goal}\n\n"
            f"Nova modules available:\n{file_list}\n\n"
            "Suggest up to 2 small, safe improvements. For each, output JSON:\n"
            '{"file": "nova_xxx.py", "description": "...", '
            '"old_code": "exact snippet", "new_code": "replacement"}\n'
            "One JSON object per line. Only suggest changes to error handling, "
            "logging, or resilience — never change core security logic."
        )
        try:
            result  = self._reasoning.think(prompt, max_tokens=500)
            patches: List[Dict] = []
            for line in (result or "").splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        patches.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return patches[:max_patches]
        except Exception:
            return []

    def apply_patch(self, patch: Dict) -> bool:
        """Apply a single patch. Returns True on success."""
        filename = patch.get("file", "")
        old_code = patch.get("old_code", "")
        new_code = patch.get("new_code", "")

        if not filename or not old_code or not new_code:
            return False

        filepath = self._repo / filename
        if not self._safe_to_modify(filepath):
            print(f"  ⛔ Evolver: skipping {filename} (forbidden/missing)")
            return False

        source = filepath.read_text(encoding="utf-8")
        if old_code not in source:
            print(f"  ⚠️  Evolver: old_code not found in {filename}")
            return False

        if self._dry_run:
            print(f"  🔍 Evolver [dry-run]: would patch {filename} — {patch.get('description','')}")
            return True

        bak = self._backup(filepath)
        try:
            filepath.write_text(source.replace(old_code, new_code, 1), encoding="utf-8")
            print(f"  ✅ Evolver: patched {filename} (backup → {bak.name})")
            return True
        except Exception as exc:
            shutil.copy2(bak, filepath)
            print(f"  ❌ Evolver: rollback after error: {exc}")
            return False

    def evolve(self, max_patches: int = 2,
               improvement_goal: str = "reliability and error handling") -> Dict:
        """Run a full evolution cycle: propose → (optionally) apply."""
        patches  = self.propose_patches(improvement_goal, max_patches)
        applied  = 0
        skipped  = 0
        for patch in patches:
            if self.apply_patch(patch):
                applied += 1
            else:
                skipped += 1
        return {
            "proposed": len(patches),
            "applied":  applied,
            "skipped":  skipped,
            "dry_run":  self._dry_run,
        }


if __name__ == "__main__":
    evolver = NovaEvolver(dry_run=True)
    print("Nova Evolver ready (dry_run=True). No LLM — no patches proposed.")
    print(f"Repo: {evolver._repo}")
