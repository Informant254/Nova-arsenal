#!/usr/bin/env python3
"""Autonomous coding-agent loop for Nova.

The agent maps a repository, plans a change, optionally asks an LLM for a
unified diff, applies only valid diffs, runs tests, retries once, and writes a
machine-readable report. It is intentionally conservative: no edits are made
unless the generated patch passes `git apply --check`.
"""

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from nova_codebase_mapper import NovaCodebaseMapper, map_to_agent_context
from nova_llm_router import get_router

WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)


@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    elapsed_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout[-6000:],
            "stderr": self.stderr[-6000:],
            "elapsed_ms": round(self.elapsed_ms, 2),
        }


@dataclass
class CodeAgentReport:
    task: str
    repo: str
    started_at: str
    completed_at: str = ""
    mode: str = "code"
    plan: List[str] = field(default_factory=list)
    mapped_files: int = 0
    primary_language: str = "Unknown"
    frameworks: List[str] = field(default_factory=list)
    patch_applied: bool = False
    changed_files: List[str] = field(default_factory=list)
    test_command: str = ""
    checks: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "started"
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class NovaCodeAgent:
    def __init__(self, repo: str = ".", task: str = "Inspect repository", test_command: str = "", max_retries: int = 1, allow_edits: bool = True):
        self.repo = Path(repo).resolve()
        self.task = task
        self.test_command = test_command
        self.max_retries = max_retries
        self.allow_edits = allow_edits
        self.report = CodeAgentReport(
            task=task,
            repo=str(self.repo),
            started_at=datetime.now().isoformat(),
            test_command=test_command,
        )

    def run(self) -> Dict[str, Any]:
        if not self.repo.is_dir():
            self.report.status = "failed"
            self.report.notes.append(f"Repository path does not exist: {self.repo}")
            return self._finish()

        cmap = NovaCodebaseMapper(str(self.repo), verbose=False, ai_analysis=False).scan()
        self.report.mapped_files = cmap.file_count
        self.report.primary_language = cmap.primary_language
        self.report.frameworks = cmap.frameworks
        self.report.plan = self._build_plan(cmap)

        preflight = self._run_command("git status --short", timeout=20)
        self.report.checks.append(preflight.to_dict())

        if self.allow_edits:
            patch = self._ask_for_patch(cmap, previous_failure="")
            if patch:
                self._apply_patch(patch)
            else:
                self.report.notes.append("No patch was produced; Nova completed repository analysis only.")
        else:
            self.report.notes.append("Edits disabled by caller; Nova completed repository analysis only.")

        command = self.test_command or self._infer_test_command()
        self.report.test_command = command
        if command:
            result = self._run_command(command, timeout=int(os.getenv("NOVA_CODE_TEST_TIMEOUT", "180")))
            self.report.checks.append(result.to_dict())
            if result.returncode != 0 and self.allow_edits and self.max_retries > 0:
                self._repair_once(cmap, result)
        else:
            self.report.notes.append("No test command inferred. Provide --test-command for verification.")

        changed = self._run_command("git diff --name-only", timeout=20)
        self.report.changed_files = [line for line in changed.stdout.splitlines() if line.strip()]
        self.report.status = "completed"
        return self._finish()

    def _build_plan(self, cmap: Any) -> List[str]:
        plan = [
            "Map repository languages, frameworks, entry points, dependencies, and risky files.",
            "Identify files most relevant to the requested coding task.",
            "Generate a minimal unified diff and validate it before applying.",
            "Run the inferred or requested tests and retry once if a generated patch fails.",
            "Write an auditable report with commands, changed files, and remaining risks.",
        ]
        if cmap.attack_surface.get("attack_priority"):
            plan.insert(1, "Use attack-surface priorities as security-review context for any code edits.")
        return plan

    def _ask_for_patch(self, cmap: Any, previous_failure: str) -> str:
        prompt = self._patch_prompt(cmap, previous_failure)
        router = get_router()
        try:
            response = router.chat(
                prompt,
                system=(
                    "You are Nova's autonomous coding agent. Return only a unified diff. "
                    "If no safe edit is justified, return NO_PATCH. Keep changes minimal."
                ),
            )
        except Exception as exc:
            self.report.notes.append(f"LLM unavailable: {exc}")
            return ""
        content = response.content.strip()
        if content == "NO_PATCH":
            return ""
        return self._extract_diff(content)

    def _patch_prompt(self, cmap: Any, previous_failure: str) -> str:
        files = self._candidate_files(cmap)
        snippets = []
        for rel in files[:12]:
            path = self.repo / rel
            if path.is_file() and path.stat().st_size <= 120_000:
                text = path.read_text(encoding="utf-8", errors="ignore")[:8000]
                snippets.append(f"--- {rel} ---\n{text}")
        return (
            f"Task:\n{self.task}\n\n"
            f"Repository map:\n{map_to_agent_context(cmap)[:6000]}\n\n"
            f"Candidate files:\n{json.dumps(files[:30], indent=2)}\n\n"
            f"Relevant snippets:\n{'\n\n'.join(snippets)}\n\n"
            f"Previous test failure, if any:\n{previous_failure[-4000:]}\n\n"
            "Return a git-applicable unified diff rooted at the repository. "
            "Do not include prose, markdown fences, or explanations."
        )

    def _candidate_files(self, cmap: Any) -> List[str]:
        candidates: List[str] = []
        for ep in cmap.entry_points[:20]:
            candidates.append(ep)
        for item in cmap.attack_surface.get("high_value", [])[:20]:
            file_name = item.get("file")
            if file_name:
                candidates.append(file_name)
        task_words = [w for w in re.findall(r"[A-Za-z0-9_/-]{4,}", self.task.lower()) if len(w) >= 4]
        for info in getattr(cmap, "_files", []):
            rel = getattr(info, "path", "")
            haystack = rel.lower()
            if any(word in haystack for word in task_words):
                candidates.append(rel)
        return list(dict.fromkeys(candidates))

    def _extract_diff(self, content: str) -> str:
        content = re.sub(r"^```(?:diff)?\s*", "", content.strip())
        content = re.sub(r"\s*```$", "", content.strip())
        match = re.search(r"(?ms)^diff --git .+", content)
        if match:
            return match.group(0).strip() + "\n"
        match = re.search(r"(?ms)^--- .+?\n\+\+\+ .+", content)
        if match:
            return match.group(0).strip() + "\n"
        return ""

    def _apply_patch(self, patch: str) -> None:
        patch_path = WORKSPACE / f"nova_code_patch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.diff"
        patch_path.write_text(patch)
        check = self._run_command(f"git apply --check {self._shell_quote(str(patch_path))}", timeout=30)
        self.report.checks.append(check.to_dict())
        if check.returncode != 0:
            self.report.notes.append("Generated patch failed git apply --check and was not applied.")
            return
        apply = self._run_command(f"git apply {self._shell_quote(str(patch_path))}", timeout=30)
        self.report.checks.append(apply.to_dict())
        self.report.patch_applied = apply.returncode == 0
        if not self.report.patch_applied:
            self.report.notes.append("Generated patch passed validation but failed during apply.")

    def _repair_once(self, cmap: Any, failure: CommandResult) -> None:
        patch = self._ask_for_patch(cmap, previous_failure=failure.stdout + "\n" + failure.stderr)
        if not patch:
            self.report.notes.append("Repair loop did not produce a patch.")
            return
        self._apply_patch(patch)
        if self.report.test_command:
            result = self._run_command(self.report.test_command, timeout=int(os.getenv("NOVA_CODE_TEST_TIMEOUT", "180")))
            self.report.checks.append(result.to_dict())

    def _infer_test_command(self) -> str:
        if (self.repo / "package.json").exists():
            return os.getenv("NOVA_CODE_DEFAULT_NODE_TEST", "npm test")
        if (self.repo / "pyproject.toml").exists() or (self.repo / "pytest.ini").exists() or (self.repo / "tests").exists():
            return os.getenv("NOVA_CODE_DEFAULT_PY_TEST", "python3 -m pytest")
        if (self.repo / "Cargo.toml").exists():
            return "cargo test"
        if (self.repo / "go.mod").exists():
            return "go test ./..."
        return ""

    def _run_command(self, command: str, timeout: int) -> CommandResult:
        started = time.monotonic()
        try:
            result = subprocess.run(command, cwd=self.repo, shell=True, capture_output=True, text=True, timeout=timeout)
            return CommandResult(
                command=command,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                elapsed_ms=(time.monotonic() - started) * 1000,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
            stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
            return CommandResult(
                command=command,
                returncode=124,
                stdout=stdout,
                stderr=stderr + f"\nCommand timed out after {timeout}s",
                elapsed_ms=(time.monotonic() - started) * 1000,
            )

    def _finish(self) -> Dict[str, Any]:
        self.report.completed_at = datetime.now().isoformat()
        out = WORKSPACE / f"nova_code_agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(self.report.to_dict(), indent=2, default=str))
        data = self.report.to_dict()
        data["report_path"] = str(out)
        return data

    def _shell_quote(self, value: str) -> str:
        return "'" + value.replace("'", "'\\''") + "'"


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Nova autonomous coding agent")
    parser.add_argument("task", help="Coding task to perform")
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--test-command", default="", help="Verification command")
    parser.add_argument("--no-edit", action="store_true", help="Inspect and plan without editing")
    args = parser.parse_args()
    report = NovaCodeAgent(args.repo, args.task, args.test_command, allow_edits=not args.no_edit).run()
    print(json.dumps(report, indent=2, default=str))
