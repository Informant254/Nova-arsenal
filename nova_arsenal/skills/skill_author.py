"""
Nova Arsenal — Skill Authoring (self-improving skill loop)
==============================================================

Inspired by the Hermes Agent pattern: when Nova completes a novel task
successfully, she can draft a reusable skill describing the procedure —
so next time a similar task comes up, the skill loads automatically
instead of Nova re-deriving the approach from scratch.

CRITICAL DIFFERENCE FROM HERMES: Hermes auto-loads self-authored skills
immediately. Nova does not. A self-authored skill is Python that will be
dynamically imported and executed (see skill_manifest.py's SkillRegistry)
— for a framework that runs exploits and RPC calls to Metasploit/Burp,
letting Nova write-and-immediately-run her own code without review is
too large an attack/failure surface to accept. Every self-authored skill
is written to pending_skills/, not skills/, and requires an explicit
human `approve_skill()` call (or `nova skills approve <name>` CLI
command) before SkillRegistry will ever discover and load it.

This is a permanent design boundary, matching the same philosophy as
submit_finding() across every platform connector: Nova drafts, a human
approves.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


DEFAULT_PENDING_DIR = Path("pending_skills")
DEFAULT_APPROVED_DIR = Path("skills")

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{2,48}[a-z0-9]$")


class SkillAuthoringError(Exception):
    pass


@dataclass
class DraftedSkill:
    name: str
    path: Path
    manifest: dict
    source_task_summary: str
    drafted_at: str


class SkillAuthor:
    """
    Drafts new skills from successful task procedures.

    Usage:
        author = SkillAuthor()
        draft = author.draft_skill(
            name="idor-param-fuzzer",
            description="Fuzzes numeric ID params in URLs for IDOR",
            task_summary="Found IDOR on webcorp by incrementing user_id param",
            code=\"\"\"
                from platform_connector import Target
                class IdorParamFuzzerTool:
                    def run(self, url, param):
                        ...
            \"\"\",
            entry_class="IdorParamFuzzerTool",
            skill_type="tool",
        )
        # draft.path is under pending_skills/ — NOT auto-loaded.

        # A human reviews the code, then explicitly approves:
        author.approve_skill("idor-param-fuzzer")
        # Only now does it move to skills/ where SkillRegistry can find it.
    """

    def __init__(
        self,
        pending_dir: str | Path = DEFAULT_PENDING_DIR,
        approved_dir: str | Path = DEFAULT_APPROVED_DIR,
    ):
        self.pending_dir = Path(pending_dir)
        self.approved_dir = Path(approved_dir)
        self.pending_dir.mkdir(parents=True, exist_ok=True)

    def draft_skill(
        self,
        name: str,
        description: str,
        task_summary: str,
        code: str,
        entry_class: str,
        skill_type: str = "tool",
        author: str = "nova-self-authored",
        requires_credentials: Optional[list[str]] = None,
        python_requires: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
    ) -> DraftedSkill:
        """
        Write a new candidate skill to pending_skills/<name>/.
        Does NOT make it loadable — see class docstring.
        """
        if not _NAME_RE.match(name):
            raise SkillAuthoringError(
                f"Invalid skill name '{name}' — must be lowercase, "
                "alphanumeric + hyphens, 5-50 chars."
            )

        skill_dir = self.pending_dir / name
        if skill_dir.exists():
            raise SkillAuthoringError(
                f"A pending skill named '{name}' already exists at {skill_dir}. "
                "Approve, reject, or choose a different name."
            )
        if (self.approved_dir / name).exists():
            raise SkillAuthoringError(
                f"A skill named '{name}' is already approved and live. "
                "Choose a different name or version it, e.g. '{name}-v2'."
            )

        skill_dir.mkdir(parents=True)

        manifest = {
            "name": name,
            "version": "0.1.0",
            "author": author,
            "description": description,
            "type": skill_type,
            "entry": "skill.py",
            "entry_class": entry_class,
            "requires_credentials": requires_credentials or [],
            "python_requires": python_requires or [],
            "tags": tags or [],
            "nova_min_version": "1.0.0",
            "self_authored": True,
            "source_task_summary": task_summary,
        }

        (skill_dir / "skill.json").write_text(json.dumps(manifest, indent=2))
        (skill_dir / "skill.py").write_text(code)
        (skill_dir / "PENDING_REVIEW.md").write_text(
            f"# ⚠️ Self-authored skill pending human review\n\n"
            f"**Name:** {name}\n"
            f"**Drafted:** {datetime.now(timezone.utc).isoformat()}\n"
            f"**Derived from task:** {task_summary}\n\n"
            f"This skill was written automatically by Nova after completing "
            f"a task she had no existing skill for. It has NOT been loaded "
            f"or executed since being drafted — Nova's skill loader only "
            f"discovers skills under `skills/`, and this lives in `pending_skills/` "
            f"until a human reviews the code and calls `approve_skill('{name}')`.\n\n"
            f"## Before approving, check:\n"
            f"- [ ] No hardcoded credentials or secrets\n"
            f"- [ ] No unbounded shell execution (shell=True, unsanitized input)\n"
            f"- [ ] Follows the submit_finding() human-review boundary if it "
            f"touches bug bounty platforms\n"
            f"- [ ] The procedure actually matches what it claims to do\n"
        )

        return DraftedSkill(
            name=name,
            path=skill_dir,
            manifest=manifest,
            source_task_summary=task_summary,
            drafted_at=manifest.get("drafted_at", datetime.now(timezone.utc).isoformat()),
        )

    def list_pending(self) -> list[dict]:
        """List all skills awaiting human review."""
        out = []
        if not self.pending_dir.exists():
            return out
        for entry in sorted(self.pending_dir.iterdir()):
            manifest_path = entry / "skill.json"
            if entry.is_dir() and manifest_path.exists():
                out.append(json.loads(manifest_path.read_text()))
        return out

    def approve_skill(self, name: str) -> Path:
        """
        Human-triggered action: move a reviewed skill from pending_skills/
        to skills/ so SkillRegistry.discover() will find it. This is the
        ONLY way a self-authored skill becomes loadable.
        """
        src = self.pending_dir / name
        if not src.exists():
            raise SkillAuthoringError(f"No pending skill named '{name}' found at {src}")

        dst = self.approved_dir / name
        if dst.exists():
            raise SkillAuthoringError(f"A skill named '{name}' already exists at {dst}")

        self.approved_dir.mkdir(parents=True, exist_ok=True)
        src.rename(dst)

        # Bump self_authored manifest to note approval
        manifest_path = dst / "skill.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["approved_at"] = datetime.now(timezone.utc).isoformat()
        manifest_path.write_text(json.dumps(manifest, indent=2))

        pending_review = dst / "PENDING_REVIEW.md"
        if pending_review.exists():
            pending_review.unlink()

        return dst

    def reject_skill(self, name: str, reason: str = "") -> None:
        """Human-triggered action: discard a drafted skill without loading it."""
        src = self.pending_dir / name
        if not src.exists():
            raise SkillAuthoringError(f"No pending skill named '{name}' found at {src}")

        import shutil
        rejected_log = self.pending_dir / "_rejected.log"
        with rejected_log.open("a") as f:
            f.write(
                f"{datetime.now(timezone.utc).isoformat()} | {name} | {reason}\n"
            )
        shutil.rmtree(src)
