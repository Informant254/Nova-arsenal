"""
Nova Arsenal — Skill Manifest System
======================================

Defines the spec for installable Nova skills and the loader that
discovers, validates, and registers them at runtime.

A "skill" is a self-contained, optional capability — most commonly a
platform connector (HackerOne, Bugcrowd, HackTheBox, TryHackMe) but the
spec is generic enough to cover any modular capability (a new exploit
module, a reporting format, a custom OSINT pipeline, etc.).

Directory layout for a skill:

    skills/
      hackerone-connector/
        skill.json       <- manifest (required)
        connector.py      <- entry point (required)
        requirements.txt  <- optional, extra pip deps
        README.md          <- optional, human docs

Manifest schema (skill.json):
{
  "name": "hackerone-connector",
  "version": "1.0.0",
  "author": "Informant254",
  "description": "Pulls public bug bounty programs from HackerOne",
  "type": "platform_connector",        # platform_connector | tool | reporting | analysis
  "entry": "connector.py",
  "entry_class": "HackerOneConnector", # class implementing PlatformConnector
  "requires_credentials": ["api_username", "api_token"],
  "python_requires": ["httpx>=0.27"],
  "tags": ["bug-bounty", "hackerone"],
  "nova_min_version": "1.0.0"
}
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


SKILL_TYPES = {"platform_connector", "tool", "reporting", "analysis"}


class SkillValidationError(Exception):
    """Raised when a skill manifest or package fails validation."""


@dataclass
class SkillManifest:
    name: str
    version: str
    author: str
    description: str
    type: str
    entry: str
    entry_class: str
    requires_credentials: list[str] = field(default_factory=list)
    python_requires: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    nova_min_version: str = "0.0.0"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SkillManifest":
        required = ["name", "version", "author", "description", "type", "entry", "entry_class"]
        missing = [k for k in required if k not in data]
        if missing:
            raise SkillValidationError(f"skill.json missing required fields: {missing}")
        if data["type"] not in SKILL_TYPES:
            raise SkillValidationError(
                f"Unknown skill type '{data['type']}'. Must be one of {SKILL_TYPES}"
            )
        return cls(
            name=data["name"],
            version=data["version"],
            author=data["author"],
            description=data["description"],
            type=data["type"],
            entry=data["entry"],
            entry_class=data["entry_class"],
            requires_credentials=data.get("requires_credentials", []),
            python_requires=data.get("python_requires", []),
            tags=data.get("tags", []),
            nova_min_version=data.get("nova_min_version", "0.0.0"),
        )


@dataclass
class LoadedSkill:
    manifest: SkillManifest
    instance: Any
    path: Path
    missing_credentials: list[str] = field(default_factory=list)

    @property
    def is_ready(self) -> bool:
        """A skill is ready to use only if all required credentials are set."""
        return len(self.missing_credentials) == 0


class SkillRegistry:
    """
    Discovers skills under a skills directory, validates their manifests,
    and lazily loads their entry classes.

    Usage:
        registry = SkillRegistry(skills_dir="skills/")
        registry.discover()
        registry.load_all(credentials={"hackerone": {"api_username": "...", "api_token": "..."}})

        h1 = registry.get("hackerone-connector")
        programs = h1.instance.list_programs()
    """

    def __init__(self, skills_dir: str | Path = "skills"):
        self.skills_dir = Path(skills_dir)
        self._manifests: dict[str, tuple[SkillManifest, Path]] = {}
        self._loaded: dict[str, LoadedSkill] = {}

    def discover(self) -> list[str]:
        """Scan skills_dir for valid skill.json manifests. Returns list of skill names found."""
        self._manifests.clear()
        if not self.skills_dir.exists():
            return []

        found = []
        for entry in sorted(self.skills_dir.iterdir()):
            if not entry.is_dir():
                continue
            manifest_path = entry / "skill.json"
            if not manifest_path.exists():
                continue
            try:
                raw = json.loads(manifest_path.read_text())
                manifest = SkillManifest.from_dict(raw)
            except (json.JSONDecodeError, SkillValidationError) as e:
                print(f"  [!] Skipping invalid skill at {entry.name}: {e}")
                continue

            entry_file = entry / manifest.entry
            if not entry_file.exists():
                print(f"  [!] Skipping {manifest.name}: entry file '{manifest.entry}' not found")
                continue

            self._manifests[manifest.name] = (manifest, entry)
            found.append(manifest.name)

        return found

    def list_available(self) -> list[SkillManifest]:
        return [m for m, _ in self._manifests.values()]

    def load(
        self,
        skill_name: str,
        credentials: Optional[dict[str, str]] = None,
    ) -> LoadedSkill:
        """Load a single skill by name, instantiating its entry class."""
        if skill_name not in self._manifests:
            raise SkillValidationError(f"Unknown skill: {skill_name}")

        manifest, skill_path = self._manifests[skill_name]
        creds = credentials or {}

        missing = [c for c in manifest.requires_credentials if c not in creds or not creds[c]]

        # Dynamically import the entry module
        module_name = f"nova_skill_{manifest.name.replace('-', '_')}"
        entry_file = skill_path / manifest.entry
        spec = importlib.util.spec_from_file_location(module_name, entry_file)
        if spec is None or spec.loader is None:
            raise SkillValidationError(f"Could not load module for {skill_name}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        entry_cls = getattr(module, manifest.entry_class, None)
        if entry_cls is None:
            raise SkillValidationError(
                f"Entry class '{manifest.entry_class}' not found in {manifest.entry}"
            )

        instance = entry_cls(credentials=creds) if not missing else None

        loaded = LoadedSkill(
            manifest=manifest,
            instance=instance,
            path=skill_path,
            missing_credentials=missing,
        )
        self._loaded[skill_name] = loaded
        return loaded

    def load_all(self, credentials: Optional[dict[str, dict[str, str]]] = None) -> dict[str, LoadedSkill]:
        """Load every discovered skill. credentials is keyed by skill name."""
        credentials = credentials or {}
        for name in self._manifests:
            try:
                self.load(name, credentials.get(name, {}))
            except Exception as e:
                print(f"  [!] Failed to load skill '{name}': {e}")
        return self._loaded

    def get(self, skill_name: str) -> Optional[LoadedSkill]:
        return self._loaded.get(skill_name)

    def ready_skills(self) -> list[LoadedSkill]:
        """Returns only skills with all required credentials present."""
        return [s for s in self._loaded.values() if s.is_ready]

    def skills_by_type(self, skill_type: str) -> list[LoadedSkill]:
        return [s for s in self._loaded.values() if s.manifest.type == skill_type]
