"""Regression tests for release/version metadata alignment."""

import importlib.metadata
import json
from pathlib import Path

from nova_arsenal import __version__
from nova_arsenal.api.app import create_app
from nova_arsenal.config import AgentConfig

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_VERSION = "2.0.0"


def test_python_version_surfaces_match() -> None:
    assert __version__ == EXPECTED_VERSION
    assert importlib.metadata.version("nova-arsenal") == EXPECTED_VERSION
    assert AgentConfig().version == EXPECTED_VERSION
    assert create_app().version == EXPECTED_VERSION


def test_vscode_version_surfaces_match() -> None:
    package = json.loads((ROOT / "clients/vscode/package.json").read_text())
    lock = json.loads((ROOT / "clients/vscode/package-lock.json").read_text())

    assert package["version"] == EXPECTED_VERSION
    assert lock["version"] == EXPECTED_VERSION
    assert lock["packages"][""]["version"] == EXPECTED_VERSION


def test_changelog_contains_release_version() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert "## [2.0.0] - 2026-10-01" in changelog
    assert "2026-XX-XX" not in changelog


def test_release_workflow_publishes_all_runtime_images() -> None:
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    production_compose = (ROOT / "docker-compose.prod.yml").read_text()

    assert "image: [agent, web, kali]" in workflow
    assert "${{ env.REGISTRY_GHCR }}/informant254/nova-${{ matrix.image }}" in workflow
    assert workflow.count("needs: validate") >= 3

    for image in ("agent", "web", "kali"):
        assert f"ghcr.io/informant254/nova-{image}:latest" in production_compose
