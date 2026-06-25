"""
Unit tests for Nova Tool Kit module.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nova_tool_kit import (
    NovaToolKit,
    PermissionProfile,
    ScopeGuard,
    GovernedTool,
)


class TestPermissionProfiles:
    """Test permission profile behavior."""

    def test_read_only_blocks_shell(self):
        """Test that read-only profile blocks shell execution."""
        kit = NovaToolKit(profile=PermissionProfile.READ_ONLY)
        tools = {t.name: t for t in kit.build()}
        result = tools["shell"].call(
            {"command": "echo test"},
            profile=PermissionProfile.READ_ONLY,
        )
        assert "BLOCKED" in result

    def test_scoped_allows_http(self, sample_scope):
        """Test that scoped profile allows HTTP requests."""
        kit = NovaToolKit(
            profile=PermissionProfile.SCOPED,
            scope=sample_scope,
        )
        tools = {t.name: t for t in kit.build()}
        assert "http_probe" in tools

    def test_full_profile_allows_all(self, sample_scope):
        """Test that full profile allows all operations."""
        kit = NovaToolKit(
            profile=PermissionProfile.FULL,
            scope=sample_scope,
        )
        tools = {t.name: t for t in kit.build()}
        assert len(tools) > 0


class TestScopeGuard:
    """Test ScopeGuard class."""

    def test_in_scope_allowed(self):
        """Test that in-scope targets are allowed."""
        guard = ScopeGuard(["example.com"])
        ok, msg = guard.check_url("https://example.com/api")
        assert ok is True
        assert "in scope" in msg

    def test_subdomain_allowed(self):
        """Test that subdomains are allowed."""
        guard = ScopeGuard(["example.com"])
        ok, msg = guard.check_url("https://api.example.com/v1")
        assert ok is True

    def test_wildcard_allowed(self):
        """Test that wildcard scope works."""
        guard = ScopeGuard(["*.example.com"])
        ok, msg = guard.check_url("https://api.example.com")
        assert ok is True

    def test_blocked_host(self):
        """Test that well-known hosts are blocked."""
        guard = ScopeGuard(["example.com"])
        ok, msg = guard.check_url("https://google.com/search")
        assert ok is False
        assert "blocked" in msg

    def test_no_scope_allows_all(self):
        """Test that empty scope allows all (non-strict)."""
        guard = ScopeGuard([])
        ok, msg = guard.check_url("https://anything.com")
        assert ok is True

    def test_safe_path_allowed(self):
        """Test that safe paths are allowed."""
        guard = ScopeGuard([])
        ok, msg = guard.check_path("/home/user/file.txt")
        assert ok is True

    def test_sensitive_path_blocked(self):
        """Test that sensitive paths are blocked."""
        guard = ScopeGuard([])
        ok, msg = guard.check_path("/etc/shadow")
        assert ok is False
        assert "blocked" in msg


class TestGovernedTool:
    """Test GovernedTool class."""

    def test_tool_has_schema(self):
        """Test that tools have schema."""
        kit = NovaToolKit()
        tools = kit.build()
        for tool in tools:
            assert hasattr(tool, "schema")
            assert isinstance(tool.schema, dict)

    def test_tool_schema_str(self):
        """Test schema string generation."""
        kit = NovaToolKit()
        tools = kit.build()
        for tool in tools:
            schema_str = tool.schema_str()
            assert isinstance(schema_str, str)


class TestNovaToolKit:
    """Test NovaToolKit class."""

    def test_build_returns_tools(self, sample_scope):
        """Test that build returns list of tools."""
        kit = NovaToolKit(scope=sample_scope)
        tools = kit.build()
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_all_expected_tools_present(self, sample_scope):
        """Test that all expected tools are present."""
        kit = NovaToolKit(scope=sample_scope)
        tools = {t.name: t for t in kit.build()}
        expected = ["http_probe", "shell", "read_file", "grep_code", "write_file"]
        for name in expected:
            assert name in tools

    def test_tool_names_are_strings(self, sample_scope):
        """Test that all tool names are strings."""
        kit = NovaToolKit(scope=sample_scope)
        tools = kit.build()
        for tool in tools:
            assert isinstance(tool.name, str)
            assert len(tool.name) > 0

    def test_tool_descriptions_are_strings(self, sample_scope):
        """Test that all tool descriptions are strings."""
        kit = NovaToolKit(scope=sample_scope)
        tools = kit.build()
        for tool in tools:
            assert isinstance(tool.description, str)
            assert len(tool.description) > 0
