"""
Unit tests for Nova Toolbox module.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nova_toolbox import NovaToolbox


class TestNovaToolbox:
    """Test NovaToolbox class."""

    def test_initialization(self):
        """Test toolbox initialization."""
        tb = NovaToolbox()
        assert tb is not None

    def test_has_tools(self):
        """Test that toolbox has tools."""
        tb = NovaToolbox()
        assert len(tb.tools) > 0

    def test_tool_categories(self):
        """Test that all expected categories exist."""
        tb = NovaToolbox()
        expected = [
            "recon",
            "web_exploit",
            "network",
            "binary",
            "cloud",
            "forensics",
            "password",
        ]
        for category in expected:
            assert category in tb.tools

    def test_get_tools_for_target(self):
        """Test getting tools for target type."""
        tb = NovaToolbox()
        tools = tb.get_tools_for_target("linux")
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_get_tools_for_unknown_target(self):
        """Test getting tools for unknown target type."""
        tb = NovaToolbox()
        tools = tb.get_tools_for_target("unknown")
        assert isinstance(tools, list)
        assert len(tools) > 0  # Should return default

    def test_get_tools_for_attack(self):
        """Test getting tools for attack type."""
        tb = NovaToolbox()
        tools = tb.get_tools_for_attack("sql_injection")
        assert isinstance(tools, list)
        assert "sqlmap" in tools

    def test_get_tools_for_unknown_attack(self):
        """Test getting tools for unknown attack type."""
        tb = NovaToolbox()
        tools = tb.get_tools_for_attack("unknown")
        assert isinstance(tools, list)
        assert len(tools) == 0  # Should return empty

    def test_count_all(self):
        """Test counting all tools."""
        tb = NovaToolbox()
        count = tb.count_all()
        assert count > 0
        assert isinstance(count, int)

    def test_list_all_tools(self):
        """Test listing all tools."""
        tb = NovaToolbox()
        all_tools = tb.list_all_tools()
        assert isinstance(all_tools, dict)
        assert len(all_tools) > 0

    def test_get_top_tools(self):
        """Test getting top tools."""
        tb = NovaToolbox()
        top = tb.get_top_tools(10)
        assert isinstance(top, list)
        assert len(top) <= 10

    def test_target_mapping_exists(self):
        """Test that target mapping exists."""
        tb = NovaToolbox()
        assert hasattr(tb, "target_mapping")
        assert isinstance(tb.target_mapping, dict)

    def test_attack_mapping_exists(self):
        """Test that attack mapping exists."""
        tb = NovaToolbox()
        assert hasattr(tb, "attack_mapping")
        assert isinstance(tb.attack_mapping, dict)

    def test_web_exploit_tools(self):
        """Test that web exploit tools are present."""
        tb = NovaToolbox()
        web_tools = tb.tools.get("web_exploit", [])
        assert "sqlmap" in web_tools
        assert "nuclei" in web_tools or "nikto" in web_tools

    def test_recon_tools(self):
        """Test that recon tools are present."""
        tb = NovaToolbox()
        recon_tools = tb.tools.get("recon", [])
        assert "nmap" in recon_tools
        assert "subfinder" in recon_tools
