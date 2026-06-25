"""
Full cycle integration tests.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.mark.integration
class TestFullCycle:
    """Test complete agent workflow."""

    def test_tool_kit_builds(self):
        """Test that tool kit can be built."""
        from nova_tool_kit import NovaToolKit, PermissionProfile

        kit = NovaToolKit(
            profile=PermissionProfile.SCOPED,
            scope=["example.com"],
        )
        tools = kit.build()
        assert len(tools) > 0

    def test_skills_library_loads(self):
        """Test that skills library loads."""
        from nova_skills import SkillLibrary

        lib = SkillLibrary()
        skills = lib.list_skills()
        assert len(skills) > 0

    def test_toolbox_loads(self):
        """Test that toolbox loads."""
        from nova_toolbox import NovaToolbox

        tb = NovaToolbox()
        count = tb.count_all()
        assert count > 0
