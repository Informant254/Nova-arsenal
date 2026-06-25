"""
Unit tests for Nova Skills module.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nova_skills import SkillLibrary, BUILTIN_SKILLS


class TestSkillLibrary:
    """Test SkillLibrary class."""

    def test_load_builtin_skills(self, nova_skills_library):
        """Test that builtin skills are loaded."""
        skills = nova_skills_library.list_skills()
        assert len(skills) > 0
        assert len(skills) == len(BUILTIN_SKILLS)

    def test_skill_categories(self, nova_skills_library):
        """Test that all expected categories exist."""
        categories = nova_skills_library.categories()
        assert "recon" in categories
        assert "attack" in categories
        assert "analysis" in categories
        assert "report" in categories

    def test_render_sqli_skill(self, nova_skills_library):
        """Test rendering SQL injection skill."""
        result = nova_skills_library.render(
            "sqli_analysis",
            target="example.com",
            endpoint="/api/search",
            param="q",
            method="GET",
            request_sample="GET /api/search?q=test",
        )
        assert "system" in result
        assert "user" in result
        assert "example.com" in result["user"]
        assert "/api/search" in result["user"]

    def test_render_xss_skill(self, nova_skills_library):
        """Test rendering XSS skill."""
        result = nova_skills_library.render(
            "xss_analysis",
            target="example.com",
            endpoint="/search",
            context="HTML attribute",
            filters="none",
        )
        assert "system" in result
        assert "user" in result

    def test_missing_params_raises(self, nova_skills_library):
        """Test that missing parameters raise ValueError."""
        with pytest.raises(ValueError):
            nova_skills_library.render("sqli_analysis")

    def test_unknown_skill_raises(self, nova_skills_library):
        """Test that unknown skill raises KeyError."""
        with pytest.raises(KeyError):
            nova_skills_library.get("nonexistent_skill")

    def test_list_skills_by_category(self, nova_skills_library):
        """Test filtering skills by category."""
        recon_skills = nova_skills_library.list_skills(category="recon")
        assert len(recon_skills) > 0
        for skill in recon_skills:
            assert skill["category"] == "recon"

    def test_list_skills_by_tag(self, nova_skills_library):
        """Test filtering skills by tag."""
        sqli_skills = nova_skills_library.list_skills(tag="sqli")
        assert len(sqli_skills) > 0
        for skill in sqli_skills:
            assert "sqli" in skill["tags"]

    def test_skill_has_required_fields(self, nova_skills_library):
        """Test that all skills have required fields."""
        skills = nova_skills_library.list_skills()
        for skill in skills:
            assert "name" in skill
            assert "category" in skill
            assert "description" in skill
            assert "params" in skill
            assert "tags" in skill


class TestSkill:
    """Test Skill dataclass."""

    def test_skill_render(self):
        """Test skill rendering."""
        from nova_skills import Skill

        skill = Skill(
            name="test_skill",
            category="test",
            description="Test skill",
            system="You are testing {target}",
            template="Test {endpoint}",
            params=["target", "endpoint"],
            tags=["test"],
        )

        result = skill.render(target="example.com", endpoint="/api")
        assert result["system"] == "You are testing example.com"
        assert result["user"] == "Test /api"

    def test_skill_to_dict(self):
        """Test skill serialization."""
        from nova_skills import Skill

        skill = Skill(
            name="test_skill",
            category="test",
            description="Test skill",
            system="test",
            template="test",
            params=["param1"],
            tags=["test"],
        )

        d = skill.to_dict()
        assert d["name"] == "test_skill"
        assert d["category"] == "test"
        assert "param1" in d["params"]
