"""
Nova-Arsenal Test Configuration

Shared fixtures and test utilities.
"""

import pytest
from pathlib import Path


@pytest.fixture
def sample_scope():
    """Sample target scope for testing."""
    return ["example.com", "*.example.com"]


@pytest.fixture
def mock_target():
    """Mock target for testing."""
    return {
        "host": "test.example.com",
        "port": 443,
        "protocol": "https",
    }


@pytest.fixture
def nova_config():
    """Nova configuration for testing."""
    from nova_arsenal.config import NovaConfig
    return NovaConfig()


@pytest.fixture
def nova_skills_library():
    """Nova skills library for testing."""
    from nova_skills import SkillLibrary
    return SkillLibrary()


@pytest.fixture
def nova_toolkit(sample_scope):
    """Nova tool kit for testing."""
    from nova_tool_kit import NovaToolKit, PermissionProfile
    return NovaToolKit(
        profile=PermissionProfile.SCOPED,
        scope=sample_scope,
    )
