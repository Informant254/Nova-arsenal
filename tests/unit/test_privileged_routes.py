"""Regression tests for access control on privileged API routes."""

from fastapi.testclient import TestClient
import pytest

from nova_arsenal.api.app import create_app


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/mcp/tools"),
        ("GET", "/api/llm/accounts"),
        ("GET", "/api/work-sessions"),
    ],
)
def test_privileged_routes_reject_unauthenticated_requests(method: str, path: str) -> None:
    """Management and execution surfaces must not be publicly accessible."""
    app = create_app()
    with TestClient(app) as client:
        response = client.request(method, path)

    assert response.status_code == 401
