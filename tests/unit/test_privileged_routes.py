"""Regression tests for privileged API access and CORS policy."""

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
import pytest

from nova_arsenal.api.app import _cors_origins, create_app
from nova_arsenal.auth.middleware import require_admin, require_analyst


def _route_dependency_calls(app, path: str, method: str) -> set[object]:
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path == path and method in route.methods:
            return {dependency.call for dependency in route.dependant.dependencies}
    raise AssertionError(f"Route not found: {method} {path}")


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("GET", "/api/mcp/tools", {}),
        ("GET", "/api/mcp/resources", {}),
        ("POST", "/api/mcp/call", {"params": {"tool_name": "cve_lookup"}}),
        ("GET", "/api/llm/accounts", {}),
        ("GET", "/api/llm/local", {}),
        ("POST", "/api/llm/reload", {}),
        ("POST", "/api/llm/accounts/import", {}),
        ("DELETE", "/api/llm/accounts/openai", {}),
        ("GET", "/api/work-sessions", {}),
    ],
)
def test_privileged_routes_reject_unauthenticated_requests(
    method: str,
    path: str,
    kwargs: dict,
) -> None:
    app = create_app()
    with TestClient(app) as client:
        response = client.request(method, path, **kwargs)
    assert response.status_code == 401


def test_shared_llm_credential_mutations_require_admin() -> None:
    app = create_app()
    admin_routes = [
        ("POST", "/api/llm/reload"),
        ("GET", "/api/llm/accounts"),
        ("POST", "/api/llm/accounts/login"),
        ("POST", "/api/llm/accounts/import"),
        ("DELETE", "/api/llm/accounts/{provider}"),
    ]
    for method, path in admin_routes:
        assert require_admin in _route_dependency_calls(app, path, method)


def test_mcp_and_local_discovery_require_analyst() -> None:
    app = create_app()
    analyst_routes = [
        ("GET", "/api/llm/local"),
        ("GET", "/api/mcp/tools"),
        ("GET", "/api/mcp/resources"),
        ("POST", "/api/mcp/call"),
    ]
    for method, path in analyst_routes:
        assert require_analyst in _route_dependency_calls(app, path, method)


def test_cors_origins_reject_wildcard(monkeypatch) -> None:
    monkeypatch.setenv("NOVA_CORS_ORIGINS", "*")
    with pytest.raises(RuntimeError, match="explicit origins"):
        _cors_origins()


def test_cors_origins_accept_explicit_origins(monkeypatch) -> None:
    monkeypatch.setenv(
        "NOVA_CORS_ORIGINS",
        "https://nova.example, https://admin.example",
    )
    assert _cors_origins() == ["https://nova.example", "https://admin.example"]
