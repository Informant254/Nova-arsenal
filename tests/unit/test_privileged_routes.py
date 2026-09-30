"""Regression tests for privileged API access and CORS policy."""

import inspect

import pytest
from fastapi.params import Depends
from fastapi.testclient import TestClient

from nova_arsenal.api import routes as api_routes
from nova_arsenal.api.app import _cors_origins, create_app
from nova_arsenal.auth.middleware import require_admin, require_analyst


def _dependency_for(function, parameter: str):
    default = inspect.signature(function).parameters[parameter].default
    assert isinstance(default, Depends)
    return default.dependency


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
    assert _dependency_for(api_routes.llm_reload_config, "_current_user") is require_admin
    assert _dependency_for(api_routes.llm_list_accounts, "_current_user") is require_admin
    assert _dependency_for(api_routes.llm_account_login, "_current_user") is require_admin
    assert _dependency_for(api_routes.llm_account_import, "_current_user") is require_admin
    assert _dependency_for(api_routes.llm_account_logout, "_current_user") is require_admin


def test_mcp_and_local_discovery_require_analyst() -> None:
    assert _dependency_for(api_routes.llm_local_status, "_current_user") is require_analyst
    assert _dependency_for(api_routes.mcp_tools, "_current_user") is require_analyst
    assert _dependency_for(api_routes.mcp_resources, "_current_user") is require_analyst
    assert _dependency_for(api_routes.mcp_call_tool, "_current_user") is require_analyst


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
