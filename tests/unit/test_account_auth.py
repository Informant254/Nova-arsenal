"""Tests for account-style AI login (Codex / Claude Code)."""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.fixture
def store(tmp_path, monkeypatch):
    from nova_arsenal.llm import account_auth as aa

    path = tmp_path / "accounts.json"
    monkeypatch.setattr(aa, "STORE_PATH", path)
    aa.reset_account_store()
    s = aa.AccountAuthStore(path=path)
    yield s
    aa.reset_account_store()


class TestAccountAuth:
    def test_login_with_token(self, store):
        cred = store.login_with_token(
            "anthropic",
            "sk-ant-testtoken1234567890",
            label="claude",
        )
        assert cred.provider == "anthropic"
        assert store.get_token("anthropic").startswith("sk-ant-")
        pub = cred.to_public_dict()
        assert "sk-ant-testtoken1234567890" not in json.dumps(pub)
        assert pub["has_token"] is True

    def test_store_openai_tokens(self, store):
        cred = store._store_openai_tokens(
            {
                "access_token": "access-tok-abcdefghijklmnopqrstuv",
                "refresh_token": "refresh-tok-xyz",
                "expires_in": 3600,
            },
            source="test",
            client_id="app_test",
        )
        assert cred.provider == "openai"
        assert cred.auth_type == "oauth"
        assert (cred.meta or {}).get("subscription_auth") is True
        assert store.get_token("openai").startswith("access-tok")

    def test_pkce_challenge_shape(self):
        from nova_arsenal.llm.account_auth import _pkce_challenge

        c = _pkce_challenge("verifier-value-1234567890")
        assert len(c) >= 40
        assert "=" not in c

    def test_resolve_uses_account_token(self, store, monkeypatch):
        store.login_with_token("openai", "session-token-codex-abcdef012345")
        # Ensure no env key shadows
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        from nova_arsenal.llm.keys import resolve_api_key

        # account_token_for uses singleton — point singleton at our store
        import nova_arsenal.llm.account_auth as aa

        aa._store = store
        assert resolve_api_key("openai") == "session-token-codex-abcdef012345"

    def test_import_from_env_session(self, store, monkeypatch):
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-token-from-claude-code-xyz")
        imported = store.import_from_environment()
        assert any(c.provider == "anthropic" for c in imported)
        assert store.get_token("anthropic").startswith("oauth-token")

    def test_import_from_json_file(self, store, tmp_path):
        cred_file = tmp_path / "auth.json"
        cred_file.write_text(
            json.dumps({"claudeAiOauth": {"accessToken": "imported-claude-token-abc123xyz"}})
        )
        from nova_arsenal.llm.account_auth import _extract_token_from_paths

        token, source = _extract_token_from_paths([cred_file])
        assert token == "imported-claude-token-abc123xyz"
        assert str(cred_file) in source

    def test_logout(self, store):
        store.login_with_token("gemini", "g-token-123456789012345")
        assert store.remove("gemini") is True
        assert store.get_token("gemini") == ""
