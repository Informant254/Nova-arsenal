"""
Tests for Nova-Arsenal Authentication (OAuth, API Keys, Subscriptions, Audit).
"""

import hashlib
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── OAuth State Tests ─────────────────────────────────────────────────────────

class TestOAuthState:
    def test_generate_and_verify_state(self):
        from nova_arsenal.auth.oauth import generate_oauth_state, verify_oauth_state

        state = generate_oauth_state("github", "/dashboard")
        assert verify_oauth_state(state, "github")

    def test_state_wrong_provider(self):
        from nova_arsenal.auth.oauth import generate_oauth_state, verify_oauth_state

        state = generate_oauth_state("github", "/dashboard")
        assert not verify_oauth_state(state, "google")

    def test_state_tampered(self):
        from nova_arsenal.auth.oauth import generate_oauth_state, verify_oauth_state

        state = generate_oauth_state("github", "/dashboard")
        tampered = state[:-4] + "XXXX"
        assert not verify_oauth_state(tampered, "github")

    def test_extract_redirect(self):
        from nova_arsenal.auth.oauth import extract_redirect, generate_oauth_state

        state = generate_oauth_state("github", "/dashboard")
        assert extract_redirect(state) == "/dashboard"


class TestPKCE:
    def test_generate_pkce(self):
        from nova_arsenal.auth.oauth import PKCEChallenge

        pkce = PKCEChallenge.generate()
        assert len(pkce.code_verifier) <= 128
        assert len(pkce.code_challenge) == 43
        assert pkce.code_verifier != ""

    def test_pkce_in_state(self):
        from nova_arsenal.auth.oauth import (
            PKCEChallenge,
            extract_pkce_verifier,
            generate_oauth_state,
            verify_oauth_state,
        )

        pkce = PKCEChallenge.generate()
        state = generate_oauth_state("github", "/dashboard", pkce)
        assert verify_oauth_state(state, "github")
        assert extract_pkce_verifier(state) == pkce.code_verifier

    def test_pkce_challenge_deterministic(self):
        from nova_arsenal.auth.oauth import PKCEChallenge
        import hashlib
        import base64

        pkce = PKCEChallenge.generate()
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(pkce.code_verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        assert pkce.code_challenge == expected


class TestOAuthProviders:
    def test_github_authorize_url(self):
        from nova_arsenal.auth.oauth import GitHubOAuthProvider

        with patch("nova_arsenal.auth.oauth.get_config") as mock_cfg:
            mock_cfg.return_value.auth.oauth.github_client_id = "test_id"
            mock_cfg.return_value.auth.oauth.github_client_secret = "secret"
            mock_cfg.return_value.auth.oauth.github_redirect_uri = "http://callback"
            provider = GitHubOAuthProvider()
            url = provider.get_authorize_url("test_state", "test_challenge")
            assert "client_id=test_id" in url
            assert "state=test_state" in url
            assert "code_challenge=test_challenge" in url
            assert "code_challenge_method=S256" in url

    def test_github_authorize_url_no_pkce(self):
        from nova_arsenal.auth.oauth import GitHubOAuthProvider

        with patch("nova_arsenal.auth.oauth.get_config") as mock_cfg:
            mock_cfg.return_value.auth.oauth.github_client_id = "test_id"
            mock_cfg.return_value.auth.oauth.github_client_secret = "secret"
            mock_cfg.return_value.auth.oauth.github_redirect_uri = "http://callback"
            provider = GitHubOAuthProvider()
            url = provider.get_authorize_url("test_state")
            assert "code_challenge" not in url

    def test_google_authorize_url(self):
        from nova_arsenal.auth.oauth import GoogleOAuthProvider

        with patch("nova_arsenal.auth.oauth.get_config") as mock_cfg:
            mock_cfg.return_value.auth.oauth.google_client_id = "g_id"
            mock_cfg.return_value.auth.oauth.google_client_secret = "g_secret"
            mock_cfg.return_value.auth.oauth.google_redirect_uri = "http://g_callback"
            provider = GoogleOAuthProvider()
            url = provider.get_authorize_url("g_state", "g_challenge")
            assert "client_id=g_id" in url
            assert "code_challenge=g_challenge" in url

    def test_get_oauth_provider(self):
        from nova_arsenal.auth.oauth import get_oauth_provider

        with patch("nova_arsenal.auth.oauth.get_config"):
            github = get_oauth_provider("github")
            assert github.provider_name() == "github"
            google = get_oauth_provider("google")
            assert google.provider_name() == "google"

    def test_unsupported_provider(self):
        from nova_arsenal.auth.oauth import get_oauth_provider

        with pytest.raises(ValueError, match="Unsupported"):
            get_oauth_provider("facebook")


# ── Audit Logging Tests ──────────────────────────────────────────────────────

class TestAuditLogging:
    def test_audit_event_to_dict(self):
        from nova_arsenal.auth.audit import AuditEvent, AuditEventType

        event = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=1,
            email="test@example.com",
            ip_address="127.0.0.1",
        )
        d = event.to_dict()
        assert d["event"] == "login_success"
        assert d["user_id"] == 1
        assert d["email"] == "test@example.com"
        assert "ts" in d

    def test_audit_log_functions(self):
        from nova_arsenal.auth.audit import (
            audit_api_key_created,
            audit_api_key_revoked,
            audit_login_failure,
            audit_login_success,
            audit_oauth_login,
            audit_subscription_upgraded,
            audit_unauthorized,
        )
        # Just verify they don't raise
        audit_login_success(1, "test@test.com", "127.0.0.1")
        audit_login_failure("test@test.com", "127.0.0.1", "bad password")
        audit_oauth_login("github", 1, "test@test.com", "127.0.0.1", True)
        audit_api_key_created(1, "na_abc123")
        audit_api_key_revoked(1, "na_abc123")
        audit_subscription_upgraded(1, "pro")
        audit_unauthorized("127.0.0.1", "invalid_key")


# ── Rate Limiter Tests ───────────────────────────────────────────────────────

class TestRateLimiter:
    def test_token_bucket_consume(self):
        from nova_arsenal.auth.rate_limit import TokenBucket

        bucket = TokenBucket(capacity=5, refill_rate=10.0)
        for _ in range(5):
            assert bucket.consume()
        assert not bucket.consume()

    def test_token_bucket_refill(self):
        from nova_arsenal.auth.rate_limit import TokenBucket

        bucket = TokenBucket(capacity=2, refill_rate=100.0)
        assert bucket.consume()
        assert bucket.consume()
        assert not bucket.consume()
        # Simulate time passing
        bucket.last_refill -= 0.05  # 50ms ago
        assert bucket.consume()

    def test_retry_after(self):
        from nova_arsenal.auth.rate_limit import TokenBucket

        bucket = TokenBucket(capacity=2, refill_rate=10.0)
        assert bucket.consume()
        assert bucket.consume()
        # now empty
        retry = bucket.retry_after()
        assert retry > 0.0


# ── API Key Tests ─────────────────────────────────────────────────────────────

class TestAPIKeyGeneration:
    def test_generate_api_key(self):
        from nova_arsenal.auth.routes import generate_api_key

        full_key, prefix, key_hash = generate_api_key()
        assert full_key.startswith("na_")
        assert len(full_key) == 67  # na_ + 64 hex chars
        assert len(prefix) == 19    # na_ + 16 hex chars
        assert len(key_hash) == 64  # SHA256 hex
        assert full_key[:19] == prefix

    def test_key_hash_matches(self):
        from nova_arsenal.auth.routes import generate_api_key

        full_key, _, key_hash = generate_api_key()
        expected = hashlib.sha256(full_key.encode()).hexdigest()
        assert key_hash == expected

    def test_unique_keys(self):
        from nova_arsenal.auth.routes import generate_api_key

        keys = {generate_api_key()[0] for _ in range(100)}
        assert len(keys) == 100


# ── Cleanup Tests ─────────────────────────────────────────────────────────────

class TestCleanup:
    def test_cleanup_task_exists(self):
        from nova_arsenal.auth.cleanup import cleanup_expired_api_keys, start_cleanup_task
        assert callable(cleanup_expired_api_keys)
        assert callable(start_cleanup_task)
