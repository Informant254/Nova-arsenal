"""
Nova-Arsenal Auth Audit Logging

Structured logging for authentication events: logins, failures, key usage, subscription changes.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("nova_arsenal.auth.audit")


class AuditEventType(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    OAUTH_LOGIN = "oauth_login"
    OAUTH_CALLBACK = "oauth_callback"
    TOKEN_REFRESH = "token_refresh"
    API_KEY_CREATED = "api_key_created"
    API_KEY_USED = "api_key_used"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_EXPIRED = "api_key_expired"
    SUBSCRIPTION_CREATED = "subscription_created"
    SUBSCRIPTION_UPGRADED = "subscription_upgraded"
    QUOTA_EXCEEDED = "quota_exceeded"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


@dataclass
class AuditEvent:
    event_type: AuditEventType
    user_id: Optional[int] = None
    email: Optional[str] = None
    ip_address: Optional[str] = None
    provider: Optional[str] = None
    key_prefix: Optional[str] = None
    tier: Optional[str] = None
    detail: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event_type.value,
            "user_id": self.user_id,
            "email": self.email,
            "ip": self.ip_address,
            "provider": self.provider,
            "key_prefix": self.key_prefix,
            "tier": self.tier,
            "detail": self.detail,
            "ts": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
        }


def audit_log(event: AuditEvent) -> None:
    """Emit a structured audit log entry."""
    data = event.to_dict()
    level = logging.WARNING if event.event_type in (
        AuditEventType.LOGIN_FAILURE,
        AuditEventType.UNAUTHORIZED_ACCESS,
        AuditEventType.QUOTA_EXCEEDED,
    ) else logging.INFO
    logger.log(level, "auth_audit %s", data)


def audit_login_success(user_id: int, email: str, ip: str) -> None:
    audit_log(AuditEvent(AuditEventType.LOGIN_SUCCESS, user_id=user_id, email=email, ip_address=ip))


def audit_login_failure(email: str, ip: str, reason: str = "") -> None:
    audit_log(AuditEvent(AuditEventType.LOGIN_FAILURE, email=email, ip_address=ip, detail=reason))


def audit_oauth_login(provider: str, user_id: int, email: str, ip: str, is_new: bool = False) -> None:
    audit_log(AuditEvent(
        AuditEventType.OAUTH_LOGIN,
        user_id=user_id, email=email, ip_address=ip, provider=provider,
        detail="new_user" if is_new else "existing_user",
    ))


def audit_api_key_created(user_id: int, key_prefix: str) -> None:
    audit_log(AuditEvent(AuditEventType.API_KEY_CREATED, user_id=user_id, key_prefix=key_prefix))


def audit_api_key_used(user_id: int, key_prefix: str) -> None:
    audit_log(AuditEvent(AuditEventType.API_KEY_USED, user_id=user_id, key_prefix=key_prefix))


def audit_api_key_revoked(user_id: int, key_prefix: str) -> None:
    audit_log(AuditEvent(AuditEventType.API_KEY_REVOKED, user_id=user_id, key_prefix=key_prefix))


def audit_subscription_upgraded(user_id: int, tier: str) -> None:
    audit_log(AuditEvent(AuditEventType.SUBSCRIPTION_UPGRADED, user_id=user_id, tier=tier))


def audit_quota_exceeded(user_id: int, tier: str) -> None:
    audit_log(AuditEvent(AuditEventType.QUOTA_EXCEEDED, user_id=user_id, tier=tier))


def audit_unauthorized(ip: str, detail: str = "") -> None:
    audit_log(AuditEvent(AuditEventType.UNAUTHORIZED_ACCESS, ip_address=ip, detail=detail))
