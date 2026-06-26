"""
Nova-Arsenal Database Models

SQLAlchemy models for storing agents, findings, users, and scope.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class UserRole(enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AgentStatus(enum.Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingSeverity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OAuthProvider(enum.Enum):
    GITHUB = "github"
    GOOGLE = "google"
    GITLAB = "gitlab"


class SubscriptionTier(enum.Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class User(Base):
    """User model for authentication and authorization."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.ANALYST)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    agents = relationship("Agent", back_populates="owner")
    findings_verified = relationship("Finding", back_populates="verifier")
    oauth_accounts = relationship("OAuthAccount", back_populates="user", cascade="all, delete-orphan")
    subscription = relationship("Subscription", back_populates="user", uselist=False)
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class OAuthAccount(Base):
    """OAuth-linked account for social login."""

    __tablename__ = "oauth_accounts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    provider = Column(Enum(OAuthProvider), nullable=False)
    provider_user_id = Column(String(255), nullable=False)
    provider_email = Column(String(255))
    access_token = Column(String(1024))
    refresh_token = Column(String(1024))
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="oauth_accounts")

    def __repr__(self) -> str:
        return f"<OAuthAccount {self.provider.value}:{self.provider_user_id}>"


class Subscription(Base):
    """User subscription tier for API access."""

    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    tier = Column(Enum(SubscriptionTier), default=SubscriptionTier.FREE)
    api_calls_limit = Column(Integer, default=100)
    api_calls_used = Column(Integer, default=0)
    api_calls_reset_at = Column(DateTime)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

    user = relationship("User", back_populates="subscription")

    def __repr__(self) -> str:
        return f"<Subscription {self.tier.value} user={self.user_id}>"


class ApiKey(Base):
    """API key for programmatic access linked to subscription."""

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    key_prefix = Column(String(8), nullable=False)
    key_hash = Column(String(255), nullable=False)
    name = Column(String(100), default="default")
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="api_keys")

    def __repr__(self) -> str:
        return f"<ApiKey {self.key_prefix}... user={self.user_id}>"


class Agent(Base):
    """Agent model for tracking security agents."""

    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    target = Column(String(500), nullable=False)
    objective = Column(Text)
    status = Column(Enum(AgentStatus), default=AgentStatus.IDLE)
    owner_id = Column(Integer, ForeignKey("users.id"))
    config = Column(Text)  # JSON string
    max_steps = Column(Integer, default=40)
    current_step = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    owner = relationship("User", back_populates="agents")
    findings = relationship("Finding", back_populates="agent")

    def __repr__(self) -> str:
        return f"<Agent {self.name} targeting {self.target}>"


class Finding(Base):
    """Finding model for storing discovered vulnerabilities."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"))
    title = Column(String(500), nullable=False)
    severity = Column(Enum(FindingSeverity))
    description = Column(Text)
    evidence = Column(Text)
    endpoint = Column(String(500))
    cwe_id = Column(String(50))
    cvss_score = Column(Float)
    verified = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    remediation = Column(Text)
    references = Column(Text)  # JSON string
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    verified_at = Column(DateTime)
    verified_by = Column(Integer, ForeignKey("users.id"))

    # Relationships
    agent = relationship("Agent", back_populates="findings")
    verifier = relationship("User", back_populates="findings_verified")

    def __repr__(self) -> str:
        return f"<Finding {self.title} [{self.severity.value}]>"


class Scope(Base):
    """Scope model for managing target scope."""

    __tablename__ = "scope"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(500), nullable=False)
    description = Column(String(500))
    owner_id = Column(Integer, ForeignKey("users.id"))
    is_active = Column(Boolean, default=True)
    is_wildcard = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return f"<Scope {self.target}>"


class ChatSession(Base):
    """Chat session model for conversational history."""

    __tablename__ = "chat_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(36), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    title = Column(String(255), default="New Chat")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    messages = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan",
                            order_by="ChatMessage.timestamp")

    def __repr__(self) -> str:
        return f"<ChatSession {self.session_id}>"


class ChatMessage(Base):
    """Individual message within a chat session."""

    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(36), ForeignKey("chat_sessions.session_id"), nullable=False)
    role = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    metadata_json = Column(Text)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    session = relationship("ChatSession", back_populates="messages")

    def __repr__(self) -> str:
        return f"<ChatMessage {self.role}:{self.content[:50]}>"


class ScheduleEntryModel(Base):
    """Persistent model for schedule entries."""

    __tablename__ = "schedule_entries"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    cron = Column(String(100), nullable=False)
    target = Column(String(500), nullable=False)
    task_type = Column(String(100), default="security_scan")
    objective = Column(Text)
    max_steps = Column(Integer, default=40)
    status = Column(String(20), default="active")
    run_count = Column(Integer, default=0)
    last_run = Column(DateTime, nullable=True)
    last_result = Column(Text)
    next_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return f"<ScheduleEntryModel {self.name}>"


class AgentRunResult(Base):
    """Persistent model for agent run results."""

    __tablename__ = "agent_run_results"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    status = Column(String(20), default="running")
    steps_taken = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    summary = Column(Text)
    result_json = Column(Text)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    agent = relationship("Agent")

    def __repr__(self) -> str:
        return f"<AgentRunResult agent={self.agent_id} status={self.status}>"


class ChatSessionMessage(Base):
    """Alias for ChatMessage for backwards compatibility."""
    __abstract__ = True
