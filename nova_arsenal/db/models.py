"""
Nova-Arsenal Database Models

SQLAlchemy models for storing agents, findings, users, and scope.
"""

import enum
from datetime import datetime

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


class User(Base):
    """User model for authentication and authorization."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.ANALYST)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    agents = relationship("Agent", back_populates="owner")
    findings_verified = relationship("Finding", back_populates="verifier")

    def __repr__(self) -> str:
        return f"<User {self.username}>"


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
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    created_at = Column(DateTime, default=datetime.utcnow)
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
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Scope {self.target}>"
