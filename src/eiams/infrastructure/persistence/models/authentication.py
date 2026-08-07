"""Authentication entity models.

Sessions and refresh tokens for authentication lifecycle management.
"""

import enum
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from eiams.infrastructure.persistence.database import Base


class SessionStatus(str, enum.Enum):
    """Authentication session lifecycle status."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    LOGGED_OUT = "logged_out"


class Session(Base):
    """Authentication session for a user.
    
    Tracks active user sessions with metadata for audit
    and session management.
    """
    
    __tablename__ = "sessions"
    
    # Primary key - immutable UUID
    id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    
    # Tenant ownership
    tenant_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    
    # User reference
    user_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    
    # Session lifecycle
    status: Mapped[SessionStatus] = mapped_column(
        Enum(SessionStatus, name="session_status", native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=SessionStatus.ACTIVE,
    )
    
    # Session metadata (for audit, not secrets)
    ip_address: Mapped[str | None] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
    )
    user_agent: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    device_fingerprint: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    # Relationships
    tenant = relationship("Tenant")
    user = relationship("User", back_populates="sessions")
    refresh_tokens = relationship(
        "RefreshToken",
        back_populates="session",
        cascade="all, delete-orphan",
    )
    
    __table_args__ = (
        # Indexes
        Index("ix_sessions_tenant_id", "tenant_id"),
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_status", "status"),
        Index("ix_sessions_user_id_status", "user_id", "status"),
        Index("ix_sessions_tenant_id_status_expires_at", "tenant_id", "status", "expires_at"),
        Index("ix_sessions_expires_at", "expires_at"),
        Index("ix_sessions_tenant_id_created_at", "tenant_id", "created_at"),
        # Ensure status is valid
        CheckConstraint(
            "status IN ('active', 'expired', 'revoked', 'logged_out')",
            name="valid_session_status",
        ),
    )
    
    def __repr__(self) -> str:
        return (
            f"Session(id={self.id!r}, user_id={self.user_id!r}, "
            f"status={self.status!r})"
        )


class RefreshToken(Base):
    """Refresh token for session renewal.
    
    Stores refresh token metadata and hash for rotation.
    Raw tokens are NEVER stored - only hashes for validation.
    """
    
    __tablename__ = "refresh_tokens"
    
    # Primary key - immutable UUID
    id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    
    # Tenant ownership
    tenant_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    
    # Session reference
    session_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    
    # User reference (denormalized for efficient lookups)
    user_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    
    # Token hash - NEVER contains raw token
    token_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        unique=True,
    )
    
    # Token family for rotation detection
    # All tokens in a rotation chain share the same family
    token_family: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        nullable=False,
    )
    
    # Previous token in rotation chain (for replay detection)
    previous_token_id: Mapped[str | None] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"),
        nullable=True,
    )
    
    # Token status
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    # Relationships
    tenant = relationship("Tenant")
    session = relationship("Session", back_populates="refresh_tokens")
    user = relationship("User")
    previous_token = relationship(
        "RefreshToken",
        remote_side=[id],
        backref="next_token",
    )
    
    __table_args__ = (
        # Indexes
        Index("ix_refresh_tokens_tenant_id", "tenant_id"),
        Index("ix_refresh_tokens_session_id", "session_id"),
        Index("ix_refresh_tokens_user_id", "user_id"),
        Index("ix_refresh_tokens_token_hash", "token_hash"),
        Index("ix_refresh_tokens_token_family", "token_family"),
        Index("ix_refresh_tokens_is_revoked", "is_revoked"),
        Index("ix_refresh_tokens_token_family_is_revoked", "token_family", "is_revoked"),
        Index("ix_refresh_tokens_expires_at", "expires_at"),
        Index("ix_refresh_tokens_tenant_id_created_at", "tenant_id", "created_at"),
        Index("ix_refresh_tokens_user_id_is_revoked", "user_id", "is_revoked"),
    )
    
    def __repr__(self) -> str:
        return (
            f"RefreshToken(id={self.id!r}, session_id={self.session_id!r}, "
            f"is_revoked={self.is_revoked})"
        )
