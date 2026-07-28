"""Credential entity models.

User credentials, OAuth clients, and API keys with secure
metadata storage (no raw secrets stored).
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
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from eiams.infrastructure.persistence.database import Base


class CredentialType(str, enum.Enum):
    """Type of user credential."""
    PASSWORD = "password"
    TOTP = "totp"  # Time-based One-Time Password
    WEBAUTHN = "webauthn"  # WebAuthn/FIDO2
    RECOVERY_CODE = "recovery_code"


class OAuthClientType(str, enum.Enum):
    """OAuth 2.0 client type."""
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


class ApiKeyStatus(str, enum.Enum):
    """API key lifecycle status."""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class UserCredential(Base):
    """User credential for authentication.
    
    Stores hashed credentials and metadata. Raw secrets are
    NEVER stored - only secure hashes or encrypted data.
    """
    
    __tablename__ = "user_credentials"
    
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
    
    # Credential type
    credential_type: Mapped[CredentialType] = mapped_column(
        Enum(CredentialType, name="credential_type", native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    
    # Secure credential data (hashed password, encrypted TOTP secret, etc.)
    # NEVER contains raw secrets
    credential_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    
    # Hash algorithm identifier (e.g., "argon2id", "bcrypt")
    hash_algorithm: Mapped[str] = mapped_column(
        String(63),
        nullable=False,
        default="argon2id",
    )
    
    # Credential status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    
    # Password policy tracking
    requires_reset: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    failed_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    # Relationships
    tenant = relationship("Tenant")
    user = relationship("User", back_populates="credentials")
    
    __table_args__ = (
        # One active credential per type per user
        UniqueConstraint(
            "user_id", "credential_type",
            name="uq_user_credentials_user_type",
        ),
        # Indexes
        Index("ix_user_credentials_tenant_id", "tenant_id"),
        Index("ix_user_credentials_user_id", "user_id"),
        Index("ix_user_credentials_user_id_type", "user_id", "credential_type"),
        Index("ix_user_credentials_tenant_id_created_at", "tenant_id", "created_at"),
        # Ensure credential type is valid
        CheckConstraint(
            "credential_type IN ('password', 'totp', 'webauthn', 'recovery_code')",
            name="valid_credential_type",
        ),
    )
    
    def __repr__(self) -> str:
        return (
            f"UserCredential(id={self.id!r}, user_id={self.user_id!r}, "
            f"credential_type={self.credential_type!r})"
        )


class OAuthClient(Base):
    """OAuth 2.0 client application.
    
    Stores client metadata and hashed secrets for confidential clients.
    Raw client secrets are NEVER stored.
    """
    
    __tablename__ = "oauth_clients"
    
    # Primary key - immutable UUID (also the OAuth client_id)
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
    
    # Client identification
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    
    # Client type
    client_type: Mapped[OAuthClientType] = mapped_column(
        Enum(OAuthClientType, name="oauth_client_type", native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    
    # Client secret hash (NULL for public clients)
    # NEVER contains raw secrets
    client_secret_hash: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )
    
    # Secret rotation tracking
    secret_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )
    secret_rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    # OAuth configuration - stored as comma-separated values for simplicity
    redirect_uris: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    allowed_scopes: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    allowed_grant_types: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="authorization_code,refresh_token",
    )
    
    # Token configuration
    access_token_lifetime_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3600,  # 1 hour
    )
    refresh_token_lifetime_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=2592000,  # 30 days
    )
    
    # Lifecycle status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    
    # Relationships
    tenant = relationship("Tenant")
    
    __table_args__ = (
        # Unique name within tenant
        UniqueConstraint("tenant_id", "name", name="uq_oauth_clients_tenant_name"),
        # Indexes
        Index("ix_oauth_clients_tenant_id", "tenant_id"),
        Index("ix_oauth_clients_is_active", "is_active"),
        Index("ix_oauth_clients_tenant_id_is_active", "tenant_id", "is_active"),
        Index("ix_oauth_clients_tenant_id_created_at", "tenant_id", "created_at"),
        # Ensure client type is valid
        CheckConstraint(
            "client_type IN ('confidential', 'public')",
            name="valid_oauth_client_type",
        ),
        # Confidential clients must have a secret hash
        CheckConstraint(
            "(client_type = 'public') OR (client_secret_hash IS NOT NULL)",
            name="confidential_client_requires_secret",
        ),
    )
    
    def __repr__(self) -> str:
        return (
            f"OAuthClient(id={self.id!r}, name={self.name!r}, "
            f"client_type={self.client_type!r})"
        )


class ApiKey(Base):
    """API key for programmatic access.
    
    Stores key metadata and hash. Raw API keys are NEVER stored -
    only the prefix for identification and the hash for validation.
    """
    
    __tablename__ = "api_keys"
    
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
    
    # Optional user owner (NULL for service-level keys)
    user_id: Mapped[str | None] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    
    # Key identification
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    
    # Key prefix for identification (e.g., "eiams_" + first 8 chars)
    key_prefix: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        unique=True,
    )
    
    # Key hash for validation - NEVER contains raw key
    key_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    
    # Allowed scopes (comma-separated)
    scopes: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    
    # Lifecycle status
    status: Mapped[ApiKeyStatus] = mapped_column(
        Enum(ApiKeyStatus, name="api_key_status", native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=ApiKeyStatus.ACTIVE,
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    # Relationships
    tenant = relationship("Tenant")
    user = relationship("User", back_populates="api_keys")
    
    __table_args__ = (
        # Unique name within tenant
        UniqueConstraint("tenant_id", "name", name="uq_api_keys_tenant_name"),
        # Indexes
        Index("ix_api_keys_tenant_id", "tenant_id"),
        Index("ix_api_keys_user_id", "user_id"),
        Index("ix_api_keys_key_prefix", "key_prefix"),
        Index("ix_api_keys_status", "status"),
        Index("ix_api_keys_tenant_id_status", "tenant_id", "status"),
        Index("ix_api_keys_user_id_status", "user_id", "status"),
        Index("ix_api_keys_tenant_id_created_at", "tenant_id", "created_at"),
        # Ensure status is valid
        CheckConstraint(
            "status IN ('active', 'revoked', 'expired')",
            name="valid_api_key_status",
        ),
    )
    
    def __repr__(self) -> str:
        return (
            f"ApiKey(id={self.id!r}, name={self.name!r}, "
            f"key_prefix={self.key_prefix!r}, status={self.status!r})"
        )
