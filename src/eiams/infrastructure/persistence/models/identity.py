"""Identity entity models.

Organizations, Users, and Memberships with tenant ownership
and cross-tenant protection constraints.
"""

import enum
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
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


class UserStatus(str, enum.Enum):
    """User account lifecycle status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


class MembershipStatus(str, enum.Enum):
    """Membership relationship status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"


class Organization(Base):
    """Organization entity within a tenant.
    
    Organizations provide hierarchical grouping of users within
    a tenant. They can have a parent organization for nested structures.
    """
    
    __tablename__ = "organizations"
    
    # Primary key - immutable UUID
    id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    
    # Tenant ownership - required, immutable after creation
    tenant_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    
    # Organization identification
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    slug: Mapped[str] = mapped_column(
        String(63),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    
    # Hierarchical structure - self-referential parent
    parent_id: Mapped[str | None] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("organizations.id", ondelete="SET NULL"),
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
    
    # Relationships
    tenant = relationship("Tenant", back_populates="organizations")
    parent = relationship("Organization", remote_side=[id], backref="children")
    memberships = relationship(
        "Membership",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    
    __table_args__ = (
        # Unique name within tenant
        UniqueConstraint("tenant_id", "name", name="uq_organizations_tenant_name"),
        # Unique slug within tenant
        UniqueConstraint("tenant_id", "slug", name="uq_organizations_tenant_slug"),
        # Index for tenant-scoped lookups
        Index("ix_organizations_tenant_id", "tenant_id"),
        Index("ix_organizations_tenant_id_name", "tenant_id", "name"),
        Index("ix_organizations_tenant_id_created_at", "tenant_id", "created_at"),
        # Index for hierarchy queries
        Index("ix_organizations_parent_id", "parent_id"),
    )
    
    def __repr__(self) -> str:
        return f"Organization(id={self.id!r}, name={self.name!r}, tenant_id={self.tenant_id!r})"


class User(Base):
    """User identity entity within a tenant.
    
    Users represent authenticated identities that can be assigned
    roles and memberships within organizations.
    """
    
    __tablename__ = "users"
    
    # Primary key - immutable UUID
    id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    
    # Tenant ownership - required, immutable after creation
    tenant_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    
    # User identification
    email: Mapped[str] = mapped_column(
        String(320),  # RFC 5321 max email length
        nullable=False,
    )
    username: Mapped[str | None] = mapped_column(
        String(63),
        nullable=True,
    )
    display_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    
    # Lifecycle status
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, name="user_status", native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=UserStatus.PENDING_VERIFICATION,
    )
    
    # Email verification tracking
    email_verified_at: Mapped[datetime | None] = mapped_column(
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
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    memberships = relationship(
        "Membership",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    credentials = relationship(
        "UserCredential",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    sessions = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    api_keys = relationship(
        "ApiKey",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    role_assignments = relationship(
        "RoleAssignment",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    
    __table_args__ = (
        # Unique email within tenant
        UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
        # Unique username within tenant (if provided)
        UniqueConstraint("tenant_id", "username", name="uq_users_tenant_username"),
        # Indexes
        Index("ix_users_tenant_id", "tenant_id"),
        Index("ix_users_status", "status"),
        Index("ix_users_tenant_id_email", "tenant_id", "email"),
        Index("ix_users_tenant_id_status", "tenant_id", "status"),
        Index("ix_users_tenant_id_created_at", "tenant_id", "created_at"),
        # Ensure status is valid
        CheckConstraint(
            "status IN ('active', 'inactive', 'suspended', 'pending_verification')",
            name="valid_user_status",
        ),
    )
    
    def __repr__(self) -> str:
        return f"User(id={self.id!r}, email={self.email!r}, tenant_id={self.tenant_id!r})"


class Membership(Base):
    """Membership relationship between user and organization.
    
    Represents a user's association with an organization within
    a tenant, including their role within that organization.
    """
    
    __tablename__ = "memberships"
    
    # Primary key - immutable UUID
    id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    
    # Tenant ownership - must match user and organization tenant
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
    
    # Organization reference
    organization_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    
    # Role within organization (e.g., "owner", "admin", "member")
    role: Mapped[str] = mapped_column(
        String(63),
        nullable=False,
        default="member",
    )
    
    # Lifecycle status
    status: Mapped[MembershipStatus] = mapped_column(
        Enum(MembershipStatus, name="membership_status", native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=MembershipStatus.ACTIVE,
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
    user = relationship("User", back_populates="memberships")
    organization = relationship("Organization", back_populates="memberships")
    
    __table_args__ = (
        # Unique membership per user-organization pair
        UniqueConstraint(
            "user_id", "organization_id",
            name="uq_memberships_user_organization",
        ),
        # Indexes
        Index("ix_memberships_tenant_id", "tenant_id"),
        Index("ix_memberships_user_id", "user_id"),
        Index("ix_memberships_organization_id", "organization_id"),
        Index("ix_memberships_status", "status"),
        Index("ix_memberships_user_id_status", "user_id", "status"),
        Index("ix_memberships_organization_id_status", "organization_id", "status"),
        Index("ix_memberships_tenant_id_created_at", "tenant_id", "created_at"),
        # Ensure status is valid
        CheckConstraint(
            "status IN ('active', 'inactive', 'pending')",
            name="valid_membership_status",
        ),
    )
    
    def __repr__(self) -> str:
        return (
            f"Membership(id={self.id!r}, user_id={self.user_id!r}, "
            f"organization_id={self.organization_id!r}, role={self.role!r})"
        )
