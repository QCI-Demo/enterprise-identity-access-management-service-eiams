"""Tenant entity model.

Tenants are the root of the multi-tenant hierarchy. All tenant-scoped
entities reference a tenant through tenant_id foreign keys.
"""

import enum
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    Index,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from eiams.infrastructure.persistence.database import Base


class TenantStatus(str, enum.Enum):
    """Tenant lifecycle status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_SETUP = "pending_setup"


class Tenant(Base):
    """Tenant entity representing a multi-tenant boundary.
    
    Tenants are the root isolation unit. All tenant-scoped entities
    must reference a tenant to ensure data isolation.
    """
    
    __tablename__ = "tenants"
    
    # Primary key - immutable UUID
    id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    
    # Tenant identification
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
    )
    slug: Mapped[str] = mapped_column(
        String(63),
        nullable=False,
        unique=True,
    )
    
    # Optional metadata
    display_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    
    # Lifecycle status
    status: Mapped[TenantStatus] = mapped_column(
        Enum(TenantStatus, name="tenant_status", native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=TenantStatus.PENDING_SETUP,
    )
    
    # Timestamps - immutable created_at, mutable updated_at
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
    
    # Relationships (defined for ORM convenience, not required for migrations)
    organizations = relationship(
        "Organization",
        back_populates="tenant",
        cascade="all, delete-orphan",
    )
    users = relationship(
        "User",
        back_populates="tenant",
        cascade="all, delete-orphan",
    )
    
    __table_args__ = (
        # Ensure status is valid
        CheckConstraint(
            "status IN ('active', 'inactive', 'suspended', 'pending_setup')",
            name="valid_tenant_status",
        ),
        # Indexes
        Index("ix_tenants_name", "name"),
        Index("ix_tenants_slug", "slug"),
        Index("ix_tenants_status", "status"),
        Index("ix_tenants_status_created_at", "status", "created_at"),
    )
    
    def __repr__(self) -> str:
        return f"Tenant(id={self.id!r}, name={self.name!r}, status={self.status!r})"
