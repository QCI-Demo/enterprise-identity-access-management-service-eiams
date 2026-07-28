"""Authorization entity models.

Permissions, Roles, and Role Assignments with tenant scoping
and uniqueness constraints for RBAC.
"""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from eiams.infrastructure.persistence.database import Base


class Permission(Base):
    """Permission entity defining a granular access right.
    
    Permissions define what actions can be taken on resources.
    System permissions (tenant_id=NULL) are available across all tenants.
    """
    
    __tablename__ = "permissions"
    
    # Primary key - immutable UUID
    id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    
    # Tenant ownership - NULL for system-wide permissions
    tenant_id: Mapped[str | None] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
    )
    
    # Permission identification
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    
    # Permission scope definition
    resource_type: Mapped[str] = mapped_column(
        String(63),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(
        String(63),
        nullable=False,
    )
    
    # System permission flag (cannot be deleted by tenants)
    is_system: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    
    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    
    # Relationships
    tenant = relationship("Tenant")
    role_permissions = relationship(
        "RolePermission",
        back_populates="permission",
        cascade="all, delete-orphan",
    )
    
    __table_args__ = (
        # Unique permission key (resource_type:action) per tenant
        UniqueConstraint(
            "tenant_id", "resource_type", "action",
            name="uq_permissions_tenant_resource_action",
        ),
        # Indexes
        Index("ix_permissions_tenant_id", "tenant_id"),
        Index("ix_permissions_resource_type_action", "resource_type", "action"),
        Index("ix_permissions_tenant_id_name", "tenant_id", "name"),
    )
    
    def __repr__(self) -> str:
        return (
            f"Permission(id={self.id!r}, name={self.name!r}, "
            f"resource_type={self.resource_type!r}, action={self.action!r})"
        )


class Role(Base):
    """Role entity grouping permissions for assignment.
    
    Roles aggregate permissions and can be assigned to users.
    System roles (tenant_id=NULL) are available across all tenants.
    """
    
    __tablename__ = "roles"
    
    # Primary key - immutable UUID
    id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    
    # Tenant ownership - NULL for system-wide roles
    tenant_id: Mapped[str | None] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
    )
    
    # Role identification
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    
    # System role flag (cannot be deleted by tenants)
    is_system: Mapped[bool] = mapped_column(
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
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    
    # Relationships
    tenant = relationship("Tenant")
    role_permissions = relationship(
        "RolePermission",
        back_populates="role",
        cascade="all, delete-orphan",
    )
    assignments = relationship(
        "RoleAssignment",
        back_populates="role",
        cascade="all, delete-orphan",
    )
    
    __table_args__ = (
        # Unique role name per tenant
        UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_name"),
        # Indexes
        Index("ix_roles_tenant_id", "tenant_id"),
        Index("ix_roles_tenant_id_name", "tenant_id", "name"),
        Index("ix_roles_is_system", "is_system"),
    )
    
    def __repr__(self) -> str:
        return f"Role(id={self.id!r}, name={self.name!r}, is_system={self.is_system})"


class RolePermission(Base):
    """Junction table linking roles to permissions.
    
    Many-to-many relationship between roles and permissions
    with tenant scope protection.
    """
    
    __tablename__ = "role_permissions"
    
    # Composite primary key
    role_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    permission_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    
    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    
    # Relationships
    role = relationship("Role", back_populates="role_permissions")
    permission = relationship("Permission", back_populates="role_permissions")
    
    __table_args__ = (
        # Indexes for efficient lookups
        Index("ix_role_permissions_permission_id", "permission_id"),
    )
    
    def __repr__(self) -> str:
        return f"RolePermission(role_id={self.role_id!r}, permission_id={self.permission_id!r})"


class RoleAssignment(Base):
    """Role assignment linking users to roles with scope.
    
    Represents the assignment of a role to a user, optionally
    scoped to a specific resource (e.g., organization).
    """
    
    __tablename__ = "role_assignments"
    
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
    
    # User receiving the role
    user_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    
    # Role being assigned
    role_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
    )
    
    # Optional scope restriction (e.g., organization_id, resource_id)
    scope_type: Mapped[str | None] = mapped_column(
        String(63),
        nullable=True,
    )
    scope_id: Mapped[str | None] = mapped_column(
        Uuid(as_uuid=False),
        nullable=True,
    )
    
    # Assignment lifecycle
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    # Relationships
    tenant = relationship("Tenant")
    user = relationship("User", back_populates="role_assignments")
    role = relationship("Role", back_populates="assignments")
    
    __table_args__ = (
        # Unique assignment per user-role-scope combination
        UniqueConstraint(
            "user_id", "role_id", "scope_type", "scope_id",
            name="uq_role_assignments_user_role_scope",
        ),
        # Indexes
        Index("ix_role_assignments_tenant_id", "tenant_id"),
        Index("ix_role_assignments_user_id", "user_id"),
        Index("ix_role_assignments_role_id", "role_id"),
        Index("ix_role_assignments_user_id_role_id", "user_id", "role_id"),
        Index("ix_role_assignments_scope_type_scope_id", "scope_type", "scope_id"),
        Index("ix_role_assignments_tenant_id_created_at", "tenant_id", "created_at"),
        # Check that scope_type and scope_id are both set or both null
        CheckConstraint(
            "(scope_type IS NULL AND scope_id IS NULL) OR "
            "(scope_type IS NOT NULL AND scope_id IS NOT NULL)",
            name="valid_scope_combination",
        ),
    )
    
    def __repr__(self) -> str:
        return (
            f"RoleAssignment(id={self.id!r}, user_id={self.user_id!r}, "
            f"role_id={self.role_id!r}, scope_type={self.scope_type!r})"
        )
