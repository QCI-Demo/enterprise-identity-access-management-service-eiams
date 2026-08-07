"""Authorization domain contracts.

Framework-isolated interfaces for RBAC and policy evaluation.
Includes extension hooks for later RBAC middleware implementation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from eiams.shared.kernel import EntityId, TenantId, Timestamp
from eiams.shared.context import RequestContext
from eiams.domain.base import DomainEntity, TenantScopedRepository, DomainService
from eiams.domain.identity.contracts import UserId


class RoleId(EntityId):
    """Unique identifier for a role."""
    pass


class PermissionId(EntityId):
    """Unique identifier for a permission."""
    pass


class RoleAssignmentId(EntityId):
    """Unique identifier for a role assignment."""
    pass


class AuthorizationDecision(str, Enum):
    """Result of an authorization decision."""
    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class OperationContext:
    """Context for an operation being authorized.

    This value object captures the metadata needed for authorization
    decisions without coupling to HTTP or other transport details.
    """

    resource_type: str
    resource_id: str | None
    action: str
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serialize for logging and audit."""
        return {
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class Permission(DomainEntity):
    """Permission entity contract.

    Represents a granular permission that can be assigned to roles.
    """

    permission_id: PermissionId
    tenant_id: TenantId | None  # None for system permissions
    name: str
    description: str | None
    resource_type: str
    action: str
    created_at: Timestamp
    is_system_permission: bool = False

    @property
    def id(self) -> EntityId:
        return self.permission_id

    @property
    def permission_key(self) -> str:
        """The unique key for this permission (resource:action)."""
        return f"{self.resource_type}:{self.action}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Permission):
            return NotImplemented
        return self.permission_id == other.permission_id

    def __hash__(self) -> int:
        return hash(self.permission_id)


@dataclass(frozen=True)
class Role(DomainEntity):
    """Role entity contract.

    Represents a named role with associated permissions.
    """

    role_id: RoleId
    tenant_id: TenantId | None  # None for system roles
    name: str
    description: str | None
    permissions: tuple[PermissionId, ...]
    is_system_role: bool
    created_at: Timestamp
    updated_at: Timestamp

    @property
    def id(self) -> EntityId:
        return self.role_id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Role):
            return NotImplemented
        return self.role_id == other.role_id

    def __hash__(self) -> int:
        return hash(self.role_id)


@dataclass(frozen=True)
class RoleAssignment(DomainEntity):
    """Role assignment entity contract.

    Represents the assignment of a role to a user within a scope.

    ``scope`` identifies the resource the assignment is restricted to and
    ``scope_type`` names what kind of resource that is. The schema requires
    both or neither, so repositories default ``scope_type`` to
    ``"organization"`` when only a scope identifier is supplied.
    """

    assignment_id: RoleAssignmentId
    tenant_id: TenantId
    user_id: UserId
    role_id: RoleId
    scope: str | None  # Optional scope restriction (e.g., organization ID)
    created_at: Timestamp
    expires_at: Timestamp | None
    scope_type: str | None = None
    revoked_at: Timestamp | None = None

    @property
    def is_revoked(self) -> bool:
        """Check if the assignment has been revoked."""
        return self.revoked_at is not None

    @property
    def id(self) -> EntityId:
        return self.assignment_id

    @property
    def is_expired(self) -> bool:
        """Check if the assignment has expired."""
        if self.expires_at is None:
            return False
        return Timestamp.now() > self.expires_at

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RoleAssignment):
            return NotImplemented
        return self.assignment_id == other.assignment_id

    def __hash__(self) -> int:
        return hash(self.assignment_id)


class RoleRepository(TenantScopedRepository[Role, RoleId], ABC):
    """Repository contract for role persistence operations.

    Reads cover the tenant's own roles plus the platform-shared system role
    catalogue. Writes are always confined to the tenant in context; system
    roles cannot be modified through this repository.
    """

    @abstractmethod
    def find_by_name(
        self, context: RequestContext, name: str
    ) -> Role | None:
        """Find a role by name within the tenant scope."""
        ...

    @abstractmethod
    def find_system_roles(self, context: RequestContext) -> list[Role]:
        """Find all system-defined roles."""
        ...


class PermissionRepository(TenantScopedRepository[Permission, PermissionId], ABC):
    """Repository contract for permission persistence operations.

    As with roles, reads include the platform-shared system permission
    catalogue while writes stay inside the tenant in context.
    """

    @abstractmethod
    def find_by_key(
        self, context: RequestContext, resource_type: str, action: str
    ) -> Permission | None:
        """Find a permission by its resource type and action."""
        ...

    @abstractmethod
    def find_by_resource_type(
        self, context: RequestContext, resource_type: str
    ) -> list[Permission]:
        """Find all permissions for a resource type."""
        ...


class RoleAssignmentRepository(
    TenantScopedRepository[RoleAssignment, RoleAssignmentId], ABC
):
    """Repository contract for role assignment persistence operations."""

    @abstractmethod
    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[RoleAssignment]:
        """Find all role assignments for a user."""
        ...

    @abstractmethod
    def find_by_role(
        self, context: RequestContext, role_id: RoleId
    ) -> list[RoleAssignment]:
        """Find all role assignments for a role."""
        ...

    @abstractmethod
    def find_active_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[RoleAssignment]:
        """Find all non-expired role assignments for a user."""
        ...


class AuthorizationHook(Protocol):
    """Protocol for authorization extension hooks.

    This is a policy-neutral hook that receives operation metadata
    and returns an authorization decision. The actual policy evaluation
    logic will be implemented in later RBAC middleware.

    Implementers can use this hook to:
    - Log authorization attempts for audit
    - Integrate with external policy engines
    - Implement custom authorization rules
    """

    def authorize(
        self,
        context: RequestContext,
        operation: OperationContext,
    ) -> AuthorizationDecision:
        """Evaluate authorization for an operation.

        Args:
            context: The request context with actor and tenant info.
            operation: The operation being authorized.

        Returns:
            AuthorizationDecision indicating allow, deny, or not applicable.
        """
        ...


class AuthorizationService(DomainService, ABC):
    """Domain service contract for authorization operations.

    Note: This is an extension point. Actual policy evaluation
    will be implemented in later epics.
    """

    @abstractmethod
    def check_permission(
        self,
        context: RequestContext,
        permission_key: str,
        resource_id: str | None = None,
    ) -> bool:
        """Check if the actor has a specific permission."""
        ...

    @abstractmethod
    def get_effective_permissions(
        self,
        context: RequestContext,
        user_id: UserId,
    ) -> list[str]:
        """Get all effective permissions for a user."""
        ...

    @abstractmethod
    def assign_role(
        self,
        context: RequestContext,
        user_id: UserId,
        role_id: RoleId,
        scope: str | None = None,
        expires_at: Timestamp | None = None,
    ) -> RoleAssignment:
        """Assign a role to a user."""
        ...

    @abstractmethod
    def revoke_role(
        self,
        context: RequestContext,
        assignment_id: RoleAssignmentId,
    ) -> bool:
        """Revoke a role assignment."""
        ...

    def register_hook(self, hook: AuthorizationHook) -> None:
        """Register an authorization hook for policy evaluation.

        This is an extension point for later RBAC middleware.
        Default implementation does nothing.
        """
        pass
