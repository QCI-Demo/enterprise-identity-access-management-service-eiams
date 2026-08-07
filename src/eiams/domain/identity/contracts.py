"""Identity domain contracts.

Framework-isolated interfaces for identity management operations.
These contracts define the structure and behavior expectations
without any implementation details.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

from eiams.shared.kernel import EntityId, TenantId, Timestamp
from eiams.shared.context import RequestContext
from eiams.domain.base import DomainEntity, TenantScopedRepository, DomainService


class UserId(EntityId):
    """Unique identifier for a user entity."""
    pass


class OrganizationId(EntityId):
    """Unique identifier for an organization entity."""
    pass


class MembershipId(EntityId):
    """Unique identifier for a membership relationship."""
    pass


class UserStatus(str, Enum):
    """Status of a user account."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


class MembershipStatus(str, Enum):
    """Status of a membership relationship."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"


class OrganizationStatus(str, Enum):
    """Lifecycle status of an organization.

    The approved organization schema has no durable status column, so
    repositories materialize existing rows as ``ACTIVE``. Deactivation is a
    terminal transition that removes the organization from the tenant scope.
    """

    ACTIVE = "active"
    INACTIVE = "inactive"


@dataclass(frozen=True)
class User(DomainEntity):
    """User identity entity contract.

    Represents an authenticated user in the system with their
    identity attributes and account status.
    """

    user_id: UserId
    tenant_id: TenantId
    email: str
    display_name: str
    status: UserStatus
    created_at: Timestamp
    updated_at: Timestamp
    username: str | None = None
    email_verified_at: Timestamp | None = None
    last_login_at: Timestamp | None = None

    @property
    def id(self) -> EntityId:
        return self.user_id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, User):
            return NotImplemented
        return self.user_id == other.user_id

    def __hash__(self) -> int:
        return hash(self.user_id)


@dataclass(frozen=True)
class Organization(DomainEntity):
    """Organization entity contract.

    Represents an organizational unit that can contain users
    through membership relationships.
    """

    organization_id: OrganizationId
    tenant_id: TenantId
    name: str
    description: str | None
    parent_id: OrganizationId | None
    created_at: Timestamp
    updated_at: Timestamp
    slug: str | None = None
    status: OrganizationStatus = OrganizationStatus.ACTIVE

    @property
    def id(self) -> EntityId:
        return self.organization_id

    @property
    def is_active(self) -> bool:
        """Check if the organization is currently active."""
        return self.status == OrganizationStatus.ACTIVE

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Organization):
            return NotImplemented
        return self.organization_id == other.organization_id

    def __hash__(self) -> int:
        return hash(self.organization_id)


@dataclass(frozen=True)
class Membership(DomainEntity):
    """Membership relationship entity contract.

    Represents the association between a user and an organization,
    including the role they hold within that organization.
    """

    membership_id: MembershipId
    tenant_id: TenantId
    user_id: UserId
    organization_id: OrganizationId
    role: str
    status: MembershipStatus
    created_at: Timestamp
    updated_at: Timestamp

    @property
    def id(self) -> EntityId:
        return self.membership_id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Membership):
            return NotImplemented
        return self.membership_id == other.membership_id

    def __hash__(self) -> int:
        return hash(self.membership_id)


class UserRepository(TenantScopedRepository[User, UserId], ABC):
    """Repository contract for user persistence operations."""

    @abstractmethod
    def find_by_email(
        self, context: RequestContext, email: str
    ) -> User | None:
        """Find a user by email within the tenant scope."""
        ...

    @abstractmethod
    def find_by_status(
        self,
        context: RequestContext,
        status: UserStatus,
        offset: int = 0,
        limit: int = 100,
    ) -> list[User]:
        """Find users with a given status within the tenant scope."""
        ...


class OrganizationRepository(
    TenantScopedRepository[Organization, OrganizationId], ABC
):
    """Repository contract for organization persistence operations."""

    @abstractmethod
    def find_by_name(
        self, context: RequestContext, name: str
    ) -> Organization | None:
        """Find an organization by name within the tenant scope."""
        ...

    @abstractmethod
    def find_children(
        self, context: RequestContext, parent_id: OrganizationId
    ) -> list[Organization]:
        """Find all child organizations of a parent."""
        ...


class MembershipRepository(TenantScopedRepository[Membership, MembershipId], ABC):
    """Repository contract for membership persistence operations."""

    @abstractmethod
    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[Membership]:
        """Find all memberships for a user."""
        ...

    @abstractmethod
    def find_by_organization(
        self, context: RequestContext, organization_id: OrganizationId
    ) -> list[Membership]:
        """Find all memberships in an organization."""
        ...

    @abstractmethod
    def find_by_user_and_organization(
        self,
        context: RequestContext,
        user_id: UserId,
        organization_id: OrganizationId,
    ) -> Membership | None:
        """Find a specific membership relationship."""
        ...


class IdentityService(DomainService, ABC):
    """Domain service contract for identity operations.

    Coordinates complex identity operations that span multiple
    entities or require business rule enforcement.
    """

    @abstractmethod
    def create_user(
        self,
        context: RequestContext,
        email: str,
        display_name: str,
    ) -> User:
        """Create a new user identity."""
        ...

    @abstractmethod
    def update_user_status(
        self,
        context: RequestContext,
        user_id: UserId,
        status: UserStatus,
    ) -> User:
        """Update a user's account status."""
        ...

    @abstractmethod
    def create_organization(
        self,
        context: RequestContext,
        name: str,
        description: str | None = None,
        parent_id: OrganizationId | None = None,
    ) -> Organization:
        """Create a new organization."""
        ...

    @abstractmethod
    def add_member(
        self,
        context: RequestContext,
        user_id: UserId,
        organization_id: OrganizationId,
        role: str,
    ) -> Membership:
        """Add a user to an organization with a role."""
        ...
