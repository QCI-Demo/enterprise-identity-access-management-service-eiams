"""Base domain contracts for all IAM modules.

These abstract base classes define the foundational contracts that
all domain modules implement. They are framework-isolated and have
no dependencies on persistence or web frameworks.
"""

from abc import ABC, abstractmethod
from typing import Any, ClassVar, Generic, TypeVar

from eiams.shared.kernel import EntityId, Timestamp
from eiams.shared.context import RepositoryScope, RequestContext, TenantPredicate


T = TypeVar("T", bound="DomainEntity")
ID = TypeVar("ID", bound=EntityId)


class DomainEntity(ABC):
    """Base class for domain entities.

    Domain entities have a unique identity that persists across
    state changes. They encapsulate business logic and invariants.
    """

    @property
    @abstractmethod
    def id(self) -> EntityId:
        """The unique identifier of this entity."""
        ...

    @abstractmethod
    def __eq__(self, other: object) -> bool:
        """Entities are compared by identity."""
        ...

    @abstractmethod
    def __hash__(self) -> int:
        """Entities must be hashable by identity."""
        ...


class DomainEvent(ABC):
    """Base class for domain events.

    Domain events represent significant occurrences in the domain
    that other parts of the system may need to react to.
    """

    @property
    @abstractmethod
    def event_type(self) -> str:
        """The type identifier of this event."""
        ...

    @property
    @abstractmethod
    def occurred_at(self) -> Timestamp:
        """When this event occurred."""
        ...

    @property
    @abstractmethod
    def correlation_id(self) -> str:
        """The correlation ID for tracing."""
        ...

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Serialize event for storage or transmission."""
        ...


class Repository(ABC, Generic[T, ID]):
    """Base contract for domain repositories.

    Repositories provide persistence operations for domain entities.
    They are defined as contracts in the domain layer and implemented
    in the infrastructure layer.
    """

    @abstractmethod
    def find_by_id(self, context: RequestContext, entity_id: ID) -> T | None:
        """Find an entity by its identifier.

        Args:
            context: Request context for tenant scope and audit.
            entity_id: The unique identifier of the entity.

        Returns:
            The entity if found, None otherwise.
        """
        ...

    @abstractmethod
    def save(self, context: RequestContext, entity: T) -> T:
        """Persist an entity.

        Args:
            context: Request context for tenant scope and audit.
            entity: The entity to persist.

        Returns:
            The persisted entity.
        """
        ...

    @abstractmethod
    def delete(self, context: RequestContext, entity_id: ID) -> bool:
        """Delete an entity by its identifier.

        Args:
            context: Request context for tenant scope and audit.
            entity_id: The unique identifier of the entity.

        Returns:
            True if the entity was deleted, False if not found.
        """
        ...


class ReadableRepository(ABC, Generic[T, ID]):
    """Read primitives shared by every repository regardless of scope."""

    #: Isolation scope every operation of the repository runs in.
    scope: ClassVar[RepositoryScope]

    @abstractmethod
    def exists(self, context: RequestContext, entity_id: ID) -> bool:
        """Check whether an entity is visible in the caller's scope.

        Args:
            context: Request context for scope resolution and audit.
            entity_id: The unique identifier of the entity.

        Returns:
            True if the entity exists and is in scope, False otherwise.
        """
        ...

    @abstractmethod
    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[T]:
        """List entities visible in the caller's scope, most recent first.

        Args:
            context: Request context for scope resolution and audit.
            offset: Number of entities to skip.
            limit: Maximum number of entities to return.

        Returns:
            The entities in scope for the requested page.
        """
        ...

    @abstractmethod
    def count(self, context: RequestContext) -> int:
        """Count the entities visible in the caller's scope."""
        ...


class PlatformScopedRepository(Repository[T, ID], ReadableRepository[T, ID], ABC):
    """Contract for repositories that intentionally span tenants.

    Platform scope is reserved for entity groups the schema does not place
    inside a tenant, such as the tenant registry itself. Implementations
    still require an authenticated caller; they simply do not bind a tenant
    predicate because the data has no tenant owner.
    """

    scope: ClassVar[RepositoryScope] = RepositoryScope.PLATFORM


class TenantScopedRepository(Repository[T, ID], ReadableRepository[T, ID], ABC):
    """Contract for repositories confined to a single validated tenant.

    Every operation resolves tenant scope from the request context and binds
    the resulting predicate before any lookup, filter, or mutation runs.
    Absent tenant context is a hard failure, never a full-table operation.
    """

    scope: ClassVar[RepositoryScope] = RepositoryScope.TENANT

    @abstractmethod
    def tenant_predicate(self, context: RequestContext) -> TenantPredicate:
        """Build the tenant filter bound to every operation of this repository.

        Args:
            context: Request context supplying tenant scope.

        Returns:
            The predicate constraining reads and writes to one tenant.

        Raises:
            TenantRequiredError: If the context carries no tenant scope.
        """
        ...


class AppendOnlyRepository(ReadableRepository[T, ID], ABC):
    """Contract for stores whose records are immutable once written.

    Update and delete primitives are intentionally absent from this
    interface rather than present and failing: callers cannot express a
    mutation of an append-only record at all.
    """

    scope: ClassVar[RepositoryScope] = RepositoryScope.TENANT

    @abstractmethod
    def append(self, context: RequestContext, entity: T) -> T:
        """Write a new immutable record.

        Args:
            context: Request context for scope resolution and audit.
            entity: The record to append.

        Returns:
            The appended record.
        """
        ...

    @abstractmethod
    def find_by_id(self, context: RequestContext, entity_id: ID) -> T | None:
        """Read a single record by identifier within the caller's scope."""
        ...


class DomainService(ABC):
    """Base contract for domain services.

    Domain services encapsulate domain logic that doesn't naturally
    belong to a single entity. They operate on entities and value
    objects using the request context for security and audit.
    """

    pass
