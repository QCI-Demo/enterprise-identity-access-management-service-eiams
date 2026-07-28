"""Base domain contracts for all IAM modules.

These abstract base classes define the foundational contracts that
all domain modules implement. They are framework-isolated and have
no dependencies on persistence or web frameworks.
"""

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from eiams.shared.kernel import EntityId, Timestamp
from eiams.shared.context import RequestContext


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


class DomainService(ABC):
    """Base contract for domain services.

    Domain services encapsulate domain logic that doesn't naturally
    belong to a single entity. They operate on entities and value
    objects using the request context for security and audit.
    """

    pass
