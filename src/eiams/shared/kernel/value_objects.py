"""Framework-isolated value objects for the shared kernel.

These value objects are immutable and validated upon construction.
They form the foundation for domain-driven design across EIAMS modules.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, TypeVar
import re
import uuid

from eiams.shared.errors import (
    ValidationError,
    InvalidTenantError,
    InvalidActorError,
    InvalidCorrelationIdError,
)


T = TypeVar("T", bound="ValueObject")


class ValueObject(ABC):
    """Base class for immutable value objects.

    Value objects are compared by value, not identity. They are
    immutable after construction and validate their state during
    initialization.
    """

    __slots__ = ()

    @abstractmethod
    def __eq__(self, other: object) -> bool:
        """Value objects are compared by their values."""
        ...

    @abstractmethod
    def __hash__(self) -> int:
        """Value objects must be hashable for use as dict keys."""
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


class EntityId(ValueObject):
    """Base class for entity identifiers.

    Entity IDs are immutable, validated UUIDs that uniquely identify
    domain entities across the system.
    """

    __slots__ = ("_value",)

    # UUID v4 pattern
    _UUID_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )

    def __init__(self, value: str) -> None:
        """Create an entity ID from a string value.

        Args:
            value: UUID string in standard format.

        Raises:
            ValidationError: If value is not a valid UUID format.
        """
        if not value or not isinstance(value, str):
            raise ValidationError("Entity ID must be a non-empty string", field="id")

        normalized = value.strip().lower()
        if not self._UUID_PATTERN.match(normalized):
            raise ValidationError(
                f"Invalid UUID format: {value}",
                field="id",
                details={"value": value},
            )

        self._value = normalized

    @classmethod
    def generate(cls: type[T]) -> T:
        """Generate a new random entity ID."""
        return cls(str(uuid.uuid4()))

    @property
    def value(self) -> str:
        """The string value of the ID."""
        return self._value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EntityId):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._value!r})"

    def to_dict(self) -> dict[str, str]:
        """Serialize to dictionary for safe API response."""
        return {"id": self._value}


class TenantId(EntityId):
    """Immutable tenant identifier with validation.

    Tenant IDs are critical for data isolation in multi-tenant operations.
    They must be valid UUIDs and are validated strictly.
    """

    def __init__(self, value: str) -> None:
        """Create a tenant ID from a string value.

        Args:
            value: UUID string in standard format.

        Raises:
            InvalidTenantError: If value is not a valid UUID format.
        """
        if not value or not isinstance(value, str):
            raise InvalidTenantError(
                "Tenant ID must be a non-empty string",
                tenant_id=str(value) if value else None,
            )

        normalized = value.strip().lower()
        if not self._UUID_PATTERN.match(normalized):
            raise InvalidTenantError(
                f"Invalid tenant ID format: {value}",
                tenant_id=value,
            )

        # Bypass parent __init__ validation since we've already validated
        self._value = normalized


class ActorId(EntityId):
    """Immutable actor (user/service) identifier with validation.

    Actor IDs identify the authenticated entity performing an operation.
    They must be valid UUIDs.
    """

    def __init__(self, value: str) -> None:
        """Create an actor ID from a string value.

        Args:
            value: UUID string in standard format.

        Raises:
            InvalidActorError: If value is not a valid UUID format.
        """
        if not value or not isinstance(value, str):
            raise InvalidActorError(
                "Actor ID must be a non-empty string",
                actor_id=str(value) if value else None,
            )

        normalized = value.strip().lower()
        if not self._UUID_PATTERN.match(normalized):
            raise InvalidActorError(
                f"Invalid actor ID format: {value}",
                actor_id=value,
            )

        self._value = normalized


class CorrelationId(ValueObject):
    """Immutable correlation identifier for request tracing.

    Correlation IDs flow through all layers of the system to enable
    distributed tracing and log correlation. They can be UUIDs or
    other structured identifiers.
    """

    __slots__ = ("_value",)

    # Accept UUIDs or alphanumeric strings with dashes/underscores (max 128 chars)
    _CORRELATION_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")

    def __init__(self, value: str) -> None:
        """Create a correlation ID from a string value.

        Args:
            value: Correlation ID string.

        Raises:
            InvalidCorrelationIdError: If value format is invalid.
        """
        if not value or not isinstance(value, str):
            raise InvalidCorrelationIdError(
                "Correlation ID must be a non-empty string",
                correlation_id=str(value) if value else None,
            )

        normalized = value.strip()
        if not self._CORRELATION_PATTERN.match(normalized):
            raise InvalidCorrelationIdError(
                f"Invalid correlation ID format: {value}",
                correlation_id=value,
            )

        self._value = normalized

    @classmethod
    def generate(cls) -> "CorrelationId":
        """Generate a new random correlation ID."""
        return cls(str(uuid.uuid4()))

    @property
    def value(self) -> str:
        """The string value of the correlation ID."""
        return self._value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CorrelationId):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"CorrelationId({self._value!r})"


class Timestamp(ValueObject):
    """Immutable UTC timestamp for domain events and audit.

    Timestamps are always stored and compared in UTC to ensure
    consistent ordering across time zones.
    """

    __slots__ = ("_value",)

    def __init__(self, value: datetime | None = None) -> None:
        """Create a timestamp.

        Args:
            value: Datetime value. If None, uses current UTC time.
                   If timezone-naive, assumes UTC.
        """
        if value is None:
            value = datetime.now(timezone.utc)
        elif value.tzinfo is None:
            # Assume UTC for naive datetimes
            value = value.replace(tzinfo=timezone.utc)
        else:
            # Convert to UTC
            value = value.astimezone(timezone.utc)

        self._value = value

    @classmethod
    def now(cls) -> "Timestamp":
        """Create a timestamp for the current moment."""
        return cls()

    @classmethod
    def from_iso(cls, iso_string: str) -> "Timestamp":
        """Create a timestamp from an ISO 8601 string.

        Args:
            iso_string: ISO 8601 formatted datetime string.

        Raises:
            ValidationError: If the string cannot be parsed.
        """
        try:
            dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
            return cls(dt)
        except (ValueError, AttributeError) as e:
            raise ValidationError(
                f"Invalid ISO 8601 timestamp: {iso_string}",
                field="timestamp",
                details={"value": iso_string, "error": str(e)},
            )

    @property
    def value(self) -> datetime:
        """The datetime value in UTC."""
        return self._value

    def to_iso(self) -> str:
        """Convert to ISO 8601 string with Z suffix."""
        return self._value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Timestamp):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __lt__(self, other: "Timestamp") -> bool:
        if not isinstance(other, Timestamp):
            return NotImplemented
        return self._value < other._value

    def __le__(self, other: "Timestamp") -> bool:
        if not isinstance(other, Timestamp):
            return NotImplemented
        return self._value <= other._value

    def __gt__(self, other: "Timestamp") -> bool:
        if not isinstance(other, Timestamp):
            return NotImplemented
        return self._value > other._value

    def __ge__(self, other: "Timestamp") -> bool:
        if not isinstance(other, Timestamp):
            return NotImplemented
        return self._value >= other._value

    def __repr__(self) -> str:
        return f"Timestamp({self.to_iso()!r})"
