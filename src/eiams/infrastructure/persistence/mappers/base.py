"""Mapping between ORM rows and domain entities.

Repositories never hand an ORM row to a caller. Every read passes through a
mapper that produces an immutable domain entity, so callers cannot reach the
session, trigger lazy loads, or mutate persistent state by assignment.

Writes go the other way in two forms: ``to_model`` builds a new row for an
insert, and ``apply`` copies the attributes the domain owns onto an existing
row. Updates use ``apply`` so that columns the domain contract does not model
keep whatever the schema or another module set on them.
"""

import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, ClassVar, Generic, TypeVar

from eiams.shared.kernel import Timestamp


Entity = TypeVar("Entity")
Model = TypeVar("Model")

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")
_SLUG_MAX_LENGTH = 63


class EntityMapper(ABC, Generic[Entity, Model]):
    """Bidirectional mapping for one entity group."""

    #: Caller-facing name of the entity group, used in error messages.
    entity_name: ClassVar[str]

    @abstractmethod
    def to_entity(self, row: Model) -> Entity:
        """Build an immutable domain entity from a persistent row."""
        ...

    @abstractmethod
    def to_model(self, entity: Entity) -> Model:
        """Build a new persistent row from a domain entity."""
        ...

    @abstractmethod
    def apply(self, entity: Entity, row: Model) -> None:
        """Copy the domain-owned attributes of an entity onto a row."""
        ...


def utc_now() -> datetime:
    """Current UTC time, for columns the schema stamps on state changes."""
    return datetime.now(timezone.utc)


def to_timestamp(value: datetime | None) -> Timestamp | None:
    """Convert a stored datetime into a UTC timestamp value object."""
    if value is None:
        return None
    return Timestamp(value)


def require_timestamp(value: datetime | None) -> Timestamp:
    """Convert a non-null stored datetime into a UTC timestamp."""
    return Timestamp(value)


def from_timestamp(value: Timestamp | None) -> datetime | None:
    """Convert a timestamp value object into a storable datetime."""
    if value is None:
        return None
    return value.value


def to_tuple(value: str | None) -> tuple[str, ...]:
    """Split a stored comma-separated list into a tuple of entries."""
    if not value:
        return ()
    return tuple(entry.strip() for entry in value.split(",") if entry.strip())


def from_tuple(values: tuple[str, ...] | list[str] | None) -> str:
    """Join a sequence of entries into the stored comma-separated form."""
    if not values:
        return ""
    return ",".join(str(value).strip() for value in values if str(value).strip())


def slugify(value: str, fallback: str) -> str:
    """Derive a URL-safe slug, falling back when nothing usable remains."""
    slug = _SLUG_STRIP.sub("-", value.strip().lower()).strip("-")
    slug = slug[:_SLUG_MAX_LENGTH].strip("-")
    return slug or fallback[:_SLUG_MAX_LENGTH]


def identifier(value: Any) -> str:
    """Render an entity identifier as the string form the schema stores."""
    return str(value)


def optional_identifier(value: Any) -> str | None:
    """Render an optional entity identifier, preserving absence."""
    return None if value is None else str(value)
