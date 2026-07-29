"""Shared kernel containing base value objects and types.

The shared kernel provides foundational types that are used across
all domain modules. These types are framework-isolated and have
no external dependencies beyond the Python standard library.
"""

from .value_objects import (
    ValueObject,
    EntityId,
    TenantId,
    ActorId,
    CorrelationId,
    Timestamp,
)
from .secrets import (
    SecretString,
    REDACTED_REPRESENTATION,
)

__all__ = [
    "ValueObject",
    "EntityId",
    "TenantId",
    "ActorId",
    "CorrelationId",
    "Timestamp",
    "SecretString",
    "REDACTED_REPRESENTATION",
]
