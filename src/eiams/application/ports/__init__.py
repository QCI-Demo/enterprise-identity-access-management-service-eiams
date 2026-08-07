"""Application ports defining boundaries with infrastructure.

Ports define the interfaces that infrastructure adapters implement.
This enables dependency inversion - the application layer depends
on abstractions, not concrete implementations.
"""

from .base import InputPort, OutputPort
from .repository import (
    AppendOnlyRepository,
    PlatformScopedRepository,
    ReadableRepository,
    Repository,
    TenantScopedRepository,
    TransactionRunnerPort,
    UnitOfWorkPort,
)

__all__ = [
    "InputPort",
    "OutputPort",
    "Repository",
    "ReadableRepository",
    "PlatformScopedRepository",
    "TenantScopedRepository",
    "AppendOnlyRepository",
    "UnitOfWorkPort",
    "TransactionRunnerPort",
]
