"""Infrastructure persistence adapters.

Repository implementations and database access patterns.
"""

from .in_memory import (
    InMemoryAuditEventRepository,
    InMemoryPasswordCredentialRepository,
    InMemoryUnitOfWork,
    InMemoryUnitOfWorkFactory,
    InMemoryUserRepository,
)

__all__ = [
    "InMemoryAuditEventRepository",
    "InMemoryPasswordCredentialRepository",
    "InMemoryUnitOfWork",
    "InMemoryUnitOfWorkFactory",
    "InMemoryUserRepository",
]
