"""Infrastructure persistence adapters.

Repository implementations and database access patterns.
"""

from eiams.infrastructure.persistence.database import (
    Base,
    DatabaseConfig,
    DatabaseManager,
    NAMING_CONVENTION,
)

__all__ = [
    "Base",
    "DatabaseConfig",
    "DatabaseManager",
    "NAMING_CONVENTION",
]
