"""Application services orchestrating domain logic.

Application services coordinate domain operations, enforce business
rules, and manage transactions. They receive validated context and
delegate to domain services and repositories.
"""

from .base import ApplicationService

__all__ = [
    "ApplicationService",
]
