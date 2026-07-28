"""Domain error definitions for EIAMS.

This module provides framework-isolated error types that can be used
across all domain modules without introducing external dependencies.
"""

from .domain_errors import (
    DomainError,
    ValidationError,
    ContextError,
    TenantRequiredError,
    TenantMismatchError,
    ActorRequiredError,
    InvalidTenantError,
    InvalidActorError,
    InvalidCorrelationIdError,
    AuthorizationError,
    PermissionDeniedError,
    ErrorCode,
)
from .repository_errors import (
    RepositoryError,
    EntityNotFoundError,
    DuplicateEntityError,
    IntegrityViolationError,
    TransactionError,
    AppendOnlyViolationError,
)

__all__ = [
    "DomainError",
    "ValidationError",
    "ContextError",
    "TenantRequiredError",
    "TenantMismatchError",
    "ActorRequiredError",
    "InvalidTenantError",
    "InvalidActorError",
    "InvalidCorrelationIdError",
    "AuthorizationError",
    "PermissionDeniedError",
    "ErrorCode",
    "RepositoryError",
    "EntityNotFoundError",
    "DuplicateEntityError",
    "IntegrityViolationError",
    "TransactionError",
    "AppendOnlyViolationError",
]
