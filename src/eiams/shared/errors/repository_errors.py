"""Persistence error definitions.

These errors describe failures of data-access primitives without exposing
any persistence implementation detail (SQL text, driver messages, table or
column names) to callers. Adapters translate driver-specific exceptions
into these types so that application and domain code stays framework
isolated.
"""

from typing import Any

from .domain_errors import DomainError, ErrorCode


class RepositoryError(DomainError):
    """Base class for failures raised by repository implementations."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.PERSISTENCE_ERROR,
        entity: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if entity is not None:
            details["entity"] = entity
        super().__init__(message, code, details)


class EntityNotFoundError(RepositoryError):
    """Error raised when a required entity is absent from the current scope.

    A tenant-scoped lookup that resolves a real row owned by another tenant
    also raises this error, so that callers cannot distinguish "does not
    exist" from "exists in another tenant".
    """

    def __init__(
        self,
        message: str = "Entity not found",
        entity: str | None = None,
        entity_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if entity_id is not None:
            details["entity_id"] = entity_id
        super().__init__(message, ErrorCode.RESOURCE_NOT_FOUND, entity, details)


class DuplicateEntityError(RepositoryError):
    """Error raised when a write violates a uniqueness constraint."""

    def __init__(
        self,
        message: str = "Entity already exists",
        entity: str | None = None,
        conflicting_fields: tuple[str, ...] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if conflicting_fields:
            details["conflicting_fields"] = list(conflicting_fields)
        super().__init__(message, ErrorCode.RESOURCE_ALREADY_EXISTS, entity, details)


class IntegrityViolationError(RepositoryError):
    """Error raised when a write violates a non-uniqueness integrity rule."""

    def __init__(
        self,
        message: str = "Operation violates a data integrity rule",
        entity: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.RESOURCE_CONFLICT, entity, details)


class TransactionError(RepositoryError):
    """Error raised when a unit of work cannot be committed or rolled back."""

    def __init__(
        self,
        message: str = "Transaction failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.TRANSACTION_FAILED, None, details)


class AppendOnlyViolationError(RepositoryError):
    """Error raised when a mutation is attempted on an append-only store."""

    def __init__(
        self,
        message: str = "Records in this store are immutable once written",
        entity: str | None = None,
        operation: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if operation is not None:
            details["operation"] = operation
        super().__init__(message, ErrorCode.OPERATION_NOT_PERMITTED, entity, details)
