"""Domain error definitions for EIAMS.

This module provides framework-isolated error types that can be used
across all domain modules without introducing external dependencies.
"""

from .domain_errors import (
    DomainError,
    ValidationError,
    ContextError,
    TenantRequiredError,
    ActorRequiredError,
    InvalidTenantError,
    InvalidActorError,
    InvalidCorrelationIdError,
    AuthorizationError,
    PermissionDeniedError,
    ErrorCode,
)

from .api_errors import (
    ApiError,
    ApiErrorCode,
    ApiErrorPayload,
    FieldError,
    HttpStatusCode,
    ValidationApiError,
    AuthenticationApiError,
    AuthorizationApiError,
    NotFoundApiError,
    ConflictApiError,
    InternalApiError,
)

__all__ = [
    # Domain errors
    "DomainError",
    "ValidationError",
    "ContextError",
    "TenantRequiredError",
    "ActorRequiredError",
    "InvalidTenantError",
    "InvalidActorError",
    "InvalidCorrelationIdError",
    "AuthorizationError",
    "PermissionDeniedError",
    "ErrorCode",
    # API errors
    "ApiError",
    "ApiErrorCode",
    "ApiErrorPayload",
    "FieldError",
    "HttpStatusCode",
    "ValidationApiError",
    "AuthenticationApiError",
    "AuthorizationApiError",
    "NotFoundApiError",
    "ConflictApiError",
    "InternalApiError",
    # Exception mapping - lazy loaded
    "ExceptionMapper",
    "get_exception_mapper",
    "map_exception_to_response",
]


# Lazy load exception_mapping to avoid circular import
def __getattr__(name):
    if name in ("ExceptionMapper", "get_exception_mapper", "map_exception_to_response"):
        from . import exception_mapping
        return getattr(exception_mapping, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
