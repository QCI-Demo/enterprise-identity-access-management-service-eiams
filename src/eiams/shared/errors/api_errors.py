"""Standardized API error codes and response payloads.

Provides versioned EIAMS error payloads with correlation ID propagation
and safe field-error handling without exposing internal implementation details.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from eiams.shared.errors.domain_errors import DomainError, ErrorCode


class HttpStatusCode(int, Enum):
    """HTTP status codes for API responses."""

    OK = 200
    CREATED = 201
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    TOO_MANY_REQUESTS = 429
    INTERNAL_SERVER_ERROR = 500
    SERVICE_UNAVAILABLE = 503


# API error codes extending domain error codes
class ApiErrorCode(str, Enum):
    """API-level error codes for EIAMS responses."""

    # Validation errors (400, 422)
    VALIDATION_FAILED = "VALIDATION_FAILED"
    INVALID_REQUEST_FORMAT = "INVALID_REQUEST_FORMAT"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    INVALID_FIELD_VALUE = "INVALID_FIELD_VALUE"
    INVALID_FIELD_FORMAT = "INVALID_FIELD_FORMAT"

    # Authentication errors (401)
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_INVALID = "TOKEN_INVALID"
    CREDENTIALS_INVALID = "CREDENTIALS_INVALID"

    # Authorization errors (403)
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    INSUFFICIENT_SCOPE = "INSUFFICIENT_SCOPE"
    TENANT_ACCESS_DENIED = "TENANT_ACCESS_DENIED"

    # Resource errors (404, 409)
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RESOURCE_ALREADY_EXISTS = "RESOURCE_ALREADY_EXISTS"
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"
    VERSION_CONFLICT = "VERSION_CONFLICT"

    # Rate limiting (429)
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"

    # Internal errors (500)
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


@dataclass(frozen=True)
class FieldError:
    """Represents a single field validation error.

    Safe for external exposure - no internal details.
    """

    field: str
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary for API response."""
        return {
            "field": self.field,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True)
class ApiErrorPayload:
    """Versioned EIAMS API error response payload.

    Designed for safe external exposure with correlation tracking.
    """

    code: str
    message: str
    correlation_id: str | None = None
    status_code: int = 400
    field_errors: tuple[FieldError, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)
    api_version: str = "v1"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API response.

        Returns a versioned error response structure.
        """
        error: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }

        if self.correlation_id:
            error["correlation_id"] = self.correlation_id

        if self.field_errors:
            error["field_errors"] = [fe.to_dict() for fe in self.field_errors]

        if self.details:
            error["details"] = self.details

        return {
            "error": error,
            "api_version": self.api_version,
        }

    @property
    def http_status(self) -> HttpStatusCode:
        """Get the HTTP status code enum."""
        return HttpStatusCode(self.status_code)


class ApiError(Exception):
    """Base API error with structured payload.

    Designed for safe exposure through API responses.
    """

    def __init__(
        self,
        code: str | ApiErrorCode,
        message: str,
        status_code: int | HttpStatusCode = HttpStatusCode.BAD_REQUEST,
        correlation_id: str | None = None,
        field_errors: list[FieldError] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self._code = code.value if isinstance(code, ApiErrorCode) else code
        self._message = message
        self._status_code = status_code.value if isinstance(status_code, HttpStatusCode) else status_code
        self._correlation_id = correlation_id
        self._field_errors = tuple(field_errors) if field_errors else ()
        self._details = details or {}

    @property
    def code(self) -> str:
        """Error code."""
        return self._code

    @property
    def message(self) -> str:
        """Error message."""
        return self._message

    @property
    def status_code(self) -> int:
        """HTTP status code."""
        return self._status_code

    @property
    def correlation_id(self) -> str | None:
        """Request correlation ID."""
        return self._correlation_id

    @property
    def field_errors(self) -> tuple[FieldError, ...]:
        """Field-level validation errors."""
        return self._field_errors

    @property
    def details(self) -> dict[str, Any]:
        """Additional error details."""
        return self._details.copy()

    def with_correlation_id(self, correlation_id: str) -> "ApiError":
        """Create a copy with correlation ID set."""
        return ApiError(
            code=self._code,
            message=self._message,
            status_code=self._status_code,
            correlation_id=correlation_id,
            field_errors=list(self._field_errors),
            details=self._details,
        )

    def to_payload(self) -> ApiErrorPayload:
        """Convert to API error payload."""
        return ApiErrorPayload(
            code=self._code,
            message=self._message,
            status_code=self._status_code,
            correlation_id=self._correlation_id,
            field_errors=self._field_errors,
            details=self._details,
        )


# Specific error classes for common scenarios


class ValidationApiError(ApiError):
    """Validation error for API requests."""

    def __init__(
        self,
        message: str = "Validation failed",
        field_errors: list[FieldError] | None = None,
        correlation_id: str | None = None,
    ) -> None:
        super().__init__(
            code=ApiErrorCode.VALIDATION_FAILED,
            message=message,
            status_code=HttpStatusCode.UNPROCESSABLE_ENTITY,
            correlation_id=correlation_id,
            field_errors=field_errors,
        )


class AuthenticationApiError(ApiError):
    """Authentication error for API requests."""

    def __init__(
        self,
        message: str = "Authentication required",
        code: ApiErrorCode = ApiErrorCode.AUTHENTICATION_REQUIRED,
        correlation_id: str | None = None,
    ) -> None:
        super().__init__(
            code=code,
            message=message,
            status_code=HttpStatusCode.UNAUTHORIZED,
            correlation_id=correlation_id,
        )


class AuthorizationApiError(ApiError):
    """Authorization error for API requests."""

    def __init__(
        self,
        message: str = "Access denied",
        code: ApiErrorCode = ApiErrorCode.AUTHORIZATION_DENIED,
        correlation_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code=code,
            message=message,
            status_code=HttpStatusCode.FORBIDDEN,
            correlation_id=correlation_id,
            details=details,
        )


class NotFoundApiError(ApiError):
    """Resource not found error for API requests."""

    def __init__(
        self,
        message: str = "Resource not found",
        resource_type: str | None = None,
        resource_id: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        details: dict[str, Any] = {}
        if resource_type:
            details["resource_type"] = resource_type
        if resource_id:
            details["resource_id"] = resource_id

        super().__init__(
            code=ApiErrorCode.RESOURCE_NOT_FOUND,
            message=message,
            status_code=HttpStatusCode.NOT_FOUND,
            correlation_id=correlation_id,
            details=details,
        )


class ConflictApiError(ApiError):
    """Resource conflict error for API requests."""

    def __init__(
        self,
        message: str = "Resource conflict",
        code: ApiErrorCode = ApiErrorCode.RESOURCE_CONFLICT,
        correlation_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code=code,
            message=message,
            status_code=HttpStatusCode.CONFLICT,
            correlation_id=correlation_id,
            details=details,
        )


class InternalApiError(ApiError):
    """Internal server error for API requests.

    Does not expose internal details externally.
    """

    def __init__(
        self,
        message: str = "An unexpected error occurred",
        correlation_id: str | None = None,
    ) -> None:
        super().__init__(
            code=ApiErrorCode.INTERNAL_ERROR,
            message=message,
            status_code=HttpStatusCode.INTERNAL_SERVER_ERROR,
            correlation_id=correlation_id,
        )
