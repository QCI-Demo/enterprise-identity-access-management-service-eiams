"""Framework-isolated domain error definitions.

These error types form the foundation of EIAMS error handling and are
designed to be completely independent of any web framework or external
library. They can be safely used in domain contracts.
"""

from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    """Standardized error codes for EIAMS domain errors."""

    # General validation errors
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_FORMAT = "INVALID_FORMAT"
    REQUIRED_FIELD = "REQUIRED_FIELD"

    # Context errors
    CONTEXT_INVALID = "CONTEXT_INVALID"
    TENANT_REQUIRED = "TENANT_REQUIRED"
    TENANT_INVALID = "TENANT_INVALID"
    ACTOR_REQUIRED = "ACTOR_REQUIRED"
    ACTOR_INVALID = "ACTOR_INVALID"
    CORRELATION_ID_INVALID = "CORRELATION_ID_INVALID"

    # Authentication errors
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"

    # Authorization errors
    PERMISSION_DENIED = "PERMISSION_DENIED"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    INSUFFICIENT_PRIVILEGES = "INSUFFICIENT_PRIVILEGES"

    # Configuration errors
    CONFIGURATION_INVALID = "CONFIGURATION_INVALID"
    CONFIGURATION_MISSING = "CONFIGURATION_MISSING"

    # Resource errors
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RESOURCE_ALREADY_EXISTS = "RESOURCE_ALREADY_EXISTS"
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"


class DomainError(Exception):
    """Base class for all domain errors in EIAMS.

    Domain errors are framework-isolated and carry structured information
    that can be safely serialized for API responses or logging.
    """

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.VALIDATION_ERROR,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self._message = message
        self._code = code
        self._details = details or {}

    @property
    def message(self) -> str:
        """Human-readable error message."""
        return self._message

    @property
    def code(self) -> ErrorCode:
        """Machine-readable error code."""
        return self._code

    @property
    def details(self) -> dict[str, Any]:
        """Additional error context for debugging."""
        return self._details.copy()

    def to_dict(self) -> dict[str, Any]:
        """Serialize error to a dictionary for safe API response."""
        return {
            "error": {
                "code": self._code.value,
                "message": self._message,
                "details": self._details,
            }
        }

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(code={self._code.value}, message={self._message!r})"


class ValidationError(DomainError):
    """Error raised when input validation fails."""

    def __init__(
        self,
        message: str,
        field: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if field:
            details["field"] = field
        super().__init__(message, ErrorCode.VALIDATION_ERROR, details)
        self._field = field

    @property
    def field(self) -> str | None:
        """The field that failed validation, if applicable."""
        return self._field


class ContextError(DomainError):
    """Base class for request context validation errors."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.CONTEXT_INVALID,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class TenantRequiredError(ContextError):
    """Error raised when tenant context is required but missing.

    This error triggers fail-closed behavior - operations that require
    tenant scope must not proceed without valid tenant context.
    """

    def __init__(
        self,
        message: str = "Tenant context is required for this operation",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.TENANT_REQUIRED, details)


class InvalidTenantError(ContextError):
    """Error raised when tenant identifier is malformed or invalid."""

    def __init__(
        self,
        message: str = "Invalid tenant identifier",
        tenant_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if tenant_id is not None:
            details["tenant_id"] = tenant_id
        super().__init__(message, ErrorCode.TENANT_INVALID, details)


class ActorRequiredError(ContextError):
    """Error raised when actor identity is required but missing."""

    def __init__(
        self,
        message: str = "Actor identity is required for this operation",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.ACTOR_REQUIRED, details)


class InvalidActorError(ContextError):
    """Error raised when actor identifier is malformed or invalid."""

    def __init__(
        self,
        message: str = "Invalid actor identifier",
        actor_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if actor_id is not None:
            details["actor_id"] = actor_id
        super().__init__(message, ErrorCode.ACTOR_INVALID, details)


class InvalidCorrelationIdError(ContextError):
    """Error raised when correlation ID format is invalid."""

    def __init__(
        self,
        message: str = "Invalid correlation ID format",
        correlation_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if correlation_id is not None:
            details["correlation_id"] = correlation_id
        super().__init__(message, ErrorCode.CORRELATION_ID_INVALID, details)


class AuthorizationError(DomainError):
    """Base class for authorization-related errors."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.AUTHORIZATION_FAILED,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class AuthenticationError(DomainError):
    """Base class for authentication-related errors."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.AUTHENTICATION_FAILED,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class AuthenticationFailedError(AuthenticationError):
    """Error raised when an authentication attempt does not succeed.

    This error is deliberately uniform: unknown identifiers, wrong
    passwords, missing credentials, and ineligible account states all
    produce the same message and carry no externally visible details.
    The internal reason is retained as a private attribute for audit
    and diagnostics but is never serialized.
    """

    SAFE_MESSAGE = "Authentication failed"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(self.SAFE_MESSAGE, ErrorCode.AUTHENTICATION_FAILED, {})
        self._reason = reason

    @property
    def reason(self) -> str | None:
        """Internal failure reason for audit use only."""
        return self._reason

    def __repr__(self) -> str:
        return "AuthenticationFailedError(code=AUTHENTICATION_FAILED)"


class ConfigurationError(DomainError):
    """Error raised when configuration values are missing or invalid.

    Only the configuration key is reported; values are never included
    because configuration may carry sensitive material.
    """

    def __init__(
        self,
        message: str,
        key: str | None = None,
        code: ErrorCode = ErrorCode.CONFIGURATION_INVALID,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if key:
            details["configuration_key"] = key
        super().__init__(message, code, details)
        self._key = key

    @property
    def key(self) -> str | None:
        """The configuration key that failed to resolve or validate."""
        return self._key


class MissingConfigurationError(ConfigurationError):
    """Error raised when a required configuration value is absent."""

    def __init__(self, key: str, message: str | None = None) -> None:
        super().__init__(
            message or f"Required configuration is missing: {key}",
            key=key,
            code=ErrorCode.CONFIGURATION_MISSING,
        )


class PermissionDeniedError(AuthorizationError):
    """Error raised when an operation is denied due to insufficient permissions."""

    def __init__(
        self,
        message: str = "Permission denied",
        resource: str | None = None,
        action: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if resource:
            details["resource"] = resource
        if action:
            details["action"] = action
        super().__init__(message, ErrorCode.PERMISSION_DENIED, details)
