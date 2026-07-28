"""Exception classification and mapping for API responses.

Translates domain errors and exceptions into standardized EIAMS API
error payloads with safe handling that prevents internal detail leakage.
"""

from typing import Any, Callable, Type

from eiams.shared.errors.domain_errors import (
    DomainError,
    ErrorCode,
    ValidationError,
    ContextError,
    TenantRequiredError,
    InvalidTenantError,
    ActorRequiredError,
    InvalidActorError,
    InvalidCorrelationIdError,
    AuthorizationError,
    PermissionDeniedError,
)
from eiams.shared.errors.api_errors import (
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
from eiams.shared.logging.redaction import SecretRedactor


class ExceptionMapper:
    """Maps exceptions to safe API error responses.

    Classifies exceptions and produces API-safe error payloads with
    appropriate status codes and correlation tracking.
    """

    def __init__(
        self,
        redactor: SecretRedactor | None = None,
        safe_mode: bool = True,
    ) -> None:
        """Initialize the exception mapper.

        Args:
            redactor: Secret redactor for sanitizing error details.
            safe_mode: If True, internal errors produce generic messages.
        """
        self._redactor = redactor or SecretRedactor()
        self._safe_mode = safe_mode
        self._custom_mappers: dict[Type[Exception], Callable[[Exception, str | None], ApiError]] = {}

    def register_mapper(
        self,
        exception_type: Type[Exception],
        mapper: Callable[[Exception, str | None], ApiError],
    ) -> None:
        """Register a custom exception mapper.

        Args:
            exception_type: Exception type to handle.
            mapper: Function that converts the exception to ApiError.
        """
        self._custom_mappers[exception_type] = mapper

    def map_exception(
        self,
        exc: Exception,
        correlation_id: str | None = None,
    ) -> ApiErrorPayload:
        """Map an exception to a safe API error payload.

        Args:
            exc: The exception to map.
            correlation_id: Request correlation ID.

        Returns:
            Safe ApiErrorPayload suitable for API response.
        """
        api_error = self._to_api_error(exc, correlation_id)
        return api_error.to_payload()

    def _to_api_error(
        self,
        exc: Exception,
        correlation_id: str | None,
    ) -> ApiError:
        """Convert exception to ApiError."""
        # Check custom mappers first
        for exc_type, mapper in self._custom_mappers.items():
            if isinstance(exc, exc_type):
                return mapper(exc, correlation_id)

        # Handle ApiError pass-through
        if isinstance(exc, ApiError):
            if correlation_id and not exc.correlation_id:
                return exc.with_correlation_id(correlation_id)
            return exc

        # Handle domain errors
        if isinstance(exc, DomainError):
            return self._map_domain_error(exc, correlation_id)

        # Handle standard Python exceptions
        return self._map_standard_exception(exc, correlation_id)

    def _map_domain_error(
        self,
        exc: DomainError,
        correlation_id: str | None,
    ) -> ApiError:
        """Map domain error to API error."""
        code = exc.code

        # Validation errors
        if isinstance(exc, ValidationError):
            safe_msg = self._safe_message(exc.message, "Validation failed")
            field_errors = []
            if exc.field:
                field_errors.append(
                    FieldError(
                        field=exc.field,
                        code="invalid",
                        message=safe_msg,
                    )
                )
            return ValidationApiError(
                message=safe_msg,
                field_errors=field_errors,
                correlation_id=correlation_id,
            )

        # Context errors (authentication/authorization)
        if isinstance(exc, (ActorRequiredError, InvalidActorError)):
            return AuthenticationApiError(
                message=self._safe_message(exc.message, "Authentication required"),
                code=ApiErrorCode.AUTHENTICATION_REQUIRED,
                correlation_id=correlation_id,
            )

        if isinstance(exc, (TenantRequiredError, InvalidTenantError)):
            return AuthorizationApiError(
                message=self._safe_message(exc.message, "Tenant access required"),
                code=ApiErrorCode.TENANT_ACCESS_DENIED,
                correlation_id=correlation_id,
            )

        if isinstance(exc, InvalidCorrelationIdError):
            return ValidationApiError(
                message="Invalid request format",
                field_errors=[
                    FieldError(
                        field="correlation_id",
                        code="invalid_format",
                        message="Correlation ID format is invalid",
                    )
                ],
                correlation_id=correlation_id,
            )

        # Authorization errors
        if isinstance(exc, PermissionDeniedError):
            details = self._safe_details(exc.details)
            return AuthorizationApiError(
                message=self._safe_message(exc.message, "Permission denied"),
                code=ApiErrorCode.PERMISSION_DENIED,
                correlation_id=correlation_id,
                details=details,
            )

        if isinstance(exc, AuthorizationError):
            return AuthorizationApiError(
                message=self._safe_message(exc.message, "Access denied"),
                code=ApiErrorCode.AUTHORIZATION_DENIED,
                correlation_id=correlation_id,
            )

        # Resource errors
        if code == ErrorCode.RESOURCE_NOT_FOUND:
            return NotFoundApiError(
                message=self._safe_message(exc.message, "Resource not found"),
                correlation_id=correlation_id,
            )

        if code == ErrorCode.RESOURCE_ALREADY_EXISTS:
            return ConflictApiError(
                message=self._safe_message(exc.message, "Resource already exists"),
                code=ApiErrorCode.RESOURCE_ALREADY_EXISTS,
                correlation_id=correlation_id,
            )

        if code == ErrorCode.RESOURCE_CONFLICT:
            return ConflictApiError(
                message=self._safe_message(exc.message, "Resource conflict"),
                code=ApiErrorCode.RESOURCE_CONFLICT,
                correlation_id=correlation_id,
            )

        # Default domain error mapping
        return ApiError(
            code=code.value,
            message=self._safe_message(exc.message, "Request failed"),
            status_code=HttpStatusCode.BAD_REQUEST,
            correlation_id=correlation_id,
            details=self._safe_details(exc.details),
        )

    def _map_standard_exception(
        self,
        exc: Exception,
        correlation_id: str | None,
    ) -> ApiError:
        """Map standard Python exceptions to safe API errors."""
        # ValueError often indicates validation issues
        if isinstance(exc, ValueError):
            return ValidationApiError(
                message=self._safe_message(str(exc), "Invalid input"),
                correlation_id=correlation_id,
            )

        # TypeError indicates programming errors - don't expose
        if isinstance(exc, TypeError):
            return InternalApiError(
                message="An unexpected error occurred",
                correlation_id=correlation_id,
            )

        # KeyError might indicate missing required data
        if isinstance(exc, KeyError):
            return ValidationApiError(
                message="Required data missing",
                correlation_id=correlation_id,
            )

        # PermissionError from OS-level
        if isinstance(exc, PermissionError):
            return InternalApiError(
                message="An unexpected error occurred",
                correlation_id=correlation_id,
            )

        # Default: internal error
        return InternalApiError(
            message="An unexpected error occurred" if self._safe_mode else str(exc),
            correlation_id=correlation_id,
        )

    def _safe_message(self, message: str, fallback: str) -> str:
        """Return safe message, redacting sensitive content."""
        if not self._safe_mode:
            return self._redactor.redact(message)

        # Redact the message
        redacted = self._redactor.redact(message)

        # If message was heavily redacted, use fallback
        if redacted == "[REDACTED]":
            return fallback

        return redacted

    def _safe_details(self, details: dict[str, Any]) -> dict[str, Any]:
        """Return safe details dictionary, filtering sensitive data."""
        if not details:
            return {}

        # Redact all values
        redacted = self._redactor.redact_for_logging(details)

        # Filter out internal implementation details
        safe_keys = {
            "field",
            "resource",
            "action",
            "resource_type",
            "resource_id",
            "valid_types",
            "valid_values",
        }

        return {k: v for k, v in redacted.items() if k in safe_keys}


# Default singleton instance
_default_mapper: ExceptionMapper | None = None


def get_exception_mapper() -> ExceptionMapper:
    """Get the default exception mapper instance."""
    global _default_mapper
    if _default_mapper is None:
        _default_mapper = ExceptionMapper()
    return _default_mapper


def map_exception_to_response(
    exc: Exception,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Convenience function to map exception to response dict.

    Args:
        exc: Exception to map.
        correlation_id: Request correlation ID.

    Returns:
        Dictionary suitable for JSON API response.
    """
    mapper = get_exception_mapper()
    payload = mapper.map_exception(exc, correlation_id)
    return payload.to_dict()
