"""Request validation adapters for EIAMS API endpoints.

Provides adapter integration points for request validation and
exception mapping with correlation ID propagation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, TYPE_CHECKING

from eiams.shared.context import RequestContext
from eiams.shared.errors import (
    ValidationError,
    ValidationApiError,
    FieldError,
    ApiErrorPayload,
)
from eiams.shared.logging import (
    StructuredLogger,
    LogOutcome,
    get_logger,
)

if TYPE_CHECKING:
    from eiams.shared.errors.exception_mapping import ExceptionMapper

T = TypeVar("T")


@dataclass(frozen=True)
class ValidationResult(Generic[T]):
    """Result of a validation operation.

    Either contains the validated value or validation errors.
    """

    value: T | None = None
    errors: tuple[FieldError, ...] = ()
    is_valid: bool = True

    @classmethod
    def success(cls, value: T) -> ValidationResult[T]:
        """Create a successful validation result."""
        return cls(value=value, is_valid=True)

    @classmethod
    def failure(cls, *errors: FieldError) -> ValidationResult[T]:
        """Create a failed validation result."""
        return cls(errors=errors, is_valid=False)

    def get_or_raise(self, correlation_id: str | None = None) -> T:
        """Get the validated value or raise ValidationApiError.

        Args:
            correlation_id: Correlation ID for error response.

        Returns:
            The validated value.

        Raises:
            ValidationApiError: If validation failed.
        """
        if not self.is_valid or self.value is None:
            raise ValidationApiError(
                message="Validation failed",
                field_errors=list(self.errors),
                correlation_id=correlation_id,
            )
        return self.value


class RequestValidator(ABC, Generic[T]):
    """Abstract base for request validators.

    Validators transform and validate raw request data into
    validated domain objects.
    """

    @abstractmethod
    def validate(
        self,
        data: dict[str, Any],
        context: RequestContext | None = None,
    ) -> ValidationResult[T]:
        """Validate request data.

        Args:
            data: Raw request data dictionary.
            context: Optional request context for contextual validation.

        Returns:
            ValidationResult with validated value or errors.
        """
        ...


class CompositeValidator(RequestValidator[T]):
    """Validator that chains multiple validators.

    Runs all validators and aggregates errors.
    """

    def __init__(self, validators: list[RequestValidator[T]] | None = None) -> None:
        """Initialize with list of validators.

        Args:
            validators: List of validators to run in order.
        """
        self._validators = validators or []

    def add_validator(self, validator: RequestValidator[T]) -> None:
        """Add a validator to the chain."""
        self._validators.append(validator)

    def validate(
        self,
        data: dict[str, Any],
        context: RequestContext | None = None,
    ) -> ValidationResult[T]:
        """Run all validators and aggregate results.

        Returns the first successful value if any validator succeeds,
        otherwise returns all aggregated errors.
        """
        all_errors: list[FieldError] = []
        last_value: T | None = None

        for validator in self._validators:
            result = validator.validate(data, context)
            if result.is_valid and result.value is not None:
                last_value = result.value
            else:
                all_errors.extend(result.errors)

        if last_value is not None and not all_errors:
            return ValidationResult.success(last_value)

        return ValidationResult.failure(*all_errors)


class FieldValidator:
    """Utility class for common field validations."""

    @staticmethod
    def required(
        data: dict[str, Any],
        field: str,
        message: str | None = None,
    ) -> FieldError | None:
        """Validate that a required field is present and not empty.

        Returns FieldError if validation fails, None if valid.
        """
        value = data.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            return FieldError(
                field=field,
                code="required",
                message=message or f"{field} is required",
            )
        return None

    @staticmethod
    def string_length(
        data: dict[str, Any],
        field: str,
        min_length: int | None = None,
        max_length: int | None = None,
    ) -> FieldError | None:
        """Validate string field length.

        Returns FieldError if validation fails, None if valid.
        """
        value = data.get(field)
        if value is None:
            return None  # Use required() to check presence

        if not isinstance(value, str):
            return FieldError(
                field=field,
                code="invalid_type",
                message=f"{field} must be a string",
            )

        if min_length is not None and len(value) < min_length:
            return FieldError(
                field=field,
                code="too_short",
                message=f"{field} must be at least {min_length} characters",
            )

        if max_length is not None and len(value) > max_length:
            return FieldError(
                field=field,
                code="too_long",
                message=f"{field} must be at most {max_length} characters",
            )

        return None

    @staticmethod
    def pattern(
        data: dict[str, Any],
        field: str,
        pattern: str,
        message: str | None = None,
    ) -> FieldError | None:
        """Validate field matches a regex pattern.

        Returns FieldError if validation fails, None if valid.
        """
        import re

        value = data.get(field)
        if value is None:
            return None

        if not isinstance(value, str):
            return FieldError(
                field=field,
                code="invalid_type",
                message=f"{field} must be a string",
            )

        if not re.match(pattern, value):
            return FieldError(
                field=field,
                code="invalid_format",
                message=message or f"{field} format is invalid",
            )

        return None

    @staticmethod
    def enum_value(
        data: dict[str, Any],
        field: str,
        valid_values: list[str],
    ) -> FieldError | None:
        """Validate field is one of the valid values.

        Returns FieldError if validation fails, None if valid.
        """
        value = data.get(field)
        if value is None:
            return None

        if value not in valid_values:
            return FieldError(
                field=field,
                code="invalid_value",
                message=f"{field} must be one of: {', '.join(valid_values)}",
            )

        return None


class ValidationAdapter:
    """Adapter for integrating validation with error mapping and logging.

    Coordinates validation, exception mapping, and logging for
    consistent API behavior.
    """

    def __init__(
        self,
        exception_mapper: ExceptionMapper | None = None,
        logger: StructuredLogger | None = None,
    ) -> None:
        """Initialize the validation adapter.

        Args:
            exception_mapper: Exception mapper for error responses.
            logger: Structured logger for validation events.
        """
        if exception_mapper is None:
            from eiams.shared.errors.exception_mapping import get_exception_mapper
            exception_mapper = get_exception_mapper()
        self._exception_mapper = exception_mapper
        self._logger = logger or get_logger("validation")

    def validate_request(
        self,
        validator: RequestValidator[T],
        data: dict[str, Any],
        context: RequestContext,
    ) -> T:
        """Validate request and return validated value.

        Logs validation outcome and raises appropriate API errors.

        Args:
            validator: Validator to use.
            data: Raw request data.
            context: Request context for correlation.

        Returns:
            Validated value.

        Raises:
            ValidationApiError: If validation fails.
        """
        result = validator.validate(data, context)

        if result.is_valid and result.value is not None:
            self._logger.log_operation(
                context=context,
                operation="request_validation",
                outcome=LogOutcome.SUCCESS,
                message="Request validation passed",
            )
            return result.value

        self._logger.log_operation(
            context=context,
            operation="request_validation",
            outcome=LogOutcome.FAILURE,
            message="Request validation failed",
            error_count=len(result.errors),
        )

        raise ValidationApiError(
            message="Validation failed",
            field_errors=list(result.errors),
            correlation_id=str(context.correlation_id),
        )

    def handle_exception(
        self,
        exc: Exception,
        context: RequestContext | None = None,
    ) -> ApiErrorPayload:
        """Map exception to API error payload with logging.

        Args:
            exc: Exception to handle.
            context: Optional request context.

        Returns:
            Safe API error payload.
        """
        correlation_id = str(context.correlation_id) if context else None

        self._logger.log_error(
            context=context,
            message=f"Exception handled: {type(exc).__name__}",
            exception=exc,
            operation="exception_handling",
        )

        return self._exception_mapper.map_exception(exc, correlation_id)
