"""Tests for exception mapping to API responses."""

import pytest

from eiams.shared.errors import (
    DomainError,
    ValidationError,
    TenantRequiredError,
    InvalidTenantError,
    ActorRequiredError,
    InvalidActorError,
    InvalidCorrelationIdError,
    AuthorizationError,
    PermissionDeniedError,
    ErrorCode,
    ApiError,
    ApiErrorCode,
    ExceptionMapper,
    map_exception_to_response,
)


class TestExceptionMapper:
    """Tests for ExceptionMapper."""

    def test_maps_validation_error(self):
        """ValidationError should map to 422 response."""
        mapper = ExceptionMapper()
        exc = ValidationError("Invalid email format", field="email")

        payload = mapper.map_exception(exc, "corr-123")

        assert payload.code == "VALIDATION_FAILED"
        assert payload.status_code == 422
        assert payload.correlation_id == "corr-123"
        assert len(payload.field_errors) == 1
        assert payload.field_errors[0].field == "email"

    def test_maps_actor_required_error(self):
        """ActorRequiredError should map to 401 response."""
        mapper = ExceptionMapper()
        exc = ActorRequiredError()

        payload = mapper.map_exception(exc)

        assert payload.code == "AUTHENTICATION_REQUIRED"
        assert payload.status_code == 401

    def test_maps_invalid_actor_error(self):
        """InvalidActorError should map to 401 response."""
        mapper = ExceptionMapper()
        exc = InvalidActorError("Actor ID is invalid")

        payload = mapper.map_exception(exc)

        assert payload.code == "AUTHENTICATION_REQUIRED"
        assert payload.status_code == 401

    def test_maps_tenant_required_error(self):
        """TenantRequiredError should map to 403 response."""
        mapper = ExceptionMapper()
        exc = TenantRequiredError()

        payload = mapper.map_exception(exc)

        assert payload.code == "TENANT_ACCESS_DENIED"
        assert payload.status_code == 403

    def test_maps_invalid_tenant_error(self):
        """InvalidTenantError should map to 403 response."""
        mapper = ExceptionMapper()
        exc = InvalidTenantError("Tenant not found")

        payload = mapper.map_exception(exc)

        assert payload.code == "TENANT_ACCESS_DENIED"
        assert payload.status_code == 403

    def test_maps_permission_denied_error(self):
        """PermissionDeniedError should map to 403 response."""
        mapper = ExceptionMapper()
        exc = PermissionDeniedError(
            "Cannot delete user",
            resource="user",
            action="delete",
        )

        payload = mapper.map_exception(exc)

        assert payload.code == "PERMISSION_DENIED"
        assert payload.status_code == 403

    def test_maps_authorization_error(self):
        """AuthorizationError should map to 403 response."""
        mapper = ExceptionMapper()
        exc = AuthorizationError("Not authorized")

        payload = mapper.map_exception(exc)

        assert payload.code == "AUTHORIZATION_DENIED"
        assert payload.status_code == 403

    def test_maps_not_found_domain_error(self):
        """Resource not found errors should map to 404."""
        mapper = ExceptionMapper()
        exc = DomainError(
            "User not found",
            code=ErrorCode.RESOURCE_NOT_FOUND,
        )

        payload = mapper.map_exception(exc)

        assert payload.code == "RESOURCE_NOT_FOUND"
        assert payload.status_code == 404

    def test_maps_conflict_domain_error(self):
        """Resource conflict errors should map to 409."""
        mapper = ExceptionMapper()
        exc = DomainError(
            "User already exists",
            code=ErrorCode.RESOURCE_ALREADY_EXISTS,
        )

        payload = mapper.map_exception(exc)

        assert payload.code == "RESOURCE_ALREADY_EXISTS"
        assert payload.status_code == 409

    def test_maps_value_error(self):
        """Python ValueError should map to validation error."""
        mapper = ExceptionMapper()
        exc = ValueError("Invalid value provided")

        payload = mapper.map_exception(exc, "corr-456")

        assert payload.status_code == 422
        assert payload.correlation_id == "corr-456"

    def test_maps_type_error_safely(self):
        """TypeError should map to safe internal error."""
        mapper = ExceptionMapper()
        exc = TypeError("unsupported operand type")

        payload = mapper.map_exception(exc)

        assert payload.status_code == 500
        assert "unexpected" in payload.message.lower()
        # Should not expose internal details
        assert "operand" not in payload.message

    def test_maps_unknown_exception_safely(self):
        """Unknown exceptions should map to safe internal error."""
        mapper = ExceptionMapper()
        exc = RuntimeError("Internal implementation detail")

        payload = mapper.map_exception(exc)

        assert payload.status_code == 500
        assert "unexpected" in payload.message.lower()
        assert "implementation" not in payload.message

    def test_passes_through_api_error(self):
        """ApiError should pass through unchanged."""
        mapper = ExceptionMapper()
        original = ApiError(
            code=ApiErrorCode.RATE_LIMIT_EXCEEDED,
            message="Too many requests",
            status_code=429,
        )

        payload = mapper.map_exception(original, "corr-789")

        assert payload.code == "RATE_LIMIT_EXCEEDED"
        assert payload.status_code == 429
        assert payload.correlation_id == "corr-789"

    def test_correlation_id_propagation(self):
        """Correlation ID should be included in all responses."""
        mapper = ExceptionMapper()
        exc = ValidationError("Test error")

        payload = mapper.map_exception(exc, "test-correlation-id")

        assert payload.correlation_id == "test-correlation-id"


class TestExceptionMapperSafeMode:
    """Tests for safe mode in exception mapper."""

    def test_safe_mode_redacts_secrets(self):
        """Safe mode should redact sensitive data in messages."""
        mapper = ExceptionMapper(safe_mode=True)
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        exc = ValidationError(f"Invalid token: {jwt}")

        payload = mapper.map_exception(exc)

        assert jwt not in payload.message

    def test_safe_mode_filters_details(self):
        """Safe mode should filter internal details."""
        mapper = ExceptionMapper(safe_mode=True)
        exc = PermissionDeniedError(
            "Access denied",
            details={
                "resource": "user",
                "action": "delete",
                "internal_trace": "some/internal/path",
                "stack_frame": "frame info",
            },
        )

        payload = mapper.map_exception(exc)

        # Safe keys should be preserved
        assert payload.details.get("resource") == "user"
        assert payload.details.get("action") == "delete"
        # Internal keys should be filtered
        assert "internal_trace" not in payload.details
        assert "stack_frame" not in payload.details


class TestCustomExceptionMappers:
    """Tests for custom exception mapper registration."""

    def test_register_custom_mapper(self):
        """Custom mappers should be invoked for matching exceptions."""
        mapper = ExceptionMapper()

        class CustomException(Exception):
            pass

        def custom_mapper(exc, corr_id):
            return ApiError(
                code="CUSTOM_ERROR",
                message="Custom error handled",
                status_code=418,
                correlation_id=corr_id,
            )

        mapper.register_mapper(CustomException, custom_mapper)

        payload = mapper.map_exception(
            CustomException("test"),
            "corr-custom",
        )

        assert payload.code == "CUSTOM_ERROR"
        assert payload.status_code == 418
        assert payload.correlation_id == "corr-custom"

    def test_custom_mapper_inheritance(self):
        """Custom mappers should work with exception inheritance."""
        mapper = ExceptionMapper()

        class BaseException(Exception):
            pass

        class DerivedExc(BaseException):
            pass

        def base_mapper(exc, corr_id):
            return ApiError(
                code="BASE_ERROR",
                message="Base handled",
                status_code=400,
                correlation_id=corr_id,
            )

        mapper.register_mapper(BaseException, base_mapper)

        # Derived exception should use base mapper
        payload = mapper.map_exception(DerivedExc("test"))

        assert payload.code == "BASE_ERROR"


class TestMapExceptionToResponse:
    """Tests for convenience function."""

    def test_returns_dict(self):
        """Convenience function should return response dict."""
        exc = ValidationError("Invalid input")

        result = map_exception_to_response(exc, "corr-123")

        assert isinstance(result, dict)
        assert "error" in result
        assert "api_version" in result
        assert result["error"]["correlation_id"] == "corr-123"


class TestMalformedInputHandling:
    """Tests for safe handling of malformed input."""

    def test_handles_none_in_error_details(self):
        """Mapper should handle None values in error details."""
        mapper = ExceptionMapper()
        exc = DomainError("Error", details={"key": None})

        payload = mapper.map_exception(exc)

        # Should not raise
        assert payload is not None

    def test_handles_circular_reference(self):
        """Mapper should handle complex nested structures."""
        mapper = ExceptionMapper()
        details: dict = {"level1": {"level2": {}}}
        details["level1"]["level2"]["back"] = details  # Circular
        exc = DomainError("Error", details=details)

        # Should not raise or infinite loop due to max depth
        payload = mapper.map_exception(exc)
        assert payload is not None

    def test_handles_invalid_correlation_id_error(self):
        """InvalidCorrelationIdError should map to validation error."""
        mapper = ExceptionMapper()
        exc = InvalidCorrelationIdError("Invalid format")

        payload = mapper.map_exception(exc)

        assert payload.status_code == 422
        assert len(payload.field_errors) == 1
        assert payload.field_errors[0].field == "correlation_id"
