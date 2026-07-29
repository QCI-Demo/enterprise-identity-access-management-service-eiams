"""Tests for API error codes and response payloads."""

import pytest

from eiams.shared.errors import (
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


class TestFieldError:
    """Tests for FieldError."""

    def test_field_error_to_dict(self):
        """FieldError should serialize to dictionary."""
        error = FieldError(
            field="email",
            code="invalid_format",
            message="Email format is invalid",
        )

        result = error.to_dict()

        assert result["field"] == "email"
        assert result["code"] == "invalid_format"
        assert result["message"] == "Email format is invalid"


class TestApiErrorPayload:
    """Tests for ApiErrorPayload."""

    def test_basic_payload_structure(self):
        """Payload should have versioned structure."""
        payload = ApiErrorPayload(
            code="VALIDATION_FAILED",
            message="Validation failed",
            correlation_id="corr-123",
            status_code=422,
        )

        result = payload.to_dict()

        assert "error" in result
        assert "api_version" in result
        assert result["api_version"] == "v1"
        assert result["error"]["code"] == "VALIDATION_FAILED"
        assert result["error"]["message"] == "Validation failed"
        assert result["error"]["correlation_id"] == "corr-123"

    def test_payload_with_field_errors(self):
        """Payload should include field errors when present."""
        payload = ApiErrorPayload(
            code="VALIDATION_FAILED",
            message="Validation failed",
            field_errors=(
                FieldError("email", "required", "Email is required"),
                FieldError("name", "too_short", "Name too short"),
            ),
        )

        result = payload.to_dict()

        assert "field_errors" in result["error"]
        assert len(result["error"]["field_errors"]) == 2
        assert result["error"]["field_errors"][0]["field"] == "email"
        assert result["error"]["field_errors"][1]["field"] == "name"

    def test_payload_without_optional_fields(self):
        """Payload should omit optional fields when not set."""
        payload = ApiErrorPayload(
            code="INTERNAL_ERROR",
            message="Error occurred",
        )

        result = payload.to_dict()

        assert "correlation_id" not in result["error"]
        assert "field_errors" not in result["error"]
        assert "details" not in result["error"]

    def test_http_status_property(self):
        """Payload should expose HTTP status as enum."""
        payload = ApiErrorPayload(
            code="NOT_FOUND",
            message="Not found",
            status_code=404,
        )

        assert payload.http_status == HttpStatusCode.NOT_FOUND


class TestApiError:
    """Tests for ApiError base class."""

    def test_api_error_properties(self):
        """ApiError should expose all properties."""
        error = ApiError(
            code=ApiErrorCode.VALIDATION_FAILED,
            message="Validation failed",
            status_code=HttpStatusCode.UNPROCESSABLE_ENTITY,
            correlation_id="corr-123",
            field_errors=[FieldError("email", "invalid", "Invalid email")],
            details={"hint": "Use valid format"},
        )

        assert error.code == "VALIDATION_FAILED"
        assert error.message == "Validation failed"
        assert error.status_code == 422
        assert error.correlation_id == "corr-123"
        assert len(error.field_errors) == 1
        assert error.details["hint"] == "Use valid format"

    def test_with_correlation_id(self):
        """ApiError should support adding correlation ID."""
        original = ApiError(
            code="TEST_ERROR",
            message="Test",
        )

        with_corr = original.with_correlation_id("corr-456")

        assert original.correlation_id is None
        assert with_corr.correlation_id == "corr-456"
        assert with_corr.code == original.code
        assert with_corr.message == original.message

    def test_to_payload(self):
        """ApiError should convert to payload."""
        error = ApiError(
            code=ApiErrorCode.INTERNAL_ERROR,
            message="Something went wrong",
            correlation_id="corr-789",
        )

        payload = error.to_payload()

        assert isinstance(payload, ApiErrorPayload)
        assert payload.code == "INTERNAL_ERROR"
        assert payload.correlation_id == "corr-789"


class TestValidationApiError:
    """Tests for ValidationApiError."""

    def test_default_values(self):
        """ValidationApiError should have correct defaults."""
        error = ValidationApiError()

        assert error.code == "VALIDATION_FAILED"
        assert error.status_code == 422

    def test_with_field_errors(self):
        """ValidationApiError should accept field errors."""
        error = ValidationApiError(
            message="Invalid input",
            field_errors=[
                FieldError("field1", "invalid", "Invalid value"),
            ],
            correlation_id="corr-001",
        )

        assert len(error.field_errors) == 1
        assert error.correlation_id == "corr-001"


class TestAuthenticationApiError:
    """Tests for AuthenticationApiError."""

    def test_default_values(self):
        """AuthenticationApiError should have correct defaults."""
        error = AuthenticationApiError()

        assert error.code == "AUTHENTICATION_REQUIRED"
        assert error.status_code == 401
        assert error.message == "Authentication required"

    def test_custom_code(self):
        """AuthenticationApiError should support custom codes."""
        error = AuthenticationApiError(
            message="Token has expired",
            code=ApiErrorCode.TOKEN_EXPIRED,
        )

        assert error.code == "TOKEN_EXPIRED"
        assert error.message == "Token has expired"


class TestAuthorizationApiError:
    """Tests for AuthorizationApiError."""

    def test_default_values(self):
        """AuthorizationApiError should have correct defaults."""
        error = AuthorizationApiError()

        assert error.code == "AUTHORIZATION_DENIED"
        assert error.status_code == 403
        assert error.message == "Access denied"

    def test_with_details(self):
        """AuthorizationApiError should support details."""
        error = AuthorizationApiError(
            message="Cannot access resource",
            details={"resource_type": "user", "action": "delete"},
        )

        assert error.details["resource_type"] == "user"
        assert error.details["action"] == "delete"


class TestNotFoundApiError:
    """Tests for NotFoundApiError."""

    def test_default_values(self):
        """NotFoundApiError should have correct defaults."""
        error = NotFoundApiError()

        assert error.code == "RESOURCE_NOT_FOUND"
        assert error.status_code == 404

    def test_with_resource_info(self):
        """NotFoundApiError should include resource info."""
        error = NotFoundApiError(
            message="User not found",
            resource_type="user",
            resource_id="user-123",
        )

        assert error.details["resource_type"] == "user"
        assert error.details["resource_id"] == "user-123"


class TestConflictApiError:
    """Tests for ConflictApiError."""

    def test_default_values(self):
        """ConflictApiError should have correct defaults."""
        error = ConflictApiError()

        assert error.code == "RESOURCE_CONFLICT"
        assert error.status_code == 409


class TestInternalApiError:
    """Tests for InternalApiError."""

    def test_default_values(self):
        """InternalApiError should have correct defaults."""
        error = InternalApiError()

        assert error.code == "INTERNAL_ERROR"
        assert error.status_code == 500
        assert error.message == "An unexpected error occurred"

    def test_does_not_expose_details(self):
        """InternalApiError should not expose internal details."""
        error = InternalApiError(correlation_id="corr-999")

        # Internal error should have generic message
        assert "unexpected" in error.message.lower()
        # Should have correlation for tracking
        assert error.correlation_id == "corr-999"


class TestResponsePayloadShape:
    """Tests ensuring response payload shape is correct for all error types."""

    @pytest.mark.parametrize("error_class,expected_status", [
        (lambda: ValidationApiError(), 422),
        (lambda: AuthenticationApiError(), 401),
        (lambda: AuthorizationApiError(), 403),
        (lambda: NotFoundApiError(), 404),
        (lambda: ConflictApiError(), 409),
        (lambda: InternalApiError(), 500),
    ])
    def test_all_error_types_have_correct_status(self, error_class, expected_status):
        """All error types should have correct HTTP status codes."""
        error = error_class()
        assert error.status_code == expected_status

    def test_all_errors_produce_valid_payload(self):
        """All error types should produce valid API payloads."""
        errors = [
            ValidationApiError(correlation_id="c1"),
            AuthenticationApiError(correlation_id="c2"),
            AuthorizationApiError(correlation_id="c3"),
            NotFoundApiError(correlation_id="c4"),
            ConflictApiError(correlation_id="c5"),
            InternalApiError(correlation_id="c6"),
        ]

        for error in errors:
            payload = error.to_payload()
            result = payload.to_dict()

            # Verify common structure
            assert "error" in result
            assert "api_version" in result
            assert "code" in result["error"]
            assert "message" in result["error"]
            assert result["error"]["correlation_id"] is not None
