"""Unit tests for domain errors."""

import pytest

from eiams.shared.errors import (
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


class TestDomainError:
    """Tests for base DomainError."""

    def test_create_with_message(self):
        """DomainError should accept a message."""
        error = DomainError("Something went wrong")
        assert error.message == "Something went wrong"
        assert str(error) == "Something went wrong"

    def test_default_error_code(self):
        """DomainError should have default error code."""
        error = DomainError("Error")
        assert error.code == ErrorCode.VALIDATION_ERROR

    def test_custom_error_code(self):
        """DomainError should accept custom error code."""
        error = DomainError("Not found", code=ErrorCode.RESOURCE_NOT_FOUND)
        assert error.code == ErrorCode.RESOURCE_NOT_FOUND

    def test_details(self):
        """DomainError should store details."""
        error = DomainError("Error", details={"key": "value"})
        assert error.details == {"key": "value"}

    def test_details_returns_copy(self):
        """details property should return a copy."""
        details = {"key": "value"}
        error = DomainError("Error", details=details)

        # Modifying returned dict shouldn't affect error
        error.details["new_key"] = "new_value"
        assert "new_key" not in error.details

    def test_to_dict_serialization(self):
        """to_dict should return API-safe structure."""
        error = DomainError(
            "Something wrong",
            code=ErrorCode.VALIDATION_ERROR,
            details={"field": "email"},
        )
        result = error.to_dict()

        assert "error" in result
        assert result["error"]["code"] == "VALIDATION_ERROR"
        assert result["error"]["message"] == "Something wrong"
        assert result["error"]["details"]["field"] == "email"

    def test_repr(self):
        """repr should be informative."""
        error = DomainError("Test error", code=ErrorCode.VALIDATION_ERROR)
        repr_str = repr(error)
        assert "DomainError" in repr_str
        assert "VALIDATION_ERROR" in repr_str


class TestValidationError:
    """Tests for ValidationError."""

    def test_create_with_field(self):
        """ValidationError should accept field name."""
        error = ValidationError("Invalid email", field="email")
        assert error.field == "email"
        assert error.details["field"] == "email"

    def test_create_without_field(self):
        """ValidationError should work without field."""
        error = ValidationError("Invalid input")
        assert error.field is None

    def test_error_code(self):
        """ValidationError should have VALIDATION_ERROR code."""
        error = ValidationError("Error")
        assert error.code == ErrorCode.VALIDATION_ERROR


class TestContextErrors:
    """Tests for context-related errors."""

    def test_tenant_required_error_defaults(self):
        """TenantRequiredError should have sensible defaults."""
        error = TenantRequiredError()
        assert "tenant" in error.message.lower()
        assert error.code == ErrorCode.TENANT_REQUIRED

    def test_tenant_required_error_custom_message(self):
        """TenantRequiredError should accept custom message."""
        error = TenantRequiredError("Custom tenant message")
        assert error.message == "Custom tenant message"

    def test_invalid_tenant_error_with_id(self):
        """InvalidTenantError should include tenant ID in details."""
        error = InvalidTenantError(tenant_id="bad-id-123")
        assert error.details["tenant_id"] == "bad-id-123"

    def test_actor_required_error_defaults(self):
        """ActorRequiredError should have sensible defaults."""
        error = ActorRequiredError()
        assert "actor" in error.message.lower()
        assert error.code == ErrorCode.ACTOR_REQUIRED

    def test_invalid_actor_error_with_id(self):
        """InvalidActorError should include actor ID in details."""
        error = InvalidActorError(actor_id="bad-actor")
        assert error.details["actor_id"] == "bad-actor"

    def test_invalid_correlation_id_error_with_id(self):
        """InvalidCorrelationIdError should include ID in details."""
        error = InvalidCorrelationIdError(correlation_id="bad@id")
        assert error.details["correlation_id"] == "bad@id"


class TestAuthorizationErrors:
    """Tests for authorization-related errors."""

    def test_authorization_error_defaults(self):
        """AuthorizationError should have default code."""
        error = AuthorizationError("Not authorized")
        assert error.code == ErrorCode.AUTHORIZATION_FAILED

    def test_permission_denied_error_defaults(self):
        """PermissionDeniedError should have sensible defaults."""
        error = PermissionDeniedError()
        assert error.code == ErrorCode.PERMISSION_DENIED
        assert "denied" in error.message.lower()

    def test_permission_denied_error_with_resource(self):
        """PermissionDeniedError should accept resource info."""
        error = PermissionDeniedError(
            "Cannot delete user",
            resource="user",
            action="delete",
        )
        assert error.details["resource"] == "user"
        assert error.details["action"] == "delete"


class TestErrorCodes:
    """Tests for ErrorCode enum."""

    def test_error_codes_are_strings(self):
        """ErrorCode values should be strings."""
        assert isinstance(ErrorCode.VALIDATION_ERROR.value, str)
        assert isinstance(ErrorCode.TENANT_REQUIRED.value, str)

    def test_error_codes_are_uppercase(self):
        """ErrorCode values should be uppercase."""
        for code in ErrorCode:
            assert code.value == code.value.upper()

    def test_all_context_errors_have_codes(self):
        """All context-related error types should have appropriate codes."""
        assert ErrorCode.TENANT_REQUIRED.value == "TENANT_REQUIRED"
        assert ErrorCode.TENANT_INVALID.value == "TENANT_INVALID"
        assert ErrorCode.ACTOR_REQUIRED.value == "ACTOR_REQUIRED"
        assert ErrorCode.ACTOR_INVALID.value == "ACTOR_INVALID"
        assert ErrorCode.CORRELATION_ID_INVALID.value == "CORRELATION_ID_INVALID"
