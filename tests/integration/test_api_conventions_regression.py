"""Regression tests for API convention components.

Tests the integrated behavior of validation, error mapping,
correlation tracking, redaction, and authorization hooks.
"""

import pytest

from eiams.shared.kernel import ActorId, TenantId, CorrelationId
from eiams.shared.context import RequestContextFactory
from eiams.shared.errors import (
    ValidationError,
    TenantRequiredError,
    PermissionDeniedError,
    DomainError,
    ErrorCode,
    ExceptionMapper,
    ValidationApiError,
    AuthorizationApiError,
    FieldError,
    map_exception_to_response,
)
from eiams.shared.logging import (
    StructuredLogger,
    LogOutcome,
    SecretRedactor,
)
from eiams.shared.logging.structured_logging import CaptureLogOutput
from eiams.domain.authorization.contracts import AuthorizationDecision
from eiams.infrastructure.adapters import (
    AuthorizationMiddleware,
    ProtectedOperationMetadata,
    ValidationAdapter,
    ValidationResult,
    FieldValidator,
    HttpContextExtractor,
)


class TestValidationErrorContractRegression:
    """Regression tests for validation error response contracts."""

    def test_validation_error_response_shape(self):
        """Validation errors should have standardized shape."""
        exc = ValidationError("Invalid email", field="email")

        response = map_exception_to_response(exc, "corr-001")

        # Verify response structure
        assert "error" in response
        assert "api_version" in response
        assert response["api_version"] == "v1"

        error = response["error"]
        assert "code" in error
        assert "message" in error
        assert error["code"] == "VALIDATION_FAILED"
        assert error["correlation_id"] == "corr-001"

    def test_multiple_field_errors_preserved(self):
        """Multiple field errors should be included in response."""
        exc = ValidationApiError(
            message="Validation failed",
            field_errors=[
                FieldError("email", "invalid_format", "Invalid email format"),
                FieldError("name", "required", "Name is required"),
                FieldError("age", "invalid_range", "Age must be positive"),
            ],
            correlation_id="corr-002",
        )

        payload = exc.to_payload()
        response = payload.to_dict()

        field_errors = response["error"]["field_errors"]
        assert len(field_errors) == 3

        fields = {e["field"] for e in field_errors}
        assert fields == {"email", "name", "age"}

    def test_correlation_id_always_present(self):
        """Correlation ID should always be in error responses."""
        test_cases = [
            ValidationError("Test"),
            TenantRequiredError(),
            PermissionDeniedError(),
            DomainError("Generic error"),
        ]

        for exc in test_cases:
            response = map_exception_to_response(exc, "test-corr-id")
            assert response["error"]["correlation_id"] == "test-corr-id"


class TestSecretRedactionRegression:
    """Regression tests for secret redaction in all outputs."""

    def test_secrets_never_in_log_output(self):
        """Secrets should never appear in log JSON output."""
        output = CaptureLogOutput()
        logger = StructuredLogger(output=output)

        # Test various secret types
        secrets = {
            "password": "MyP@ssw0rd!123",
            "api_key": "sk-live-1234567890abcdef",
            "client_secret": "cs_secret_value_here",
            "refresh_token": "rt_1234567890abcdef",
            "access_token": "at_1234567890abcdef",
        }

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )

        logger.log_operation(
            context=context,
            operation="auth_test",
            outcome=LogOutcome.SUCCESS,
            message="Auth succeeded",
            **secrets,
        )

        # Get JSON output
        json_output = output.events[0].to_json()

        # Verify no secrets appear
        for secret_value in secrets.values():
            assert secret_value not in json_output, f"Secret {secret_value} found in log output"

    def test_jwt_redacted_everywhere(self):
        """JWTs should be redacted in all contexts."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

        # In log messages
        output = CaptureLogOutput()
        logger = StructuredLogger(output=output)
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        logger.log_operation(
            context=context,
            operation="token_process",
            outcome=LogOutcome.SUCCESS,
            message="Processed",
            token=jwt,
        )
        assert jwt not in output.events[0].to_json()

        # In exception mapping
        exc = ValidationError(f"Invalid token: {jwt}")
        response = map_exception_to_response(exc)
        import json
        response_str = json.dumps(response)
        assert jwt not in response_str

    def test_nested_secrets_redacted(self):
        """Secrets in nested structures should be redacted."""
        redactor = SecretRedactor()

        data = {
            "user": {
                "name": "John",
                "security": {
                    "password": "secret123",
                    "sessions": [
                        {"refresh_token": "rt1"},
                        {"refresh_token": "rt2"},
                    ]
                }
            }
        }

        result = redactor.redact(data)

        assert result["user"]["name"] == "John"
        assert result["user"]["security"]["password"] == "[REDACTED]"
        assert result["user"]["security"]["sessions"][0]["refresh_token"] == "[REDACTED]"
        assert result["user"]["security"]["sessions"][1]["refresh_token"] == "[REDACTED]"


class TestCorrelationTrackingRegression:
    """Regression tests for correlation ID propagation."""

    def test_correlation_flows_through_validation(self):
        """Correlation ID should flow through validation errors."""
        corr_id = str(CorrelationId.generate())
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            correlation_id=corr_id,
        )

        output = CaptureLogOutput()
        logger = StructuredLogger(output=output)

        try:
            raise ValidationApiError(
                message="Invalid input",
                correlation_id=corr_id,
            )
        except ValidationApiError as exc:
            logger.log_error(
                context=context,
                message="Validation failed",
                exception=exc,
            )

            payload = exc.to_payload()

        # Check correlation in log
        assert output.events[0].correlation_id == corr_id
        # Check correlation in error payload
        assert payload.correlation_id == corr_id

    def test_correlation_flows_through_authorization(self):
        """Correlation ID should flow through authorization errors."""
        corr_id = str(CorrelationId.generate())

        class DenyingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.DENY

        middleware = AuthorizationMiddleware()
        middleware.register_hook(DenyingHook())

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            correlation_id=corr_id,
        )

        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="delete",
        )

        with pytest.raises(AuthorizationApiError) as exc_info:
            middleware.require_authorization(context, metadata)

        assert exc_info.value.correlation_id == corr_id


class TestAuthorizationHookRegression:
    """Regression tests for authorization hook behavior."""

    def test_protected_operation_receives_validated_actor(self):
        """Protected operations should receive validated actor context."""
        captured_contexts = []

        class CapturingHook:
            def authorize(self, context, operation):
                captured_contexts.append(context)
                return AuthorizationDecision.ALLOW

        middleware = AuthorizationMiddleware()
        middleware.register_hook(CapturingHook())

        actor_id = ActorId.generate()
        context = RequestContextFactory.create(
            actor_id=str(actor_id),
            roles=["admin"],
            permissions=["user:read", "user:write"],
        )

        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="update",
        )

        middleware.check_authorization(context, metadata)

        assert len(captured_contexts) == 1
        captured = captured_contexts[0]
        assert captured.actor_id == actor_id
        assert "admin" in captured.actor.roles

    def test_protected_operation_receives_validated_tenant(self):
        """Protected operations should receive validated tenant context."""
        captured_contexts = []

        class CapturingHook:
            def authorize(self, context, operation):
                captured_contexts.append(context)
                return AuthorizationDecision.ALLOW

        middleware = AuthorizationMiddleware()
        middleware.register_hook(CapturingHook())

        tenant_id = TenantId.generate()
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            tenant_id=str(tenant_id),
        )

        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="read",
        )

        middleware.check_authorization(context, metadata)

        assert len(captured_contexts) == 1
        assert captured_contexts[0].tenant_id == tenant_id

    def test_malformed_context_yields_safe_error(self):
        """Malformed protected-operation context should yield safe errors."""
        middleware = AuthorizationMiddleware()

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )

        # Malformed metadata - empty resource type
        metadata = ProtectedOperationMetadata(
            resource_type="",
            action="read",
        )

        decision = middleware.check_authorization(context, metadata)

        # Should be denied safely (not raise, not expose internals)
        assert decision == AuthorizationDecision.DENY


class TestIntegratedValidationAndErrorFlow:
    """Integration tests for complete validation and error flow."""

    def test_end_to_end_validation_error_flow(self):
        """Test complete flow from validation failure to API response."""
        output = CaptureLogOutput()
        logger = StructuredLogger(output=output)
        mapper = ExceptionMapper()
        adapter = ValidationAdapter(
            exception_mapper=mapper,
            logger=logger,
        )

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            correlation_id="e2e-corr-123",
        )

        # Create validation result with errors
        result = ValidationResult.failure(
            FieldError("email", "invalid", "Invalid email format"),
            FieldError("password", "too_short", "Password too short"),
        )

        # Get or raise should produce proper error
        with pytest.raises(ValidationApiError) as exc_info:
            result.get_or_raise(str(context.correlation_id))

        exc = exc_info.value
        payload = exc.to_payload()
        response = payload.to_dict()

        # Verify complete response
        assert response["error"]["correlation_id"] == "e2e-corr-123"
        assert len(response["error"]["field_errors"]) == 2
        assert response["api_version"] == "v1"

    def test_end_to_end_authorization_error_flow(self):
        """Test complete flow from authorization failure to API response."""
        class DenyingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.DENY

        output = CaptureLogOutput()
        logger = StructuredLogger(output=output)
        middleware = AuthorizationMiddleware(logger=logger)
        middleware.register_hook(DenyingHook())
        mapper = ExceptionMapper()

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            correlation_id="e2e-auth-456",
        )

        metadata = ProtectedOperationMetadata(
            resource_type="admin",
            action="delete",
        )

        try:
            middleware.require_authorization(context, metadata)
            assert False, "Should have raised"
        except AuthorizationApiError as exc:
            payload = mapper.map_exception(exc, str(context.correlation_id))
            response = payload.to_dict()

        # Verify complete response
        assert response["error"]["code"] == "PERMISSION_DENIED"
        assert response["error"]["correlation_id"] == "e2e-auth-456"
        assert payload.status_code == 403

        # Verify logging occurred
        auth_events = output.find_by_operation("authorization_check")
        assert len(auth_events) >= 1


class TestHttpContextExtractionRegression:
    """Regression tests for HTTP context extraction."""

    def test_extracts_valid_context(self):
        """Should extract valid context from headers."""
        extractor = HttpContextExtractor(require_actor=True)

        request = {
            "X-Correlation-ID": "http-corr-123",
            "X-Actor-ID": str(ActorId.generate()),
            "X-Tenant-ID": str(TenantId.generate()),
            "X-Roles": "admin,user",
            "path": "/api/users",
            "method": "GET",
        }

        context = extractor.extract_context(request)

        assert context.correlation_id.value == "http-corr-123"
        assert "admin" in context.actor.roles
        assert "user" in context.actor.roles
        assert context.metadata.request_path == "/api/users"
        assert context.metadata.request_method == "GET"

    def test_generates_correlation_id_if_missing(self):
        """Should generate correlation ID if not provided."""
        extractor = HttpContextExtractor(require_actor=False)

        request = {
            "path": "/api/health",
            "method": "GET",
        }

        context = extractor.extract_context(request)

        assert context.correlation_id is not None
        assert len(str(context.correlation_id)) > 0
