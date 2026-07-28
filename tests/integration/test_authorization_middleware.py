"""Integration tests for authorization middleware with request context."""

import pytest

from eiams.shared.kernel import ActorId, TenantId
from eiams.shared.context import RequestContextFactory, ActorType
from eiams.shared.errors import AuthorizationApiError
from eiams.shared.logging.structured_logging import CaptureLogOutput
from eiams.shared.logging import StructuredLogger
from eiams.domain.authorization.contracts import (
    AuthorizationDecision,
    OperationContext,
)
from eiams.infrastructure.adapters import (
    AuthorizationMiddleware,
    AuthorizationGuard,
    ProtectedOperationMetadata,
    CompositeAuthorizationHook,
    create_authorization_middleware,
)


class TestProtectedOperationMetadata:
    """Tests for ProtectedOperationMetadata."""

    def test_valid_metadata(self):
        """Valid metadata should pass validation."""
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="update",
            resource_id="user-123",
        )

        assert metadata.is_valid()

    def test_invalid_metadata_missing_resource_type(self):
        """Metadata without resource_type should be invalid."""
        metadata = ProtectedOperationMetadata(
            resource_type="",
            action="update",
        )

        assert not metadata.is_valid()

    def test_invalid_metadata_missing_action(self):
        """Metadata without action should be invalid."""
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="",
        )

        assert not metadata.is_valid()

    def test_to_operation_context(self):
        """Should convert to OperationContext."""
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="delete",
            resource_id="user-456",
            attributes={"reason": "test"},
        )

        op = metadata.to_operation_context()

        assert isinstance(op, OperationContext)
        assert op.resource_type == "user"
        assert op.action == "delete"
        assert op.resource_id == "user-456"
        assert op.attributes["reason"] == "test"


class TestAuthorizationGuard:
    """Tests for AuthorizationGuard validation."""

    def test_validate_context_valid(self):
        """Valid context should have no errors."""
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )

        errors = AuthorizationGuard.validate_context(context)

        assert len(errors) == 0

    def test_validate_context_none(self):
        """None context should report error."""
        errors = AuthorizationGuard.validate_context(None)

        assert len(errors) > 0
        assert "context is required" in errors[0].lower()

    def test_validate_operation_valid(self):
        """Valid operation should have no errors."""
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="read",
        )

        errors = AuthorizationGuard.validate_operation(metadata)

        assert len(errors) == 0

    def test_validate_operation_missing_resource(self):
        """Operation without resource_type should report error."""
        metadata = ProtectedOperationMetadata(
            resource_type="",
            action="read",
        )

        errors = AuthorizationGuard.validate_operation(metadata)

        assert any("resource type" in e.lower() for e in errors)

    def test_validate_operation_missing_action(self):
        """Operation without action should report error."""
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="",
        )

        errors = AuthorizationGuard.validate_operation(metadata)

        assert any("action" in e.lower() for e in errors)


class TestAuthorizationMiddleware:
    """Tests for AuthorizationMiddleware."""

    def test_check_authorization_with_allowing_hook(self):
        """Should return ALLOW when hook allows."""

        class AllowingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.ALLOW

        middleware = AuthorizationMiddleware()
        middleware.register_hook(AllowingHook())

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="read",
        )

        decision = middleware.check_authorization(context, metadata)

        assert decision == AuthorizationDecision.ALLOW

    def test_check_authorization_with_denying_hook(self):
        """Should return DENY when hook denies."""

        class DenyingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.DENY

        middleware = AuthorizationMiddleware()
        middleware.register_hook(DenyingHook())

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="delete",
        )

        decision = middleware.check_authorization(context, metadata)

        assert decision == AuthorizationDecision.DENY

    def test_deny_safe_for_malformed_metadata(self):
        """Should DENY when metadata is malformed (deny-safe)."""
        middleware = AuthorizationMiddleware()

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        # Invalid metadata - missing action
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="",
        )

        decision = middleware.check_authorization(context, metadata)

        assert decision == AuthorizationDecision.DENY

    def test_fail_closed_by_default(self):
        """Should DENY when no hooks decide (fail-closed)."""
        middleware = AuthorizationMiddleware(fail_open=False)

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="read",
        )

        decision = middleware.check_authorization(context, metadata)

        # No hooks registered, should default to DENY
        assert decision == AuthorizationDecision.DENY

    def test_fail_open_when_configured(self):
        """Should ALLOW when configured to fail open."""
        middleware = AuthorizationMiddleware(fail_open=True)

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="read",
        )

        decision = middleware.check_authorization(context, metadata)

        # No hooks registered, should default to ALLOW
        assert decision == AuthorizationDecision.ALLOW

    def test_require_authorization_raises_on_deny(self):
        """require_authorization should raise AuthorizationApiError on DENY."""

        class DenyingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.DENY

        middleware = AuthorizationMiddleware()
        middleware.register_hook(DenyingHook())

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="delete",
        )

        with pytest.raises(AuthorizationApiError) as exc_info:
            middleware.require_authorization(context, metadata)

        assert exc_info.value.status_code == 403
        assert exc_info.value.correlation_id == str(context.correlation_id)

    def test_require_authorization_passes_on_allow(self):
        """require_authorization should not raise on ALLOW."""

        class AllowingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.ALLOW

        middleware = AuthorizationMiddleware()
        middleware.register_hook(AllowingHook())

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="read",
        )

        # Should not raise
        middleware.require_authorization(context, metadata)

    def test_protect_decorator(self):
        """@protect decorator should enforce authorization."""
        call_count = [0]

        class AllowingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.ALLOW

        middleware = AuthorizationMiddleware()
        middleware.register_hook(AllowingHook())

        @middleware.protect("user", "update")
        def update_user(context, user_id):
            call_count[0] += 1
            return f"Updated {user_id}"

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )

        result = update_user(context, "user-123")

        assert result == "Updated user-123"
        assert call_count[0] == 1

    def test_protect_decorator_blocks_on_deny(self):
        """@protect decorator should raise on DENY."""

        class DenyingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.DENY

        middleware = AuthorizationMiddleware()
        middleware.register_hook(DenyingHook())

        @middleware.protect("user", "delete")
        def delete_user(context, user_id):
            return f"Deleted {user_id}"

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )

        with pytest.raises(AuthorizationApiError):
            delete_user(context, "user-123")


class TestAuthorizationMiddlewareLogging:
    """Tests for authorization middleware logging."""

    def test_logs_authorization_allow(self):
        """Should log successful authorization."""

        class AllowingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.ALLOW

        log_output = CaptureLogOutput()
        logger = StructuredLogger(output=log_output)
        middleware = AuthorizationMiddleware(logger=logger)
        middleware.register_hook(AllowingHook())

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="read",
        )

        middleware.check_authorization(context, metadata)

        events = log_output.find_by_operation("authorization_check")
        assert len(events) >= 1
        assert events[0].extra.get("decision") == "allow"

    def test_logs_authorization_deny(self):
        """Should log denied authorization."""

        class DenyingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.DENY

        log_output = CaptureLogOutput()
        logger = StructuredLogger(output=log_output)
        middleware = AuthorizationMiddleware(logger=logger)
        middleware.register_hook(DenyingHook())

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="delete",
        )

        middleware.check_authorization(context, metadata)

        events = log_output.find_by_operation("authorization_check")
        assert len(events) >= 1
        assert events[0].extra.get("decision") == "deny"

    def test_logs_malformed_metadata(self):
        """Should log denial reason for malformed metadata."""
        log_output = CaptureLogOutput()
        logger = StructuredLogger(output=log_output)
        middleware = AuthorizationMiddleware(logger=logger)

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        # Malformed metadata
        metadata = ProtectedOperationMetadata(
            resource_type="",
            action="",
        )

        middleware.check_authorization(context, metadata)

        events = log_output.find_by_operation("authorization_check")
        assert len(events) >= 1
        assert events[0].extra.get("reason") == "malformed_metadata"


class TestAuthorizationHookIntegration:
    """Integration tests for hooks receiving validated context."""

    def test_hook_receives_actor_context(self):
        """Authorization hooks should receive actor metadata."""
        received_contexts = []

        class CapturingHook:
            def authorize(self, context, operation):
                received_contexts.append(context)
                return AuthorizationDecision.ALLOW

        middleware = AuthorizationMiddleware()
        middleware.register_hook(CapturingHook())

        actor_id = ActorId.generate()
        context = RequestContextFactory.create(
            actor_id=str(actor_id),
            roles=["admin", "user"],
        )
        metadata = ProtectedOperationMetadata(
            resource_type="user",
            action="read",
        )

        middleware.check_authorization(context, metadata)

        assert len(received_contexts) == 1
        captured = received_contexts[0]
        assert captured.actor_id == actor_id
        assert "admin" in captured.actor.roles

    def test_hook_receives_tenant_context(self):
        """Authorization hooks should receive tenant metadata."""
        received_contexts = []

        class CapturingHook:
            def authorize(self, context, operation):
                received_contexts.append(context)
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

        assert len(received_contexts) == 1
        assert received_contexts[0].tenant_id == tenant_id

    def test_hook_receives_operation_metadata(self):
        """Authorization hooks should receive operation metadata."""
        received_operations = []

        class CapturingHook:
            def authorize(self, context, operation):
                received_operations.append(operation)
                return AuthorizationDecision.ALLOW

        middleware = AuthorizationMiddleware()
        middleware.register_hook(CapturingHook())

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        metadata = ProtectedOperationMetadata(
            resource_type="document",
            action="delete",
            resource_id="doc-789",
            attributes={"reason": "cleanup"},
        )

        middleware.check_authorization(context, metadata)

        assert len(received_operations) == 1
        captured = received_operations[0]
        assert captured.resource_type == "document"
        assert captured.action == "delete"
        assert captured.resource_id == "doc-789"
        assert captured.attributes["reason"] == "cleanup"


class TestCreateAuthorizationMiddleware:
    """Tests for factory function."""

    def test_creates_default_middleware(self):
        """Factory should create middleware with default settings."""
        middleware = create_authorization_middleware()

        assert isinstance(middleware, AuthorizationMiddleware)
        # Default is fail-closed
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        metadata = ProtectedOperationMetadata(
            resource_type="test",
            action="test",
        )
        decision = middleware.check_authorization(context, metadata)
        assert decision == AuthorizationDecision.DENY

    def test_creates_fail_open_middleware(self):
        """Factory should support fail_open configuration."""
        middleware = create_authorization_middleware(fail_open=True)

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        metadata = ProtectedOperationMetadata(
            resource_type="test",
            action="test",
        )
        decision = middleware.check_authorization(context, metadata)
        assert decision == AuthorizationDecision.ALLOW
