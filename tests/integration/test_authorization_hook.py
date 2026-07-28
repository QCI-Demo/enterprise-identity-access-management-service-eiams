"""Integration tests for authorization hooks."""

import pytest

from eiams.shared.kernel import TenantId, ActorId
from eiams.shared.context import RequestContextFactory
from eiams.domain.authorization.contracts import (
    AuthorizationDecision,
    OperationContext,
)
from eiams.infrastructure.adapters import (
    CompositeAuthorizationHook,
    LoggingAuthorizationHook,
)
from eiams.infrastructure.adapters.authorization_hook import PassThroughAuthorizationHook


class TestAuthorizationHook:
    """Tests for authorization hook contracts."""

    def test_logging_hook_returns_not_applicable(self):
        """Logging hook should not make decisions."""
        log_messages = []
        hook = LoggingAuthorizationHook(logger=log_messages.append)

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        operation = OperationContext(
            resource_type="user",
            resource_id="123",
            action="read",
            attributes={},
        )

        decision = hook.authorize(context, operation)

        assert decision == AuthorizationDecision.NOT_APPLICABLE
        assert len(log_messages) == 1
        assert "user/123" in log_messages[0]
        assert "read" in log_messages[0]

    def test_composite_hook_evaluates_in_order(self):
        """Composite hook should evaluate hooks in registration order."""
        call_order = []

        class OrderTrackingHook:
            def __init__(self, name: str, decision: AuthorizationDecision):
                self.name = name
                self.decision = decision

            def authorize(self, context, operation):
                call_order.append(self.name)
                return self.decision

        composite = CompositeAuthorizationHook()
        composite.add_hook(OrderTrackingHook("first", AuthorizationDecision.NOT_APPLICABLE))
        composite.add_hook(OrderTrackingHook("second", AuthorizationDecision.ALLOW))
        composite.add_hook(OrderTrackingHook("third", AuthorizationDecision.DENY))

        context = RequestContextFactory.create_system()
        operation = OperationContext(
            resource_type="test",
            resource_id=None,
            action="test",
            attributes={},
        )

        decision = composite.authorize(context, operation)

        # Should stop at "second" which returns ALLOW
        assert decision == AuthorizationDecision.ALLOW
        assert call_order == ["first", "second"]

    def test_composite_hook_returns_default_when_all_not_applicable(self):
        """Composite should return default decision when all hooks abstain."""

        class AbstainingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.NOT_APPLICABLE

        # Default is DENY (fail-closed)
        composite = CompositeAuthorizationHook(default_decision=AuthorizationDecision.DENY)
        composite.add_hook(AbstainingHook())
        composite.add_hook(AbstainingHook())

        context = RequestContextFactory.create_system()
        operation = OperationContext(
            resource_type="test",
            resource_id=None,
            action="test",
            attributes={},
        )

        decision = composite.authorize(context, operation)

        assert decision == AuthorizationDecision.DENY

    def test_composite_hook_can_use_allow_default(self):
        """Composite can be configured with ALLOW default."""
        composite = CompositeAuthorizationHook(
            default_decision=AuthorizationDecision.ALLOW
        )

        context = RequestContextFactory.create_system()
        operation = OperationContext(
            resource_type="test",
            resource_id=None,
            action="test",
            attributes={},
        )

        decision = composite.authorize(context, operation)

        assert decision == AuthorizationDecision.ALLOW

    def test_hook_receives_operation_metadata(self):
        """Authorization hooks should receive full operation metadata."""
        received_operations = []

        class MetadataCapturingHook:
            def authorize(self, context, operation):
                received_operations.append(operation)
                return AuthorizationDecision.NOT_APPLICABLE

        composite = CompositeAuthorizationHook()
        composite.add_hook(MetadataCapturingHook())

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            tenant_id=str(TenantId.generate()),
        )
        operation = OperationContext(
            resource_type="user",
            resource_id="user-123",
            action="delete",
            attributes={"reason": "test"},
        )

        composite.authorize(context, operation)

        assert len(received_operations) == 1
        captured = received_operations[0]
        assert captured.resource_type == "user"
        assert captured.resource_id == "user-123"
        assert captured.action == "delete"
        assert captured.attributes["reason"] == "test"

    def test_hook_receives_request_context(self):
        """Authorization hooks should receive full request context."""
        received_contexts = []

        class ContextCapturingHook:
            def authorize(self, context, operation):
                received_contexts.append(context)
                return AuthorizationDecision.NOT_APPLICABLE

        composite = CompositeAuthorizationHook()
        composite.add_hook(ContextCapturingHook())

        actor_id = ActorId.generate()
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create(
            actor_id=str(actor_id),
            tenant_id=str(tenant_id),
            roles=["admin"],
        )
        operation = OperationContext(
            resource_type="test",
            resource_id=None,
            action="test",
            attributes={},
        )

        composite.authorize(context, operation)

        assert len(received_contexts) == 1
        captured = received_contexts[0]
        assert captured.actor_id == actor_id
        assert captured.tenant_id == tenant_id
        assert "admin" in captured.actor.roles

    def test_pass_through_hook_always_allows(self):
        """PassThroughAuthorizationHook should always allow."""
        hook = PassThroughAuthorizationHook()

        context = RequestContextFactory.create_anonymous()
        operation = OperationContext(
            resource_type="sensitive",
            resource_id="secret-123",
            action="delete",
            attributes={},
        )

        decision = hook.authorize(context, operation)

        assert decision == AuthorizationDecision.ALLOW

    def test_composite_hook_count(self):
        """Composite should track registered hook count."""
        composite = CompositeAuthorizationHook()
        assert composite.hook_count == 0

        composite.add_hook(LoggingAuthorizationHook())
        assert composite.hook_count == 1

        composite.add_hook(PassThroughAuthorizationHook())
        assert composite.hook_count == 2

    def test_composite_remove_hook(self):
        """Composite should support removing hooks."""
        hook = LoggingAuthorizationHook()
        composite = CompositeAuthorizationHook()
        composite.add_hook(hook)

        assert composite.hook_count == 1
        result = composite.remove_hook(hook)
        assert result is True
        assert composite.hook_count == 0

    def test_composite_remove_nonexistent_hook(self):
        """Removing non-existent hook should return False."""
        composite = CompositeAuthorizationHook()
        hook = LoggingAuthorizationHook()

        result = composite.remove_hook(hook)
        assert result is False

    def test_operation_context_serialization(self):
        """OperationContext should be serializable for audit."""
        operation = OperationContext(
            resource_type="user",
            resource_id="user-123",
            action="update",
            attributes={"field": "email"},
        )

        serialized = operation.to_dict()

        assert serialized["resource_type"] == "user"
        assert serialized["resource_id"] == "user-123"
        assert serialized["action"] == "update"
        assert serialized["attributes"]["field"] == "email"


class TestAuthorizationIntegration:
    """Integration tests for authorization in request flow."""

    def test_authorization_hook_in_service_flow(self):
        """Authorization hook should be invoked during service calls."""
        authorization_calls = []

        class AuditingHook:
            def authorize(self, context, operation):
                authorization_calls.append({
                    "actor": str(context.actor_id),
                    "resource": operation.resource_type,
                    "action": operation.action,
                })
                return AuthorizationDecision.ALLOW

        # Setup
        composite = CompositeAuthorizationHook()
        composite.add_hook(AuditingHook())

        # Simulated service that checks authorization
        def user_service_update(context, user_id: str):
            operation = OperationContext(
                resource_type="user",
                resource_id=user_id,
                action="update",
                attributes={},
            )
            decision = composite.authorize(context, operation)
            if decision != AuthorizationDecision.ALLOW:
                raise PermissionError("Not authorized")
            return f"Updated user {user_id}"

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            tenant_id=str(TenantId.generate()),
        )

        result = user_service_update(context, "user-456")

        assert result == "Updated user user-456"
        assert len(authorization_calls) == 1
        assert authorization_calls[0]["resource"] == "user"
        assert authorization_calls[0]["action"] == "update"

    def test_fail_closed_on_authorization_failure(self):
        """System should fail closed on authorization denial."""

        class DenyingHook:
            def authorize(self, context, operation):
                return AuthorizationDecision.DENY

        composite = CompositeAuthorizationHook()
        composite.add_hook(DenyingHook())

        def protected_operation(context):
            operation = OperationContext(
                resource_type="sensitive",
                resource_id="data-123",
                action="delete",
                attributes={},
            )
            decision = composite.authorize(context, operation)
            if decision != AuthorizationDecision.ALLOW:
                raise PermissionError("Operation denied")
            return "Deleted"

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )

        with pytest.raises(PermissionError):
            protected_operation(context)
