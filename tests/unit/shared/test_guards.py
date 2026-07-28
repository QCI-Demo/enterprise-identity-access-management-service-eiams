"""Unit tests for context guard functions."""

import pytest

from eiams.shared.kernel import TenantId, ActorId, CorrelationId, Timestamp
from eiams.shared.context import (
    RequestContext,
    RequestContextFactory,
    ActorContext,
    TenantContext,
    RequestMetadata,
    ActorType,
    require_tenant,
    require_actor,
    require_context,
)
from eiams.shared.context.guards import tenant_required, actor_required
from eiams.shared.errors import (
    TenantRequiredError,
    ActorRequiredError,
    ContextError,
)


class TestRequireTenant:
    """Tests for require_tenant guard function."""

    def test_passes_with_valid_tenant(self):
        """require_tenant should pass when tenant is present."""
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            tenant_id=str(TenantId.generate()),
        )
        # Should not raise
        require_tenant(context)

    def test_raises_when_tenant_missing(self):
        """require_tenant should raise when tenant is None."""
        context = RequestContextFactory.create_anonymous()
        with pytest.raises(TenantRequiredError) as exc_info:
            require_tenant(context)
        assert "correlation_id" in exc_info.value.details

    def test_raises_when_context_is_none(self):
        """require_tenant should raise when context is None."""
        with pytest.raises(ContextError):
            require_tenant(None)  # type: ignore

    def test_fail_closed_behavior(self):
        """require_tenant implements fail-closed: missing tenant = denied."""
        # Even with valid actor, missing tenant should fail
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            # No tenant_id
        )
        with pytest.raises(TenantRequiredError):
            require_tenant(context)


class TestRequireActor:
    """Tests for require_actor guard function."""

    def test_passes_with_authenticated_actor(self):
        """require_actor should pass for authenticated users."""
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            actor_type="user",
        )
        # Should not raise
        require_actor(context)

    def test_passes_with_service_actor(self):
        """require_actor should pass for service actors."""
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            actor_type="service",
        )
        require_actor(context)

    def test_passes_with_system_actor(self):
        """require_actor should pass for system actors."""
        context = RequestContextFactory.create_system()
        require_actor(context)

    def test_raises_for_anonymous_actor(self):
        """require_actor should raise for anonymous actors."""
        context = RequestContextFactory.create_anonymous()
        with pytest.raises(ActorRequiredError) as exc_info:
            require_actor(context)
        assert "anonymous" in exc_info.value.details.get("actor_type", "")

    def test_raises_when_context_is_none(self):
        """require_actor should raise when context is None."""
        with pytest.raises(ContextError):
            require_actor(None)  # type: ignore


class TestRequireContext:
    """Tests for require_context guard function."""

    def test_passes_with_valid_context(self):
        """require_context should pass for valid context."""
        context = RequestContextFactory.create_anonymous()
        # Should not raise
        require_context(context)

    def test_raises_when_context_is_none(self):
        """require_context should raise when context is None."""
        with pytest.raises(ContextError):
            require_context(None)  # type: ignore


class TestTenantRequiredDecorator:
    """Tests for tenant_required decorator."""

    def test_decorator_passes_with_tenant(self):
        """Decorated function should execute with valid tenant."""

        @tenant_required
        def my_service(context: RequestContext, value: str) -> str:
            return f"processed: {value}"

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            tenant_id=str(TenantId.generate()),
        )
        result = my_service(context, "test")
        assert result == "processed: test"

    def test_decorator_raises_without_tenant(self):
        """Decorated function should raise without tenant."""

        @tenant_required
        def my_service(context: RequestContext, value: str) -> str:
            return f"processed: {value}"

        context = RequestContextFactory.create_anonymous()
        with pytest.raises(TenantRequiredError):
            my_service(context, "test")

    def test_decorator_works_with_kwargs(self):
        """Decorated function should work with context as kwarg."""

        @tenant_required
        def my_service(value: str, context: RequestContext) -> str:
            return f"processed: {value}"

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            tenant_id=str(TenantId.generate()),
        )
        # Should work when context is passed as kwarg
        result = my_service("test", context=context)
        assert result == "processed: test"

    def test_decorator_raises_without_context(self):
        """Decorated function should raise when no context provided."""

        @tenant_required
        def my_service(value: str) -> str:
            return f"processed: {value}"

        with pytest.raises(ContextError):
            my_service("test")


class TestActorRequiredDecorator:
    """Tests for actor_required decorator."""

    def test_decorator_passes_with_authenticated_actor(self):
        """Decorated function should execute with authenticated actor."""

        @actor_required
        def my_service(context: RequestContext) -> str:
            return f"actor: {context.actor_id}"

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        result = my_service(context)
        assert "actor:" in result

    def test_decorator_raises_for_anonymous(self):
        """Decorated function should raise for anonymous actors."""

        @actor_required
        def my_service(context: RequestContext) -> str:
            return f"actor: {context.actor_id}"

        context = RequestContextFactory.create_anonymous()
        with pytest.raises(ActorRequiredError):
            my_service(context)


class TestContextPropagation:
    """Tests for context propagation through layers."""

    def test_context_propagates_through_service_chain(self):
        """Context should propagate through multiple service calls."""
        call_log = []

        def service_a(context: RequestContext) -> None:
            require_tenant(context)
            call_log.append(("service_a", str(context.tenant_id)))
            service_b(context)

        def service_b(context: RequestContext) -> None:
            require_tenant(context)
            call_log.append(("service_b", str(context.tenant_id)))
            repository_call(context)

        def repository_call(context: RequestContext) -> None:
            require_tenant(context)
            call_log.append(("repository", str(context.tenant_id)))

        tenant_id = TenantId.generate()
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            tenant_id=str(tenant_id),
        )

        service_a(context)

        assert len(call_log) == 3
        assert all(tid == str(tenant_id) for _, tid in call_log)

    def test_correlation_id_preserved_through_chain(self):
        """Correlation ID should be preserved through all calls."""
        correlation_ids = []

        def service_a(context: RequestContext) -> None:
            correlation_ids.append(str(context.correlation_id))
            service_b(context)

        def service_b(context: RequestContext) -> None:
            correlation_ids.append(str(context.correlation_id))

        correlation_id = CorrelationId.generate()
        context = RequestContextFactory.create(
            correlation_id=str(correlation_id),
            actor_id=str(ActorId.generate()),
        )

        service_a(context)

        assert len(correlation_ids) == 2
        assert all(cid == str(correlation_id) for cid in correlation_ids)

    def test_immutability_prevents_context_modification(self):
        """Context should not be modifiable after creation."""
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            tenant_id=str(TenantId.generate()),
        )

        with pytest.raises(AttributeError):
            context.correlation_id = CorrelationId.generate()  # type: ignore

        with pytest.raises(AttributeError):
            context.tenant = None  # type: ignore
