"""Unit tests for request context and context factory."""

import pytest

from eiams.shared.kernel import TenantId, ActorId, CorrelationId, Timestamp
from eiams.shared.context import (
    ActorContext,
    TenantContext,
    RequestContext,
    RequestContextFactory,
    RequestMetadata,
    ActorType,
)
from eiams.shared.errors import (
    TenantRequiredError,
    ActorRequiredError,
    InvalidTenantError,
    InvalidActorError,
    ValidationError,
)


class TestActorContext:
    """Tests for ActorContext value object."""

    def test_create_valid_actor_context(self):
        """ActorContext should accept valid values."""
        actor_id = ActorId.generate()
        context = ActorContext(
            actor_id=actor_id,
            actor_type=ActorType.USER,
            roles=("admin", "user"),
            permissions=("read", "write"),
        )
        assert context.actor_id == actor_id
        assert context.actor_type == ActorType.USER
        assert "admin" in context.roles
        assert "read" in context.permissions

    def test_reject_none_actor_id(self):
        """ActorContext should reject None actor_id."""
        with pytest.raises(ActorRequiredError):
            ActorContext(
                actor_id=None,  # type: ignore
                actor_type=ActorType.USER,
            )

    def test_system_actor_creation(self):
        """ActorContext.system() should create system actor."""
        actor = ActorContext.system()
        assert actor.actor_type == ActorType.SYSTEM
        assert "system" in actor.roles
        assert "*" in actor.permissions

    def test_anonymous_actor_creation(self):
        """ActorContext.anonymous() should create anonymous actor."""
        actor = ActorContext.anonymous()
        assert actor.actor_type == ActorType.ANONYMOUS
        assert len(actor.roles) == 0
        assert len(actor.permissions) == 0

    def test_has_role_check(self):
        """has_role() should check role membership."""
        actor = ActorContext(
            actor_id=ActorId.generate(),
            actor_type=ActorType.USER,
            roles=("admin",),
        )
        assert actor.has_role("admin")
        assert not actor.has_role("superadmin")

    def test_has_permission_check(self):
        """has_permission() should check permission grants."""
        actor = ActorContext(
            actor_id=ActorId.generate(),
            actor_type=ActorType.USER,
            permissions=("user:read", "user:write"),
        )
        assert actor.has_permission("user:read")
        assert not actor.has_permission("user:delete")

    def test_wildcard_permission(self):
        """Wildcard permission should grant all permissions."""
        actor = ActorContext(
            actor_id=ActorId.generate(),
            actor_type=ActorType.SYSTEM,
            permissions=("*",),
        )
        assert actor.has_permission("anything")
        assert actor.has_permission("user:delete")

    def test_to_dict_serialization(self):
        """to_dict() should return safe serializable dict."""
        actor_id = ActorId.generate()
        actor = ActorContext(
            actor_id=actor_id,
            actor_type=ActorType.USER,
            roles=("admin",),
        )
        result = actor.to_dict()
        assert result["actor_id"] == str(actor_id)
        assert result["actor_type"] == "user"
        assert "admin" in result["roles"]

    def test_immutability(self):
        """ActorContext should be immutable (frozen dataclass)."""
        actor = ActorContext(
            actor_id=ActorId.generate(),
            actor_type=ActorType.USER,
        )
        with pytest.raises(AttributeError):
            actor.actor_type = ActorType.SYSTEM  # type: ignore


class TestTenantContext:
    """Tests for TenantContext value object."""

    def test_create_valid_tenant_context(self):
        """TenantContext should accept valid tenant_id."""
        tenant_id = TenantId.generate()
        context = TenantContext(tenant_id=tenant_id)
        assert context.tenant_id == tenant_id

    def test_reject_none_tenant_id(self):
        """TenantContext should reject None tenant_id."""
        with pytest.raises(TenantRequiredError):
            TenantContext(tenant_id=None)  # type: ignore

    def test_to_dict_serialization(self):
        """to_dict() should return safe serializable dict."""
        tenant_id = TenantId.generate()
        context = TenantContext(tenant_id=tenant_id)
        result = context.to_dict()
        assert result["tenant_id"] == str(tenant_id)


class TestRequestMetadata:
    """Tests for RequestMetadata value object."""

    def test_create_with_all_fields(self):
        """RequestMetadata should accept all optional fields."""
        timestamp = Timestamp.now()
        metadata = RequestMetadata(
            timestamp=timestamp,
            source_ip="192.168.1.1",
            user_agent="TestAgent/1.0",
            request_path="/api/users",
            request_method="GET",
        )
        assert metadata.timestamp == timestamp
        assert metadata.source_ip == "192.168.1.1"
        assert metadata.user_agent == "TestAgent/1.0"
        assert metadata.request_path == "/api/users"
        assert metadata.request_method == "GET"

    def test_create_with_minimal_fields(self):
        """RequestMetadata should work with only timestamp."""
        timestamp = Timestamp.now()
        metadata = RequestMetadata(timestamp=timestamp)
        assert metadata.timestamp == timestamp
        assert metadata.source_ip is None

    def test_to_dict_excludes_none_values(self):
        """to_dict() should exclude None values."""
        metadata = RequestMetadata(timestamp=Timestamp.now())
        result = metadata.to_dict()
        assert "timestamp" in result
        assert "source_ip" not in result


class TestRequestContext:
    """Tests for RequestContext value object."""

    def test_create_valid_context(self):
        """RequestContext should accept valid values."""
        correlation_id = CorrelationId.generate()
        actor = ActorContext(
            actor_id=ActorId.generate(),
            actor_type=ActorType.USER,
        )
        tenant = TenantContext(tenant_id=TenantId.generate())
        metadata = RequestMetadata(timestamp=Timestamp.now())

        context = RequestContext(
            correlation_id=correlation_id,
            actor=actor,
            tenant=tenant,
            metadata=metadata,
        )

        assert context.correlation_id == correlation_id
        assert context.actor == actor
        assert context.tenant == tenant
        assert context.has_tenant

    def test_create_without_tenant(self):
        """RequestContext should allow None tenant."""
        context = RequestContext(
            correlation_id=CorrelationId.generate(),
            actor=ActorContext.anonymous(),
            tenant=None,
            metadata=RequestMetadata(timestamp=Timestamp.now()),
        )
        assert not context.has_tenant

    def test_tenant_id_property_raises_when_missing(self):
        """tenant_id property should raise when tenant is None."""
        context = RequestContext(
            correlation_id=CorrelationId.generate(),
            actor=ActorContext.anonymous(),
            tenant=None,
            metadata=RequestMetadata(timestamp=Timestamp.now()),
        )
        with pytest.raises(TenantRequiredError):
            _ = context.tenant_id

    def test_tenant_id_property_returns_id(self):
        """tenant_id property should return ID when present."""
        tenant_id = TenantId.generate()
        context = RequestContext(
            correlation_id=CorrelationId.generate(),
            actor=ActorContext.anonymous(),
            tenant=TenantContext(tenant_id=tenant_id),
            metadata=RequestMetadata(timestamp=Timestamp.now()),
        )
        assert context.tenant_id == tenant_id

    def test_actor_id_convenience_property(self):
        """actor_id property should return actor's ID."""
        actor_id = ActorId.generate()
        context = RequestContext(
            correlation_id=CorrelationId.generate(),
            actor=ActorContext(actor_id=actor_id, actor_type=ActorType.USER),
            tenant=None,
            metadata=RequestMetadata(timestamp=Timestamp.now()),
        )
        assert context.actor_id == actor_id

    def test_with_tenant_creates_new_context(self):
        """with_tenant() should create new context with updated tenant."""
        original_context = RequestContext(
            correlation_id=CorrelationId.generate(),
            actor=ActorContext.anonymous(),
            tenant=None,
            metadata=RequestMetadata(timestamp=Timestamp.now()),
        )
        new_tenant = TenantContext(tenant_id=TenantId.generate())
        new_context = original_context.with_tenant(new_tenant)

        assert original_context.tenant is None
        assert new_context.tenant == new_tenant
        assert new_context.correlation_id == original_context.correlation_id

    def test_to_dict_serialization(self):
        """to_dict() should return safe serializable dict."""
        context = RequestContext(
            correlation_id=CorrelationId.generate(),
            actor=ActorContext.anonymous(),
            tenant=TenantContext(tenant_id=TenantId.generate()),
            metadata=RequestMetadata(timestamp=Timestamp.now()),
        )
        result = context.to_dict()
        assert "correlation_id" in result
        assert "actor" in result
        assert "tenant" in result
        assert "metadata" in result


class TestRequestContextFactory:
    """Tests for RequestContextFactory."""

    def test_create_with_all_values(self):
        """Factory should create context with all provided values."""
        actor_id = ActorId.generate()
        tenant_id = TenantId.generate()
        correlation_id = CorrelationId.generate()

        context = RequestContextFactory.create(
            correlation_id=str(correlation_id),
            actor_id=str(actor_id),
            actor_type="user",
            tenant_id=str(tenant_id),
            roles=["admin"],
            permissions=["read"],
            source_ip="192.168.1.1",
            user_agent="TestAgent/1.0",
            request_path="/api/test",
            request_method="POST",
        )

        assert str(context.correlation_id) == str(correlation_id)
        assert context.actor_id == actor_id
        assert context.actor.actor_type == ActorType.USER
        assert context.tenant_id == tenant_id
        assert "admin" in context.actor.roles
        assert context.metadata.source_ip == "192.168.1.1"

    def test_create_generates_correlation_id(self):
        """Factory should generate correlation ID when not provided."""
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        assert context.correlation_id is not None

    def test_create_with_invalid_actor_id(self):
        """Factory should raise InvalidActorError for bad actor ID."""
        with pytest.raises(InvalidActorError):
            RequestContextFactory.create(
                actor_id="not-a-uuid",
            )

    def test_create_with_invalid_tenant_id(self):
        """Factory should raise InvalidTenantError for bad tenant ID."""
        with pytest.raises(InvalidTenantError):
            RequestContextFactory.create(
                actor_id=str(ActorId.generate()),
                tenant_id="not-a-uuid",
            )

    def test_create_with_invalid_actor_type(self):
        """Factory should raise ValidationError for bad actor type."""
        with pytest.raises(ValidationError):
            RequestContextFactory.create(
                actor_id=str(ActorId.generate()),
                actor_type="invalid_type",
            )

    def test_create_system_context(self):
        """create_system() should create system context."""
        context = RequestContextFactory.create_system()
        assert context.actor.actor_type == ActorType.SYSTEM
        assert context.tenant is None

    def test_create_system_context_with_tenant(self):
        """create_system() should accept optional tenant."""
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        assert context.tenant is not None
        assert context.tenant_id == tenant_id

    def test_create_anonymous_context(self):
        """create_anonymous() should create anonymous context."""
        context = RequestContextFactory.create_anonymous(
            source_ip="192.168.1.1",
        )
        assert context.actor.actor_type == ActorType.ANONYMOUS
        assert context.tenant is None
        assert context.metadata.source_ip == "192.168.1.1"

    def test_create_accepts_value_objects(self):
        """Factory should accept value objects directly."""
        actor_id = ActorId.generate()
        tenant_id = TenantId.generate()
        correlation_id = CorrelationId.generate()

        context = RequestContextFactory.create(
            correlation_id=correlation_id,
            actor_id=actor_id,
            tenant_id=tenant_id,
        )

        assert context.correlation_id == correlation_id
        assert context.actor_id == actor_id
        assert context.tenant_id == tenant_id
