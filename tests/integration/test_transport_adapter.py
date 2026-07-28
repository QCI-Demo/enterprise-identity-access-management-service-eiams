"""Integration tests for transport context adapter."""

import pytest

from eiams.shared.kernel import TenantId, ActorId
from eiams.shared.context import ActorType
from eiams.infrastructure.adapters import (
    HttpContextExtractor,
    ContextExtractionError,
)
from eiams.shared.errors import (
    InvalidTenantError,
    InvalidActorError,
)


class MockHttpRequest:
    """Mock HTTP request for testing."""

    def __init__(
        self,
        headers: dict[str, str | None] | None = None,
        path: str = "/api/test",
        method: str = "GET",
        client_ip: str = "127.0.0.1",
    ):
        self._headers = headers or {}
        self.path = path
        self.method = method
        self.client_ip = client_ip

    def get_header(self, name: str) -> str | None:
        return self._headers.get(name)


class TestHttpContextExtractor:
    """Tests for HTTP context extraction."""

    def test_extract_full_context(self):
        """Should extract complete context from headers."""
        actor_id = str(ActorId.generate())
        tenant_id = str(TenantId.generate())

        request = MockHttpRequest(
            headers={
                "X-Correlation-ID": "test-correlation-123",
                "X-Actor-ID": actor_id,
                "X-Actor-Type": "user",
                "X-Tenant-ID": tenant_id,
                "X-Roles": "admin,user",
                "User-Agent": "TestClient/1.0",
            },
            path="/api/users",
            method="POST",
            client_ip="192.168.1.100",
        )

        extractor = HttpContextExtractor()
        context = extractor.extract_context(request)

        assert str(context.correlation_id) == "test-correlation-123"
        assert str(context.actor_id) == actor_id
        assert context.actor.actor_type == ActorType.USER
        assert str(context.tenant_id) == tenant_id
        assert "admin" in context.actor.roles
        assert "user" in context.actor.roles
        assert context.metadata.source_ip == "192.168.1.100"
        assert context.metadata.request_path == "/api/users"
        assert context.metadata.request_method == "POST"
        assert context.metadata.user_agent == "TestClient/1.0"

    def test_generate_correlation_id_when_missing(self):
        """Should generate correlation ID when not in headers."""
        request = MockHttpRequest(
            headers={
                "X-Actor-ID": str(ActorId.generate()),
            },
        )

        extractor = HttpContextExtractor()
        context = extractor.extract_context(request)

        assert context.correlation_id is not None
        assert len(str(context.correlation_id)) == 36  # UUID format

    def test_anonymous_context_when_no_actor(self):
        """Should create anonymous context when no actor provided."""
        request = MockHttpRequest(headers={})

        extractor = HttpContextExtractor(require_actor=False)
        context = extractor.extract_context(request)

        assert context.actor.actor_type == ActorType.ANONYMOUS

    def test_require_actor_raises_when_missing(self):
        """Should raise when actor required but missing."""
        request = MockHttpRequest(headers={})

        extractor = HttpContextExtractor(require_actor=True)
        with pytest.raises(InvalidActorError):
            extractor.extract_context(request)

    def test_require_tenant_raises_when_missing(self):
        """Should raise when tenant required but missing."""
        request = MockHttpRequest(
            headers={
                "X-Actor-ID": str(ActorId.generate()),
            },
        )

        extractor = HttpContextExtractor(require_tenant=True)
        with pytest.raises(InvalidTenantError):
            extractor.extract_context(request)

    def test_invalid_actor_id_raises_error(self):
        """Should raise InvalidActorError for malformed actor ID."""
        request = MockHttpRequest(
            headers={
                "X-Actor-ID": "not-a-valid-uuid",
            },
        )

        extractor = HttpContextExtractor()
        with pytest.raises(InvalidActorError):
            extractor.extract_context(request)

    def test_invalid_tenant_id_raises_error(self):
        """Should raise InvalidTenantError for malformed tenant ID."""
        request = MockHttpRequest(
            headers={
                "X-Actor-ID": str(ActorId.generate()),
                "X-Tenant-ID": "not-a-valid-uuid",
            },
        )

        extractor = HttpContextExtractor()
        with pytest.raises(InvalidTenantError):
            extractor.extract_context(request)

    def test_extract_from_dict_request(self):
        """Should extract context from dict-like requests."""
        actor_id = str(ActorId.generate())

        request = {
            "X-Correlation-ID": "dict-correlation",
            "X-Actor-ID": actor_id,
            "path": "/api/test",
            "method": "GET",
            "client_ip": "10.0.0.1",
        }

        extractor = HttpContextExtractor()
        context = extractor.extract_context(request)

        assert str(context.correlation_id) == "dict-correlation"
        assert str(context.actor_id) == actor_id

    def test_extract_from_headers_attribute(self):
        """Should extract from request.headers attribute."""

        class RequestWithHeaders:
            def __init__(self):
                self.headers = {
                    "X-Actor-ID": str(ActorId.generate()),
                    "X-Correlation-ID": "headers-attr-test",
                }
                self.path = "/test"
                self.method = "GET"
                self.remote_addr = "127.0.0.1"

        extractor = HttpContextExtractor()
        context = extractor.extract_context(RequestWithHeaders())

        assert str(context.correlation_id) == "headers-attr-test"

    def test_unsupported_request_type_raises_error(self):
        """Should raise ContextExtractionError for unsupported types."""
        extractor = HttpContextExtractor()

        with pytest.raises(ContextExtractionError) as exc_info:
            extractor.extract_context(12345)  # Invalid type

        assert "Unsupported request type" in str(exc_info.value)

    def test_parse_roles_from_comma_separated_string(self):
        """Should parse comma-separated roles header."""
        request = MockHttpRequest(
            headers={
                "X-Actor-ID": str(ActorId.generate()),
                "X-Roles": "admin, user, viewer",  # With spaces
            },
        )

        extractor = HttpContextExtractor()
        context = extractor.extract_context(request)

        assert "admin" in context.actor.roles
        assert "user" in context.actor.roles
        assert "viewer" in context.actor.roles

    def test_default_actor_type(self):
        """Should use default actor type when not specified."""
        request = MockHttpRequest(
            headers={
                "X-Actor-ID": str(ActorId.generate()),
                # No X-Actor-Type
            },
        )

        extractor = HttpContextExtractor(default_actor_type=ActorType.SERVICE)
        context = extractor.extract_context(request)

        assert context.actor.actor_type == ActorType.SERVICE

    def test_actor_type_case_insensitive(self):
        """Should handle actor type case insensitively."""
        request = MockHttpRequest(
            headers={
                "X-Actor-ID": str(ActorId.generate()),
                "X-Actor-Type": "SERVICE",  # Uppercase
            },
        )

        extractor = HttpContextExtractor()
        context = extractor.extract_context(request)

        assert context.actor.actor_type == ActorType.SERVICE


class TestContextReachesService:
    """Contract tests proving context reaches service layer."""

    def test_context_reaches_repository_facing_service(self):
        """Context extracted at transport should reach repository layer."""
        # Simulate the full flow from transport to repository

        # 1. Transport layer extracts context
        request = MockHttpRequest(
            headers={
                "X-Correlation-ID": "flow-test-123",
                "X-Actor-ID": str(ActorId.generate()),
                "X-Tenant-ID": str(TenantId.generate()),
            },
        )

        extractor = HttpContextExtractor()
        context = extractor.extract_context(request)

        # 2. Application service receives context
        received_contexts = []

        def application_service(ctx):
            received_contexts.append(ctx)
            # 3. Service calls repository with context
            repository_find(ctx)

        def repository_find(ctx):
            received_contexts.append(ctx)

        # Execute flow
        application_service(context)

        # Verify context propagated correctly
        assert len(received_contexts) == 2
        for ctx in received_contexts:
            assert str(ctx.correlation_id) == "flow-test-123"
            assert ctx.has_tenant

    def test_tenant_isolation_enforced_at_repository(self):
        """Repository should receive tenant context for isolation."""
        tenant_id = TenantId.generate()

        request = MockHttpRequest(
            headers={
                "X-Actor-ID": str(ActorId.generate()),
                "X-Tenant-ID": str(tenant_id),
            },
        )

        extractor = HttpContextExtractor()
        context = extractor.extract_context(request)

        # Simulated repository that enforces tenant scope
        def tenant_scoped_repository(ctx):
            from eiams.shared.context import require_tenant

            require_tenant(ctx)
            # Repository would use ctx.tenant_id for queries
            return ctx.tenant_id

        result = tenant_scoped_repository(context)
        assert result == tenant_id
