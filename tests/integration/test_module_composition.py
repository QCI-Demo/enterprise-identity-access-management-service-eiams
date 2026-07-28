"""Integration tests for module composition and wiring."""

import pytest

from eiams.composition import (
    ModuleContainer,
    ModuleRegistry,
    create_container,
)
from eiams.shared.kernel import TenantId, ActorId
from eiams.shared.context import RequestContextFactory
from eiams.infrastructure.adapters import (
    HttpContextExtractor,
    CompositeAuthorizationHook,
)


class TestModuleRegistry:
    """Tests for ModuleRegistry."""

    def test_register_and_resolve(self):
        """Should register and resolve contracts."""
        registry = ModuleRegistry()

        class MyContract:
            pass

        class MyImplementation(MyContract):
            pass

        registry.register(MyContract, MyImplementation)
        resolved = registry.resolve(MyContract)

        assert isinstance(resolved, MyImplementation)

    def test_register_singleton_instance(self):
        """Should register and resolve singleton instances."""
        registry = ModuleRegistry()

        class MyService:
            def __init__(self):
                self.id = id(self)

        instance = MyService()
        registry.register_instance(MyService, instance)

        resolved1 = registry.resolve(MyService)
        resolved2 = registry.resolve(MyService)

        assert resolved1 is instance
        assert resolved2 is instance
        assert resolved1 is resolved2

    def test_register_factory(self):
        """Should register and resolve via factory."""
        registry = ModuleRegistry()
        call_count = [0]

        class MyService:
            pass

        def factory():
            call_count[0] += 1
            return MyService()

        registry.register_factory(MyService, factory)

        registry.resolve(MyService)
        registry.resolve(MyService)

        # Factory called each time (not singleton)
        assert call_count[0] == 2

    def test_is_registered(self):
        """Should track registered contracts."""
        registry = ModuleRegistry()

        class MyContract:
            pass

        assert not registry.is_registered(MyContract)
        registry.register(MyContract)
        assert registry.is_registered(MyContract)

    def test_registered_contracts_list(self):
        """Should list all registered contracts."""
        registry = ModuleRegistry()

        class ContractA:
            pass

        class ContractB:
            pass

        registry.register(ContractA)
        registry.register(ContractB)

        contracts = registry.registered_contracts
        assert ContractA in contracts
        assert ContractB in contracts

    def test_resolve_unregistered_returns_none(self):
        """Should return None for unregistered contracts."""
        registry = ModuleRegistry()

        class UnregisteredContract:
            pass

        result = registry.resolve(UnregisteredContract)
        assert result is None


class TestModuleContainer:
    """Tests for ModuleContainer."""

    def test_default_container_creation(self):
        """Should create container with default settings."""
        container = ModuleContainer()

        assert container.context_extractor is not None
        assert container.authorization_hook is not None
        assert container.registry is not None

    def test_container_registers_infrastructure(self):
        """Should auto-register infrastructure components."""
        container = ModuleContainer()

        resolved_extractor = container.registry.resolve(HttpContextExtractor)
        resolved_hook = container.registry.resolve(CompositeAuthorizationHook)

        assert resolved_extractor is container.context_extractor
        assert resolved_hook is container.authorization_hook

    def test_add_authorization_hook(self):
        """Should allow adding authorization hooks."""
        container = ModuleContainer()
        initial_count = container.authorization_hook.hook_count

        class CustomHook:
            def authorize(self, context, operation):
                from eiams.domain.authorization.contracts import AuthorizationDecision
                return AuthorizationDecision.NOT_APPLICABLE

        container.add_authorization_hook(CustomHook())

        assert container.authorization_hook.hook_count == initial_count + 1

    def test_enable_authorization_logging(self):
        """Should enable authorization logging."""
        container = ModuleContainer()
        initial_count = container.authorization_hook.hook_count

        container.enable_authorization_logging()

        assert container.authorization_hook.hook_count == initial_count + 1

    def test_verify_modules_instantiable(self):
        """Should verify all modules can be instantiated."""
        container = ModuleContainer()
        results = container.verify_modules_instantiable()

        # All core modules should be instantiable
        assert results["shared.kernel"] is True
        assert results["shared.context"] is True
        assert results["shared.errors"] is True
        assert results["infrastructure.adapters"] is True

        # All domain modules should be importable
        domain_modules = [
            "domain.identity",
            "domain.authentication",
            "domain.authorization",
            "domain.credentials",
            "domain.audit",
            "domain.administration",
        ]
        for module in domain_modules:
            assert results.get(module) is True, f"{module} failed to instantiate"


class TestCreateContainer:
    """Tests for create_container factory function."""

    def test_create_with_defaults(self):
        """Should create container with default settings."""
        container = create_container()

        assert container.context_extractor is not None
        assert container.authorization_hook is not None

    def test_create_with_tenant_required(self):
        """Should configure tenant requirement."""
        container = create_container(require_tenant=True)

        # Context extractor should require tenant
        assert container.context_extractor._require_tenant is True

    def test_create_with_actor_required(self):
        """Should configure actor requirement."""
        container = create_container(require_actor=True)

        assert container.context_extractor._require_actor is True

    def test_create_with_logging_enabled(self):
        """Should enable authorization logging when requested."""
        container = create_container(enable_logging=True)

        # Should have at least the logging hook
        assert container.authorization_hook.hook_count >= 1


class TestModuleIntegration:
    """Integration tests for complete module wiring."""

    def test_full_request_flow(self):
        """Should handle complete request flow through all modules."""
        container = create_container()

        # 1. Create request context via factory
        actor_id = ActorId.generate()
        tenant_id = TenantId.generate()

        context = RequestContextFactory.create(
            actor_id=str(actor_id),
            tenant_id=str(tenant_id),
            roles=["user"],
        )

        # 2. Extract would happen at transport edge
        # (simulated - in real app, extractor parses HTTP request)

        # 3. Context flows to application service
        from eiams.shared.context import require_tenant, require_actor

        # Service method that requires both tenant and actor
        def user_service_operation(ctx):
            require_tenant(ctx)
            require_actor(ctx)
            return {
                "tenant_id": str(ctx.tenant_id),
                "actor_id": str(ctx.actor_id),
            }

        result = user_service_operation(context)

        # 4. Verify context propagated correctly
        assert result["tenant_id"] == str(tenant_id)
        assert result["actor_id"] == str(actor_id)

    def test_authorization_hook_integration(self):
        """Should integrate authorization hooks in request flow."""
        authorization_log = []

        container = create_container()

        class AuditHook:
            def authorize(self, context, operation):
                from eiams.domain.authorization.contracts import AuthorizationDecision
                authorization_log.append({
                    "actor": str(context.actor_id),
                    "resource": operation.resource_type,
                })
                return AuthorizationDecision.ALLOW

        container.add_authorization_hook(AuditHook())

        # Simulate service call with authorization
        from eiams.domain.authorization.contracts import OperationContext

        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            tenant_id=str(TenantId.generate()),
        )

        operation = OperationContext(
            resource_type="user",
            resource_id="123",
            action="read",
            attributes={},
        )

        decision = container.authorization_hook.authorize(context, operation)

        from eiams.domain.authorization.contracts import AuthorizationDecision
        assert decision == AuthorizationDecision.ALLOW
        assert len(authorization_log) == 1
        assert authorization_log[0]["resource"] == "user"

    def test_domain_contracts_importable_without_implementations(self):
        """Domain contracts should be importable without implementations."""
        # This verifies the module boundaries are correct

        # Import all domain contracts
        from eiams.domain.identity import (
            User, Organization, Membership,
            UserRepository, IdentityService,
        )
        from eiams.domain.authentication import (
            Session, SessionRepository, AuthenticationService,
        )
        from eiams.domain.authorization import (
            Role, Permission, RoleAssignment,
            AuthorizationService, AuthorizationHook,
        )
        from eiams.domain.credentials import (
            ApiKey, OAuthClient, CredentialService,
        )
        from eiams.domain.audit import (
            AuditEvent, AuditService,
        )
        from eiams.domain.administration import (
            Tenant, AdministrationService,
        )

        # All imports should succeed without any framework dependencies
        assert User is not None
        assert Session is not None
        assert Role is not None
        assert ApiKey is not None
        assert AuditEvent is not None
        assert Tenant is not None
