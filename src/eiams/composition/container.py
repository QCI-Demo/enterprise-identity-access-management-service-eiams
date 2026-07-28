"""Module container and dependency injection for EIAMS.

Provides minimal composition wiring that verifies modules can be
instantiated without requiring future service implementations.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar, Generic

from eiams.shared.context import RequestContextFactory
from eiams.domain.authorization.contracts import AuthorizationHook
from eiams.infrastructure.adapters import (
    HttpContextExtractor,
    CompositeAuthorizationHook,
    LoggingAuthorizationHook,
)


T = TypeVar("T")


class ModuleRegistry:
    """Registry for module contracts and implementations.

    Tracks registered contracts and their implementations for
    dependency resolution during composition.
    """

    def __init__(self) -> None:
        self._contracts: dict[type, type | Callable[..., Any]] = {}
        self._instances: dict[type, Any] = {}
        self._factories: dict[type, Callable[..., Any]] = {}

    def register(
        self,
        contract: type[T],
        implementation: type[T] | Callable[..., T] | None = None,
    ) -> None:
        """Register a contract with an optional implementation.

        Args:
            contract: The contract (interface) type.
            implementation: The implementation type or factory.
        """
        self._contracts[contract] = implementation or contract

    def register_instance(self, contract: type[T], instance: T) -> None:
        """Register a singleton instance for a contract.

        Args:
            contract: The contract type.
            instance: The singleton instance.
        """
        self._instances[contract] = instance

    def register_factory(
        self,
        contract: type[T],
        factory: Callable[..., T],
    ) -> None:
        """Register a factory function for a contract.

        Args:
            contract: The contract type.
            factory: The factory function.
        """
        self._factories[contract] = factory

    def resolve(self, contract: type[T]) -> T | None:
        """Resolve a contract to its implementation/instance.

        Args:
            contract: The contract type to resolve.

        Returns:
            The resolved instance or None if not registered.
        """
        # Check for singleton instance
        if contract in self._instances:
            return self._instances[contract]

        # Check for factory
        if contract in self._factories:
            instance = self._factories[contract]()
            return instance

        # Check for implementation type
        if contract in self._contracts:
            impl = self._contracts[contract]
            if callable(impl):
                return impl()
            return impl

        return None

    def is_registered(self, contract: type) -> bool:
        """Check if a contract is registered.

        Args:
            contract: The contract type to check.

        Returns:
            True if the contract is registered.
        """
        return (
            contract in self._contracts
            or contract in self._instances
            or contract in self._factories
        )

    @property
    def registered_contracts(self) -> list[type]:
        """List all registered contracts."""
        contracts = set(self._contracts.keys())
        contracts.update(self._instances.keys())
        contracts.update(self._factories.keys())
        return list(contracts)


@dataclass
class ModuleContainer:
    """Container for EIAMS module dependencies.

    Provides access to shared infrastructure components and
    module-specific registries.
    """

    registry: ModuleRegistry = field(default_factory=ModuleRegistry)

    # Shared infrastructure components
    context_extractor: HttpContextExtractor = field(
        default_factory=lambda: HttpContextExtractor(
            require_tenant=False,
            require_actor=False,
        )
    )
    authorization_hook: CompositeAuthorizationHook = field(
        default_factory=CompositeAuthorizationHook
    )
    context_factory: type[RequestContextFactory] = field(
        default=RequestContextFactory
    )

    def __post_init__(self) -> None:
        """Initialize the container with default registrations."""
        # Register infrastructure components
        self.registry.register_instance(
            HttpContextExtractor, self.context_extractor
        )
        self.registry.register_instance(
            CompositeAuthorizationHook, self.authorization_hook
        )

    def add_authorization_hook(self, hook: AuthorizationHook) -> None:
        """Add an authorization hook to the composite.

        Args:
            hook: The authorization hook to add.
        """
        self.authorization_hook.add_hook(hook)

    def enable_authorization_logging(
        self,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        """Enable authorization logging for audit.

        Args:
            logger: Optional logging function.
        """
        self.add_authorization_hook(LoggingAuthorizationHook(logger))

    def verify_modules_instantiable(self) -> dict[str, bool]:
        """Verify that all modules can be instantiated.

        Returns:
            Dict mapping module names to instantiation success.
        """
        results: dict[str, bool] = {}

        # Verify shared kernel
        try:
            from eiams.shared.kernel import TenantId, ActorId, CorrelationId
            TenantId.generate()
            ActorId.generate()
            CorrelationId.generate()
            results["shared.kernel"] = True
        except Exception:
            results["shared.kernel"] = False

        # Verify context
        try:
            from eiams.shared.context import RequestContextFactory
            ctx = RequestContextFactory.create_system()
            assert ctx is not None
            results["shared.context"] = True
        except Exception:
            results["shared.context"] = False

        # Verify errors
        try:
            from eiams.shared.errors import TenantRequiredError, DomainError
            err = TenantRequiredError()
            assert err.to_dict() is not None
            results["shared.errors"] = True
        except Exception:
            results["shared.errors"] = False

        # Verify domain modules (contracts only)
        domain_modules = [
            "identity",
            "authentication",
            "authorization",
            "credentials",
            "audit",
            "administration",
        ]
        for module in domain_modules:
            try:
                mod = __import__(
                    f"eiams.domain.{module}",
                    fromlist=[module],
                )
                # Just verify import works
                results[f"domain.{module}"] = True
            except Exception:
                results[f"domain.{module}"] = False

        # Verify infrastructure adapters
        try:
            from eiams.infrastructure.adapters import (
                HttpContextExtractor,
                CompositeAuthorizationHook,
            )
            extractor = HttpContextExtractor()
            hook = CompositeAuthorizationHook()
            results["infrastructure.adapters"] = True
        except Exception:
            results["infrastructure.adapters"] = False

        return results


def create_container(
    require_tenant: bool = False,
    require_actor: bool = False,
    enable_logging: bool = False,
) -> ModuleContainer:
    """Create a configured module container.

    Args:
        require_tenant: Whether to require tenant context.
        require_actor: Whether to require actor context.
        enable_logging: Whether to enable authorization logging.

    Returns:
        Configured ModuleContainer instance.
    """
    container = ModuleContainer(
        context_extractor=HttpContextExtractor(
            require_tenant=require_tenant,
            require_actor=require_actor,
        ),
    )

    if enable_logging:
        container.enable_authorization_logging()

    return container
