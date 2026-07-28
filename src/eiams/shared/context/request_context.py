"""Immutable request context value objects.

These context objects are validated at construction time and carry
critical security context through all layers of the application.
They are designed to be framework-isolated and serialization-safe.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from eiams.shared.kernel import (
    TenantId,
    ActorId,
    CorrelationId,
    Timestamp,
)
from eiams.shared.errors import (
    ValidationError,
    TenantRequiredError,
    ActorRequiredError,
    InvalidTenantError,
    InvalidActorError,
)


class ActorType(str, Enum):
    """Type of actor performing an operation."""

    USER = "user"
    SERVICE = "service"
    SYSTEM = "system"
    ANONYMOUS = "anonymous"


@dataclass(frozen=True, slots=True)
class ActorContext:
    """Immutable actor identity context.

    Represents the authenticated entity performing an operation.
    This is frozen (immutable) after construction.
    """

    actor_id: ActorId
    actor_type: ActorType
    roles: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate actor context after initialization."""
        if self.actor_id is None:
            raise ActorRequiredError("Actor ID is required")
        if not isinstance(self.actor_id, ActorId):
            raise InvalidActorError("Actor ID must be an ActorId instance")
        if self.actor_type is None:
            raise ValidationError("Actor type is required", field="actor_type")

    @classmethod
    def system(cls) -> "ActorContext":
        """Create a system actor context for internal operations."""
        return cls(
            actor_id=ActorId("00000000-0000-0000-0000-000000000000"),
            actor_type=ActorType.SYSTEM,
            roles=("system",),
            permissions=("*",),
        )

    @classmethod
    def anonymous(cls) -> "ActorContext":
        """Create an anonymous actor context for unauthenticated requests."""
        return cls(
            actor_id=ActorId("00000000-0000-0000-0000-000000000001"),
            actor_type=ActorType.ANONYMOUS,
            roles=(),
            permissions=(),
        )

    def has_role(self, role: str) -> bool:
        """Check if actor has a specific role."""
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        """Check if actor has a specific permission."""
        return "*" in self.permissions or permission in self.permissions

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for safe logging/API response."""
        return {
            "actor_id": str(self.actor_id),
            "actor_type": self.actor_type.value,
            "roles": list(self.roles),
        }


@dataclass(frozen=True, slots=True)
class TenantContext:
    """Immutable tenant scope context.

    Represents the tenant boundary for data isolation. Operations
    that require tenant scope must have valid tenant context.
    """

    tenant_id: TenantId

    def __post_init__(self) -> None:
        """Validate tenant context after initialization."""
        if self.tenant_id is None:
            raise TenantRequiredError("Tenant ID is required")
        if not isinstance(self.tenant_id, TenantId):
            raise InvalidTenantError("Tenant ID must be a TenantId instance")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for safe logging/API response."""
        return {
            "tenant_id": str(self.tenant_id),
        }


@dataclass(frozen=True, slots=True)
class RequestMetadata:
    """Immutable request metadata for audit and tracing.

    Contains non-security-critical information about the request
    origin and timing.
    """

    timestamp: Timestamp
    source_ip: str | None = None
    user_agent: str | None = None
    request_path: str | None = None
    request_method: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for safe logging."""
        result: dict[str, Any] = {
            "timestamp": self.timestamp.to_iso(),
        }
        if self.source_ip:
            result["source_ip"] = self.source_ip
        if self.user_agent:
            result["user_agent"] = self.user_agent
        if self.request_path:
            result["request_path"] = self.request_path
        if self.request_method:
            result["request_method"] = self.request_method
        return result


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Immutable request context carrying all security-relevant state.

    This is the primary context object that flows through all layers
    of the application. It is constructed at the transport edge and
    passed explicitly to ensure fail-closed behavior.
    """

    correlation_id: CorrelationId
    actor: ActorContext
    tenant: TenantContext | None
    metadata: RequestMetadata

    def __post_init__(self) -> None:
        """Validate request context after initialization."""
        if self.correlation_id is None:
            raise ValidationError("Correlation ID is required", field="correlation_id")
        if self.actor is None:
            raise ActorRequiredError("Actor context is required")
        if self.metadata is None:
            raise ValidationError("Request metadata is required", field="metadata")

    @property
    def has_tenant(self) -> bool:
        """Check if tenant context is present."""
        return self.tenant is not None

    @property
    def tenant_id(self) -> TenantId:
        """Get the tenant ID, raising if not present.

        Raises:
            TenantRequiredError: If tenant context is missing.
        """
        if self.tenant is None:
            raise TenantRequiredError(
                "Tenant context is required for this operation",
                details={"correlation_id": str(self.correlation_id)},
            )
        return self.tenant.tenant_id

    @property
    def actor_id(self) -> ActorId:
        """Convenience property to get actor ID."""
        return self.actor.actor_id

    def with_tenant(self, tenant: TenantContext) -> "RequestContext":
        """Create a new context with updated tenant scope.

        This is useful for operations that need to switch tenant
        context while preserving other context attributes.
        """
        return RequestContext(
            correlation_id=self.correlation_id,
            actor=self.actor,
            tenant=tenant,
            metadata=self.metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for safe logging/API response."""
        result = {
            "correlation_id": str(self.correlation_id),
            "actor": self.actor.to_dict(),
            "metadata": self.metadata.to_dict(),
        }
        if self.tenant:
            result["tenant"] = self.tenant.to_dict()
        return result


class RequestContextFactory:
    """Factory for creating validated request contexts.

    This factory provides a consistent way to construct request
    contexts from various input sources while ensuring validation.
    """

    @staticmethod
    def create(
        *,
        correlation_id: str | CorrelationId | None = None,
        actor_id: str | ActorId,
        actor_type: str | ActorType = ActorType.USER,
        tenant_id: str | TenantId | None = None,
        roles: list[str] | tuple[str, ...] | None = None,
        permissions: list[str] | tuple[str, ...] | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
        request_path: str | None = None,
        request_method: str | None = None,
        timestamp: Timestamp | None = None,
    ) -> RequestContext:
        """Create a validated request context from raw inputs.

        Args:
            correlation_id: Request correlation ID (generated if not provided).
            actor_id: Actor (user/service) identifier.
            actor_type: Type of actor (user, service, system, anonymous).
            tenant_id: Tenant identifier (optional for cross-tenant operations).
            roles: Actor's assigned roles.
            permissions: Actor's granted permissions.
            source_ip: Client IP address.
            user_agent: Client user agent string.
            request_path: HTTP request path.
            request_method: HTTP request method.
            timestamp: Request timestamp (defaults to now).

        Returns:
            Validated RequestContext instance.

        Raises:
            InvalidActorError: If actor_id is invalid.
            InvalidTenantError: If tenant_id is invalid.
            InvalidCorrelationIdError: If correlation_id format is invalid.
            ValidationError: For other validation failures.
        """
        # Parse correlation ID
        if correlation_id is None:
            parsed_correlation = CorrelationId.generate()
        elif isinstance(correlation_id, str):
            parsed_correlation = CorrelationId(correlation_id)
        else:
            parsed_correlation = correlation_id

        # Parse actor ID
        if isinstance(actor_id, str):
            parsed_actor_id = ActorId(actor_id)
        else:
            parsed_actor_id = actor_id

        # Parse actor type
        if isinstance(actor_type, str):
            try:
                parsed_actor_type = ActorType(actor_type)
            except ValueError:
                raise ValidationError(
                    f"Invalid actor type: {actor_type}",
                    field="actor_type",
                    details={"valid_types": [t.value for t in ActorType]},
                )
        else:
            parsed_actor_type = actor_type

        # Parse tenant ID
        parsed_tenant: TenantContext | None = None
        if tenant_id is not None:
            if isinstance(tenant_id, str):
                parsed_tenant_id = TenantId(tenant_id)
            else:
                parsed_tenant_id = tenant_id
            parsed_tenant = TenantContext(tenant_id=parsed_tenant_id)

        # Create actor context
        actor = ActorContext(
            actor_id=parsed_actor_id,
            actor_type=parsed_actor_type,
            roles=tuple(roles) if roles else (),
            permissions=tuple(permissions) if permissions else (),
        )

        # Create metadata
        metadata = RequestMetadata(
            timestamp=timestamp or Timestamp.now(),
            source_ip=source_ip,
            user_agent=user_agent,
            request_path=request_path,
            request_method=request_method,
        )

        return RequestContext(
            correlation_id=parsed_correlation,
            actor=actor,
            tenant=parsed_tenant,
            metadata=metadata,
        )

    @staticmethod
    def create_system(
        *,
        correlation_id: str | CorrelationId | None = None,
        tenant_id: str | TenantId | None = None,
    ) -> RequestContext:
        """Create a system context for internal operations.

        Args:
            correlation_id: Request correlation ID (generated if not provided).
            tenant_id: Optional tenant scope for tenant-specific operations.

        Returns:
            RequestContext with system actor.
        """
        if correlation_id is None:
            parsed_correlation = CorrelationId.generate()
        elif isinstance(correlation_id, str):
            parsed_correlation = CorrelationId(correlation_id)
        else:
            parsed_correlation = correlation_id

        parsed_tenant: TenantContext | None = None
        if tenant_id is not None:
            if isinstance(tenant_id, str):
                parsed_tenant_id = TenantId(tenant_id)
            else:
                parsed_tenant_id = tenant_id
            parsed_tenant = TenantContext(tenant_id=parsed_tenant_id)

        return RequestContext(
            correlation_id=parsed_correlation,
            actor=ActorContext.system(),
            tenant=parsed_tenant,
            metadata=RequestMetadata(timestamp=Timestamp.now()),
        )

    @staticmethod
    def create_anonymous(
        *,
        correlation_id: str | CorrelationId | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
        request_path: str | None = None,
        request_method: str | None = None,
    ) -> RequestContext:
        """Create an anonymous context for unauthenticated requests.

        Args:
            correlation_id: Request correlation ID (generated if not provided).
            source_ip: Client IP address.
            user_agent: Client user agent string.
            request_path: HTTP request path.
            request_method: HTTP request method.

        Returns:
            RequestContext with anonymous actor and no tenant.
        """
        if correlation_id is None:
            parsed_correlation = CorrelationId.generate()
        elif isinstance(correlation_id, str):
            parsed_correlation = CorrelationId(correlation_id)
        else:
            parsed_correlation = correlation_id

        return RequestContext(
            correlation_id=parsed_correlation,
            actor=ActorContext.anonymous(),
            tenant=None,
            metadata=RequestMetadata(
                timestamp=Timestamp.now(),
                source_ip=source_ip,
                user_agent=user_agent,
                request_path=request_path,
                request_method=request_method,
            ),
        )
