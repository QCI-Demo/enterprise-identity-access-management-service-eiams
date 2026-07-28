"""Request context contracts and validation for EIAMS.

This module provides immutable context objects that carry actor identity,
tenant scope, correlation ID, and request metadata through all layers
of the application. Context is constructed at the transport edge and
propagated explicitly to ensure fail-closed behavior.
"""

from .request_context import (
    ActorContext,
    TenantContext,
    RequestContext,
    RequestContextFactory,
    RequestMetadata,
    ActorType,
)
from .guards import (
    require_tenant,
    require_actor,
    require_context,
)

__all__ = [
    # Context objects
    "ActorContext",
    "TenantContext",
    "RequestContext",
    "RequestContextFactory",
    "RequestMetadata",
    "ActorType",
    # Guards
    "require_tenant",
    "require_actor",
    "require_context",
]
