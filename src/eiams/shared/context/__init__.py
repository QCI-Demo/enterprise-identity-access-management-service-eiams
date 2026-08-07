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
from .scope import (
    RepositoryScope,
    TenantPredicate,
)
from .guards import (
    DEFAULT_TENANT_COLUMN,
    require_tenant,
    require_actor,
    require_context,
    require_tenant_scope,
    require_platform_scope,
    build_tenant_predicate,
    assert_tenant_match,
    tenant_required,
    actor_required,
)

__all__ = [
    # Context objects
    "ActorContext",
    "TenantContext",
    "RequestContext",
    "RequestContextFactory",
    "RequestMetadata",
    "ActorType",
    # Scope
    "RepositoryScope",
    "TenantPredicate",
    "DEFAULT_TENANT_COLUMN",
    # Guards
    "require_tenant",
    "require_actor",
    "require_context",
    "require_tenant_scope",
    "require_platform_scope",
    "build_tenant_predicate",
    "assert_tenant_match",
    "tenant_required",
    "actor_required",
]
