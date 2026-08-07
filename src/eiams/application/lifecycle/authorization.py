"""Authorization integration points for lifecycle command services."""

from __future__ import annotations

from eiams.shared.context import ActorType, RequestContext, require_actor
from eiams.shared.errors import PermissionDeniedError

PLATFORM_ADMIN_ROLES = frozenset({"platform_admin", "system"})
PLATFORM_ADMIN_PERMISSIONS = frozenset({"tenant:admin", "platform:admin", "*"})
TENANT_ORG_ADMIN_ROLES = frozenset(
    {"tenant_admin", "organization_admin", "admin", "system"}
)
TENANT_ORG_ADMIN_PERMISSIONS = frozenset(
    {"organization:admin", "organization:write", "*"}
)


def require_platform_administration(
    context: RequestContext,
    *,
    resource: str = "tenant",
    action: str = "administer",
) -> None:
    """Require a validated actor with platform-administration privileges.

    System actors and callers holding an approved platform-admin role or
    permission may proceed. All other authenticated callers are denied.
    """
    require_actor(context)
    actor = context.actor
    assert actor is not None

    if actor.actor_type == ActorType.SYSTEM:
        return
    if any(role in PLATFORM_ADMIN_ROLES for role in actor.roles):
        return
    if any(
        permission in PLATFORM_ADMIN_PERMISSIONS
        for permission in actor.permissions
    ):
        return

    raise PermissionDeniedError(
        "Platform administration privileges are required",
        resource=resource,
        action=action,
    )


def require_tenant_organization_administration(
    context: RequestContext,
    *,
    resource: str = "organization",
    action: str = "administer",
) -> None:
    """Require a validated tenant actor authorized for organization commands."""
    require_actor(context)
    actor = context.actor
    assert actor is not None

    if actor.actor_type == ActorType.SYSTEM:
        return
    if any(role in TENANT_ORG_ADMIN_ROLES for role in actor.roles):
        return
    if any(
        permission in TENANT_ORG_ADMIN_PERMISSIONS
        for permission in actor.permissions
    ):
        return

    raise PermissionDeniedError(
        "Organization administration privileges are required",
        resource=resource,
        action=action,
    )
