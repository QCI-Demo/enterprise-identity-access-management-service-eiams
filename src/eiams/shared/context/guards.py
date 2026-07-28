"""Context guard functions for fail-closed behavior.

These guards enforce that required context is present before
operations proceed. They implement fail-closed behavior - if
required context is missing, the operation is rejected.
"""

from typing import Callable, TypeVar, ParamSpec
from functools import wraps

from eiams.shared.errors import (
    TenantRequiredError,
    TenantMismatchError,
    ActorRequiredError,
    ContextError,
)
from eiams.shared.kernel import TenantId
from .request_context import RequestContext, ActorType
from .scope import TenantPredicate


P = ParamSpec("P")
R = TypeVar("R")

#: Attribute every tenant-owned entity uses to record its owning tenant.
DEFAULT_TENANT_COLUMN = "tenant_id"


def require_tenant(context: RequestContext) -> None:
    """Guard function that requires tenant context to be present.

    This is the primary mechanism for enforcing tenant isolation.
    Call this at the start of any operation that requires tenant scope.

    Args:
        context: The request context to validate.

    Raises:
        TenantRequiredError: If tenant context is missing.

    Example:
        def get_user(context: RequestContext, user_id: str) -> User:
            require_tenant(context)  # Fail-closed if no tenant
            return repository.find_by_id(context.tenant_id, user_id)
    """
    if context is None:
        raise ContextError("Request context is required")
    if not context.has_tenant:
        raise TenantRequiredError(
            "Tenant context is required for this operation",
            details={"correlation_id": str(context.correlation_id)},
        )


def require_actor(context: RequestContext) -> None:
    """Guard function that requires authenticated actor context.

    Call this at the start of any operation that requires an
    authenticated user or service identity.

    Args:
        context: The request context to validate.

    Raises:
        ActorRequiredError: If actor is anonymous or missing.

    Example:
        def update_profile(context: RequestContext, profile: Profile) -> Profile:
            require_actor(context)  # Fail-closed if anonymous
            return repository.update(context.actor_id, profile)
    """
    if context is None:
        raise ContextError("Request context is required")
    if context.actor is None:
        raise ActorRequiredError("Actor context is required")
    if context.actor.actor_type == ActorType.ANONYMOUS:
        raise ActorRequiredError(
            "Authenticated actor is required for this operation",
            details={
                "correlation_id": str(context.correlation_id),
                "actor_type": context.actor.actor_type.value,
            },
        )


def require_context(context: RequestContext) -> None:
    """Guard function that validates the basic context structure.

    This performs minimal validation that a context object is present
    and structurally valid. Use more specific guards (require_tenant,
    require_actor) for operations with specific requirements.

    Args:
        context: The request context to validate.

    Raises:
        ContextError: If context is None or invalid.
    """
    if context is None:
        raise ContextError("Request context is required")
    if context.correlation_id is None:
        raise ContextError("Correlation ID is required in context")
    if context.actor is None:
        raise ContextError("Actor context is required")


def require_tenant_scope(
    context: RequestContext, *, operation: str | None = None
) -> TenantId:
    """Resolve the tenant a scoped data-access operation must be confined to.

    This is the entry point for every tenant-scoped repository operation. It
    fails closed: without a context, or without validated tenant context, no
    tenant can be resolved and the operation must not proceed.

    Args:
        context: The request context to validate.
        operation: Optional operation name recorded in error details.

    Returns:
        The validated tenant identifier.

    Raises:
        ContextError: If no context was supplied.
        TenantRequiredError: If the context carries no tenant scope.
    """
    if context is None:
        raise ContextError(
            "Request context is required for tenant-scoped access",
            details={"operation": operation} if operation else None,
        )
    if not context.has_tenant:
        details: dict[str, object] = {
            "correlation_id": str(context.correlation_id),
        }
        if operation:
            details["operation"] = operation
        raise TenantRequiredError(
            "Tenant context is required for tenant-scoped access",
            details=details,
        )
    return context.tenant_id


def require_platform_scope(
    context: RequestContext, *, operation: str | None = None
) -> None:
    """Guard a platform-scoped operation that intentionally spans tenants.

    Platform scope does not relax authentication: an anonymous caller can
    never reach data that crosses tenant boundaries.

    Args:
        context: The request context to validate.
        operation: Optional operation name recorded in error details.

    Raises:
        ContextError: If no context was supplied.
        ActorRequiredError: If the caller is not authenticated.
    """
    if context is None:
        raise ContextError(
            "Request context is required for platform-scoped access",
            details={"operation": operation} if operation else None,
        )
    require_actor(context)


def build_tenant_predicate(
    context: RequestContext,
    column: str = DEFAULT_TENANT_COLUMN,
    *,
    include_shared: bool = False,
    operation: str | None = None,
) -> TenantPredicate:
    """Build the tenant filter that must be bound before any scoped access.

    Args:
        context: The request context supplying tenant scope.
        column: Persistence attribute carrying tenant ownership.
        include_shared: Also match rows with no tenant owner. Reserved for
            platform-shared catalogues; never used to guard a mutation.
        operation: Optional operation name recorded in error details.

    Returns:
        A predicate bound to the validated tenant of the context.

    Raises:
        ContextError: If no context was supplied.
        TenantRequiredError: If the context carries no tenant scope.
    """
    tenant_id = require_tenant_scope(context, operation=operation)
    return TenantPredicate(
        column=column,
        tenant_id=tenant_id,
        include_shared=include_shared,
    )


def assert_tenant_match(
    context: RequestContext,
    resource_tenant_id: str | TenantId | None,
    *,
    resource_type: str | None = None,
    resource_id: str | None = None,
    allow_shared: bool = False,
) -> None:
    """Reject a resource that is not owned by the tenant in context.

    Args:
        context: The request context supplying tenant scope.
        resource_tenant_id: Tenant recorded on the resource being touched.
        resource_type: Optional resource type recorded in error details.
        resource_id: Optional resource identifier recorded in error details.
        allow_shared: Treat an absent owner as in scope. Only platform-shared
            catalogue rows may be read this way.

    Raises:
        ContextError: If no context was supplied.
        TenantRequiredError: If the context carries no tenant scope.
        TenantMismatchError: If the resource belongs to another tenant.
    """
    tenant_id = require_tenant_scope(context, operation=resource_type)

    if resource_tenant_id is None:
        if allow_shared:
            return
        raise TenantMismatchError(
            "Resource has no tenant owner and cannot be accessed in tenant scope",
            expected_tenant_id=tenant_id.value,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    candidate = (
        resource_tenant_id.value
        if isinstance(resource_tenant_id, TenantId)
        else str(resource_tenant_id).strip().lower()
    )
    if candidate != tenant_id.value:
        raise TenantMismatchError(
            expected_tenant_id=tenant_id.value,
            resource_type=resource_type,
            resource_id=resource_id,
        )


def tenant_required(func: Callable[P, R]) -> Callable[P, R]:
    """Decorator that enforces tenant context requirement.

    Apply this decorator to service methods that require tenant scope.
    The first argument must be a RequestContext.

    Args:
        func: The function to wrap.

    Returns:
        Wrapped function that validates tenant context before execution.

    Example:
        @tenant_required
        def list_users(context: RequestContext, filters: Filters) -> list[User]:
            return repository.find_all(context.tenant_id, filters)
    """

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        # Find context in args or kwargs
        context: RequestContext | None = None

        if args and isinstance(args[0], RequestContext):
            context = args[0]
        elif "context" in kwargs and isinstance(kwargs["context"], RequestContext):
            context = kwargs["context"]

        if context is None:
            raise ContextError(
                "Request context is required as first argument or 'context' kwarg"
            )

        require_tenant(context)
        return func(*args, **kwargs)

    return wrapper


def actor_required(func: Callable[P, R]) -> Callable[P, R]:
    """Decorator that enforces authenticated actor requirement.

    Apply this decorator to service methods that require authenticated access.
    The first argument must be a RequestContext.

    Args:
        func: The function to wrap.

    Returns:
        Wrapped function that validates actor context before execution.

    Example:
        @actor_required
        def get_my_profile(context: RequestContext) -> Profile:
            return repository.find_by_actor(context.actor_id)
    """

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        context: RequestContext | None = None

        if args and isinstance(args[0], RequestContext):
            context = args[0]
        elif "context" in kwargs and isinstance(kwargs["context"], RequestContext):
            context = kwargs["context"]

        if context is None:
            raise ContextError(
                "Request context is required as first argument or 'context' kwarg"
            )

        require_actor(context)
        return func(*args, **kwargs)

    return wrapper
