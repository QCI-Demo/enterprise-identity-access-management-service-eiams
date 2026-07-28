"""Context guard functions for fail-closed behavior.

These guards enforce that required context is present before
operations proceed. They implement fail-closed behavior - if
required context is missing, the operation is rejected.
"""

from typing import Callable, TypeVar, ParamSpec
from functools import wraps

from eiams.shared.errors import (
    TenantRequiredError,
    ActorRequiredError,
    ContextError,
)
from .request_context import RequestContext, ActorType


P = ParamSpec("P")
R = TypeVar("R")


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
