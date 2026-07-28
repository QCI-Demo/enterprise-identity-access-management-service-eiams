"""Authorization extension hooks for RBAC middleware.

These hooks provide extension points for later RBAC middleware
implementation without making authorization decisions themselves.
"""

from abc import ABC, abstractmethod
from typing import Any, Callable

from eiams.shared.context import RequestContext
from eiams.domain.authorization.contracts import (
    AuthorizationHook,
    AuthorizationDecision,
    OperationContext,
)


class AuthorizationHookAdapter(ABC):
    """Base adapter for authorization hooks.

    Adapters can transform or enrich operation context before
    passing it to authorization hooks.
    """

    @abstractmethod
    def adapt(
        self,
        context: RequestContext,
        operation: OperationContext,
    ) -> OperationContext:
        """Adapt or enrich the operation context.

        Args:
            context: The request context.
            operation: The original operation context.

        Returns:
            Possibly modified operation context.
        """
        ...


class LoggingAuthorizationHook:
    """Authorization hook that logs authorization attempts.

    This is a non-deciding hook that can be used for audit purposes.
    It always returns NOT_APPLICABLE, allowing other hooks to decide.
    """

    def __init__(
        self,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize the logging hook.

        Args:
            logger: Optional logging function. Defaults to print.
        """
        self._logger = logger or print

    def authorize(
        self,
        context: RequestContext,
        operation: OperationContext,
    ) -> AuthorizationDecision:
        """Log the authorization attempt and return NOT_APPLICABLE.

        Args:
            context: The request context.
            operation: The operation being authorized.

        Returns:
            AuthorizationDecision.NOT_APPLICABLE (does not make decisions).
        """
        self._logger(
            f"Authorization check: actor={context.actor_id}, "
            f"resource={operation.resource_type}/{operation.resource_id}, "
            f"action={operation.action}"
        )
        return AuthorizationDecision.NOT_APPLICABLE


class CompositeAuthorizationHook:
    """Composite hook that combines multiple authorization hooks.

    Hooks are evaluated in order. The first hook that returns
    ALLOW or DENY wins. If all hooks return NOT_APPLICABLE,
    the final decision is configurable (default: DENY for fail-closed).
    """

    def __init__(
        self,
        hooks: list[AuthorizationHook] | None = None,
        default_decision: AuthorizationDecision = AuthorizationDecision.DENY,
    ) -> None:
        """Initialize the composite hook.

        Args:
            hooks: List of hooks to evaluate in order.
            default_decision: Decision when all hooks return NOT_APPLICABLE.
        """
        self._hooks: list[AuthorizationHook] = list(hooks) if hooks else []
        self._default_decision = default_decision

    def add_hook(self, hook: AuthorizationHook) -> None:
        """Add a hook to the evaluation chain.

        Args:
            hook: The hook to add.
        """
        self._hooks.append(hook)

    def remove_hook(self, hook: AuthorizationHook) -> bool:
        """Remove a hook from the evaluation chain.

        Args:
            hook: The hook to remove.

        Returns:
            True if the hook was found and removed.
        """
        try:
            self._hooks.remove(hook)
            return True
        except ValueError:
            return False

    def authorize(
        self,
        context: RequestContext,
        operation: OperationContext,
    ) -> AuthorizationDecision:
        """Evaluate all hooks and return the first decisive result.

        Args:
            context: The request context.
            operation: The operation being authorized.

        Returns:
            The authorization decision.
        """
        for hook in self._hooks:
            decision = hook.authorize(context, operation)
            if decision != AuthorizationDecision.NOT_APPLICABLE:
                return decision

        return self._default_decision

    @property
    def hook_count(self) -> int:
        """Number of registered hooks."""
        return len(self._hooks)


class PassThroughAuthorizationHook:
    """Authorization hook that always allows (for development/testing).

    WARNING: This hook should never be used in production as it
    bypasses all authorization checks.
    """

    def authorize(
        self,
        context: RequestContext,
        operation: OperationContext,
    ) -> AuthorizationDecision:
        """Always return ALLOW.

        Args:
            context: The request context (ignored).
            operation: The operation (ignored).

        Returns:
            AuthorizationDecision.ALLOW always.
        """
        return AuthorizationDecision.ALLOW
