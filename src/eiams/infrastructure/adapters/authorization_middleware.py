"""Authorization middleware hook integration with validated request context.

Provides policy-neutral authorization middleware that connects validated
request context with authorization hooks and error mapping.
"""

from dataclasses import dataclass
from typing import Any, Callable, TypeVar

from eiams.shared.context import RequestContext
from eiams.shared.errors import (
    AuthorizationError,
    PermissionDeniedError,
    AuthorizationApiError,
    ApiErrorCode,
)
from eiams.shared.logging import (
    StructuredLogger,
    LogOutcome,
    LogLevel,
    get_logger,
)
from eiams.domain.authorization.contracts import (
    AuthorizationDecision,
    AuthorizationHook,
    OperationContext,
)
from eiams.infrastructure.adapters.authorization_hook import (
    CompositeAuthorizationHook,
)


T = TypeVar("T")


@dataclass(frozen=True)
class ProtectedOperationMetadata:
    """Metadata for a protected operation requiring authorization.

    This value object captures the authorization context needed
    for middleware hook invocation.
    """

    resource_type: str
    action: str
    resource_id: str | None = None
    attributes: dict[str, Any] | None = None

    def to_operation_context(self) -> OperationContext:
        """Convert to OperationContext for authorization hooks."""
        return OperationContext(
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            action=self.action,
            attributes=self.attributes or {},
        )

    def is_valid(self) -> bool:
        """Check if the metadata is valid for authorization."""
        return bool(self.resource_type and self.action)


class AuthorizationMiddleware:
    """Policy-neutral authorization middleware.

    Connects validated request context with authorization hooks
    and produces safe error responses. Uses deny-safe behavior
    for malformed or missing context.
    """

    def __init__(
        self,
        hooks: CompositeAuthorizationHook | None = None,
        logger: StructuredLogger | None = None,
        fail_open: bool = False,
    ) -> None:
        """Initialize the authorization middleware.

        Args:
            hooks: Composite authorization hooks to invoke.
            logger: Structured logger for authorization events.
            fail_open: If True, allow when no hooks decide.
                       Default is False (fail-closed/deny-safe).
        """
        self._hooks = hooks or CompositeAuthorizationHook(
            default_decision=(
                AuthorizationDecision.ALLOW if fail_open
                else AuthorizationDecision.DENY
            )
        )
        self._logger = logger or get_logger("authorization")
        self._fail_open = fail_open

    @property
    def hooks(self) -> CompositeAuthorizationHook:
        """The authorization hooks."""
        return self._hooks

    def register_hook(self, hook: AuthorizationHook) -> None:
        """Register an authorization hook.

        Args:
            hook: Hook to add to the evaluation chain.
        """
        self._hooks.add_hook(hook)

    def check_authorization(
        self,
        context: RequestContext,
        operation_metadata: ProtectedOperationMetadata,
    ) -> AuthorizationDecision:
        """Check authorization for a protected operation.

        Uses validated actor and tenant context from the request.
        Returns DENY for malformed metadata (deny-safe behavior).

        Args:
            context: Validated request context.
            operation_metadata: Protected operation metadata.

        Returns:
            AuthorizationDecision (ALLOW, DENY, or NOT_APPLICABLE).
        """
        # Deny-safe: reject malformed metadata
        if not operation_metadata.is_valid():
            self._log_authorization_result(
                context=context,
                operation_metadata=operation_metadata,
                decision=AuthorizationDecision.DENY,
                reason="malformed_metadata",
            )
            return AuthorizationDecision.DENY

        operation = operation_metadata.to_operation_context()
        decision = self._hooks.authorize(context, operation)

        self._log_authorization_result(
            context=context,
            operation_metadata=operation_metadata,
            decision=decision,
        )

        return decision

    def require_authorization(
        self,
        context: RequestContext,
        operation_metadata: ProtectedOperationMetadata,
    ) -> None:
        """Require authorization for a protected operation.

        Raises AuthorizationApiError if authorization is denied.

        Args:
            context: Validated request context.
            operation_metadata: Protected operation metadata.

        Raises:
            AuthorizationApiError: If authorization is denied.
        """
        decision = self.check_authorization(context, operation_metadata)

        if decision != AuthorizationDecision.ALLOW:
            raise AuthorizationApiError(
                message="Access denied",
                code=ApiErrorCode.PERMISSION_DENIED,
                correlation_id=str(context.correlation_id),
                details={
                    "resource_type": operation_metadata.resource_type,
                    "action": operation_metadata.action,
                },
            )

    def protect(
        self,
        resource_type: str,
        action: str,
        resource_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Decorator factory for protecting operations.

        Creates a decorator that enforces authorization before
        the decorated function executes.

        Args:
            resource_type: Resource type being accessed.
            action: Action being performed.
            resource_id: Optional specific resource ID.
            attributes: Optional additional attributes.

        Returns:
            Decorator function.

        Example:
            @middleware.protect("user", "update")
            def update_user(context: RequestContext, user_id: str): ...
        """
        metadata = ProtectedOperationMetadata(
            resource_type=resource_type,
            action=action,
            resource_id=resource_id,
            attributes=attributes,
        )

        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            def wrapper(context: RequestContext, *args: Any, **kwargs: Any) -> T:
                self.require_authorization(context, metadata)
                return func(context, *args, **kwargs)
            return wrapper
        return decorator

    def _log_authorization_result(
        self,
        context: RequestContext,
        operation_metadata: ProtectedOperationMetadata,
        decision: AuthorizationDecision,
        reason: str | None = None,
    ) -> None:
        """Log authorization decision for audit."""
        outcome = (
            LogOutcome.SUCCESS if decision == AuthorizationDecision.ALLOW
            else LogOutcome.DENIED
        )
        level = (
            LogLevel.INFO if decision == AuthorizationDecision.ALLOW
            else LogLevel.WARNING
        )

        extra: dict[str, Any] = {
            "decision": decision.value,
        }
        if reason:
            extra["reason"] = reason

        self._logger.log_operation(
            context=context,
            operation="authorization_check",
            outcome=outcome,
            message=f"Authorization {decision.value} for {operation_metadata.action} on {operation_metadata.resource_type}",
            level=level,
            resource_type=operation_metadata.resource_type,
            resource_id=operation_metadata.resource_id,
            **extra,
        )


class AuthorizationGuard:
    """Guard for validating authorization context before hook invocation.

    Validates that request context contains the required metadata
    for authorization decisions.
    """

    @staticmethod
    def validate_context(context: RequestContext) -> list[str]:
        """Validate request context for authorization.

        Returns a list of validation errors (empty if valid).

        Args:
            context: Request context to validate.

        Returns:
            List of validation error messages.
        """
        errors: list[str] = []

        if not context:
            errors.append("Request context is required")
            return errors

        if not context.actor:
            errors.append("Actor context is required")

        if not context.correlation_id:
            errors.append("Correlation ID is required")

        return errors

    @staticmethod
    def validate_operation(metadata: ProtectedOperationMetadata) -> list[str]:
        """Validate protected operation metadata.

        Returns a list of validation errors (empty if valid).

        Args:
            metadata: Operation metadata to validate.

        Returns:
            List of validation error messages.
        """
        errors: list[str] = []

        if not metadata:
            errors.append("Operation metadata is required")
            return errors

        if not metadata.resource_type:
            errors.append("Resource type is required")

        if not metadata.action:
            errors.append("Action is required")

        return errors


def create_authorization_middleware(
    fail_open: bool = False,
    logger: StructuredLogger | None = None,
) -> AuthorizationMiddleware:
    """Factory function to create authorization middleware.

    Args:
        fail_open: If True, allow when no hooks decide.
        logger: Optional structured logger.

    Returns:
        Configured AuthorizationMiddleware instance.
    """
    return AuthorizationMiddleware(
        fail_open=fail_open,
        logger=logger,
    )
