"""Safe audit recording for authentication outcomes.

Login attempts are recorded through the foundation audit contract with a
strict allow-list of metadata. Passwords, protected credential values,
tokens, and submitted identifiers never reach an audit event, a log
event, or an error payload.
"""

from typing import Any, Mapping

from eiams.shared.context import RequestContext
from eiams.shared.logging import (
    LogLevel,
    LogOutcome,
    RedactionConfig,
    SecretRedactor,
    StructuredLogger,
    get_logger,
)
from eiams.domain.audit.contracts import (
    AuditEvent,
    AuditEventType,
    AuditService,
)
from eiams.domain.authentication.contracts import (
    AuthenticationFailureCategory,
    AuthenticationMethod,
    AuthenticationOutcome,
)
from eiams.domain.identity.contracts import UserId


LOGIN_OPERATION = "password_login"

# Only these keys may appear in authentication audit metadata. Anything
# else is dropped, which keeps submitted identifiers and credential
# material out of the audit trail even if a caller passes them in.
SAFE_AUDIT_DETAIL_KEYS: frozenset[str] = frozenset(
    {
        "method",
        "outcome",
        "failure_category",
        "credential_algorithm",
        "needs_rehash",
        "token_issued",
        "session_created",
    }
)

# Allow-listed keys whose names resemble secret-bearing keys but hold only
# flags or algorithm names. Their values are still pattern-scanned.
_NON_SECRET_KEY_NAMES = ("token_issued", "session_created", "credential_algorithm")


def default_audit_redactor() -> SecretRedactor:
    """Build the redactor used for authentication audit metadata."""
    return SecretRedactor(
        RedactionConfig().with_safe_keys(*_NON_SECRET_KEY_NAMES)
    )

# Audit resource naming for authentication targets. The identifier used is
# always the resolved internal user ID, never the submitted identifier.
AUDIT_RESOURCE_TYPE = "user"


class AuthenticationAuditRecorder:
    """Records authentication outcomes through the audit contract.

    Emits one audit event and one structured log event per attempt, both
    limited to allow-listed, redacted metadata.
    """

    def __init__(
        self,
        audit_service: AuditService,
        logger: StructuredLogger | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        """Initialize the recorder.

        Args:
            audit_service: Foundation audit contract implementation.
            logger: Structured logger for safe authentication events.
            redactor: Secret redactor applied to metadata before emission.
        """
        self._audit_service = audit_service
        self._logger = logger or get_logger("authentication")
        self._redactor = redactor or default_audit_redactor()

    def record_login_success(
        self,
        context: RequestContext,
        user_id: UserId,
        details: Mapping[str, Any] | None = None,
    ) -> AuditEvent:
        """Record a successful password authentication.

        Args:
            context: Request context supplying tenant and correlation ID.
            user_id: The resolved user that authenticated, used as actor.
            details: Optional additional metadata, filtered to the
                allow-list before emission.

        Returns:
            The recorded audit event.
        """
        payload = self._build_details(
            outcome=AuthenticationOutcome.SUCCESS,
            details=details,
        )

        event = self._audit_service.record_authentication_event(
            context=context,
            event_type=AuditEventType.LOGIN_SUCCESS,
            outcome=AuthenticationOutcome.SUCCESS.value,
            user_id=user_id,
            details=payload,
        )

        self._log(
            context=context,
            outcome=LogOutcome.SUCCESS,
            level=LogLevel.INFO,
            message="Password authentication succeeded",
            resource_id=str(user_id),
            details=payload,
        )
        return event

    def record_login_failure(
        self,
        context: RequestContext,
        failure_category: AuthenticationFailureCategory,
        user_id: UserId | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> AuditEvent:
        """Record a failed password authentication.

        Args:
            context: Request context supplying tenant and correlation ID.
            failure_category: Coarse failure classification.
            user_id: The resolved user when known; omitted for
                unresolved identifiers so the event carries no evidence
                about whether an identifier exists.
            details: Optional additional metadata, filtered to the
                allow-list before emission.

        Returns:
            The recorded audit event.
        """
        payload = self._build_details(
            outcome=AuthenticationOutcome.FAILURE,
            failure_category=failure_category,
            details=details,
        )

        event = self._audit_service.record_authentication_event(
            context=context,
            event_type=AuditEventType.LOGIN_FAILURE,
            outcome=AuthenticationOutcome.FAILURE.value,
            user_id=user_id,
            details=payload,
        )

        self._log(
            context=context,
            outcome=LogOutcome.FAILURE,
            level=LogLevel.WARNING,
            message="Password authentication failed",
            resource_id=str(user_id) if user_id else None,
            details=payload,
        )
        return event

    def _build_details(
        self,
        outcome: AuthenticationOutcome,
        failure_category: AuthenticationFailureCategory | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build allow-listed, redacted audit metadata."""
        payload: dict[str, Any] = {
            "method": AuthenticationMethod.PASSWORD.value,
            "outcome": outcome.value,
            "token_issued": False,
            "session_created": False,
        }
        if failure_category is not None:
            payload["failure_category"] = failure_category.value

        for key, value in (details or {}).items():
            if key in SAFE_AUDIT_DETAIL_KEYS and key not in payload:
                payload[key] = value

        return self._redactor.redact_for_logging(payload)

    def _log(
        self,
        context: RequestContext,
        outcome: LogOutcome,
        level: LogLevel,
        message: str,
        resource_id: str | None,
        details: Mapping[str, Any],
    ) -> None:
        """Emit a safe structured log event for the attempt."""
        self._logger.log_operation(
            context=context,
            operation=LOGIN_OPERATION,
            outcome=outcome,
            message=message,
            level=level,
            resource_type=AUDIT_RESOURCE_TYPE if resource_id else None,
            resource_id=resource_id,
            **{key: value for key, value in details.items() if key != "outcome"},
        )
