"""Audit service adapter that records redacted, correlated events.

Implements the foundation audit contract: each event carries the actor
when known, the tenant, the outcome, a timestamp, target-safe metadata,
and the request correlation ID. Details pass through secret redaction
before persistence so credential material cannot enter the audit trail.
"""

from typing import Any

from eiams.shared.context import ActorType, RequestContext
from eiams.shared.kernel import Timestamp
from eiams.shared.logging import SecretRedactor
from eiams.domain.audit.contracts import (
    AuditEvent,
    AuditEventId,
    AuditEventRepository,
    AuditEventType,
    AuditService,
    AuditSeverity,
)
from eiams.domain.identity.contracts import UserId
from eiams.application.services.authentication_audit import default_audit_redactor


# Event types that represent a security-relevant failure and are therefore
# recorded at a raised severity.
_FAILURE_OUTCOME = "failure"


class RedactingAuditService(AuditService):
    """Audit service that redacts details and persists through a repository."""

    def __init__(
        self,
        repository: AuditEventRepository,
        redactor: SecretRedactor | None = None,
    ) -> None:
        """Initialize the audit service.

        Args:
            repository: Append-only audit event repository.
            redactor: Secret redactor applied to event details.
        """
        self._repository = repository
        self._redactor = redactor or default_audit_redactor()

    def record_event(
        self,
        context: RequestContext,
        event_type: AuditEventType,
        action: str,
        outcome: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        resource_type: str | None = None,
        resource_id: str | None = None,
        details: dict[str, Any] | None = None,
        actor_id: str | None = None,
    ) -> AuditEvent:
        """Record an audit event with redacted details."""
        event = AuditEvent(
            audit_event_id=AuditEventId.generate(),
            event_type=event_type,
            severity=severity,
            action=action,
            outcome=outcome,
            details=self._redactor.redact_for_logging(details or {}),
            correlation_id_value=str(context.correlation_id),
            timestamp=Timestamp.now(),
            tenant_id=context.tenant.tenant_id if context.tenant else None,
            actor_id=actor_id or self._resolve_actor(context),
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=context.metadata.source_ip,
            user_agent=context.metadata.user_agent,
        )
        return self._repository.save(context, event)

    def record_authentication_event(
        self,
        context: RequestContext,
        event_type: AuditEventType,
        outcome: str,
        user_id: UserId | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Record an authentication outcome.

        The resolved user becomes both the actor and the target when
        known. When identity could not be resolved, the event carries no
        actor and no target so it reveals nothing about whether the
        submitted identifier exists.
        """
        return self.record_event(
            context=context,
            event_type=event_type,
            action=event_type.value,
            outcome=outcome,
            severity=(
                AuditSeverity.WARNING
                if outcome == _FAILURE_OUTCOME
                else AuditSeverity.INFO
            ),
            resource_type="user" if user_id else None,
            resource_id=str(user_id) if user_id else None,
            details=details,
            actor_id=str(user_id) if user_id else self._resolve_actor(context),
        )

    def record_authorization_event(
        self,
        context: RequestContext,
        event_type: AuditEventType,
        outcome: str,
        resource_type: str,
        resource_id: str | None = None,
        action: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Record an authorization decision."""
        return self.record_event(
            context=context,
            event_type=event_type,
            action=action or event_type.value,
            outcome=outcome,
            severity=(
                AuditSeverity.WARNING
                if outcome == _FAILURE_OUTCOME
                else AuditSeverity.INFO
            ),
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
        )

    def query_events(
        self,
        context: RequestContext,
        filters: dict[str, Any],
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query audit events by a small set of supported filters."""
        if "correlation_id" in filters:
            events = self._repository.find_by_correlation_id(
                context, str(filters["correlation_id"])
            )
            return events[offset : offset + limit]
        if "event_type" in filters:
            return self._repository.find_by_event_type(
                context, filters["event_type"], offset, limit
            )
        if "actor_id" in filters:
            return self._repository.find_by_actor(
                context, str(filters["actor_id"]), offset, limit
            )
        return []

    @staticmethod
    def _resolve_actor(context: RequestContext) -> str | None:
        """Resolve the acting principal, omitting placeholder actors.

        Anonymous transport actors carry a placeholder identifier that
        would be misleading in an audit trail, so they are recorded as an
        absent actor instead.
        """
        if context.actor is None:
            return None
        if context.actor.actor_type == ActorType.ANONYMOUS:
            return None
        return str(context.actor_id)
