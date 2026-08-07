"""Mapping for the audit entity group.

The audit mapper has no ``apply`` behaviour that changes recorded facts:
audit rows are written once and never rewritten, so the update path exists
only to satisfy the mapper contract and refuses to run.
"""

from eiams.domain.audit.contracts import (
    AuditActorType,
    AuditEvent,
    AuditEventId,
    AuditEventType,
    AuditSeverity,
)
from eiams.infrastructure.persistence.models import audit as audit_models
from eiams.shared.errors import AppendOnlyViolationError
from eiams.shared.kernel import TenantId

from .base import (
    EntityMapper,
    from_timestamp,
    identifier,
    optional_identifier,
    require_timestamp,
)


class AuditEventMapper(EntityMapper[AuditEvent, audit_models.AuditEvent]):
    """Maps audit rows to and from the audit event entity."""

    entity_name = "audit event"

    def to_entity(self, row: audit_models.AuditEvent) -> AuditEvent:
        return AuditEvent(
            audit_event_id=AuditEventId(row.id),
            event_type=AuditEventType(row.event_type.value),
            severity=AuditSeverity(row.severity.value),
            action=row.action,
            outcome=row.outcome,
            details=dict(row.event_metadata or {}),
            correlation_id_value=row.correlation_id,
            timestamp=require_timestamp(row.event_time),
            tenant_id=TenantId(row.tenant_id) if row.tenant_id else None,
            actor_id=row.actor_id,
            resource_type=row.target_type,
            resource_id=row.target_id,
            ip_address=row.ip_address,
            user_agent=row.user_agent,
            actor_type=AuditActorType(row.actor_type),
            error_code=row.error_code,
            error_message=row.error_message,
        )

    def to_model(self, entity: AuditEvent) -> audit_models.AuditEvent:
        row = audit_models.AuditEvent(
            id=identifier(entity.audit_event_id),
            event_type=audit_models.AuditEventType(entity.event_type.value),
            severity=audit_models.AuditSeverity(entity.severity.value),
            actor_id=optional_identifier(entity.actor_id),
            actor_type=entity.actor_type.value,
            tenant_id=optional_identifier(entity.tenant_id),
            target_type=entity.resource_type,
            target_id=entity.resource_id,
            action=entity.action,
            outcome=entity.outcome,
            correlation_id=entity.correlation_id_value,
            ip_address=entity.ip_address,
            user_agent=entity.user_agent,
            event_metadata=dict(entity.details) if entity.details else None,
            error_code=entity.error_code,
            error_message=entity.error_message,
        )
        if entity.timestamp is not None:
            row.event_time = from_timestamp(entity.timestamp)
        return row

    def apply(self, entity: AuditEvent, row: audit_models.AuditEvent) -> None:
        raise AppendOnlyViolationError(
            "Audit events cannot be modified after they are recorded",
            entity=self.entity_name,
            operation="update",
        )
