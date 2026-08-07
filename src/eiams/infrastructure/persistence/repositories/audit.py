"""Append-only repository for the audit entity group."""

from eiams.domain.audit.contracts import (
    AuditEvent,
    AuditEventId,
    AuditEventRepository,
    AuditEventType,
)
from eiams.infrastructure.persistence.models import audit as audit_models
from eiams.shared.context import RequestContext
from eiams.shared.kernel import Timestamp

from ..mappers import AuditEventMapper
from .base import AppendOnlySqlRepository


class SqlAlchemyAuditEventRepository(
    AppendOnlySqlRepository[AuditEvent, AuditEventId, audit_models.AuditEvent],
    AuditEventRepository,
):
    """Audit trail for one tenant.

    Only ``append`` writes. The class exposes no update or delete primitive,
    so an audit record cannot be rewritten or erased through it. Reads are
    bound to the tenant predicate, so one tenant's trail is never visible
    to another.
    """

    __model__ = audit_models.AuditEvent
    __mapper__ = AuditEventMapper()
    __entity_name__ = "audit event"
    __order_column__ = "event_time"

    def find_by_actor(
        self,
        context: RequestContext,
        actor_id: str,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        statement = self._scoped_select(context).where(
            audit_models.AuditEvent.actor_id == str(actor_id)
        )
        return self._entities(
            self._rows(self._paginated(self._ordered(statement), offset, limit))
        )

    def find_by_event_type(
        self,
        context: RequestContext,
        event_type: AuditEventType,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        statement = self._scoped_select(context).where(
            audit_models.AuditEvent.event_type
            == audit_models.AuditEventType(event_type.value)
        )
        return self._entities(
            self._rows(self._paginated(self._ordered(statement), offset, limit))
        )

    def find_by_correlation_id(
        self, context: RequestContext, correlation_id: str
    ) -> list[AuditEvent]:
        statement = self._scoped_select(context).where(
            audit_models.AuditEvent.correlation_id == str(correlation_id)
        )
        return self._entities(self._rows(self._ordered(statement)))

    def find_by_time_range(
        self,
        context: RequestContext,
        start: Timestamp,
        end: Timestamp,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        statement = (
            self._scoped_select(context)
            .where(audit_models.AuditEvent.event_time >= start.value)
            .where(audit_models.AuditEvent.event_time <= end.value)
        )
        return self._entities(
            self._rows(self._paginated(self._ordered(statement), offset, limit))
        )

    def find_by_resource(
        self,
        context: RequestContext,
        resource_type: str,
        resource_id: str,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        statement = (
            self._scoped_select(context)
            .where(audit_models.AuditEvent.target_type == resource_type)
            .where(audit_models.AuditEvent.target_id == str(resource_id))
        )
        return self._entities(
            self._rows(self._paginated(self._ordered(statement), offset, limit))
        )
