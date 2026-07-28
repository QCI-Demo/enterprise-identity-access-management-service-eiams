"""Audit domain module.

Manages security event logging and compliance tracking, including:
- Immutable audit event recording
- Security-relevant action logging
- Compliance audit trail
- Event querying and reporting
"""

from .contracts import (
    AuditEvent,
    AuditEventId,
    AuditEventType,
    AuditSeverity,
    AuditEventRepository,
    AuditService,
)

__all__ = [
    "AuditEvent",
    "AuditEventId",
    "AuditEventType",
    "AuditSeverity",
    "AuditEventRepository",
    "AuditService",
]
