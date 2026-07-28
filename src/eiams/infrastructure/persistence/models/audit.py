"""Audit event model.

Append-only audit events for security compliance and traceability.
This table is designed for write-heavy workloads with time-based queries.
"""

import enum
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    Index,
    String,
    Text,
    Uuid,
)
from sqlalchemy.types import JSON
from sqlalchemy.orm import Mapped, mapped_column

from eiams.infrastructure.persistence.database import Base


class AuditEventType(str, enum.Enum):
    """Classification of audit events."""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    TOKEN_ISSUED = "token_issued"
    TOKEN_REFRESHED = "token_refreshed"
    TOKEN_REVOKED = "token_revoked"
    
    # Authorization events
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    
    # Identity events
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_STATUS_CHANGED = "user_status_changed"
    
    # Organization events
    ORGANIZATION_CREATED = "organization_created"
    ORGANIZATION_UPDATED = "organization_updated"
    ORGANIZATION_DELETED = "organization_deleted"
    
    # Membership events
    MEMBERSHIP_CREATED = "membership_created"
    MEMBERSHIP_UPDATED = "membership_updated"
    MEMBERSHIP_REMOVED = "membership_removed"
    
    # Credential events
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    OAUTH_CLIENT_CREATED = "oauth_client_created"
    OAUTH_CLIENT_UPDATED = "oauth_client_updated"
    OAUTH_CLIENT_SECRET_ROTATED = "oauth_client_secret_rotated"
    
    # Administrative events
    TENANT_CREATED = "tenant_created"
    TENANT_UPDATED = "tenant_updated"
    TENANT_SUSPENDED = "tenant_suspended"
    CONFIGURATION_CHANGED = "configuration_changed"
    
    # System events
    SYSTEM_ERROR = "system_error"
    SECURITY_ALERT = "security_alert"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


class AuditSeverity(str, enum.Enum):
    """Severity level of audit events."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditEvent(Base):
    """Append-only audit event for security compliance.
    
    This table is designed for:
    - High-volume inserts
    - Time-based range queries
    - Tenant-scoped filtering
    - Correlation ID tracking
    
    NO UPDATE OR DELETE operations should be performed.
    Events are immutable once written.
    """
    
    __tablename__ = "audit_events"
    
    # Primary key - immutable UUID
    id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    
    # Event classification
    event_type: Mapped[AuditEventType] = mapped_column(
        Enum(AuditEventType, name="audit_event_type", native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    severity: Mapped[AuditSeverity] = mapped_column(
        Enum(AuditSeverity, name="audit_severity", native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=AuditSeverity.INFO,
    )
    
    # Actor information (who performed the action)
    # Can be NULL for system-generated events
    actor_id: Mapped[str | None] = mapped_column(
        Uuid(as_uuid=False),
        nullable=True,
    )
    actor_type: Mapped[str] = mapped_column(
        String(63),
        nullable=False,
        default="user",  # user, service, system
    )
    
    # Tenant scope (NULL for cross-tenant or system events)
    tenant_id: Mapped[str | None] = mapped_column(
        Uuid(as_uuid=False),
        nullable=True,
    )
    
    # Target resource information
    target_type: Mapped[str | None] = mapped_column(
        String(63),
        nullable=True,
    )
    target_id: Mapped[str | None] = mapped_column(
        Uuid(as_uuid=False),
        nullable=True,
    )
    
    # Action description
    action: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    
    # Outcome (success, failure, error)
    outcome: Mapped[str] = mapped_column(
        String(63),
        nullable=False,
    )
    
    # Correlation ID for request tracing
    correlation_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    
    # Request metadata (safe, non-secret data)
    ip_address: Mapped[str | None] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
    )
    user_agent: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    
    # Additional safe metadata as JSON
    # NEVER contains secrets, PII beyond what's necessary for audit
    event_metadata: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )
    
    # Error details for failure events
    error_code: Mapped[str | None] = mapped_column(
        String(63),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    
    # Event timestamp - immutable, used for time-based queries
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    
    __table_args__ = (
        # Primary query pattern: tenant + time range
        Index("ix_audit_events_tenant_id", "tenant_id"),
        Index("ix_audit_events_event_type", "event_type"),
        Index("ix_audit_events_severity", "severity"),
        Index("ix_audit_events_actor_id", "actor_id"),
        Index("ix_audit_events_event_time", "event_time"),
        Index("ix_audit_events_correlation_id", "correlation_id"),
        Index("ix_audit_events_tenant_id_event_time", "tenant_id", "event_time"),
        Index("ix_audit_events_actor_id_event_time", "actor_id", "event_time"),
        Index("ix_audit_events_target_type_target_id_event_time", "target_type", "target_id", "event_time"),
        Index("ix_audit_events_tenant_id_event_type_event_time", "tenant_id", "event_type", "event_time"),
        Index("ix_audit_events_severity_event_time", "severity", "event_time"),
        # Ensure outcome is valid
        CheckConstraint(
            "outcome IN ('success', 'failure', 'error', 'denied', 'timeout')",
            name="valid_audit_outcome",
        ),
        # Ensure actor_type is valid
        CheckConstraint(
            "actor_type IN ('user', 'service', 'system', 'anonymous')",
            name="valid_audit_actor_type",
        ),
    )
    
    def __repr__(self) -> str:
        return (
            f"AuditEvent(id={self.id!r}, event_type={self.event_type!r}, "
            f"action={self.action!r}, outcome={self.outcome!r})"
        )
