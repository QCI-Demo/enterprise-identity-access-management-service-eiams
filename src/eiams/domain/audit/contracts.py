"""Audit domain contracts.

Framework-isolated interfaces for security event auditing.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

from eiams.shared.kernel import EntityId, TenantId, Timestamp
from eiams.shared.context import RequestContext
from eiams.domain.base import DomainEntity, DomainEvent, Repository, DomainService
from eiams.domain.identity.contracts import UserId


class AuditEventId(EntityId):
    """Unique identifier for an audit event."""
    pass


class AuditEventType(str, Enum):
    """Type of audit event."""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    TOKEN_ISSUED = "token_issued"
    TOKEN_REFRESHED = "token_refreshed"

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

    # Credential events
    PASSWORD_CHANGED = "password_changed"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    CLIENT_CREATED = "client_created"
    CLIENT_SECRET_ROTATED = "client_secret_rotated"

    # Administrative events
    TENANT_CREATED = "tenant_created"
    TENANT_UPDATED = "tenant_updated"
    CONFIGURATION_CHANGED = "configuration_changed"

    # System events
    SYSTEM_ERROR = "system_error"
    SECURITY_ALERT = "security_alert"


class AuditSeverity(str, Enum):
    """Severity level of audit events."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AuditEvent:
    """Audit event entity contract.

    Represents an immutable security-relevant event for compliance.
    Implements DomainEntity and DomainEvent contracts.
    """

    # Required fields (no defaults)
    audit_event_id: AuditEventId
    event_type: AuditEventType
    severity: AuditSeverity
    action: str
    outcome: str  # "success" or "failure"
    details: dict[str, Any]
    correlation_id_value: str
    timestamp: Timestamp
    # Optional fields (with defaults)
    tenant_id: TenantId | None = None
    actor_id: str | None = None  # String to handle system/anonymous actors
    resource_type: str | None = None
    resource_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None

    @property
    def id(self) -> EntityId:
        return self.audit_event_id

    # DomainEvent interface
    @property
    def occurred_at(self) -> Timestamp:
        return self.timestamp

    @property
    def correlation_id(self) -> str:
        return self.correlation_id_value

    def to_dict(self) -> dict[str, Any]:
        """Serialize event for storage or transmission."""
        return {
            "event_id": str(self.audit_event_id),
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "actor_id": self.actor_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "outcome": self.outcome,
            "details": self.details,
            "correlation_id": self.correlation_id_value,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "timestamp": self.timestamp.to_iso(),
        }

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AuditEvent):
            return NotImplemented
        return self.audit_event_id == other.audit_event_id

    def __hash__(self) -> int:
        return hash(self.audit_event_id)


class AuditEventRepository(Repository[AuditEvent, AuditEventId], ABC):
    """Repository contract for audit event persistence operations.

    Note: Audit events are append-only. Update and delete operations
    should raise NotImplementedError to maintain immutability.
    """

    @abstractmethod
    def find_by_actor(
        self,
        context: RequestContext,
        actor_id: str,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Find audit events by actor."""
        ...

    @abstractmethod
    def find_by_event_type(
        self,
        context: RequestContext,
        event_type: AuditEventType,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Find audit events by type."""
        ...

    @abstractmethod
    def find_by_correlation_id(
        self,
        context: RequestContext,
        correlation_id: str,
    ) -> list[AuditEvent]:
        """Find audit events by correlation ID."""
        ...

    @abstractmethod
    def find_by_time_range(
        self,
        context: RequestContext,
        start: Timestamp,
        end: Timestamp,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Find audit events within a time range."""
        ...

    @abstractmethod
    def find_by_resource(
        self,
        context: RequestContext,
        resource_type: str,
        resource_id: str,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Find audit events for a specific resource."""
        ...


class AuditService(DomainService, ABC):
    """Domain service contract for audit operations."""

    @abstractmethod
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
    ) -> AuditEvent:
        """Record a new audit event."""
        ...

    @abstractmethod
    def record_authentication_event(
        self,
        context: RequestContext,
        event_type: AuditEventType,
        outcome: str,
        user_id: UserId | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Record an authentication-related audit event."""
        ...

    @abstractmethod
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
        """Record an authorization-related audit event."""
        ...

    @abstractmethod
    def query_events(
        self,
        context: RequestContext,
        filters: dict[str, Any],
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query audit events with filters."""
        ...
