"""SQLAlchemy ORM models for EIAMS persistence.

This module defines all database table models with proper relationships,
constraints, and indexes for tenant-aware IAM operations.
"""

from eiams.infrastructure.persistence.models.tenant import Tenant, TenantStatus
from eiams.infrastructure.persistence.models.identity import (
    Organization,
    User,
    UserStatus,
    Membership,
    MembershipStatus,
)
from eiams.infrastructure.persistence.models.authorization import (
    Permission,
    Role,
    RolePermission,
    RoleAssignment,
)
from eiams.infrastructure.persistence.models.credentials import (
    UserCredential,
    CredentialType,
    OAuthClient,
    OAuthClientType,
    ApiKey,
    ApiKeyStatus,
)
from eiams.infrastructure.persistence.models.authentication import (
    Session,
    SessionStatus,
    RefreshToken,
)
from eiams.infrastructure.persistence.models.audit import (
    AuditEvent,
    AuditEventType,
    AuditSeverity,
)

__all__ = [
    # Tenant
    "Tenant",
    "TenantStatus",
    # Identity
    "Organization",
    "User",
    "UserStatus",
    "Membership",
    "MembershipStatus",
    # Authorization
    "Permission",
    "Role",
    "RolePermission",
    "RoleAssignment",
    # Credentials
    "UserCredential",
    "CredentialType",
    "OAuthClient",
    "OAuthClientType",
    "ApiKey",
    "ApiKeyStatus",
    # Authentication
    "Session",
    "SessionStatus",
    "RefreshToken",
    # Audit
    "AuditEvent",
    "AuditEventType",
    "AuditSeverity",
]
