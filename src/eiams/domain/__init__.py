"""Domain layer containing IAM module contracts.

The domain layer defines framework-isolated interfaces and contracts
for the six IAM domains. These contracts have no dependencies on
frameworks or infrastructure concerns.

Modules:
- identity: User and organization identity management
- authentication: Login, session, and token management
- authorization: RBAC, permissions, and policy evaluation
- credentials: Password, API key, and OAuth client management
- audit: Security event logging and compliance tracking
- administration: Tenant and system administration
"""

from .base import (
    DomainEntity,
    DomainEvent,
    Repository,
    ReadableRepository,
    PlatformScopedRepository,
    TenantScopedRepository,
    AppendOnlyRepository,
    DomainService,
)

__all__ = [
    "DomainEntity",
    "DomainEvent",
    "Repository",
    "ReadableRepository",
    "PlatformScopedRepository",
    "TenantScopedRepository",
    "AppendOnlyRepository",
    "DomainService",
]
