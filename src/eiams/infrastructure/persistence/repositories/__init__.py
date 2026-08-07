"""SQLAlchemy repository implementations for the IAM entity groups.

Every repository here is bound to the session of a unit of work and returns
domain entities. Tenant-scoped repositories refuse to run without validated
tenant context.
"""

from .administration import SqlAlchemyTenantRepository
from .audit import SqlAlchemyAuditEventRepository
from .authentication import (
    SqlAlchemyRefreshTokenRepository,
    SqlAlchemySessionRepository,
)
from .authorization import (
    SqlAlchemyPermissionRepository,
    SqlAlchemyRoleAssignmentRepository,
    SqlAlchemyRoleRepository,
)
from .base import (
    MAX_PAGE_SIZE,
    AppendOnlySqlRepository,
    PlatformScopedSqlRepository,
    SqlAlchemyRepository,
    TenantScopedSqlRepository,
)
from .credentials import (
    SqlAlchemyApiKeyRepository,
    SqlAlchemyOAuthClientRepository,
    SqlAlchemyUserCredentialRepository,
)
from .identity import (
    SqlAlchemyMembershipRepository,
    SqlAlchemyOrganizationRepository,
    SqlAlchemyUserRepository,
)

__all__ = [
    "MAX_PAGE_SIZE",
    "SqlAlchemyRepository",
    "PlatformScopedSqlRepository",
    "TenantScopedSqlRepository",
    "AppendOnlySqlRepository",
    "SqlAlchemyTenantRepository",
    "SqlAlchemyUserRepository",
    "SqlAlchemyOrganizationRepository",
    "SqlAlchemyMembershipRepository",
    "SqlAlchemyPermissionRepository",
    "SqlAlchemyRoleRepository",
    "SqlAlchemyRoleAssignmentRepository",
    "SqlAlchemyUserCredentialRepository",
    "SqlAlchemyApiKeyRepository",
    "SqlAlchemyOAuthClientRepository",
    "SqlAlchemySessionRepository",
    "SqlAlchemyRefreshTokenRepository",
    "SqlAlchemyAuditEventRepository",
]
