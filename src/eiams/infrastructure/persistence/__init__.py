"""Infrastructure persistence adapters.

Repository implementations and database access patterns.
"""

from eiams.infrastructure.persistence.database import (
    Base,
    DatabaseConfig,
    DatabaseManager,
    NAMING_CONVENTION,
)
from eiams.infrastructure.persistence.errors import (
    translate_database_error,
    translate_integrity_error,
    translate_transaction_error,
)
from eiams.infrastructure.persistence.repositories import (
    MAX_PAGE_SIZE,
    AppendOnlySqlRepository,
    PlatformScopedSqlRepository,
    SqlAlchemyApiKeyRepository,
    SqlAlchemyAuditEventRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyOAuthClientRepository,
    SqlAlchemyOrganizationRepository,
    SqlAlchemyPermissionRepository,
    SqlAlchemyRefreshTokenRepository,
    SqlAlchemyRepository,
    SqlAlchemyRoleAssignmentRepository,
    SqlAlchemyRoleRepository,
    SqlAlchemySessionRepository,
    SqlAlchemyTenantRepository,
    SqlAlchemyUserCredentialRepository,
    SqlAlchemyUserRepository,
    TenantScopedSqlRepository,
)
from eiams.infrastructure.persistence.transaction import (
    SqlAlchemyTransactionRunner,
    SqlAlchemyUnitOfWork,
)

__all__ = [
    "Base",
    "DatabaseConfig",
    "DatabaseManager",
    "NAMING_CONVENTION",
    "MAX_PAGE_SIZE",
    "translate_database_error",
    "translate_integrity_error",
    "translate_transaction_error",
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
    "SqlAlchemyTransactionRunner",
    "SqlAlchemyUnitOfWork",
]
