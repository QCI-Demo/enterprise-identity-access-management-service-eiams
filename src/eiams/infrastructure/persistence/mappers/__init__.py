"""Mappers between persistent rows and domain entities.

Repositories return domain entities built by these mappers, never ORM rows,
so no caller can reach the session or mutate persistent state directly.
"""

from .administration import TenantMapper
from .audit import AuditEventMapper
from .authentication import RefreshTokenMapper, SessionMapper
from .authorization import (
    DEFAULT_SCOPE_TYPE,
    PermissionMapper,
    RoleAssignmentMapper,
    RoleMapper,
)
from .base import EntityMapper
from .credentials import ApiKeyMapper, OAuthClientMapper, UserCredentialMapper
from .identity import MembershipMapper, OrganizationMapper, UserMapper

__all__ = [
    "EntityMapper",
    "DEFAULT_SCOPE_TYPE",
    "TenantMapper",
    "UserMapper",
    "OrganizationMapper",
    "MembershipMapper",
    "PermissionMapper",
    "RoleMapper",
    "RoleAssignmentMapper",
    "UserCredentialMapper",
    "ApiKeyMapper",
    "OAuthClientMapper",
    "SessionMapper",
    "RefreshTokenMapper",
    "AuditEventMapper",
]
