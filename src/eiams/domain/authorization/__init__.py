"""Authorization domain module.

Manages role-based access control and permissions, including:
- Role definitions and assignments
- Permission grants and checks
- Policy evaluation hooks
- Resource-level access control
"""

from .contracts import (
    Role,
    RoleId,
    Permission,
    PermissionId,
    RoleAssignment,
    RoleAssignmentId,
    RoleRepository,
    PermissionRepository,
    RoleAssignmentRepository,
    AuthorizationService,
    AuthorizationHook,
    AuthorizationDecision,
    OperationContext,
)

__all__ = [
    "Role",
    "RoleId",
    "Permission",
    "PermissionId",
    "RoleAssignment",
    "RoleAssignmentId",
    "RoleRepository",
    "PermissionRepository",
    "RoleAssignmentRepository",
    "AuthorizationService",
    "AuthorizationHook",
    "AuthorizationDecision",
    "OperationContext",
]
