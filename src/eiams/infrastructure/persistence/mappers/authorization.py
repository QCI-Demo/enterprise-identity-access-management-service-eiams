"""Mapping for the authorization entity group."""

from eiams.domain.authorization.contracts import (
    Permission,
    PermissionId,
    Role,
    RoleAssignment,
    RoleAssignmentId,
    RoleId,
)
from eiams.domain.identity.contracts import UserId
from eiams.infrastructure.persistence.models import (
    authorization as authorization_models,
)
from eiams.shared.kernel import TenantId

from .base import (
    EntityMapper,
    from_timestamp,
    identifier,
    optional_identifier,
    require_timestamp,
    to_timestamp,
)


#: Scope kind assumed when an assignment names a scope but not its kind.
DEFAULT_SCOPE_TYPE = "organization"


class PermissionMapper(EntityMapper[Permission, authorization_models.Permission]):
    """Maps permission rows to and from the permission entity."""

    entity_name = "permission"

    def to_entity(self, row: authorization_models.Permission) -> Permission:
        return Permission(
            permission_id=PermissionId(row.id),
            tenant_id=TenantId(row.tenant_id) if row.tenant_id else None,
            name=row.name,
            description=row.description,
            resource_type=row.resource_type,
            action=row.action,
            created_at=require_timestamp(row.created_at),
            is_system_permission=row.is_system,
        )

    def to_model(self, entity: Permission) -> authorization_models.Permission:
        row = authorization_models.Permission(
            id=identifier(entity.permission_id),
            tenant_id=optional_identifier(entity.tenant_id),
            name=entity.name,
            description=entity.description,
            resource_type=entity.resource_type,
            action=entity.action,
            is_system=entity.is_system_permission,
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
        return row

    def apply(
        self, entity: Permission, row: authorization_models.Permission
    ) -> None:
        row.name = entity.name
        row.description = entity.description
        row.resource_type = entity.resource_type
        row.action = entity.action


class RoleMapper(EntityMapper[Role, authorization_models.Role]):
    """Maps role rows to and from the role entity.

    The permissions of a role live in a join table. They are read here and
    written by the repository, which has the session needed to reconcile the
    join rows and to check that each permission is in the caller's scope.
    """

    entity_name = "role"

    def to_entity(self, row: authorization_models.Role) -> Role:
        return Role(
            role_id=RoleId(row.id),
            tenant_id=TenantId(row.tenant_id) if row.tenant_id else None,
            name=row.name,
            description=row.description,
            permissions=tuple(
                PermissionId(link.permission_id) for link in row.role_permissions
            ),
            is_system_role=row.is_system,
            created_at=require_timestamp(row.created_at),
            updated_at=require_timestamp(row.updated_at),
        )

    def to_model(self, entity: Role) -> authorization_models.Role:
        row = authorization_models.Role(
            id=identifier(entity.role_id),
            tenant_id=optional_identifier(entity.tenant_id),
            name=entity.name,
            description=entity.description,
            is_system=entity.is_system_role,
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
            row.updated_at = from_timestamp(entity.updated_at or entity.created_at)
        return row

    def apply(self, entity: Role, row: authorization_models.Role) -> None:
        row.name = entity.name
        row.description = entity.description


class RoleAssignmentMapper(
    EntityMapper[RoleAssignment, authorization_models.RoleAssignment]
):
    """Maps role assignment rows to and from the assignment entity."""

    entity_name = "role assignment"

    def to_entity(
        self, row: authorization_models.RoleAssignment
    ) -> RoleAssignment:
        return RoleAssignment(
            assignment_id=RoleAssignmentId(row.id),
            tenant_id=TenantId(row.tenant_id),
            user_id=UserId(row.user_id),
            role_id=RoleId(row.role_id),
            scope=row.scope_id,
            created_at=require_timestamp(row.created_at),
            expires_at=to_timestamp(row.expires_at),
            scope_type=row.scope_type,
            revoked_at=to_timestamp(row.revoked_at),
        )

    def to_model(
        self, entity: RoleAssignment
    ) -> authorization_models.RoleAssignment:
        scope_type, scope_id = self._scope(entity)
        row = authorization_models.RoleAssignment(
            id=identifier(entity.assignment_id),
            tenant_id=identifier(entity.tenant_id),
            user_id=identifier(entity.user_id),
            role_id=identifier(entity.role_id),
            scope_type=scope_type,
            scope_id=scope_id,
            expires_at=from_timestamp(entity.expires_at),
            revoked_at=from_timestamp(entity.revoked_at),
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
        return row

    def apply(
        self, entity: RoleAssignment, row: authorization_models.RoleAssignment
    ) -> None:
        scope_type, scope_id = self._scope(entity)
        row.scope_type = scope_type
        row.scope_id = scope_id
        row.expires_at = from_timestamp(entity.expires_at)
        row.revoked_at = from_timestamp(entity.revoked_at)

    @staticmethod
    def _scope(entity: RoleAssignment) -> tuple[str | None, str | None]:
        """Resolve the scope pair, which the schema requires to be complete."""
        if entity.scope is None:
            return None, None
        return entity.scope_type or DEFAULT_SCOPE_TYPE, entity.scope
