"""Tenant-scoped repositories for the authorization entity group.

Roles and permissions have a platform-shared partition: rows with no tenant
owner form the system catalogue every tenant can read. Reads therefore run
with a predicate that admits shared rows, while writes run with the strict
variant so a tenant can never create or modify a system record.
"""

from datetime import datetime, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import selectinload

from eiams.domain.authorization.contracts import (
    Permission,
    PermissionId,
    PermissionRepository,
    Role,
    RoleAssignment,
    RoleAssignmentId,
    RoleAssignmentRepository,
    RoleId,
    RoleRepository,
)
from eiams.domain.identity.contracts import UserId
from eiams.infrastructure.persistence.models import (
    authorization as authorization_models,
)
from eiams.shared.context import RequestContext
from eiams.shared.errors import EntityNotFoundError

from ..mappers import PermissionMapper, RoleAssignmentMapper, RoleMapper
from ..mappers.base import identifier
from .base import TenantScopedSqlRepository


class SqlAlchemyPermissionRepository(
    TenantScopedSqlRepository[
        Permission, PermissionId, authorization_models.Permission
    ],
    PermissionRepository,
):
    """Permissions of one tenant plus the shared system catalogue."""

    __model__ = authorization_models.Permission
    __mapper__ = PermissionMapper()
    __entity_name__ = "permission"
    __shared_rows__ = True

    def find_by_key(
        self, context: RequestContext, resource_type: str, action: str
    ) -> Permission | None:
        statement = (
            self._scoped_select(context)
            .where(authorization_models.Permission.resource_type == resource_type)
            .where(authorization_models.Permission.action == action)
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)

    def find_by_resource_type(
        self, context: RequestContext, resource_type: str
    ) -> list[Permission]:
        statement = self._scoped_select(context).where(
            authorization_models.Permission.resource_type == resource_type
        )
        return self._entities(self._rows(self._ordered(statement)))


class SqlAlchemyRoleRepository(
    TenantScopedSqlRepository[Role, RoleId, authorization_models.Role],
    RoleRepository,
):
    """Roles of one tenant plus the shared system catalogue.

    A role owns the set of permissions granted through it. Writes reconcile
    the join rows and reject permissions that are outside the caller's
    scope, so a role cannot be used to reach another tenant's permissions.
    """

    __model__ = authorization_models.Role
    __mapper__ = RoleMapper()
    __entity_name__ = "role"
    __shared_rows__ = True
    __load_options__ = (selectinload(authorization_models.Role.role_permissions),)

    def find_by_name(self, context: RequestContext, name: str) -> Role | None:
        statement = self._scoped_select(context).where(
            authorization_models.Role.name == name
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)

    def find_system_roles(self, context: RequestContext) -> list[Role]:
        statement = self._scoped_select(context).where(
            authorization_models.Role.tenant_id.is_(None)
        )
        return self._entities(self._rows(self._ordered(statement)))

    def add(self, context: RequestContext, entity: Role) -> Role:
        super().add(context, entity)
        return self._write_permissions(context, entity)

    def update(self, context: RequestContext, entity: Role) -> Role:
        super().update(context, entity)
        return self._write_permissions(context, entity)

    def save(self, context: RequestContext, entity: Role) -> Role:
        super().save(context, entity)
        return self._write_permissions(context, entity)

    def _write_permissions(self, context: RequestContext, entity: Role) -> Role:
        """Reconcile the role's permission links, then re-read the role."""
        row = self._require_row(context, entity.role_id, for_write=True)
        desired = {identifier(permission) for permission in entity.permissions}
        self._assert_permissions_in_scope(context, desired)

        current = {link.permission_id: link for link in row.role_permissions}
        for permission_id, link in current.items():
            if permission_id not in desired:
                row.role_permissions.remove(link)
                self._session.delete(link)
        for permission_id in desired - set(current):
            row.role_permissions.append(
                authorization_models.RolePermission(
                    role_id=row.id, permission_id=permission_id
                )
            )
        self._flush()
        return self.__mapper__.to_entity(row)

    def _assert_permissions_in_scope(
        self, context: RequestContext, permission_ids: set[str]
    ) -> None:
        """Refuse links to permissions the caller cannot see."""
        if not permission_ids:
            return
        predicate = self.tenant_predicate(context)
        tenant_column = authorization_models.Permission.tenant_id
        statement = (
            select(authorization_models.Permission.id)
            .where(
                or_(
                    tenant_column == predicate.value,
                    tenant_column.is_(None),
                )
            )
            .where(authorization_models.Permission.id.in_(permission_ids))
        )
        visible = set(self._session.execute(statement).scalars().all())
        missing = permission_ids - visible
        if missing:
            raise EntityNotFoundError(
                "One or more permissions are not available in the caller's scope",
                entity="permission",
                entity_id=sorted(missing)[0],
            )


class SqlAlchemyRoleAssignmentRepository(
    TenantScopedSqlRepository[
        RoleAssignment, RoleAssignmentId, authorization_models.RoleAssignment
    ],
    RoleAssignmentRepository,
):
    """Assignments of roles to users within one tenant."""

    __model__ = authorization_models.RoleAssignment
    __mapper__ = RoleAssignmentMapper()
    __entity_name__ = "role assignment"

    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[RoleAssignment]:
        statement = self._scoped_select(context).where(
            authorization_models.RoleAssignment.user_id == identifier(user_id)
        )
        return self._entities(self._rows(self._ordered(statement)))

    def find_by_role(
        self, context: RequestContext, role_id: RoleId
    ) -> list[RoleAssignment]:
        statement = self._scoped_select(context).where(
            authorization_models.RoleAssignment.role_id == identifier(role_id)
        )
        return self._entities(self._rows(self._ordered(statement)))

    def find_active_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[RoleAssignment]:
        now = datetime.now(timezone.utc)
        statement = (
            self._scoped_select(context)
            .where(
                authorization_models.RoleAssignment.user_id == identifier(user_id)
            )
            .where(authorization_models.RoleAssignment.revoked_at.is_(None))
            .where(
                or_(
                    authorization_models.RoleAssignment.expires_at.is_(None),
                    authorization_models.RoleAssignment.expires_at > now,
                )
            )
        )
        return self._entities(self._rows(self._ordered(statement)))
