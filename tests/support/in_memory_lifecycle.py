"""In-memory transaction runner and repositories for lifecycle tests."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

from eiams.application.ports.repository import TransactionRunnerPort, UnitOfWorkPort
from eiams.domain.administration.contracts import Tenant
from eiams.domain.identity.contracts import Organization, OrganizationId
from eiams.shared.context import RequestContext, require_actor, require_tenant_scope
from eiams.shared.errors import DuplicateEntityError, EntityNotFoundError
from eiams.shared.kernel import TenantId


class InMemoryTenantRepository:
    """Minimal platform-scoped tenant repository for tests."""

    def __init__(self) -> None:
        self._items: dict[str, Tenant] = {}

    def find_by_id(self, context: RequestContext, entity_id: TenantId) -> Tenant | None:
        require_actor(context)
        return self._items.get(str(entity_id))

    def find_by_name(self, context: RequestContext, name: str) -> Tenant | None:
        require_actor(context)
        for tenant in self._items.values():
            if tenant.name == name:
                return tenant
        return None

    def find_by_slug(self, context: RequestContext, slug: str) -> Tenant | None:
        require_actor(context)
        for tenant in self._items.values():
            if tenant.slug == slug:
                return tenant
        return None

    def find_active(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[Tenant]:
        require_actor(context)
        active = [t for t in self._items.values() if t.is_active]
        return active[offset : offset + limit]

    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[Tenant]:
        require_actor(context)
        values = list(self._items.values())
        return values[offset : offset + limit]

    def count(self, context: RequestContext) -> int:
        require_actor(context)
        return len(self._items)

    def exists(self, context: RequestContext, entity_id: TenantId) -> bool:
        return self.find_by_id(context, entity_id) is not None

    def add(self, context: RequestContext, entity: Tenant) -> Tenant:
        require_actor(context)
        key = str(entity.tenant_id)
        if key in self._items:
            raise DuplicateEntityError("Tenant already exists", entity="tenant")
        if self.find_by_name(context, entity.name) is not None:
            raise DuplicateEntityError(
                "Tenant already exists",
                entity="tenant",
                conflicting_fields=("name",),
            )
        if entity.slug and self.find_by_slug(context, entity.slug) is not None:
            raise DuplicateEntityError(
                "Tenant already exists",
                entity="tenant",
                conflicting_fields=("slug",),
            )
        self._items[key] = entity
        return entity

    def update(self, context: RequestContext, entity: Tenant) -> Tenant:
        require_actor(context)
        key = str(entity.tenant_id)
        if key not in self._items:
            raise EntityNotFoundError(
                "Tenant not found", entity="tenant", entity_id=key
            )
        self._items[key] = entity
        return entity

    def save(self, context: RequestContext, entity: Tenant) -> Tenant:
        if self.exists(context, entity.tenant_id):
            return self.update(context, entity)
        return self.add(context, entity)

    def delete(self, context: RequestContext, entity_id: TenantId) -> bool:
        require_actor(context)
        return self._items.pop(str(entity_id), None) is not None


class InMemoryOrganizationRepository:
    """Minimal tenant-scoped organization repository for tests."""

    def __init__(self) -> None:
        self._items: dict[str, Organization] = {}

    def _visible(
        self, context: RequestContext, organization: Organization
    ) -> bool:
        tenant_id = require_tenant_scope(context, operation="organization.access")
        return str(organization.tenant_id) == str(tenant_id)

    def find_by_id(
        self, context: RequestContext, entity_id: OrganizationId
    ) -> Organization | None:
        organization = self._items.get(str(entity_id))
        if organization is None or not self._visible(context, organization):
            return None
        return organization

    def find_by_name(
        self, context: RequestContext, name: str
    ) -> Organization | None:
        tenant_id = require_tenant_scope(context, operation="organization.find_by_name")
        for organization in self._items.values():
            if (
                str(organization.tenant_id) == str(tenant_id)
                and organization.name == name
            ):
                return organization
        return None

    def find_children(
        self, context: RequestContext, parent_id: OrganizationId
    ) -> list[Organization]:
        tenant_id = require_tenant_scope(context, operation="organization.find_children")
        return [
            organization
            for organization in self._items.values()
            if str(organization.tenant_id) == str(tenant_id)
            and organization.parent_id == parent_id
        ]

    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[Organization]:
        tenant_id = require_tenant_scope(context, operation="organization.find_all")
        values = [
            organization
            for organization in self._items.values()
            if str(organization.tenant_id) == str(tenant_id)
        ]
        return values[offset : offset + limit]

    def count(self, context: RequestContext) -> int:
        return len(self.find_all(context, offset=0, limit=10_000))

    def exists(self, context: RequestContext, entity_id: OrganizationId) -> bool:
        return self.find_by_id(context, entity_id) is not None

    def add(self, context: RequestContext, entity: Organization) -> Organization:
        tenant_id = require_tenant_scope(context, operation="organization.add")
        if str(entity.tenant_id) != str(tenant_id):
            raise EntityNotFoundError(
                "Organization not found",
                entity="organization",
                entity_id=str(entity.organization_id),
            )
        key = str(entity.organization_id)
        if key in self._items:
            raise DuplicateEntityError(
                "Organization already exists", entity="organization"
            )
        if self.find_by_name(context, entity.name) is not None:
            raise DuplicateEntityError(
                "Organization already exists",
                entity="organization",
                conflicting_fields=("name",),
            )
        self._items[key] = entity
        return entity

    def update(self, context: RequestContext, entity: Organization) -> Organization:
        existing = self.find_by_id(context, entity.organization_id)
        if existing is None:
            raise EntityNotFoundError(
                "Organization not found",
                entity="organization",
                entity_id=str(entity.organization_id),
            )
        self._items[str(entity.organization_id)] = entity
        return entity

    def save(self, context: RequestContext, entity: Organization) -> Organization:
        if self.exists(context, entity.organization_id):
            return self.update(context, entity)
        return self.add(context, entity)

    def delete(self, context: RequestContext, entity_id: OrganizationId) -> bool:
        existing = self.find_by_id(context, entity_id)
        if existing is None:
            return False
        del self._items[str(entity_id)]
        return True


@dataclass
class InMemoryUnitOfWork:
    """Duck-typed unit of work exposing lifecycle repositories."""

    tenants: InMemoryTenantRepository
    organizations: InMemoryOrganizationRepository
    context: RequestContext
    _flushed: bool = field(default=False)

    def flush(self) -> None:
        self._flushed = True


class InMemoryTransactionRunner(TransactionRunnerPort):
    """Transaction runner that yields a shared in-memory unit of work."""

    def __init__(
        self,
        tenants: InMemoryTenantRepository | None = None,
        organizations: InMemoryOrganizationRepository | None = None,
    ) -> None:
        self.tenants = tenants or InMemoryTenantRepository()
        self.organizations = organizations or InMemoryOrganizationRepository()

    @contextmanager
    def unit_of_work(
        self, context: RequestContext
    ) -> Iterator[UnitOfWorkPort]:
        yield InMemoryUnitOfWork(  # type: ignore[misc]
            tenants=self.tenants,
            organizations=self.organizations,
            context=context,
        )

    def run(self, context: RequestContext, work):
        with self.unit_of_work(context) as uow:
            return work(uow)
