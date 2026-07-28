"""Platform-scoped repository for the tenant registry."""

from eiams.domain.administration.contracts import Tenant, TenantRepository
from eiams.infrastructure.persistence.models import tenant as tenant_models
from eiams.shared.context import RequestContext
from eiams.shared.kernel import TenantId

from ..mappers import TenantMapper
from .base import PlatformScopedSqlRepository


class SqlAlchemyTenantRepository(
    PlatformScopedSqlRepository[Tenant, TenantId, tenant_models.Tenant],
    TenantRepository,
):
    """Tenant registry access.

    Tenants are the isolation boundary rather than something inside it, so
    this repository is platform scoped and binds no tenant predicate. It
    still refuses anonymous callers.
    """

    __model__ = tenant_models.Tenant
    __mapper__ = TenantMapper()
    __entity_name__ = "tenant"

    def find_by_name(self, context: RequestContext, name: str) -> Tenant | None:
        statement = self._platform_select(context).where(
            tenant_models.Tenant.name == name
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)

    def find_by_slug(self, context: RequestContext, slug: str) -> Tenant | None:
        statement = self._platform_select(context).where(
            tenant_models.Tenant.slug == slug
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)

    def find_active(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[Tenant]:
        statement = self._platform_select(context).where(
            tenant_models.Tenant.status == tenant_models.TenantStatus.ACTIVE
        )
        return self._entities(
            self._rows(self._paginated(self._ordered(statement), offset, limit))
        )
