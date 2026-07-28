"""Mapping for the tenant registry."""

from eiams.domain.administration.contracts import Tenant, TenantStatus
from eiams.infrastructure.persistence.models import tenant as tenant_models
from eiams.shared.errors import ValidationError
from eiams.shared.kernel import TenantId

from .base import (
    EntityMapper,
    from_timestamp,
    identifier,
    require_timestamp,
    slugify,
)


class TenantMapper(EntityMapper[Tenant, tenant_models.Tenant]):
    """Maps tenant registry rows to and from the tenant entity."""

    entity_name = "tenant"

    def to_entity(self, row: tenant_models.Tenant) -> Tenant:
        return Tenant(
            tenant_id=TenantId(row.id),
            name=row.name,
            display_name=row.display_name or row.name,
            status=TenantStatus(row.status.value),
            settings={},
            created_at=require_timestamp(row.created_at),
            updated_at=require_timestamp(row.updated_at),
            slug=row.slug,
            description=row.description,
        )

    def to_model(self, entity: Tenant) -> tenant_models.Tenant:
        self._reject_unsupported_settings(entity)
        row = tenant_models.Tenant(
            id=identifier(entity.tenant_id),
            name=entity.name,
            slug=entity.slug or slugify(entity.name, fallback=str(entity.tenant_id)),
            display_name=entity.display_name,
            description=entity.description,
            status=tenant_models.TenantStatus(entity.status.value),
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
            row.updated_at = from_timestamp(entity.updated_at or entity.created_at)
        return row

    def apply(self, entity: Tenant, row: tenant_models.Tenant) -> None:
        self._reject_unsupported_settings(entity)
        row.name = entity.name
        row.display_name = entity.display_name
        row.description = entity.description
        row.status = tenant_models.TenantStatus(entity.status.value)
        if entity.slug:
            row.slug = entity.slug

    @staticmethod
    def _reject_unsupported_settings(entity: Tenant) -> None:
        """Refuse writes carrying settings the approved schema cannot store.

        Accepting them would drop the caller's data without any signal, so
        the write is rejected instead. A later schema epic owns adding a
        durable home for tenant settings.
        """
        if entity.settings:
            raise ValidationError(
                "Tenant settings are not persisted by the current schema",
                field="settings",
            )
