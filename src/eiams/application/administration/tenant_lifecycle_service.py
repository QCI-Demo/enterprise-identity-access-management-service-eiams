"""Platform-authorized tenant lifecycle command application service."""

from __future__ import annotations

from dataclasses import replace
from typing import Callable

from eiams.application.dto.administration import (
    CreateTenantCommand,
    TenantResponseDTO,
    UpdateTenantCommand,
    tenant_duplicate_conflict_fields,
)
from eiams.application.lifecycle.authorization import (
    require_platform_administration,
)
from eiams.application.lifecycle.slugs import slugify
from eiams.application.lifecycle.transitions import (
    assert_tenant_transition,
    deactivate_tenant_status,
)
from eiams.application.ports.repository import (
    TransactionRunnerPort,
    UnitOfWorkPort,
)
from eiams.application.services.base import ApplicationService
from eiams.domain.administration.contracts import Tenant, TenantStatus
from eiams.shared.context import RequestContext, require_platform_scope
from eiams.shared.errors import (
    DuplicateEntityError,
    EntityNotFoundError,
    ValidationError,
)
from eiams.shared.kernel import TenantId, Timestamp


class TenantLifecycleService(ApplicationService):
    """Create, retrieve, update, and deactivate tenants.

    Tenant creation and mutations are platform-administration protected.
    State changes run inside the foundation transaction runner.
    """

    def __init__(
        self,
        transaction_runner: TransactionRunnerPort,
        *,
        clock: Callable[[], Timestamp] | None = None,
    ) -> None:
        self._runner = transaction_runner
        self._clock = clock or Timestamp.now

    def create(
        self,
        context: RequestContext,
        command: CreateTenantCommand,
    ) -> TenantResponseDTO:
        """Create a tenant in ``pending_setup`` status."""
        require_platform_scope(context, operation="tenant.create")
        require_platform_administration(
            context, resource="tenant", action="create"
        )
        errors = command.validate()
        if errors:
            raise ValidationError(
                "; ".join(errors),
                field="body",
                details={"errors": errors},
            )

        def work(uow: UnitOfWorkPort) -> Tenant:
            name = command.name.strip()
            existing_name = uow.tenants.find_by_name(context, name)
            tenant_id = TenantId.generate()
            slug = (
                command.slug
                or slugify(name, fallback=str(tenant_id))
            ).strip()
            existing_slug = uow.tenants.find_by_slug(context, slug)
            if existing_name is not None or existing_slug is not None:
                raise DuplicateEntityError(
                    "Tenant already exists",
                    entity="tenant",
                    conflicting_fields=tenant_duplicate_conflict_fields(
                        name_conflict=existing_name is not None,
                        slug_conflict=existing_slug is not None,
                    ),
                )

            now = self._clock()
            tenant = Tenant(
                tenant_id=tenant_id,
                name=name,
                display_name=command.display_name.strip(),
                status=TenantStatus.PENDING_SETUP,
                settings={},
                created_at=now,
                updated_at=now,
                slug=slug,
                description=command.description,
            )
            return uow.tenants.add(context, tenant)

        return TenantResponseDTO.from_entity(self._runner.run(context, work))

    def get(
        self,
        context: RequestContext,
        tenant_id: str | TenantId,
    ) -> TenantResponseDTO:
        """Retrieve a tenant by identifier."""
        require_platform_scope(context, operation="tenant.get")
        require_platform_administration(
            context, resource="tenant", action="read"
        )
        entity_id = self._parse_tenant_id(tenant_id)

        def work(uow: UnitOfWorkPort) -> Tenant:
            tenant = uow.tenants.find_by_id(context, entity_id)
            if tenant is None:
                raise EntityNotFoundError(
                    "Tenant not found",
                    entity="tenant",
                    entity_id=str(entity_id),
                )
            return tenant

        return TenantResponseDTO.from_entity(self._runner.run(context, work))

    def update(
        self,
        context: RequestContext,
        tenant_id: str | TenantId,
        command: UpdateTenantCommand,
    ) -> TenantResponseDTO:
        """Update mutable tenant metadata and/or status."""
        require_platform_scope(context, operation="tenant.update")
        require_platform_administration(
            context, resource="tenant", action="update"
        )
        errors = command.validate()
        if errors:
            raise ValidationError(
                "; ".join(errors),
                field="body",
                details={"errors": errors},
            )
        entity_id = self._parse_tenant_id(tenant_id)

        def work(uow: UnitOfWorkPort) -> Tenant:
            tenant = uow.tenants.find_by_id(context, entity_id)
            if tenant is None:
                raise EntityNotFoundError(
                    "Tenant not found",
                    entity="tenant",
                    entity_id=str(entity_id),
                )

            updates: dict[str, object] = {"updated_at": self._clock()}
            if command.display_name is not None:
                updates["display_name"] = command.display_name.strip()
            if command.description is not None:
                updates["description"] = command.description
            if command.status is not None:
                assert_tenant_transition(tenant.status, command.status)
                updates["status"] = command.status

            updated = replace(tenant, **updates)
            return uow.tenants.update(context, updated)

        return TenantResponseDTO.from_entity(self._runner.run(context, work))

    def deactivate(
        self,
        context: RequestContext,
        tenant_id: str | TenantId,
    ) -> TenantResponseDTO:
        """Transition a tenant to inactive status."""
        require_platform_scope(context, operation="tenant.deactivate")
        require_platform_administration(
            context, resource="tenant", action="deactivate"
        )
        entity_id = self._parse_tenant_id(tenant_id)

        def work(uow: UnitOfWorkPort) -> Tenant:
            tenant = uow.tenants.find_by_id(context, entity_id)
            if tenant is None:
                raise EntityNotFoundError(
                    "Tenant not found",
                    entity="tenant",
                    entity_id=str(entity_id),
                )
            target = deactivate_tenant_status(tenant.status)
            updated = replace(
                tenant,
                status=target,
                updated_at=self._clock(),
            )
            return uow.tenants.update(context, updated)

        return TenantResponseDTO.from_entity(self._runner.run(context, work))

    def _parse_tenant_id(self, tenant_id: str | TenantId) -> TenantId:
        if isinstance(tenant_id, TenantId):
            return tenant_id
        try:
            return TenantId(tenant_id)
        except ValidationError as exc:
            raise EntityNotFoundError(
                "Tenant not found",
                entity="tenant",
                entity_id=str(tenant_id),
            ) from exc
