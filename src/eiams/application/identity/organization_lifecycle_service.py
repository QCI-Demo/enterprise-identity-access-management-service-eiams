"""Tenant-owned organization lifecycle command application service."""

from __future__ import annotations

from dataclasses import replace
from typing import Callable

from eiams.application.dto.identity import (
    CreateOrganizationCommand,
    OrganizationResponseDTO,
    UpdateOrganizationCommand,
    organization_duplicate_conflict_fields,
)
from eiams.application.lifecycle.authorization import (
    require_tenant_organization_administration,
)
from eiams.application.lifecycle.slugs import slugify
from eiams.application.lifecycle.transitions import deactivate_organization_status
from eiams.application.ports.repository import (
    TransactionRunnerPort,
    UnitOfWorkPort,
)
from eiams.application.services.base import ApplicationService
from eiams.domain.administration.contracts import TenantStatus
from eiams.domain.identity.contracts import (
    Organization,
    OrganizationId,
    OrganizationStatus,
)
from eiams.shared.context import RequestContext, require_tenant_scope
from eiams.shared.errors import (
    DomainError,
    DuplicateEntityError,
    EntityNotFoundError,
    ErrorCode,
    ValidationError,
)
from eiams.shared.kernel import Timestamp


class OrganizationLifecycleService(ApplicationService):
    """Create, retrieve, update, and deactivate tenant-owned organizations.

    All repository access uses the caller's validated tenant context before
    lookup or mutation. Inactive parent tenants and cross-tenant identifiers
    are rejected with secure standard errors.
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
        command: CreateOrganizationCommand,
    ) -> OrganizationResponseDTO:
        """Create an organization in the caller's tenant."""
        tenant_id = require_tenant_scope(context, operation="organization.create")
        require_tenant_organization_administration(
            context, resource="organization", action="create"
        )
        errors = command.validate()
        if errors:
            raise ValidationError(
                "; ".join(errors),
                field="body",
                details={"errors": errors},
            )

        def work(uow: UnitOfWorkPort) -> Organization:
            self._require_active_parent_tenant(uow, context)
            name = command.name.strip()
            existing_name = uow.organizations.find_by_name(context, name)
            organization_id = OrganizationId.generate()
            slug = (
                command.slug
                or slugify(name, fallback=str(organization_id))
            ).strip()
            # Slug uniqueness is enforced by the schema; pre-check by scanning
            # the tenant page for an exact slug match when available.
            slug_conflict = self._slug_exists(uow, context, slug)
            if existing_name is not None or slug_conflict:
                raise DuplicateEntityError(
                    "Organization already exists",
                    entity="organization",
                    conflicting_fields=organization_duplicate_conflict_fields(
                        name_conflict=existing_name is not None,
                        slug_conflict=slug_conflict,
                    ),
                )

            parent_id = None
            if command.parent_id is not None:
                parent_id = self._require_parent_organization(
                    uow, context, command.parent_id
                )

            now = self._clock()
            organization = Organization(
                organization_id=organization_id,
                tenant_id=tenant_id,
                name=name,
                description=command.description,
                parent_id=parent_id,
                created_at=now,
                updated_at=now,
                slug=slug,
                status=OrganizationStatus.ACTIVE,
            )
            return uow.organizations.add(context, organization)

        return OrganizationResponseDTO.from_entity(
            self._runner.run(context, work)
        )

    def get(
        self,
        context: RequestContext,
        organization_id: str | OrganizationId,
    ) -> OrganizationResponseDTO:
        """Retrieve an organization through tenant-predicated lookup."""
        require_tenant_scope(context, operation="organization.get")
        require_tenant_organization_administration(
            context, resource="organization", action="read"
        )
        entity_id = self._parse_organization_id(organization_id)

        def work(uow: UnitOfWorkPort) -> Organization:
            organization = uow.organizations.find_by_id(context, entity_id)
            if organization is None:
                raise EntityNotFoundError(
                    "Organization not found",
                    entity="organization",
                    entity_id=str(entity_id),
                )
            return organization

        return OrganizationResponseDTO.from_entity(
            self._runner.run(context, work)
        )

    def update(
        self,
        context: RequestContext,
        organization_id: str | OrganizationId,
        command: UpdateOrganizationCommand,
    ) -> OrganizationResponseDTO:
        """Update mutable organization metadata within the tenant."""
        require_tenant_scope(context, operation="organization.update")
        require_tenant_organization_administration(
            context, resource="organization", action="update"
        )
        errors = command.validate()
        if errors:
            raise ValidationError(
                "; ".join(errors),
                field="body",
                details={"errors": errors},
            )
        entity_id = self._parse_organization_id(organization_id)

        def work(uow: UnitOfWorkPort) -> Organization:
            self._require_active_parent_tenant(uow, context)
            organization = uow.organizations.find_by_id(context, entity_id)
            if organization is None:
                raise EntityNotFoundError(
                    "Organization not found",
                    entity="organization",
                    entity_id=str(entity_id),
                )
            if not organization.is_active:
                raise DomainError(
                    "Cannot update an inactive organization",
                    ErrorCode.RESOURCE_CONFLICT,
                    {"resource_type": "organization", "resource": "organization"},
                )

            updates: dict[str, object] = {"updated_at": self._clock()}
            if command.name is not None:
                name = command.name.strip()
                existing = uow.organizations.find_by_name(context, name)
                if (
                    existing is not None
                    and existing.organization_id != organization.organization_id
                ):
                    raise DuplicateEntityError(
                        "Organization already exists",
                        entity="organization",
                        conflicting_fields=organization_duplicate_conflict_fields(
                            name_conflict=True
                        ),
                    )
                updates["name"] = name
            if command.description is not None:
                updates["description"] = command.description
            if command.clear_parent:
                updates["parent_id"] = None
            elif command.parent_id is not None:
                parent = self._require_parent_organization(
                    uow, context, command.parent_id
                )
                if parent == organization.organization_id:
                    raise ValidationError(
                        "Organization cannot be its own parent",
                        field="parent_id",
                    )
                updates["parent_id"] = parent

            updated = replace(organization, **updates)
            return uow.organizations.update(context, updated)

        return OrganizationResponseDTO.from_entity(
            self._runner.run(context, work)
        )

    def deactivate(
        self,
        context: RequestContext,
        organization_id: str | OrganizationId,
    ) -> OrganizationResponseDTO:
        """Deactivate an organization (terminal active → inactive transition).

        Because the approved schema has no organization status column, the
        inactive transition is realized by deleting the tenant-scoped row
        after validating the lifecycle rule. The response reflects the
        deactivated state.
        """
        require_tenant_scope(context, operation="organization.deactivate")
        require_tenant_organization_administration(
            context, resource="organization", action="deactivate"
        )
        entity_id = self._parse_organization_id(organization_id)

        def work(uow: UnitOfWorkPort) -> Organization:
            self._require_active_parent_tenant(uow, context)
            organization = uow.organizations.find_by_id(context, entity_id)
            if organization is None:
                raise EntityNotFoundError(
                    "Organization not found",
                    entity="organization",
                    entity_id=str(entity_id),
                )
            deactivate_organization_status(organization.status)
            deactivated = replace(
                organization,
                status=OrganizationStatus.INACTIVE,
                updated_at=self._clock(),
            )
            deleted = uow.organizations.delete(context, entity_id)
            if not deleted:
                raise EntityNotFoundError(
                    "Organization not found",
                    entity="organization",
                    entity_id=str(entity_id),
                )
            return deactivated

        return OrganizationResponseDTO.from_entity(
            self._runner.run(context, work)
        )

    def _require_active_parent_tenant(
        self,
        uow: UnitOfWorkPort,
        context: RequestContext,
    ) -> None:
        """Reject mutations when the owning tenant is not active."""
        tenant = uow.tenants.find_by_id(context, context.tenant_id)
        if tenant is None:
            raise EntityNotFoundError(
                "Tenant not found",
                entity="tenant",
                entity_id=str(context.tenant_id),
            )
        if tenant.status != TenantStatus.ACTIVE:
            raise DomainError(
                "Cannot mutate organizations while the parent tenant is inactive",
                ErrorCode.RESOURCE_CONFLICT,
                {
                    "resource_type": "tenant",
                    "resource": "tenant",
                    "status": tenant.status.value,
                },
            )

    def _require_parent_organization(
        self,
        uow: UnitOfWorkPort,
        context: RequestContext,
        parent_id: str,
    ) -> OrganizationId:
        """Resolve a parent organization inside the caller's tenant."""
        parsed = self._parse_organization_id(parent_id)
        parent = uow.organizations.find_by_id(context, parsed)
        if parent is None:
            raise EntityNotFoundError(
                "Parent organization not found",
                entity="organization",
                entity_id=str(parsed),
            )
        return parent.organization_id

    def _slug_exists(
        self,
        uow: UnitOfWorkPort,
        context: RequestContext,
        slug: str,
    ) -> bool:
        """Best-effort slug conflict pre-check within the tenant scope."""
        for organization in uow.organizations.find_all(context, offset=0, limit=1000):
            if organization.slug == slug:
                return True
        return False

    def _parse_organization_id(
        self,
        organization_id: str | OrganizationId,
    ) -> OrganizationId:
        if isinstance(organization_id, OrganizationId):
            return organization_id
        try:
            return OrganizationId(organization_id)
        except ValidationError as exc:
            raise EntityNotFoundError(
                "Organization not found",
                entity="organization",
                entity_id=str(organization_id),
            ) from exc
