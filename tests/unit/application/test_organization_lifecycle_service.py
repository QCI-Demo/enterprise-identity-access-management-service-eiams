"""Unit tests for organization lifecycle application service."""

import pytest

from eiams.application.administration import TenantLifecycleService
from eiams.application.dto import (
    CreateOrganizationCommand,
    CreateTenantCommand,
    UpdateOrganizationCommand,
    UpdateTenantCommand,
)
from eiams.application.identity import OrganizationLifecycleService
from eiams.domain.identity.contracts import OrganizationId, OrganizationStatus
from eiams.shared.context import RequestContextFactory
from eiams.shared.errors import (
    DomainError,
    DuplicateEntityError,
    EntityNotFoundError,
    PermissionDeniedError,
)
from eiams.shared.kernel import ActorId, TenantId
from tests.support.in_memory_lifecycle import InMemoryTransactionRunner


def platform_context(**kwargs):
    return RequestContextFactory.create(
        actor_id=kwargs.pop("actor_id", ActorId.generate()),
        actor_type="user",
        roles=kwargs.pop("roles", ["platform_admin"]),
        **kwargs,
    )


def tenant_context(tenant_id: str | TenantId, **kwargs):
    return RequestContextFactory.create(
        actor_id=kwargs.pop("actor_id", ActorId.generate()),
        actor_type="user",
        tenant_id=tenant_id,
        roles=kwargs.pop("roles", ["tenant_admin"]),
        **kwargs,
    )


@pytest.fixture
def runner() -> InMemoryTransactionRunner:
    return InMemoryTransactionRunner()


@pytest.fixture
def services(runner: InMemoryTransactionRunner):
    return (
        TenantLifecycleService(runner),
        OrganizationLifecycleService(runner),
        runner,
    )


def _active_tenant(tenant_service: TenantLifecycleService) -> str:
    context = platform_context()
    created = tenant_service.create(
        context,
        CreateTenantCommand.from_dict(
            {"name": "acme", "display_name": "Acme", "slug": "acme"}
        ),
    )
    tenant_service.update(
        context,
        created.tenant_id,
        UpdateTenantCommand.from_dict({"status": "active"}),
    )
    return created.tenant_id


class TestOrganizationLifecycleService:
    def test_create_retrieve_update(self, services) -> None:
        tenant_service, org_service, _ = services
        tenant_id = _active_tenant(tenant_service)
        context = tenant_context(tenant_id)

        created = org_service.create(
            context,
            CreateOrganizationCommand.from_dict(
                {"name": "Engineering", "slug": "engineering"}
            ),
        )
        assert created.status == OrganizationStatus.ACTIVE.value
        assert created.tenant_id == tenant_id

        fetched = org_service.get(context, created.organization_id)
        assert fetched.name == "Engineering"

        updated = org_service.update(
            context,
            created.organization_id,
            UpdateOrganizationCommand.from_dict({"description": "Eng"}),
        )
        assert updated.description == "Eng"

    def test_duplicate_name_conflict(self, services) -> None:
        tenant_service, org_service, _ = services
        tenant_id = _active_tenant(tenant_service)
        context = tenant_context(tenant_id)
        org_service.create(
            context,
            CreateOrganizationCommand.from_dict({"name": "Engineering"}),
        )
        with pytest.raises(DuplicateEntityError):
            org_service.create(
                context,
                CreateOrganizationCommand.from_dict({"name": "Engineering"}),
            )

    def test_cross_tenant_id_is_not_found(self, services) -> None:
        tenant_service, org_service, runner = services
        tenant_a = _active_tenant(tenant_service)
        # Second tenant
        platform = platform_context()
        other = tenant_service.create(
            platform,
            CreateTenantCommand.from_dict(
                {"name": "other", "display_name": "Other", "slug": "other"}
            ),
        )
        tenant_service.update(
            platform,
            other.tenant_id,
            UpdateTenantCommand.from_dict({"status": "active"}),
        )

        created = org_service.create(
            tenant_context(tenant_a),
            CreateOrganizationCommand.from_dict({"name": "Engineering"}),
        )
        with pytest.raises(EntityNotFoundError):
            org_service.get(tenant_context(other.tenant_id), created.organization_id)

    def test_inactive_parent_tenant_rejected(self, services) -> None:
        tenant_service, org_service, _ = services
        platform = platform_context()
        created = tenant_service.create(
            platform,
            CreateTenantCommand.from_dict(
                {"name": "pending", "display_name": "Pending", "slug": "pending"}
            ),
        )
        with pytest.raises(DomainError) as exc_info:
            org_service.create(
                tenant_context(created.tenant_id),
                CreateOrganizationCommand.from_dict({"name": "Engineering"}),
            )
        assert exc_info.value.code.value == "RESOURCE_CONFLICT"

    def test_deactivate_then_not_found(self, services) -> None:
        tenant_service, org_service, _ = services
        tenant_id = _active_tenant(tenant_service)
        context = tenant_context(tenant_id)
        created = org_service.create(
            context,
            CreateOrganizationCommand.from_dict({"name": "Engineering"}),
        )
        deactivated = org_service.deactivate(context, created.organization_id)
        assert deactivated.status == OrganizationStatus.INACTIVE.value
        with pytest.raises(EntityNotFoundError):
            org_service.get(context, created.organization_id)

    def test_requires_organization_admin_role(self, services) -> None:
        tenant_service, org_service, _ = services
        tenant_id = _active_tenant(tenant_service)
        context = tenant_context(tenant_id, roles=["viewer"])
        with pytest.raises(PermissionDeniedError):
            org_service.create(
                context,
                CreateOrganizationCommand.from_dict({"name": "Engineering"}),
            )

    def test_missing_organization_not_found(self, services) -> None:
        tenant_service, org_service, _ = services
        tenant_id = _active_tenant(tenant_service)
        with pytest.raises(EntityNotFoundError):
            org_service.get(tenant_context(tenant_id), OrganizationId.generate())
