"""Unit tests for tenant lifecycle application service."""

import pytest

from eiams.application.administration import TenantLifecycleService
from eiams.application.dto import CreateTenantCommand, UpdateTenantCommand
from eiams.application.lifecycle import InvalidStatusTransitionError
from eiams.domain.administration.contracts import TenantStatus
from eiams.shared.context import RequestContextFactory
from eiams.shared.errors import (
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


@pytest.fixture
def runner() -> InMemoryTransactionRunner:
    return InMemoryTransactionRunner()


@pytest.fixture
def service(runner: InMemoryTransactionRunner) -> TenantLifecycleService:
    return TenantLifecycleService(runner)


class TestTenantLifecycleService:
    def test_create_returns_safe_pending_setup_payload(self, service) -> None:
        context = platform_context()
        result = service.create(
            context,
            CreateTenantCommand.from_dict(
                {"name": "acme.co", "display_name": "Acme", "slug": "acme"}
            ),
        )
        payload = result.to_dict()
        assert payload["status"] == TenantStatus.PENDING_SETUP.value
        assert payload["name"] == "acme.co"
        assert "settings" not in payload

    def test_create_requires_platform_admin(self, service) -> None:
        context = platform_context(roles=["tenant_admin"])
        with pytest.raises(PermissionDeniedError):
            service.create(
                context,
                CreateTenantCommand.from_dict(
                    {"name": "acme", "display_name": "Acme"}
                ),
            )

    def test_create_duplicate_name_conflicts(self, service) -> None:
        context = platform_context()
        command = CreateTenantCommand.from_dict(
            {"name": "acme", "display_name": "Acme", "slug": "acme"}
        )
        service.create(context, command)
        with pytest.raises(DuplicateEntityError):
            service.create(
                context,
                CreateTenantCommand.from_dict(
                    {"name": "acme", "display_name": "Acme 2", "slug": "acme-2"}
                ),
            )

    def test_get_and_update_status_transition(self, service) -> None:
        context = platform_context()
        created = service.create(
            context,
            CreateTenantCommand.from_dict(
                {"name": "acme", "display_name": "Acme", "slug": "acme"}
            ),
        )
        updated = service.update(
            context,
            created.tenant_id,
            UpdateTenantCommand.from_dict({"status": "active"}),
        )
        assert updated.status == TenantStatus.ACTIVE.value
        fetched = service.get(context, created.tenant_id)
        assert fetched.status == TenantStatus.ACTIVE.value

    def test_illegal_status_transition_rejected(self, service) -> None:
        context = platform_context()
        created = service.create(
            context,
            CreateTenantCommand.from_dict(
                {"name": "acme", "display_name": "Acme", "slug": "acme"}
            ),
        )
        with pytest.raises(InvalidStatusTransitionError):
            service.update(
                context,
                created.tenant_id,
                UpdateTenantCommand.from_dict({"status": "suspended"}),
            )

    def test_deactivate_sets_inactive(self, service) -> None:
        context = platform_context()
        created = service.create(
            context,
            CreateTenantCommand.from_dict(
                {"name": "acme", "display_name": "Acme", "slug": "acme"}
            ),
        )
        service.update(
            context,
            created.tenant_id,
            UpdateTenantCommand.from_dict({"status": "active"}),
        )
        deactivated = service.deactivate(context, created.tenant_id)
        assert deactivated.status == TenantStatus.INACTIVE.value

    def test_get_missing_tenant_not_found(self, service) -> None:
        context = platform_context()
        with pytest.raises(EntityNotFoundError):
            service.get(context, TenantId.generate())

    def test_safe_response_omits_disallowed_fields(self, service) -> None:
        context = platform_context()
        result = service.create(
            context,
            CreateTenantCommand.from_dict(
                {"name": "safe", "display_name": "Safe"}
            ),
        )
        serialized = result.to_dict()
        for forbidden in ("settings", "password", "secret", "hash", "row_id"):
            assert forbidden not in serialized
