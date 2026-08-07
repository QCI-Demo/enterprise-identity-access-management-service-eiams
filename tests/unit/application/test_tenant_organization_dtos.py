"""DTO validation tests for tenant and organization command contracts."""

import pytest

from eiams.application.dto import (
    TENANT_RESPONSE_FIELDS,
    ORGANIZATION_RESPONSE_FIELDS,
    CreateOrganizationCommand,
    CreateTenantCommand,
    OrganizationResponseDTO,
    TenantResponseDTO,
    UpdateOrganizationCommand,
    UpdateTenantCommand,
)
from eiams.domain.administration.contracts import Tenant, TenantStatus
from eiams.domain.identity.contracts import (
    Organization,
    OrganizationId,
    OrganizationStatus,
)
from eiams.shared.errors import ValidationError
from eiams.shared.kernel import TenantId, Timestamp


def _tenant(**overrides) -> Tenant:
    now = Timestamp.now()
    values = {
        "tenant_id": TenantId.generate(),
        "name": "acme",
        "display_name": "Acme Corp",
        "status": TenantStatus.PENDING_SETUP,
        "settings": {},
        "created_at": now,
        "updated_at": now,
        "slug": "acme",
        "description": "Example",
    }
    values.update(overrides)
    return Tenant(**values)


def _organization(**overrides) -> Organization:
    now = Timestamp.now()
    values = {
        "organization_id": OrganizationId.generate(),
        "tenant_id": TenantId.generate(),
        "name": "Engineering",
        "description": "Eng org",
        "parent_id": None,
        "created_at": now,
        "updated_at": now,
        "slug": "engineering",
        "status": OrganizationStatus.ACTIVE,
    }
    values.update(overrides)
    return Organization(**values)


class TestCreateTenantCommand:
    def test_accepts_valid_payload(self) -> None:
        command = CreateTenantCommand.from_dict(
            {
                "name": "acme.co",
                "display_name": "Acme",
                "slug": "acme",
                "description": "Customer",
            }
        )
        assert command.name == "acme.co"
        assert command.slug == "acme"

    def test_requires_name_and_display_name(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            CreateTenantCommand.from_dict({"name": "acme"})
        assert "display_name" in str(exc_info.value)

    def test_rejects_short_name(self) -> None:
        with pytest.raises(ValidationError):
            CreateTenantCommand.from_dict(
                {"name": "a", "display_name": "A"}
            )

    def test_rejects_invalid_slug_format(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            CreateTenantCommand.from_dict(
                {
                    "name": "acme",
                    "display_name": "Acme",
                    "slug": "Acme_Slug",
                }
            )
        assert "slug" in str(exc_info.value)

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            CreateTenantCommand.from_dict(
                {
                    "name": "acme",
                    "display_name": "Acme",
                    "settings": {"secret": True},
                }
            )
        assert "Unknown field" in str(exc_info.value)

    def test_rejects_oversized_description(self) -> None:
        with pytest.raises(ValidationError):
            CreateTenantCommand.from_dict(
                {
                    "name": "acme",
                    "display_name": "Acme",
                    "description": "x" * 2001,
                }
            )


class TestUpdateTenantCommand:
    def test_accepts_status_update(self) -> None:
        command = UpdateTenantCommand.from_dict({"status": "active"})
        assert command.status == TenantStatus.ACTIVE

    def test_rejects_immutable_name(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            UpdateTenantCommand.from_dict({"name": "other"})
        assert "immutable" in str(exc_info.value)

    def test_rejects_unknown_field(self) -> None:
        with pytest.raises(ValidationError):
            UpdateTenantCommand.from_dict({"settings": {}})

    def test_rejects_empty_update(self) -> None:
        with pytest.raises(ValidationError):
            UpdateTenantCommand.from_dict({})

    def test_rejects_invalid_status(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            UpdateTenantCommand.from_dict({"status": "archived"})
        assert exc_info.value.field == "status"


class TestCreateOrganizationCommand:
    def test_accepts_valid_payload(self) -> None:
        parent = str(OrganizationId.generate())
        command = CreateOrganizationCommand.from_dict(
            {
                "name": "Engineering",
                "slug": "engineering",
                "parent_id": parent,
            }
        )
        assert command.parent_id == parent

    def test_requires_name(self) -> None:
        with pytest.raises(ValidationError):
            CreateOrganizationCommand.from_dict({})

    def test_rejects_invalid_parent_id(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            CreateOrganizationCommand.from_dict(
                {"name": "Eng", "parent_id": "not-a-uuid"}
            )
        assert "parent_id" in str(exc_info.value)

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            CreateOrganizationCommand.from_dict(
                {"name": "Eng", "tenant_id": str(TenantId.generate())}
            )


class TestUpdateOrganizationCommand:
    def test_rejects_status_as_immutable(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            UpdateOrganizationCommand.from_dict({"status": "inactive"})
        assert "immutable" in str(exc_info.value)

    def test_rejects_empty_update(self) -> None:
        with pytest.raises(ValidationError):
            UpdateOrganizationCommand.from_dict({})

    def test_allows_clearing_parent(self) -> None:
        command = UpdateOrganizationCommand.from_dict({"parent_id": None})
        assert command.clear_parent is True


class TestSafeResponseContracts:
    def test_tenant_response_omits_settings_and_internals(self) -> None:
        dto = TenantResponseDTO.from_entity(
            _tenant(settings={"internal": True})
        )
        payload = dto.to_dict()
        assert set(payload) == TENANT_RESPONSE_FIELDS
        assert "settings" not in payload
        assert payload["status"] == TenantStatus.PENDING_SETUP.value

    def test_organization_response_allowlist(self) -> None:
        dto = OrganizationResponseDTO.from_entity(_organization())
        payload = dto.to_dict()
        assert set(payload) == ORGANIZATION_RESPONSE_FIELDS
        assert payload["status"] == OrganizationStatus.ACTIVE.value
        for forbidden in ("password", "secret", "hash", "settings"):
            assert forbidden not in payload
