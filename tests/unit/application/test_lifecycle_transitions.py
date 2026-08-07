"""Unit tests for tenant and organization status transition rules."""

import pytest

from eiams.application.lifecycle import (
    InvalidStatusTransitionError,
    assert_organization_transition,
    assert_tenant_transition,
    deactivate_organization_status,
    deactivate_tenant_status,
    is_legal_organization_transition,
    is_legal_tenant_transition,
)
from eiams.domain.administration.contracts import TenantStatus
from eiams.domain.identity.contracts import OrganizationStatus


class TestTenantTransitions:
    """Legal and illegal tenant status transitions."""

    @pytest.mark.parametrize(
        "source,target",
        [
            (TenantStatus.PENDING_SETUP, TenantStatus.ACTIVE),
            (TenantStatus.PENDING_SETUP, TenantStatus.INACTIVE),
            (TenantStatus.ACTIVE, TenantStatus.SUSPENDED),
            (TenantStatus.ACTIVE, TenantStatus.INACTIVE),
            (TenantStatus.SUSPENDED, TenantStatus.ACTIVE),
            (TenantStatus.SUSPENDED, TenantStatus.INACTIVE),
            (TenantStatus.ACTIVE, TenantStatus.ACTIVE),
        ],
    )
    def test_legal_tenant_transitions(self, source, target) -> None:
        assert is_legal_tenant_transition(source, target)
        assert_tenant_transition(source, target)

    @pytest.mark.parametrize(
        "source,target",
        [
            (TenantStatus.PENDING_SETUP, TenantStatus.SUSPENDED),
            (TenantStatus.ACTIVE, TenantStatus.PENDING_SETUP),
            (TenantStatus.INACTIVE, TenantStatus.ACTIVE),
            (TenantStatus.INACTIVE, TenantStatus.SUSPENDED),
            (TenantStatus.SUSPENDED, TenantStatus.PENDING_SETUP),
        ],
    )
    def test_illegal_tenant_transitions(self, source, target) -> None:
        assert not is_legal_tenant_transition(source, target)
        with pytest.raises(InvalidStatusTransitionError) as exc_info:
            assert_tenant_transition(source, target)
        assert exc_info.value.code.value == "RESOURCE_CONFLICT"
        assert exc_info.value.details["resource_type"] == "tenant"

    def test_deactivate_from_active(self) -> None:
        assert deactivate_tenant_status(TenantStatus.ACTIVE) == TenantStatus.INACTIVE

    def test_deactivate_from_inactive_rejected(self) -> None:
        with pytest.raises(InvalidStatusTransitionError):
            deactivate_tenant_status(TenantStatus.INACTIVE)


class TestOrganizationTransitions:
    """Legal and illegal organization status transitions."""

    def test_active_to_inactive_is_legal(self) -> None:
        assert is_legal_organization_transition(
            OrganizationStatus.ACTIVE, OrganizationStatus.INACTIVE
        )
        assert_organization_transition(
            OrganizationStatus.ACTIVE, OrganizationStatus.INACTIVE
        )

    def test_inactive_to_active_is_illegal(self) -> None:
        assert not is_legal_organization_transition(
            OrganizationStatus.INACTIVE, OrganizationStatus.ACTIVE
        )
        with pytest.raises(InvalidStatusTransitionError) as exc_info:
            assert_organization_transition(
                OrganizationStatus.INACTIVE, OrganizationStatus.ACTIVE
            )
        assert exc_info.value.details["resource_type"] == "organization"

    def test_deactivate_active_organization(self) -> None:
        assert (
            deactivate_organization_status(OrganizationStatus.ACTIVE)
            == OrganizationStatus.INACTIVE
        )

    def test_deactivate_inactive_organization_rejected(self) -> None:
        with pytest.raises(InvalidStatusTransitionError):
            deactivate_organization_status(OrganizationStatus.INACTIVE)
