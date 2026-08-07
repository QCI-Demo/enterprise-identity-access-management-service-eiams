"""Explicit tenant and organization status transition rules.

Lifecycle commands consult these helpers before mutating status so illegal
source-to-target changes fail closed with a standardized conflict error.
"""

from __future__ import annotations

from typing import Iterable

from eiams.domain.administration.contracts import TenantStatus
from eiams.domain.identity.contracts import OrganizationStatus
from eiams.shared.errors import DomainError, ErrorCode


class InvalidStatusTransitionError(DomainError):
    """Raised when a lifecycle status change is not permitted."""

    def __init__(
        self,
        resource_type: str,
        source: str,
        target: str,
        message: str | None = None,
    ) -> None:
        details = {
            "resource": resource_type,
            "resource_type": resource_type,
            "source": source,
            "target": target,
            "valid_values": sorted(
                _allowed_targets_for(resource_type, source)
            ),
        }
        super().__init__(
            message
            or (
                f"Unsupported {resource_type} status transition "
                f"from '{source}' to '{target}'"
            ),
            ErrorCode.RESOURCE_CONFLICT,
            details,
        )
        self.resource_type = resource_type
        self.source = source
        self.target = target


# Tenant lifecycle graph:
#   pending_setup -> active | inactive
#   active        -> suspended | inactive
#   suspended     -> active | inactive
#   inactive      -> (terminal)
_TENANT_TRANSITIONS: dict[TenantStatus, frozenset[TenantStatus]] = {
    TenantStatus.PENDING_SETUP: frozenset(
        {TenantStatus.ACTIVE, TenantStatus.INACTIVE}
    ),
    TenantStatus.ACTIVE: frozenset(
        {TenantStatus.SUSPENDED, TenantStatus.INACTIVE}
    ),
    TenantStatus.SUSPENDED: frozenset(
        {TenantStatus.ACTIVE, TenantStatus.INACTIVE}
    ),
    TenantStatus.INACTIVE: frozenset(),
}


# Organization lifecycle graph (persisted presence implies active):
#   active   -> inactive
#   inactive -> (terminal)
_ORGANIZATION_TRANSITIONS: dict[
    OrganizationStatus, frozenset[OrganizationStatus]
] = {
    OrganizationStatus.ACTIVE: frozenset({OrganizationStatus.INACTIVE}),
    OrganizationStatus.INACTIVE: frozenset(),
}


def _allowed_targets_for(resource_type: str, source: str) -> Iterable[str]:
    """Return allowed target status values for error details."""
    if resource_type == "tenant":
        try:
            status = TenantStatus(source)
        except ValueError:
            return ()
        return (item.value for item in allowed_tenant_transitions(status))
    if resource_type == "organization":
        try:
            status = OrganizationStatus(source)
        except ValueError:
            return ()
        return (
            item.value for item in allowed_organization_transitions(status)
        )
    return ()


def allowed_tenant_transitions(
    source: TenantStatus,
) -> frozenset[TenantStatus]:
    """Return the legal target statuses for a tenant source status."""
    return _TENANT_TRANSITIONS.get(source, frozenset())


def allowed_organization_transitions(
    source: OrganizationStatus,
) -> frozenset[OrganizationStatus]:
    """Return the legal target statuses for an organization source status."""
    return _ORGANIZATION_TRANSITIONS.get(source, frozenset())


def is_legal_tenant_transition(
    source: TenantStatus,
    target: TenantStatus,
) -> bool:
    """Return True when the tenant transition is explicitly allowed.

    A no-op transition (source == target) is treated as legal so idempotent
    writes do not fail, but produces no state change for callers.
    """
    if source == target:
        return True
    return target in allowed_tenant_transitions(source)


def is_legal_organization_transition(
    source: OrganizationStatus,
    target: OrganizationStatus,
) -> bool:
    """Return True when the organization transition is explicitly allowed."""
    if source == target:
        return True
    return target in allowed_organization_transitions(source)


def assert_tenant_transition(
    source: TenantStatus,
    target: TenantStatus,
) -> None:
    """Reject unsupported tenant status transitions.

    Raises:
        InvalidStatusTransitionError: When the transition is not allowed.
    """
    if not is_legal_tenant_transition(source, target):
        raise InvalidStatusTransitionError(
            resource_type="tenant",
            source=source.value,
            target=target.value,
        )


def assert_organization_transition(
    source: OrganizationStatus,
    target: OrganizationStatus,
) -> None:
    """Reject unsupported organization status transitions.

    Raises:
        InvalidStatusTransitionError: When the transition is not allowed.
    """
    if not is_legal_organization_transition(source, target):
        raise InvalidStatusTransitionError(
            resource_type="organization",
            source=source.value,
            target=target.value,
        )


def deactivate_tenant_status(source: TenantStatus) -> TenantStatus:
    """Resolve the deactivate target for a tenant, or reject it.

    Deactivate is not idempotent: an already-inactive tenant is an
    unsupported transition rather than a no-op.
    """
    target = TenantStatus.INACTIVE
    if source == target or target not in allowed_tenant_transitions(source):
        raise InvalidStatusTransitionError(
            resource_type="tenant",
            source=source.value,
            target=target.value,
        )
    return target


def deactivate_organization_status(
    source: OrganizationStatus,
) -> OrganizationStatus:
    """Resolve the deactivate target for an organization, or reject it.

    Deactivate is not idempotent: an already-inactive organization is an
    unsupported transition rather than a no-op.
    """
    target = OrganizationStatus.INACTIVE
    if source == target or target not in allowed_organization_transitions(
        source
    ):
        raise InvalidStatusTransitionError(
            resource_type="organization",
            source=source.value,
            target=target.value,
        )
    return target
