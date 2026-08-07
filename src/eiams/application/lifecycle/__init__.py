"""Lifecycle helpers for tenant and organization command services."""

from .transitions import (
    InvalidStatusTransitionError,
    allowed_organization_transitions,
    allowed_tenant_transitions,
    assert_organization_transition,
    assert_tenant_transition,
    deactivate_organization_status,
    deactivate_tenant_status,
    is_legal_organization_transition,
    is_legal_tenant_transition,
)

__all__ = [
    "InvalidStatusTransitionError",
    "allowed_organization_transitions",
    "allowed_tenant_transitions",
    "assert_organization_transition",
    "assert_tenant_transition",
    "deactivate_organization_status",
    "deactivate_tenant_status",
    "is_legal_organization_transition",
    "is_legal_tenant_transition",
]
