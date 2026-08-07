"""Application DTO contracts for command APIs."""

from .administration import (
    TENANT_CREATE_ALLOWED_FIELDS,
    TENANT_IMMUTABLE_FIELDS,
    TENANT_RESPONSE_FIELDS,
    TENANT_UPDATE_ALLOWED_FIELDS,
    CreateTenantCommand,
    TenantResponseDTO,
    UpdateTenantCommand,
    tenant_duplicate_conflict_fields,
)
from .identity import (
    ORGANIZATION_CREATE_ALLOWED_FIELDS,
    ORGANIZATION_IMMUTABLE_FIELDS,
    ORGANIZATION_RESPONSE_FIELDS,
    ORGANIZATION_UPDATE_ALLOWED_FIELDS,
    CreateOrganizationCommand,
    OrganizationResponseDTO,
    UpdateOrganizationCommand,
    organization_duplicate_conflict_fields,
)

__all__ = [
    "TENANT_CREATE_ALLOWED_FIELDS",
    "TENANT_IMMUTABLE_FIELDS",
    "TENANT_RESPONSE_FIELDS",
    "TENANT_UPDATE_ALLOWED_FIELDS",
    "CreateTenantCommand",
    "TenantResponseDTO",
    "UpdateTenantCommand",
    "tenant_duplicate_conflict_fields",
    "ORGANIZATION_CREATE_ALLOWED_FIELDS",
    "ORGANIZATION_IMMUTABLE_FIELDS",
    "ORGANIZATION_RESPONSE_FIELDS",
    "ORGANIZATION_UPDATE_ALLOWED_FIELDS",
    "CreateOrganizationCommand",
    "OrganizationResponseDTO",
    "UpdateOrganizationCommand",
    "organization_duplicate_conflict_fields",
]
