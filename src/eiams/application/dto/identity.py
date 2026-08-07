"""Organization command and response DTOs with safe field allowlists.

Organization mutations reject unknown/immutable fields, duplicate
constraints are described explicitly, and status changes are limited to the
deactivate command path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable
from uuid import UUID

from eiams.domain.identity.contracts import Organization, OrganizationStatus
from eiams.shared.errors import ValidationError


ORGANIZATION_RESPONSE_FIELDS: frozenset[str] = frozenset(
    {
        "organization_id",
        "tenant_id",
        "name",
        "slug",
        "description",
        "parent_id",
        "status",
        "created_at",
        "updated_at",
    }
)

ORGANIZATION_CREATE_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "name",
        "slug",
        "description",
        "parent_id",
    }
)

ORGANIZATION_UPDATE_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "name",
        "description",
        "parent_id",
    }
)

ORGANIZATION_IMMUTABLE_FIELDS: frozenset[str] = frozenset(
    {
        "organization_id",
        "tenant_id",
        "slug",
        "status",
        "created_at",
        "updated_at",
    }
)

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,254}$")
_SLUG_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

NAME_MIN_LENGTH = 1
NAME_MAX_LENGTH = 255
DESCRIPTION_MAX_LENGTH = 2000
SLUG_MAX_LENGTH = 63


def _reject_unknown_fields(
    data: dict[str, Any],
    allowed: frozenset[str],
    *,
    immutable: frozenset[str] | None = None,
) -> list[str]:
    """Collect validation errors for unknown or immutable fields."""
    errors: list[str] = []
    immutable = immutable or frozenset()
    for key in data:
        if key in immutable:
            errors.append(f"Field '{key}' is immutable")
        elif key not in allowed:
            errors.append(f"Unknown field '{key}'")
    return errors


def _validate_optional_string(
    value: Any,
    field: str,
    *,
    max_length: int,
    required: bool = False,
    min_length: int = 0,
) -> list[str]:
    """Validate an optional/required string field."""
    if value is None:
        if required:
            return [f"Field '{field}' is required"]
        return []
    if not isinstance(value, str):
        return [f"Field '{field}' must be a string"]
    if required and not value.strip():
        return [f"Field '{field}' is required"]
    if len(value) < min_length:
        return [f"Field '{field}' must be at least {min_length} characters"]
    if len(value) > max_length:
        return [f"Field '{field}' must be at most {max_length} characters"]
    return []


def _validate_optional_uuid(value: Any, field: str) -> list[str]:
    """Validate an optional UUID string field."""
    if value is None:
        return []
    if not isinstance(value, str):
        return [f"Field '{field}' must be a string"]
    try:
        UUID(value)
    except ValueError:
        return [f"Field '{field}' must be a valid UUID"]
    return []


@dataclass(frozen=True)
class OrganizationResponseDTO:
    """Safe organization direct-resource response."""

    organization_id: str
    tenant_id: str
    name: str
    slug: str | None
    description: str | None
    parent_id: str | None
    status: str
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(
        cls, organization: Organization
    ) -> "OrganizationResponseDTO":
        """Project a domain organization onto the safe response contract."""
        return cls(
            organization_id=str(organization.organization_id),
            tenant_id=str(organization.tenant_id),
            name=organization.name,
            slug=organization.slug,
            description=organization.description,
            parent_id=(
                str(organization.parent_id) if organization.parent_id else None
            ),
            status=organization.status.value,
            created_at=organization.created_at.to_iso(),
            updated_at=organization.updated_at.to_iso(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize only allowlisted fields."""
        payload = {
            "organization_id": self.organization_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "parent_id": self.parent_id,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        return {key: payload[key] for key in ORGANIZATION_RESPONSE_FIELDS}


@dataclass
class CreateOrganizationCommand:
    """Tenant-scoped command to create an organization."""

    name: str
    slug: str | None = None
    description: str | None = None
    parent_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CreateOrganizationCommand":
        """Build and validate a create command from raw request data."""
        if not isinstance(data, dict):
            raise ValidationError("Request body must be an object", field="body")

        unknown = _reject_unknown_fields(
            data, ORGANIZATION_CREATE_ALLOWED_FIELDS
        )
        if unknown:
            raise ValidationError(
                "; ".join(unknown),
                field="body",
                details={"errors": unknown},
            )

        command = cls(
            name=data.get("name"),  # type: ignore[arg-type]
            slug=data.get("slug"),
            description=data.get("description"),
            parent_id=data.get("parent_id"),
        )
        errors = command.validate()
        if errors:
            raise ValidationError(
                "; ".join(errors),
                field="body",
                details={"errors": errors},
            )
        return command

    def validate(self) -> list[str]:
        """Validate required fields, bounds, and formats."""
        errors: list[str] = []
        errors.extend(
            _validate_optional_string(
                self.name,
                "name",
                required=True,
                min_length=NAME_MIN_LENGTH,
                max_length=NAME_MAX_LENGTH,
            )
        )
        if isinstance(self.name, str) and self.name.strip():
            if not _NAME_PATTERN.match(self.name.strip()):
                errors.append(
                    "Field 'name' contains unsupported characters"
                )
        errors.extend(
            _validate_optional_string(
                self.description,
                "description",
                max_length=DESCRIPTION_MAX_LENGTH,
            )
        )
        if self.slug is not None:
            errors.extend(
                _validate_optional_string(
                    self.slug,
                    "slug",
                    min_length=1,
                    max_length=SLUG_MAX_LENGTH,
                )
            )
            if isinstance(self.slug, str) and self.slug and not _SLUG_PATTERN.match(
                self.slug
            ):
                errors.append(
                    "Field 'slug' must be a lowercase DNS-label of at most "
                    f"{SLUG_MAX_LENGTH} characters"
                )
        errors.extend(_validate_optional_uuid(self.parent_id, "parent_id"))
        return errors


@dataclass
class UpdateOrganizationCommand:
    """Tenant-scoped command to update mutable organization metadata."""

    name: str | None = None
    description: str | None = None
    parent_id: str | None = None
    clear_parent: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UpdateOrganizationCommand":
        """Build and validate an update command from raw request data."""
        if not isinstance(data, dict):
            raise ValidationError("Request body must be an object", field="body")

        unknown = _reject_unknown_fields(
            data,
            ORGANIZATION_UPDATE_ALLOWED_FIELDS,
            immutable=ORGANIZATION_IMMUTABLE_FIELDS,
        )
        if unknown:
            raise ValidationError(
                "; ".join(unknown),
                field="body",
                details={"errors": unknown},
            )

        clear_parent = "parent_id" in data and data.get("parent_id") is None
        command = cls(
            name=data.get("name"),
            description=data.get("description"),
            parent_id=data.get("parent_id"),
            clear_parent=clear_parent,
        )
        errors = command.validate()
        if errors:
            raise ValidationError(
                "; ".join(errors),
                field="body",
                details={"errors": errors},
            )
        return command

    def validate(self) -> list[str]:
        """Validate bounds and ensure at least one mutable field is present."""
        errors: list[str] = []
        if (
            self.name is None
            and self.description is None
            and self.parent_id is None
            and not self.clear_parent
        ):
            errors.append("At least one mutable field is required")

        errors.extend(
            _validate_optional_string(
                self.name,
                "name",
                min_length=NAME_MIN_LENGTH,
                max_length=NAME_MAX_LENGTH,
            )
        )
        if isinstance(self.name, str) and self.name.strip():
            if not _NAME_PATTERN.match(self.name.strip()):
                errors.append(
                    "Field 'name' contains unsupported characters"
                )
        errors.extend(
            _validate_optional_string(
                self.description,
                "description",
                max_length=DESCRIPTION_MAX_LENGTH,
            )
        )
        if self.parent_id is not None:
            errors.extend(_validate_optional_uuid(self.parent_id, "parent_id"))
        return errors


def organization_duplicate_conflict_fields(
    *,
    name_conflict: bool = False,
    slug_conflict: bool = False,
) -> tuple[str, ...]:
    """Describe uniqueness fields that conflict within a tenant."""
    fields: list[str] = []
    if name_conflict:
        fields.append("name")
    if slug_conflict:
        fields.append("slug")
    return tuple(fields)


def iter_organization_status_values() -> Iterable[str]:
    """Return supported organization status values."""
    return (status.value for status in OrganizationStatus)
