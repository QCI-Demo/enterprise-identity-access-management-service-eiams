"""Tenant command and response DTOs with safe field allowlists.

Request DTOs validate required fields, bounds, formats, and reject unknown
or immutable fields. Response DTOs expose only approved metadata and
lifecycle state — never persistence internals or settings payloads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from eiams.domain.administration.contracts import Tenant, TenantStatus
from eiams.shared.errors import ValidationError


# Safe response field allowlist (never expose settings / persistence internals)
TENANT_RESPONSE_FIELDS: frozenset[str] = frozenset(
    {
        "tenant_id",
        "name",
        "slug",
        "display_name",
        "description",
        "status",
        "created_at",
        "updated_at",
    }
)

TENANT_CREATE_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "name",
        "display_name",
        "slug",
        "description",
    }
)

TENANT_UPDATE_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "display_name",
        "description",
        "status",
    }
)

# Immutable after create — rejected on update payloads
TENANT_IMMUTABLE_FIELDS: frozenset[str] = frozenset(
    {
        "tenant_id",
        "name",
        "slug",
        "created_at",
        "updated_at",
        "settings",
    }
)

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,254}$")
_SLUG_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

NAME_MIN_LENGTH = 2
NAME_MAX_LENGTH = 255
DISPLAY_NAME_MAX_LENGTH = 255
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


@dataclass(frozen=True)
class TenantResponseDTO:
    """Safe tenant direct-resource response."""

    tenant_id: str
    name: str
    slug: str | None
    display_name: str
    description: str | None
    status: str
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, tenant: Tenant) -> "TenantResponseDTO":
        """Project a domain tenant onto the safe response contract."""
        return cls(
            tenant_id=str(tenant.tenant_id),
            name=tenant.name,
            slug=tenant.slug,
            display_name=tenant.display_name,
            description=tenant.description,
            status=tenant.status.value,
            created_at=tenant.created_at.to_iso(),
            updated_at=tenant.updated_at.to_iso(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize only allowlisted fields."""
        payload = {
            "tenant_id": self.tenant_id,
            "name": self.name,
            "slug": self.slug,
            "display_name": self.display_name,
            "description": self.description,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        return {key: payload[key] for key in TENANT_RESPONSE_FIELDS}


@dataclass
class CreateTenantCommand:
    """Platform-admin command to create a tenant."""

    name: str
    display_name: str
    slug: str | None = None
    description: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CreateTenantCommand":
        """Build and validate a create command from raw request data."""
        if not isinstance(data, dict):
            raise ValidationError("Request body must be an object", field="body")

        unknown = _reject_unknown_fields(data, TENANT_CREATE_ALLOWED_FIELDS)
        if unknown:
            raise ValidationError(
                "; ".join(unknown),
                field="body",
                details={"errors": unknown},
            )

        command = cls(
            name=data.get("name"),  # type: ignore[arg-type]
            display_name=data.get("display_name"),  # type: ignore[arg-type]
            slug=data.get("slug"),
            description=data.get("description"),
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
                    "Field 'name' must be 2-255 characters and use letters, "
                    "digits, '.', '_' or '-'"
                )

        errors.extend(
            _validate_optional_string(
                self.display_name,
                "display_name",
                required=True,
                min_length=1,
                max_length=DISPLAY_NAME_MAX_LENGTH,
            )
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
        return errors


@dataclass
class UpdateTenantCommand:
    """Platform-admin command to update mutable tenant metadata/status."""

    display_name: str | None = None
    description: str | None = None
    status: TenantStatus | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UpdateTenantCommand":
        """Build and validate an update command from raw request data."""
        if not isinstance(data, dict):
            raise ValidationError("Request body must be an object", field="body")

        unknown = _reject_unknown_fields(
            data,
            TENANT_UPDATE_ALLOWED_FIELDS,
            immutable=TENANT_IMMUTABLE_FIELDS,
        )
        if unknown:
            raise ValidationError(
                "; ".join(unknown),
                field="body",
                details={"errors": unknown},
            )

        status_value = data.get("status")
        status: TenantStatus | None = None
        if status_value is not None:
            if not isinstance(status_value, str):
                raise ValidationError(
                    "Field 'status' must be a string",
                    field="status",
                )
            try:
                status = TenantStatus(status_value)
            except ValueError as exc:
                raise ValidationError(
                    "Field 'status' has an unsupported value",
                    field="status",
                    details={
                        "valid_values": [item.value for item in TenantStatus],
                    },
                ) from exc

        command = cls(
            display_name=data.get("display_name"),
            description=data.get("description"),
            status=status,
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
            self.display_name is None
            and self.description is None
            and self.status is None
        ):
            errors.append("At least one mutable field is required")

        errors.extend(
            _validate_optional_string(
                self.display_name,
                "display_name",
                min_length=1,
                max_length=DISPLAY_NAME_MAX_LENGTH,
            )
        )
        errors.extend(
            _validate_optional_string(
                self.description,
                "description",
                max_length=DESCRIPTION_MAX_LENGTH,
            )
        )
        return errors

    def has_changes(self) -> bool:
        """Return True when the command carries a mutation."""
        return (
            self.display_name is not None
            or self.description is not None
            or self.status is not None
        )


def tenant_duplicate_conflict_fields(
    *,
    name_conflict: bool = False,
    slug_conflict: bool = False,
) -> tuple[str, ...]:
    """Describe uniqueness fields that conflict for tenant creates/updates."""
    fields: list[str] = []
    if name_conflict:
        fields.append("name")
    if slug_conflict:
        fields.append("slug")
    return tuple(fields)


def ensure_no_disallowed_response_fields(payload: dict[str, Any]) -> None:
    """Guard helper for tests/services asserting response allowlists."""
    disallowed = set(payload) - TENANT_RESPONSE_FIELDS
    if disallowed:
        raise ValidationError(
            f"Response contains disallowed fields: {sorted(disallowed)}",
            field="response",
        )


def iter_tenant_status_values() -> Iterable[str]:
    """Return supported tenant status values for validators/docs."""
    return (status.value for status in TenantStatus)
