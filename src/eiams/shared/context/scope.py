"""Scope value objects for data-access operations.

A repository operation is either *platform scoped* (it intentionally spans
tenants, such as the tenant registry itself) or *tenant scoped* (every read
and write must be constrained to a single validated tenant).

``TenantPredicate`` is the framework-isolated description of that constraint.
It names the persistence attribute that carries tenant ownership and the
tenant value it must equal. Adapters translate the predicate into whatever
their storage engine understands; nothing in this module knows about SQL.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from eiams.shared.errors import InvalidTenantError, ValidationError
from eiams.shared.kernel import TenantId


class RepositoryScope(str, Enum):
    """Isolation scope a repository operates in."""

    PLATFORM = "platform"
    TENANT = "tenant"


@dataclass(frozen=True, slots=True)
class TenantPredicate:
    """Immutable tenant ownership filter bound to a persistence attribute.

    Attributes:
        column: Name of the attribute carrying tenant ownership.
        tenant_id: The validated tenant the operation is confined to.
        include_shared: When True, rows with no tenant owner (a NULL tenant
            column) are also in scope. This is used only by entity groups
            that the approved schema defines as platform-shared catalogues,
            such as system roles and system permissions. It never widens
            scope to another tenant, and writes never use it.
    """

    column: str
    tenant_id: TenantId
    include_shared: bool = False

    def __post_init__(self) -> None:
        if not self.column or not isinstance(self.column, str):
            raise ValidationError(
                "Tenant predicate requires a column name", field="column"
            )
        if not isinstance(self.tenant_id, TenantId):
            raise InvalidTenantError(
                "Tenant predicate requires a validated TenantId"
            )

    @property
    def value(self) -> str:
        """The tenant identifier the predicate binds to."""
        return self.tenant_id.value

    def matches(self, candidate: str | None) -> bool:
        """Check whether a tenant value satisfies this predicate."""
        if candidate is None:
            return self.include_shared
        return candidate.strip().lower() == self.value

    def for_write(self) -> "TenantPredicate":
        """Return the strict variant used to guard mutations.

        Shared rows are readable by every tenant but owned by none, so they
        are always excluded when a predicate guards a write.
        """
        if not self.include_shared:
            return self
        return TenantPredicate(column=self.column, tenant_id=self.tenant_id)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for structured logging and assertions."""
        return {
            "column": self.column,
            "tenant_id": self.value,
            "include_shared": self.include_shared,
        }

    def __str__(self) -> str:
        base = f"{self.column} = {self.value}"
        if self.include_shared:
            return f"({base} OR {self.column} IS NULL)"
        return base
