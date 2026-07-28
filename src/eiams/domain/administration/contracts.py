"""Administration domain contracts.

Framework-isolated interfaces for tenant and system administration.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

from eiams.shared.kernel import TenantId, Timestamp
from eiams.shared.context import RequestContext
from eiams.domain.base import DomainEntity, Repository, DomainService


class TenantStatus(str, Enum):
    """Status of a tenant."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_SETUP = "pending_setup"


@dataclass(frozen=True)
class Tenant(DomainEntity):
    """Tenant entity contract.

    Represents a tenant (customer/organization) in the multi-tenant system.
    """

    tenant_id: TenantId
    name: str
    display_name: str
    status: TenantStatus
    settings: dict[str, Any]
    created_at: Timestamp
    updated_at: Timestamp

    @property
    def id(self) -> TenantId:
        return self.tenant_id

    @property
    def is_active(self) -> bool:
        """Check if the tenant is currently active."""
        return self.status == TenantStatus.ACTIVE

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Tenant):
            return NotImplemented
        return self.tenant_id == other.tenant_id

    def __hash__(self) -> int:
        return hash(self.tenant_id)


class TenantRepository(Repository[Tenant, TenantId], ABC):
    """Repository contract for tenant persistence operations."""

    @abstractmethod
    def find_by_name(self, context: RequestContext, name: str) -> Tenant | None:
        """Find a tenant by its unique name."""
        ...

    @abstractmethod
    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[Tenant]:
        """Find all tenants with pagination."""
        ...

    @abstractmethod
    def find_active(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[Tenant]:
        """Find all active tenants with pagination."""
        ...

    @abstractmethod
    def count(self, context: RequestContext) -> int:
        """Count all tenants."""
        ...


class AdministrationService(DomainService, ABC):
    """Domain service contract for administrative operations.

    Note: This is an extension point. Actual administrative logic
    will be implemented in later epics.
    """

    @abstractmethod
    def create_tenant(
        self,
        context: RequestContext,
        name: str,
        display_name: str,
        settings: dict[str, Any] | None = None,
    ) -> Tenant:
        """Create a new tenant."""
        ...

    @abstractmethod
    def update_tenant_status(
        self,
        context: RequestContext,
        tenant_id: TenantId,
        status: TenantStatus,
    ) -> Tenant:
        """Update a tenant's status."""
        ...

    @abstractmethod
    def update_tenant_settings(
        self,
        context: RequestContext,
        tenant_id: TenantId,
        settings: dict[str, Any],
    ) -> Tenant:
        """Update a tenant's settings."""
        ...

    @abstractmethod
    def get_tenant(
        self,
        context: RequestContext,
        tenant_id: TenantId,
    ) -> Tenant | None:
        """Get a tenant by ID."""
        ...

    @abstractmethod
    def list_tenants(
        self,
        context: RequestContext,
        offset: int = 0,
        limit: int = 100,
        status: TenantStatus | None = None,
    ) -> list[Tenant]:
        """List tenants with optional filtering."""
        ...
