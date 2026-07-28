"""Administration domain module.

Manages tenant and system administration, including:
- Tenant lifecycle management
- System configuration
- Administrative operations
- Cross-tenant management
"""

from .contracts import (
    Tenant,
    TenantStatus,
    TenantRepository,
    AdministrationService,
)

__all__ = [
    "Tenant",
    "TenantStatus",
    "TenantRepository",
    "AdministrationService",
]
