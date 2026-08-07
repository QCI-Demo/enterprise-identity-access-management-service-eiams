"""Infrastructure adapters for external interfaces.

Adapters translate between external protocols (HTTP, CLI, etc.)
and internal application contracts.
"""

from .transport import (
    TransportContextAdapter,
    ContextExtractionError,
    HttpContextExtractor,
)
from .authorization_hook import (
    AuthorizationHookAdapter,
    LoggingAuthorizationHook,
    CompositeAuthorizationHook,
)
from .authorization_middleware import (
    AuthorizationMiddleware,
    AuthorizationGuard,
    ProtectedOperationMetadata,
    create_authorization_middleware,
)
from .validation import (
    ValidationResult,
    RequestValidator,
    CompositeValidator,
    FieldValidator,
    ValidationAdapter,
)
from .http_api import (
    API_BASE_PATH,
    API_VERSION,
    ApiEndpoint,
    ApiRequest,
    ApiResponse,
    ApiRouter,
)
from .tenant_api import (
    CreateTenantEndpoint,
    DeactivateTenantEndpoint,
    GetTenantEndpoint,
    UpdateTenantEndpoint,
    register_tenant_endpoints,
)
from .organization_api import (
    CreateOrganizationEndpoint,
    DeactivateOrganizationEndpoint,
    GetOrganizationEndpoint,
    UpdateOrganizationEndpoint,
    register_organization_endpoints,
)

__all__ = [
    # Transport
    "TransportContextAdapter",
    "ContextExtractionError",
    "HttpContextExtractor",
    # Authorization hooks
    "AuthorizationHookAdapter",
    "LoggingAuthorizationHook",
    "CompositeAuthorizationHook",
    # Authorization middleware
    "AuthorizationMiddleware",
    "AuthorizationGuard",
    "ProtectedOperationMetadata",
    "create_authorization_middleware",
    # Validation
    "ValidationResult",
    "RequestValidator",
    "CompositeValidator",
    "FieldValidator",
    "ValidationAdapter",
    # HTTP API
    "API_BASE_PATH",
    "API_VERSION",
    "ApiEndpoint",
    "ApiRequest",
    "ApiResponse",
    "ApiRouter",
    # Tenant API
    "CreateTenantEndpoint",
    "DeactivateTenantEndpoint",
    "GetTenantEndpoint",
    "UpdateTenantEndpoint",
    "register_tenant_endpoints",
    # Organization API
    "CreateOrganizationEndpoint",
    "DeactivateOrganizationEndpoint",
    "GetOrganizationEndpoint",
    "UpdateOrganizationEndpoint",
    "register_organization_endpoints",
]
