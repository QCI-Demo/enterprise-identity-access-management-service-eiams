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
from .audit_recording import RedactingAuditService
from .http_api import (
    API_BASE_PATH,
    API_VERSION,
    ApiEndpoint,
    ApiRequest,
    ApiResponse,
    ApiRouter,
    InvalidRequestBodyError,
    parse_json_object,
)
from .login_api import (
    LOGIN_METHOD,
    LOGIN_PATH,
    LoginEndpoint,
    LoginRequestValidator,
    create_login_endpoint,
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
    # Audit
    "RedactingAuditService",
    # HTTP API
    "API_BASE_PATH",
    "API_VERSION",
    "ApiEndpoint",
    "ApiRequest",
    "ApiResponse",
    "ApiRouter",
    "InvalidRequestBodyError",
    "parse_json_object",
    # Login endpoint
    "LOGIN_METHOD",
    "LOGIN_PATH",
    "LoginEndpoint",
    "LoginRequestValidator",
    "create_login_endpoint",
]
