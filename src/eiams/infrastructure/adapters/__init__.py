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
]
