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

__all__ = [
    "TransportContextAdapter",
    "ContextExtractionError",
    "HttpContextExtractor",
    "AuthorizationHookAdapter",
    "LoggingAuthorizationHook",
    "CompositeAuthorizationHook",
]
