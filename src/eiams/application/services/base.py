"""Base application service definition.

Application services are the entry point for use cases. They
coordinate domain logic and infrastructure operations.
"""

from abc import ABC
from typing import Any

from eiams.shared.context import RequestContext, require_context


class ApplicationService(ABC):
    """Base class for application services.

    Application services:
    - Receive validated request context
    - Coordinate domain operations
    - Enforce application-level business rules
    - Are framework-isolated (no HTTP/web dependencies)
    """

    def _validate_context(self, context: RequestContext) -> None:
        """Validate that the context is structurally valid.

        Subclasses can override to add additional validation.
        """
        require_context(context)
