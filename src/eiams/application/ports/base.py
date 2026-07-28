"""Base port definitions for hexagonal architecture.

Ports are the boundaries between the application layer and the
outside world. They define contracts that adapters implement.
"""

from abc import ABC
from typing import TypeVar, Generic

from eiams.shared.context import RequestContext


Request = TypeVar("Request")
Response = TypeVar("Response")


class InputPort(ABC, Generic[Request, Response]):
    """Base class for input ports (driving adapters).

    Input ports receive commands/queries from the outside world
    (e.g., HTTP requests, CLI commands) and translate them into
    application service calls.
    """

    def execute(self, context: RequestContext, request: Request) -> Response:
        """Execute the use case with the given request.

        Args:
            context: The validated request context.
            request: The use case request.

        Returns:
            The use case response.
        """
        raise NotImplementedError("Subclasses must implement execute()")


class OutputPort(ABC):
    """Base class for output ports (driven adapters).

    Output ports define interfaces for infrastructure concerns
    like persistence, external APIs, messaging, etc. They are
    implemented by adapters in the infrastructure layer.
    """

    pass
