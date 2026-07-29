"""Transport context adapters for framework-edge request handling.

These adapters construct validated request context from incoming
transport-layer requests (HTTP, gRPC, etc.) and pass it explicitly
to application services.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Protocol

from eiams.shared.context import (
    RequestContext,
    RequestContextFactory,
    ActorType,
)
from eiams.shared.errors import (
    ContextError,
    InvalidTenantError,
    InvalidActorError,
    InvalidCorrelationIdError,
    ValidationError,
)


class ContextExtractionError(ContextError):
    """Error raised when context extraction from transport fails."""

    def __init__(
        self,
        message: str,
        source_error: Exception | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if source_error:
            details["source_error"] = str(source_error)
        super().__init__(message, details=details)
        self._source_error = source_error

    @property
    def source_error(self) -> Exception | None:
        """The underlying error that caused extraction to fail."""
        return self._source_error


@dataclass
class TransportRequest(Protocol):
    """Protocol for transport-layer request objects.

    This protocol defines the minimum interface that transport
    requests must implement for context extraction.
    """

    def get_header(self, name: str) -> str | None:
        """Get a header value by name."""
        ...

    @property
    def path(self) -> str:
        """The request path."""
        ...

    @property
    def method(self) -> str:
        """The request method."""
        ...

    @property
    def client_ip(self) -> str | None:
        """The client IP address."""
        ...


class TransportContextAdapter(ABC):
    """Base adapter for extracting context from transport requests.

    This adapter is responsible for:
    1. Extracting correlation ID, actor, and tenant metadata from headers
    2. Validating the extracted values
    3. Constructing a validated RequestContext
    4. Propagating validation errors through the standard error pathway
    """

    # Standard header names (can be overridden)
    CORRELATION_ID_HEADER = "X-Correlation-ID"
    ACTOR_ID_HEADER = "X-Actor-ID"
    ACTOR_TYPE_HEADER = "X-Actor-Type"
    TENANT_ID_HEADER = "X-Tenant-ID"
    ROLES_HEADER = "X-Roles"
    USER_AGENT_HEADER = "User-Agent"

    @abstractmethod
    def extract_context(self, request: Any) -> RequestContext:
        """Extract and validate request context from a transport request.

        Args:
            request: The transport-layer request object.

        Returns:
            Validated RequestContext.

        Raises:
            ContextExtractionError: If context extraction fails.
            InvalidTenantError: If tenant ID is malformed.
            InvalidActorError: If actor ID is malformed.
            InvalidCorrelationIdError: If correlation ID is malformed.
        """
        ...


class HttpContextExtractor(TransportContextAdapter):
    """Context extractor for HTTP requests.

    Extracts context from HTTP headers following standard conventions.
    """

    def __init__(
        self,
        require_tenant: bool = False,
        require_actor: bool = True,
        default_actor_type: ActorType = ActorType.USER,
    ) -> None:
        """Initialize the HTTP context extractor.

        Args:
            require_tenant: Whether to require tenant context.
            require_actor: Whether to require actor context.
            default_actor_type: Default actor type if not specified.
        """
        self._require_tenant = require_tenant
        self._require_actor = require_actor
        self._default_actor_type = default_actor_type

    def extract_context(self, request: Any) -> RequestContext:
        """Extract context from an HTTP request.

        The request object should have a get_header method or be dict-like.

        Args:
            request: HTTP request object or dict with headers.

        Returns:
            Validated RequestContext.

        Raises:
            ContextExtractionError: If extraction fails.
            InvalidTenantError: If tenant ID is invalid.
            InvalidActorError: If actor ID is invalid.
        """
        try:
            headers = self._extract_headers(request)

            # Extract correlation ID (optional, will be generated if missing)
            correlation_id = headers.get(self.CORRELATION_ID_HEADER)

            # Extract actor information
            actor_id = headers.get(self.ACTOR_ID_HEADER)
            actor_type_str = headers.get(self.ACTOR_TYPE_HEADER)

            if self._require_actor and not actor_id:
                raise InvalidActorError(
                    "Actor ID header is required but missing",
                    details={"header": self.ACTOR_ID_HEADER},
                )

            # Parse actor type
            actor_type = self._default_actor_type
            if actor_type_str:
                try:
                    actor_type = ActorType(actor_type_str.lower())
                except ValueError:
                    raise ValidationError(
                        f"Invalid actor type: {actor_type_str}",
                        field="actor_type",
                        details={"valid_types": [t.value for t in ActorType]},
                    )

            # Extract tenant information
            tenant_id = headers.get(self.TENANT_ID_HEADER)

            if self._require_tenant and not tenant_id:
                raise InvalidTenantError(
                    "Tenant ID header is required but missing",
                    details={"header": self.TENANT_ID_HEADER},
                )

            # Extract roles
            roles_str = headers.get(self.ROLES_HEADER)
            roles = self._parse_roles(roles_str) if roles_str else []

            # Extract request metadata
            user_agent = headers.get(self.USER_AGENT_HEADER)
            client_ip = self._extract_client_ip(request)
            path = self._extract_path(request)
            method = self._extract_method(request)

            # Handle anonymous requests, which may still be tenant-scoped
            if not actor_id:
                return RequestContextFactory.create_anonymous(
                    correlation_id=correlation_id,
                    tenant_id=tenant_id,
                    source_ip=client_ip,
                    user_agent=user_agent,
                    request_path=path,
                    request_method=method,
                )

            # Create full context
            return RequestContextFactory.create(
                correlation_id=correlation_id,
                actor_id=actor_id,
                actor_type=actor_type,
                tenant_id=tenant_id,
                roles=roles,
                source_ip=client_ip,
                user_agent=user_agent,
                request_path=path,
                request_method=method,
            )

        except (InvalidTenantError, InvalidActorError, InvalidCorrelationIdError):
            # Re-raise validation errors as-is
            raise
        except ValidationError as e:
            # Wrap validation errors
            raise ContextExtractionError(
                f"Context validation failed: {e.message}",
                source_error=e,
                details=e.details,
            )
        except Exception as e:
            # Wrap unexpected errors
            raise ContextExtractionError(
                f"Failed to extract context from request: {e}",
                source_error=e,
            )

    def _extract_headers(self, request: Any) -> dict[str, str | None]:
        """Extract headers from the request object."""
        if hasattr(request, "get_header"):
            return {
                self.CORRELATION_ID_HEADER: request.get_header(self.CORRELATION_ID_HEADER),
                self.ACTOR_ID_HEADER: request.get_header(self.ACTOR_ID_HEADER),
                self.ACTOR_TYPE_HEADER: request.get_header(self.ACTOR_TYPE_HEADER),
                self.TENANT_ID_HEADER: request.get_header(self.TENANT_ID_HEADER),
                self.ROLES_HEADER: request.get_header(self.ROLES_HEADER),
                self.USER_AGENT_HEADER: request.get_header(self.USER_AGENT_HEADER),
            }
        elif hasattr(request, "headers"):
            headers = request.headers
            return {
                self.CORRELATION_ID_HEADER: headers.get(self.CORRELATION_ID_HEADER),
                self.ACTOR_ID_HEADER: headers.get(self.ACTOR_ID_HEADER),
                self.ACTOR_TYPE_HEADER: headers.get(self.ACTOR_TYPE_HEADER),
                self.TENANT_ID_HEADER: headers.get(self.TENANT_ID_HEADER),
                self.ROLES_HEADER: headers.get(self.ROLES_HEADER),
                self.USER_AGENT_HEADER: headers.get(self.USER_AGENT_HEADER),
            }
        elif isinstance(request, dict):
            return {
                self.CORRELATION_ID_HEADER: request.get(self.CORRELATION_ID_HEADER),
                self.ACTOR_ID_HEADER: request.get(self.ACTOR_ID_HEADER),
                self.ACTOR_TYPE_HEADER: request.get(self.ACTOR_TYPE_HEADER),
                self.TENANT_ID_HEADER: request.get(self.TENANT_ID_HEADER),
                self.ROLES_HEADER: request.get(self.ROLES_HEADER),
                self.USER_AGENT_HEADER: request.get(self.USER_AGENT_HEADER),
            }
        else:
            raise ContextExtractionError(
                "Unsupported request type for header extraction",
                details={"request_type": type(request).__name__},
            )

    def _extract_client_ip(self, request: Any) -> str | None:
        """Extract client IP from the request."""
        if hasattr(request, "client_ip"):
            return request.client_ip
        if hasattr(request, "remote_addr"):
            return request.remote_addr
        if isinstance(request, dict):
            return request.get("client_ip")
        return None

    def _extract_path(self, request: Any) -> str | None:
        """Extract request path."""
        if hasattr(request, "path"):
            return request.path
        if hasattr(request, "url"):
            return str(request.url)
        if isinstance(request, dict):
            return request.get("path")
        return None

    def _extract_method(self, request: Any) -> str | None:
        """Extract request method."""
        if hasattr(request, "method"):
            return request.method
        if isinstance(request, dict):
            return request.get("method")
        return None

    def _parse_roles(self, roles_str: str) -> list[str]:
        """Parse comma-separated roles string."""
        if not roles_str:
            return []
        return [r.strip() for r in roles_str.split(",") if r.strip()]
