"""Framework-neutral HTTP request and response primitives for the API edge.

The service exposes versioned REST endpoints without binding to a specific
web framework. A host framework adapts its own request objects into
:class:`ApiRequest` and writes :class:`ApiResponse` back out, so routing,
validation, and error conventions stay identical across hosts.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping

from eiams.shared.errors import (
    ApiErrorCode,
    ApiErrorPayload,
    HttpStatusCode,
)


API_VERSION = "v1"
API_BASE_PATH = f"/api/{API_VERSION}"
CORRELATION_ID_HEADER = "X-Correlation-ID"
CONTENT_TYPE_HEADER = "Content-Type"
JSON_CONTENT_TYPE = "application/json"

_PARAM_PATTERN = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


@dataclass(frozen=True)
class ApiRequest:
    """An inbound HTTP request normalized for endpoint handling."""

    method: str
    path: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: Any = None
    client_ip: str | None = None
    path_params: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ApiRequest":
        """Build a request from a plain mapping.

        Header entries may be supplied either nested under ``headers`` or
        flattened alongside ``method``, ``path``, ``body``, and
        ``client_ip``, which keeps test and host adapters simple.
        """
        reserved = {
            "method",
            "path",
            "body",
            "client_ip",
            "headers",
            "path_params",
        }
        headers: dict[str, str] = {}
        nested = data.get("headers")
        if isinstance(nested, Mapping):
            headers.update(
                {str(k): str(v) for k, v in nested.items() if v is not None}
            )
        for key, value in data.items():
            if key not in reserved and value is not None:
                headers[str(key)] = str(value)

        path_params = data.get("path_params") or {}
        if not isinstance(path_params, Mapping):
            path_params = {}

        return cls(
            method=str(data.get("method", "POST")),
            path=str(data.get("path", "")),
            headers=headers,
            body=data.get("body"),
            client_ip=data.get("client_ip"),
            path_params={str(k): str(v) for k, v in path_params.items()},
        )

    def get_header(self, name: str) -> str | None:
        """Resolve a header value case-insensitively."""
        target = name.lower()
        for key, value in self.headers.items():
            if str(key).lower() == target:
                return value
        return None

    def with_path_params(self, path_params: Mapping[str, str]) -> "ApiRequest":
        """Return a copy of this request with resolved path parameters."""
        return ApiRequest(
            method=self.method,
            path=self.path,
            headers=self.headers,
            body=self.body,
            client_ip=self.client_ip,
            path_params=dict(path_params),
        )


class InvalidRequestBodyError(Exception):
    """Raised when a request body is not a usable JSON object."""


@dataclass(frozen=True)
class ApiResponse:
    """An outbound HTTP response with a JSON-serializable body."""

    status_code: int
    body: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def success(
        cls,
        data: dict[str, Any],
        status_code: int | HttpStatusCode = HttpStatusCode.OK,
        correlation_id: str | None = None,
    ) -> "ApiResponse":
        """Build a versioned success response."""
        return cls(
            status_code=(
                status_code.value
                if isinstance(status_code, HttpStatusCode)
                else status_code
            ),
            body={"data": data, "api_version": API_VERSION},
            headers=_response_headers(correlation_id),
        )

    @classmethod
    def from_error_payload(
        cls,
        payload: ApiErrorPayload,
        correlation_id: str | None = None,
    ) -> "ApiResponse":
        """Build a response from a standardized error payload."""
        return cls(
            status_code=payload.status_code,
            body=payload.to_dict(),
            headers=_response_headers(correlation_id or payload.correlation_id),
        )

    @classmethod
    def invalid_request_format(
        cls,
        message: str = "Request body must be a JSON object",
        correlation_id: str | None = None,
    ) -> "ApiResponse":
        """Build a response for an unparsable request body."""
        payload = ApiErrorPayload(
            code=ApiErrorCode.INVALID_REQUEST_FORMAT.value,
            message=message,
            correlation_id=correlation_id,
            status_code=HttpStatusCode.BAD_REQUEST.value,
        )
        return cls.from_error_payload(payload, correlation_id)

    def to_json(self) -> str:
        """Serialize the response body as JSON."""
        return json.dumps(self.body)


def _response_headers(correlation_id: str | None) -> dict[str, str]:
    """Build standard response headers, including correlation propagation."""
    headers = {CONTENT_TYPE_HEADER: JSON_CONTENT_TYPE}
    if correlation_id:
        headers[CORRELATION_ID_HEADER] = correlation_id
    return headers


def parse_json_object(body: Any) -> dict[str, Any]:
    """Coerce a request body into a JSON object.

    Args:
        body: A mapping, a JSON string, or bytes.

    Returns:
        The parsed object as a dictionary.

    Raises:
        InvalidRequestBodyError: If the body is absent or is not an object.
    """
    if body is None:
        raise InvalidRequestBodyError("Request body is required")
    if isinstance(body, Mapping):
        return dict(body)
    if isinstance(body, (str, bytes, bytearray)):
        try:
            parsed = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise InvalidRequestBodyError("Request body is not valid JSON")
        if not isinstance(parsed, dict):
            raise InvalidRequestBodyError("Request body must be a JSON object")
        return parsed
    raise InvalidRequestBodyError("Request body must be a JSON object")


def compile_path_template(template: str) -> re.Pattern[str]:
    """Compile a `/api/v1/resources/{id}` template into a matcher."""
    parts: list[str] = []
    index = 0
    for match in _PARAM_PATTERN.finditer(template):
        parts.append(re.escape(template[index:match.start()]))
        parts.append(f"(?P<{match.group(1)}>[^/]+)")
        index = match.end()
    parts.append(re.escape(template[index:]))
    return re.compile("^" + "".join(parts) + "$")


class ApiEndpoint(ABC):
    """A versioned REST endpoint."""

    @property
    @abstractmethod
    def method(self) -> str:
        """The HTTP method this endpoint serves."""
        ...

    @property
    @abstractmethod
    def path(self) -> str:
        """The versioned path this endpoint serves."""
        ...

    @abstractmethod
    def handle(self, request: ApiRequest | Mapping[str, Any]) -> ApiResponse:
        """Handle a request and return a response."""
        ...

    @staticmethod
    def coerce_request(request: ApiRequest | Mapping[str, Any]) -> ApiRequest:
        """Normalize supported request inputs into an ``ApiRequest``."""
        if isinstance(request, ApiRequest):
            return request
        if isinstance(request, Mapping):
            return ApiRequest.from_mapping(request)
        raise InvalidRequestBodyError("Unsupported request type")


@dataclass(frozen=True)
class _Route:
    method: str
    template: str
    pattern: re.Pattern[str]
    endpoint: ApiEndpoint


class ApiRouter:
    """Minimal router mapping method and path templates to endpoints."""

    def __init__(self) -> None:
        self._routes: list[_Route] = []

    def register(self, endpoint: ApiEndpoint) -> None:
        """Register an endpoint for its method and path template."""
        self._routes.append(
            _Route(
                method=endpoint.method.upper(),
                template=endpoint.path,
                pattern=compile_path_template(endpoint.path),
                endpoint=endpoint,
            )
        )

    @property
    def routes(self) -> tuple[tuple[str, str], ...]:
        """All registered method and path pairs."""
        return tuple(sorted((route.method, route.template) for route in self._routes))

    def resolve(
        self, method: str, path: str
    ) -> tuple[ApiEndpoint, dict[str, str]] | None:
        """Resolve an endpoint and path parameters for a method and path."""
        method_key = method.upper()
        for route in self._routes:
            if route.method != method_key:
                continue
            match = route.pattern.match(path)
            if match is not None:
                return route.endpoint, match.groupdict()
        return None

    def dispatch(self, request: ApiRequest | Mapping[str, Any]) -> ApiResponse:
        """Dispatch a request to its endpoint.

        Returns a 404 error response when no endpoint matches.
        """
        normalized = ApiEndpoint.coerce_request(request)
        resolved = self.resolve(normalized.method, normalized.path)
        if resolved is None:
            payload = ApiErrorPayload(
                code=ApiErrorCode.RESOURCE_NOT_FOUND.value,
                message="Resource not found",
                correlation_id=normalized.get_header(CORRELATION_ID_HEADER),
                status_code=HttpStatusCode.NOT_FOUND.value,
            )
            return ApiResponse.from_error_payload(payload)
        endpoint, path_params = resolved
        return endpoint.handle(normalized.with_path_params(path_params))
