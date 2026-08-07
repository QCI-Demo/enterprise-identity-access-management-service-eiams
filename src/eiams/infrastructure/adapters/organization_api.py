"""Versioned organization lifecycle REST command endpoints."""

from __future__ import annotations

from typing import Any, Mapping

from eiams.application.dto.identity import (
    CreateOrganizationCommand,
    UpdateOrganizationCommand,
)
from eiams.application.identity import OrganizationLifecycleService
from eiams.infrastructure.adapters.authorization_middleware import (
    AuthorizationMiddleware,
    ProtectedOperationMetadata,
    create_authorization_middleware,
)
from eiams.infrastructure.adapters.http_api import (
    API_BASE_PATH,
    ApiEndpoint,
    ApiRequest,
    ApiResponse,
    InvalidRequestBodyError,
    parse_json_object,
)
from eiams.infrastructure.adapters.transport import HttpContextExtractor
from eiams.shared.context import ActorType, RequestContext
from eiams.shared.errors import ApiErrorPayload, HttpStatusCode
from eiams.shared.errors.exception_mapping import (
    ExceptionMapper,
    get_exception_mapper,
)
from eiams.shared.logging import LogLevel, LogOutcome, StructuredLogger, get_logger


ORGANIZATIONS_COLLECTION_PATH = f"{API_BASE_PATH}/organizations"
ORGANIZATION_RESOURCE_PATH = f"{API_BASE_PATH}/organizations/{{organization_id}}"
ORGANIZATION_DEACTIVATE_PATH = (
    f"{API_BASE_PATH}/organizations/{{organization_id}}/deactivate"
)


class _OrganizationEndpointBase(ApiEndpoint):
    """Shared wiring for organization command endpoints."""

    def __init__(
        self,
        service: OrganizationLifecycleService,
        *,
        authorization: AuthorizationMiddleware | None = None,
        context_extractor: HttpContextExtractor | None = None,
        exception_mapper: ExceptionMapper | None = None,
        logger: StructuredLogger | None = None,
    ) -> None:
        self._service = service
        self._authorization = authorization or create_authorization_middleware(
            fail_open=True
        )
        self._context_extractor = context_extractor or HttpContextExtractor(
            require_tenant=True,
            require_actor=True,
            default_actor_type=ActorType.USER,
        )
        self._exception_mapper = exception_mapper or get_exception_mapper()
        self._logger = logger or get_logger("organization_api")

    def _extract_context(self, request: ApiRequest) -> RequestContext:
        return self._context_extractor.extract_context(request)

    def _authorize(
        self,
        context: RequestContext,
        action: str,
        resource_id: str | None = None,
    ) -> None:
        self._authorization.require_authorization(
            context,
            ProtectedOperationMetadata(
                resource_type="organization",
                action=action,
                resource_id=resource_id,
            ),
        )

    def _error_response(
        self,
        exc: Exception,
        correlation_id: str | None,
    ) -> ApiResponse:
        payload: ApiErrorPayload = self._exception_mapper.map_exception(
            exc, correlation_id
        )
        return ApiResponse.from_error_payload(payload, correlation_id)

    def _log(
        self,
        context: RequestContext,
        outcome: LogOutcome,
        message: str,
        **extra: Any,
    ) -> None:
        self._logger.log_operation(
            context=context,
            operation="organization_command",
            outcome=outcome,
            message=message,
            level=(
                LogLevel.INFO if outcome == LogOutcome.SUCCESS else LogLevel.WARNING
            ),
            **extra,
        )


class CreateOrganizationEndpoint(_OrganizationEndpointBase):
    """``POST /api/v1/organizations``."""

    @property
    def method(self) -> str:
        return "POST"

    @property
    def path(self) -> str:
        return ORGANIZATIONS_COLLECTION_PATH

    def handle(self, request: ApiRequest | Mapping[str, Any]) -> ApiResponse:
        normalized = self.coerce_request(request)
        try:
            context = self._extract_context(normalized)
            correlation_id = str(context.correlation_id)
            self._authorize(context, "create")
            payload = parse_json_object(normalized.body)
            command = CreateOrganizationCommand.from_dict(payload)
            result = self._service.create(context, command)
            self._log(context, LogOutcome.SUCCESS, "Organization created")
            return ApiResponse.success(
                result.to_dict(),
                status_code=HttpStatusCode.CREATED,
                correlation_id=correlation_id,
            )
        except InvalidRequestBodyError as exc:
            return ApiResponse.invalid_request_format(str(exc))
        except Exception as exc:
            correlation_id = normalized.get_header("X-Correlation-ID")
            return self._error_response(exc, correlation_id)


class GetOrganizationEndpoint(_OrganizationEndpointBase):
    """``GET /api/v1/organizations/{organization_id}``."""

    @property
    def method(self) -> str:
        return "GET"

    @property
    def path(self) -> str:
        return ORGANIZATION_RESOURCE_PATH

    def handle(self, request: ApiRequest | Mapping[str, Any]) -> ApiResponse:
        normalized = self.coerce_request(request)
        try:
            context = self._extract_context(normalized)
            correlation_id = str(context.correlation_id)
            organization_id = normalized.path_params.get("organization_id", "")
            self._authorize(context, "read", organization_id)
            result = self._service.get(context, organization_id)
            self._log(context, LogOutcome.SUCCESS, "Organization retrieved")
            return ApiResponse.success(result.to_dict(), correlation_id=correlation_id)
        except Exception as exc:
            correlation_id = normalized.get_header("X-Correlation-ID")
            return self._error_response(exc, correlation_id)


class UpdateOrganizationEndpoint(_OrganizationEndpointBase):
    """``PATCH /api/v1/organizations/{organization_id}``."""

    @property
    def method(self) -> str:
        return "PATCH"

    @property
    def path(self) -> str:
        return ORGANIZATION_RESOURCE_PATH

    def handle(self, request: ApiRequest | Mapping[str, Any]) -> ApiResponse:
        normalized = self.coerce_request(request)
        try:
            context = self._extract_context(normalized)
            correlation_id = str(context.correlation_id)
            organization_id = normalized.path_params.get("organization_id", "")
            self._authorize(context, "update", organization_id)
            payload = parse_json_object(normalized.body)
            command = UpdateOrganizationCommand.from_dict(payload)
            result = self._service.update(context, organization_id, command)
            self._log(context, LogOutcome.SUCCESS, "Organization updated")
            return ApiResponse.success(result.to_dict(), correlation_id=correlation_id)
        except InvalidRequestBodyError as exc:
            return ApiResponse.invalid_request_format(str(exc))
        except Exception as exc:
            correlation_id = normalized.get_header("X-Correlation-ID")
            return self._error_response(exc, correlation_id)


class DeactivateOrganizationEndpoint(_OrganizationEndpointBase):
    """``POST /api/v1/organizations/{organization_id}/deactivate``."""

    @property
    def method(self) -> str:
        return "POST"

    @property
    def path(self) -> str:
        return ORGANIZATION_DEACTIVATE_PATH

    def handle(self, request: ApiRequest | Mapping[str, Any]) -> ApiResponse:
        normalized = self.coerce_request(request)
        try:
            context = self._extract_context(normalized)
            correlation_id = str(context.correlation_id)
            organization_id = normalized.path_params.get("organization_id", "")
            self._authorize(context, "deactivate", organization_id)
            result = self._service.deactivate(context, organization_id)
            self._log(context, LogOutcome.SUCCESS, "Organization deactivated")
            return ApiResponse.success(result.to_dict(), correlation_id=correlation_id)
        except Exception as exc:
            correlation_id = normalized.get_header("X-Correlation-ID")
            return self._error_response(exc, correlation_id)


def register_organization_endpoints(
    router: Any,
    service: OrganizationLifecycleService,
    **endpoint_kwargs: Any,
) -> None:
    """Register all organization command endpoints on a router."""
    for endpoint_cls in (
        CreateOrganizationEndpoint,
        GetOrganizationEndpoint,
        UpdateOrganizationEndpoint,
        DeactivateOrganizationEndpoint,
    ):
        router.register(endpoint_cls(service, **endpoint_kwargs))
