"""Versioned tenant lifecycle REST command endpoints."""

from __future__ import annotations

from typing import Any, Mapping

from eiams.application.administration import TenantLifecycleService
from eiams.application.dto.administration import (
    CreateTenantCommand,
    UpdateTenantCommand,
)
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
from eiams.shared.errors import (
    ApiErrorPayload,
    HttpStatusCode,
)
from eiams.shared.errors.exception_mapping import (
    ExceptionMapper,
    get_exception_mapper,
)
from eiams.shared.logging import LogLevel, LogOutcome, StructuredLogger, get_logger


TENANTS_COLLECTION_PATH = f"{API_BASE_PATH}/tenants"
TENANT_RESOURCE_PATH = f"{API_BASE_PATH}/tenants/{{tenant_id}}"
TENANT_DEACTIVATE_PATH = f"{API_BASE_PATH}/tenants/{{tenant_id}}/deactivate"


class _TenantEndpointBase(ApiEndpoint):
    """Shared wiring for tenant command endpoints."""

    def __init__(
        self,
        service: TenantLifecycleService,
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
            require_tenant=False,
            require_actor=True,
            default_actor_type=ActorType.USER,
        )
        self._exception_mapper = exception_mapper or get_exception_mapper()
        self._logger = logger or get_logger("tenant_api")

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
                resource_type="tenant",
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
            operation="tenant_command",
            outcome=outcome,
            message=message,
            level=(
                LogLevel.INFO if outcome == LogOutcome.SUCCESS else LogLevel.WARNING
            ),
            **extra,
        )


class CreateTenantEndpoint(_TenantEndpointBase):
    """``POST /api/v1/tenants``."""

    @property
    def method(self) -> str:
        return "POST"

    @property
    def path(self) -> str:
        return TENANTS_COLLECTION_PATH

    def handle(self, request: ApiRequest | Mapping[str, Any]) -> ApiResponse:
        normalized = self.coerce_request(request)
        try:
            context = self._extract_context(normalized)
            correlation_id = str(context.correlation_id)
            self._authorize(context, "create")
            payload = parse_json_object(normalized.body)
            command = CreateTenantCommand.from_dict(payload)
            result = self._service.create(context, command)
            self._log(context, LogOutcome.SUCCESS, "Tenant created")
            return ApiResponse.success(
                result.to_dict(),
                status_code=HttpStatusCode.CREATED,
                correlation_id=correlation_id,
            )
        except InvalidRequestBodyError as exc:
            return ApiResponse.invalid_request_format(str(exc))
        except Exception as exc:
            correlation_id = None
            try:
                correlation_id = str(self._extract_context(normalized).correlation_id)
            except Exception:
                correlation_id = normalized.get_header("X-Correlation-ID")
            return self._error_response(exc, correlation_id)


class GetTenantEndpoint(_TenantEndpointBase):
    """``GET /api/v1/tenants/{tenant_id}``."""

    @property
    def method(self) -> str:
        return "GET"

    @property
    def path(self) -> str:
        return TENANT_RESOURCE_PATH

    def handle(self, request: ApiRequest | Mapping[str, Any]) -> ApiResponse:
        normalized = self.coerce_request(request)
        try:
            context = self._extract_context(normalized)
            correlation_id = str(context.correlation_id)
            tenant_id = normalized.path_params.get("tenant_id", "")
            self._authorize(context, "read", tenant_id)
            result = self._service.get(context, tenant_id)
            self._log(context, LogOutcome.SUCCESS, "Tenant retrieved")
            return ApiResponse.success(result.to_dict(), correlation_id=correlation_id)
        except Exception as exc:
            correlation_id = normalized.get_header("X-Correlation-ID")
            return self._error_response(exc, correlation_id)


class UpdateTenantEndpoint(_TenantEndpointBase):
    """``PATCH /api/v1/tenants/{tenant_id}``."""

    @property
    def method(self) -> str:
        return "PATCH"

    @property
    def path(self) -> str:
        return TENANT_RESOURCE_PATH

    def handle(self, request: ApiRequest | Mapping[str, Any]) -> ApiResponse:
        normalized = self.coerce_request(request)
        try:
            context = self._extract_context(normalized)
            correlation_id = str(context.correlation_id)
            tenant_id = normalized.path_params.get("tenant_id", "")
            self._authorize(context, "update", tenant_id)
            payload = parse_json_object(normalized.body)
            command = UpdateTenantCommand.from_dict(payload)
            result = self._service.update(context, tenant_id, command)
            self._log(context, LogOutcome.SUCCESS, "Tenant updated")
            return ApiResponse.success(result.to_dict(), correlation_id=correlation_id)
        except InvalidRequestBodyError as exc:
            return ApiResponse.invalid_request_format(str(exc))
        except Exception as exc:
            correlation_id = normalized.get_header("X-Correlation-ID")
            return self._error_response(exc, correlation_id)


class DeactivateTenantEndpoint(_TenantEndpointBase):
    """``POST /api/v1/tenants/{tenant_id}/deactivate``."""

    @property
    def method(self) -> str:
        return "POST"

    @property
    def path(self) -> str:
        return TENANT_DEACTIVATE_PATH

    def handle(self, request: ApiRequest | Mapping[str, Any]) -> ApiResponse:
        normalized = self.coerce_request(request)
        try:
            context = self._extract_context(normalized)
            correlation_id = str(context.correlation_id)
            tenant_id = normalized.path_params.get("tenant_id", "")
            self._authorize(context, "deactivate", tenant_id)
            result = self._service.deactivate(context, tenant_id)
            self._log(context, LogOutcome.SUCCESS, "Tenant deactivated")
            return ApiResponse.success(result.to_dict(), correlation_id=correlation_id)
        except Exception as exc:
            correlation_id = normalized.get_header("X-Correlation-ID")
            return self._error_response(exc, correlation_id)


def register_tenant_endpoints(
    router: Any,
    service: TenantLifecycleService,
    **endpoint_kwargs: Any,
) -> None:
    """Register all tenant command endpoints on a router."""
    for endpoint_cls in (
        CreateTenantEndpoint,
        GetTenantEndpoint,
        UpdateTenantEndpoint,
        DeactivateTenantEndpoint,
    ):
        router.register(endpoint_cls(service, **endpoint_kwargs))
