"""Versioned password login REST endpoint.

Exposes ``POST /api/v1/auth/login``. The endpoint validates bounded input
before invoking the service, requires tenant context, and returns the
standardized error payload for every authentication failure so responses
never reveal whether an identifier exists. No token is issued.
"""

from __future__ import annotations

from typing import Any, Mapping

from eiams.shared.context import ActorType, RequestContext
from eiams.shared.errors import (
    ApiErrorPayload,
    FieldError,
    ValidationApiError,
)
from eiams.shared.errors.exception_mapping import (
    ExceptionMapper,
    get_exception_mapper,
)
from eiams.shared.logging import (
    LogLevel,
    LogOutcome,
    StructuredLogger,
    get_logger,
)
from eiams.application.services.authentication import (
    LoginCommand,
    PasswordLoginService,
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
from eiams.infrastructure.adapters.validation import (
    RequestValidator,
    ValidationResult,
)


LOGIN_PATH = f"{API_BASE_PATH}/auth/login"
LOGIN_METHOD = "POST"
LOGIN_OPERATION = "password_login_request"

IDENTIFIER_FIELD = "identifier"
PASSWORD_FIELD = "password"
MIN_IDENTIFIER_LENGTH = 3


class LoginRequestValidator(RequestValidator[LoginCommand]):
    """Validates login request fields with bounded lengths.

    Field errors name the offending field and the rule that failed; they
    never echo the submitted identifier or password.
    """

    def __init__(
        self,
        max_identifier_length: int,
        max_password_length: int,
        min_identifier_length: int = MIN_IDENTIFIER_LENGTH,
    ) -> None:
        """Initialize the validator with configuration-derived bounds."""
        self._max_identifier_length = max_identifier_length
        self._max_password_length = max_password_length
        self._min_identifier_length = min_identifier_length

    def validate(
        self,
        data: dict[str, Any],
        context: RequestContext | None = None,
    ) -> ValidationResult[LoginCommand]:
        """Validate raw request data into a login command."""
        errors: list[FieldError] = []

        identifier = data.get(IDENTIFIER_FIELD)
        password = data.get(PASSWORD_FIELD)

        errors.extend(
            self._validate_field(
                field=IDENTIFIER_FIELD,
                value=identifier,
                min_length=self._min_identifier_length,
                max_length=self._max_identifier_length,
                strip=True,
            )
        )
        errors.extend(
            self._validate_field(
                field=PASSWORD_FIELD,
                value=password,
                min_length=1,
                max_length=self._max_password_length,
                strip=False,
            )
        )

        if errors:
            return ValidationResult.failure(*errors)

        return ValidationResult.success(
            LoginCommand.from_raw(identifier=identifier, password=password)
        )

    def _validate_field(
        self,
        field: str,
        value: Any,
        min_length: int,
        max_length: int,
        strip: bool,
    ) -> list[FieldError]:
        """Validate presence, type, and bounded length of one field."""
        if value is None:
            return [FieldError(field, "required", f"{field} is required")]
        if not isinstance(value, str):
            return [FieldError(field, "invalid_type", f"{field} must be a string")]

        candidate = value.strip() if strip else value
        if not candidate:
            return [FieldError(field, "required", f"{field} is required")]
        if len(candidate) < min_length:
            return [
                FieldError(
                    field,
                    "too_short",
                    f"{field} must be at least {min_length} characters",
                )
            ]
        if len(candidate) > max_length:
            return [
                FieldError(
                    field,
                    "too_long",
                    f"{field} must be at most {max_length} characters",
                )
            ]
        return []


class LoginEndpoint(ApiEndpoint):
    """Versioned REST endpoint for native password authentication."""

    def __init__(
        self,
        login_service: PasswordLoginService,
        validator: LoginRequestValidator | None = None,
        context_extractor: HttpContextExtractor | None = None,
        exception_mapper: ExceptionMapper | None = None,
        logger: StructuredLogger | None = None,
    ) -> None:
        """Initialize the endpoint.

        Args:
            login_service: Application service performing authentication.
            validator: Request validator. Defaults to bounds derived from
                the service's configured policy.
            context_extractor: Transport context extractor. Login is
                unauthenticated, so an actor header is not required, but
                tenant context is enforced by the service.
            exception_mapper: Mapper producing standardized error payloads.
            logger: Structured logger for safe request events.
        """
        self._service = login_service
        self._validator = validator or LoginRequestValidator(
            max_identifier_length=login_service.max_identifier_length,
            max_password_length=login_service.max_password_length,
        )
        self._context_extractor = context_extractor or HttpContextExtractor(
            require_tenant=False,
            require_actor=False,
            default_actor_type=ActorType.ANONYMOUS,
        )
        self._exception_mapper = exception_mapper or get_exception_mapper()
        self._logger = logger or get_logger("authentication_api")

    @property
    def method(self) -> str:
        return LOGIN_METHOD

    @property
    def path(self) -> str:
        return LOGIN_PATH

    def handle(self, request: ApiRequest | Mapping[str, Any]) -> ApiResponse:
        """Handle a login request and return a standardized response."""
        normalized = self.coerce_request(request)

        try:
            context = self._context_extractor.extract_context(normalized)
        except Exception as exc:
            return self._error_response(exc, correlation_id=None)

        correlation_id = str(context.correlation_id)

        try:
            payload = parse_json_object(normalized.body)
        except InvalidRequestBodyError as exc:
            self._log(context, LogOutcome.FAILURE, "Login request body rejected")
            return ApiResponse.invalid_request_format(
                message=str(exc),
                correlation_id=correlation_id,
            )

        try:
            command = self._validator.validate(payload, context).get_or_raise(
                correlation_id
            )
        except ValidationApiError as exc:
            self._log(context, LogOutcome.FAILURE, "Login request validation failed")
            return self._error_response(exc, correlation_id, context=context)

        try:
            result = self._service.execute(context, command)
        except Exception as exc:
            return self._error_response(exc, correlation_id, context=context)

        self._log(context, LogOutcome.SUCCESS, "Login request authenticated")
        return ApiResponse.success(result.to_dict(), correlation_id=correlation_id)

    def _error_response(
        self,
        exc: Exception,
        correlation_id: str | None,
        context: RequestContext | None = None,
    ) -> ApiResponse:
        """Map an exception to a standardized, safe error response."""
        payload: ApiErrorPayload = self._exception_mapper.map_exception(
            exc, correlation_id
        )
        if context is not None:
            self._log(
                context,
                LogOutcome.FAILURE,
                "Login request rejected",
                error_code=payload.code,
                status_code=payload.status_code,
            )
        return ApiResponse.from_error_payload(payload, correlation_id)

    def _log(
        self,
        context: RequestContext,
        outcome: LogOutcome,
        message: str,
        **extra: Any,
    ) -> None:
        """Emit a safe request-level log event.

        The request body is never logged: it carries the submitted
        identifier and password.
        """
        self._logger.log_operation(
            context=context,
            operation=LOGIN_OPERATION,
            outcome=outcome,
            message=message,
            level=(
                LogLevel.INFO if outcome == LogOutcome.SUCCESS else LogLevel.WARNING
            ),
            **extra,
        )


def create_login_endpoint(
    login_service: PasswordLoginService,
    logger: StructuredLogger | None = None,
) -> LoginEndpoint:
    """Create the versioned login endpoint for a login service."""
    return LoginEndpoint(login_service=login_service, logger=logger)
