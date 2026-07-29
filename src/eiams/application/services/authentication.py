"""Tenant-aware password login command service.

Resolves identity, evaluates configured account eligibility, and verifies
the protected password credential inside a single transactional scope.
Unknown identifiers, wrong passwords, unusable credentials, and ineligible
account states all raise the same uniform failure so callers cannot use
the login endpoint to discover which identifiers exist.

No session or token is created here; token issuance arrives with the JWT
lifecycle work.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from eiams.shared.context import RequestContext, require_tenant
from eiams.shared.errors import AuthenticationFailedError, ValidationError
from eiams.shared.kernel import SecretString, Timestamp
from eiams.shared.logging import (
    LogLevel,
    LogOutcome,
    StructuredLogger,
    get_logger,
)
from eiams.domain.authentication.contracts import (
    AuthenticationFailureCategory,
    AuthenticationMethod,
)
from eiams.domain.credentials.contracts import (
    PasswordVerificationOutcome,
    PasswordVerificationResult,
)
from eiams.domain.identity.contracts import User, UserRepository
from eiams.application.ports.transaction import UnitOfWorkFactory
from eiams.application.services.authentication_audit import (
    AuthenticationAuditRecorder,
)
from eiams.application.services.base import ApplicationService
from eiams.application.services.password_policy import AccountEligibilityPolicy
from eiams.application.services.password_verification import (
    PasswordVerificationService,
)


LOGIN_OPERATION = "password_login"
MIN_IDENTIFIER_LENGTH = 3


class LoginFailureReason(str, Enum):
    """Internal reason a login attempt did not succeed.

    Never surfaced externally; used only to choose the audit category and
    to explain failures in internal diagnostics.
    """

    UNKNOWN_IDENTITY = "unknown_identity"
    INVALID_PASSWORD = "invalid_password"
    CREDENTIAL_MISSING = "credential_missing"
    CREDENTIAL_UNUSABLE = "credential_unusable"
    INELIGIBLE_ACCOUNT_STATE = "ineligible_account_state"

    @property
    def audit_category(self) -> AuthenticationFailureCategory:
        """Coarse category recorded in the audit trail."""
        if self == LoginFailureReason.INELIGIBLE_ACCOUNT_STATE:
            return AuthenticationFailureCategory.INELIGIBLE_ACCOUNT_STATE
        return AuthenticationFailureCategory.INVALID_CREDENTIALS


_REASON_BY_VERIFICATION_OUTCOME: dict[
    PasswordVerificationOutcome, LoginFailureReason
] = {
    PasswordVerificationOutcome.NO_MATCH: LoginFailureReason.INVALID_PASSWORD,
    PasswordVerificationOutcome.CREDENTIAL_MISSING: LoginFailureReason.CREDENTIAL_MISSING,
    PasswordVerificationOutcome.CREDENTIAL_DISABLED: LoginFailureReason.CREDENTIAL_UNUSABLE,
    PasswordVerificationOutcome.CREDENTIAL_MALFORMED: LoginFailureReason.CREDENTIAL_UNUSABLE,
    PasswordVerificationOutcome.ALGORITHM_UNSUPPORTED: LoginFailureReason.CREDENTIAL_UNUSABLE,
}


@dataclass(frozen=True, repr=False)
class LoginCommand:
    """Validated input for a password login attempt.

    The password is carried as a wrapped secret so it cannot be printed,
    formatted, or serialized by accident.
    """

    identifier: str
    password: SecretString

    def __post_init__(self) -> None:
        """Validate the structural shape of the command."""
        if not isinstance(self.identifier, str):
            raise ValidationError("Identifier must be a string", field="identifier")
        if not isinstance(self.password, SecretString):
            raise ValidationError(
                "Password must be a wrapped secret value", field="password"
            )

    @classmethod
    def from_raw(cls, identifier: str, password: str) -> "LoginCommand":
        """Build a command from raw transport values."""
        if not isinstance(password, str):
            raise ValidationError("Password must be a string", field="password")
        return cls(identifier=identifier, password=SecretString(password))

    @property
    def normalized_identifier(self) -> str:
        """Identifier normalized for lookup (trimmed and lowercased)."""
        return self.identifier.strip().lower()

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize without the identifier value or the password."""
        return {
            "method": AuthenticationMethod.PASSWORD.value,
            "identifier_length": len(self.identifier.strip()),
            "password_length": self.password.length,
        }

    def __repr__(self) -> str:
        return "LoginCommand(identifier=[REDACTED], password=[REDACTED])"

    def __str__(self) -> str:
        return self.__repr__()


@dataclass(frozen=True)
class LoginResult:
    """Approved safe result of a successful password authentication.

    Contains no token and no session: this story authenticates only.
    """

    user_id: str
    tenant_id: str
    authenticated_at: Timestamp
    method: str = AuthenticationMethod.PASSWORD.value
    token_issued: bool = False
    session_created: bool = False
    credential_needs_rehash: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize for API responses."""
        return {
            "authenticated": True,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "authenticated_at": self.authenticated_at.to_iso(),
            "method": self.method,
            "token_issued": self.token_issued,
            "session_created": self.session_created,
        }


class PasswordLoginService(ApplicationService):
    """Authenticates a tenant user with an identifier and password."""

    def __init__(
        self,
        user_repository: UserRepository,
        password_verification_service: PasswordVerificationService,
        eligibility_policy: AccountEligibilityPolicy,
        audit_recorder: AuthenticationAuditRecorder,
        unit_of_work_factory: UnitOfWorkFactory,
        logger: StructuredLogger | None = None,
        clock: Callable[[], Timestamp] | None = None,
    ) -> None:
        """Initialize the login service.

        Args:
            user_repository: Repository used to resolve the identity.
            password_verification_service: Protected credential verifier.
            eligibility_policy: Configured eligible account states.
            audit_recorder: Recorder for safe authentication outcomes.
            unit_of_work_factory: Opens the transactional scope.
            logger: Structured logger for safe login events.
            clock: Timestamp source, injectable for tests.
        """
        self._user_repository = user_repository
        self._verification = password_verification_service
        self._eligibility_policy = eligibility_policy
        self._audit = audit_recorder
        self._unit_of_work_factory = unit_of_work_factory
        self._logger = logger or get_logger("authentication")
        self._clock = clock or Timestamp.now

    @property
    def eligibility_policy(self) -> AccountEligibilityPolicy:
        """The configured account eligibility policy."""
        return self._eligibility_policy

    @property
    def max_identifier_length(self) -> int:
        """Accepted upper bound for submitted identifiers."""
        return self._eligibility_policy.max_identifier_length

    @property
    def max_password_length(self) -> int:
        """Accepted upper bound for submitted passwords."""
        return self._verification.policy.max_password_length

    def execute(
        self,
        context: RequestContext,
        command: LoginCommand,
    ) -> LoginResult:
        """Authenticate a tenant user with a password.

        Args:
            context: Request context; tenant scope is required.
            command: Validated login command.

        Returns:
            The safe authentication result.

        Raises:
            TenantRequiredError: If tenant context is absent.
            ValidationError: If the command is structurally invalid.
            AuthenticationFailedError: For every authentication failure,
                regardless of the internal reason.
        """
        self._validate_context(context)
        require_tenant(context)
        self._validate_command(command)

        with self._unit_of_work_factory() as unit_of_work:
            user = self._resolve_user(context, command)
            reason, verification = self._evaluate(context, user, command)

            if reason is not None:
                self._audit.record_login_failure(
                    context=context,
                    failure_category=reason.audit_category,
                    user_id=user.user_id if user is not None else None,
                )
                unit_of_work.commit()
                self._log_internal_failure(context, reason)
                raise AuthenticationFailedError(reason=reason.value)

            assert user is not None  # guaranteed when reason is None
            result = LoginResult(
                user_id=str(user.user_id),
                tenant_id=str(context.tenant_id),
                authenticated_at=self._clock(),
                credential_needs_rehash=(
                    verification.needs_rehash if verification else False
                ),
            )

            self._audit.record_login_success(
                context=context,
                user_id=user.user_id,
                details={
                    "credential_algorithm": (
                        verification.algorithm.value
                        if verification and verification.algorithm
                        else None
                    ),
                    "needs_rehash": result.credential_needs_rehash,
                },
            )
            unit_of_work.commit()
            return result

    def _resolve_user(
        self,
        context: RequestContext,
        command: LoginCommand,
    ) -> User | None:
        """Resolve the identity for the submitted identifier."""
        return self._user_repository.find_by_email(
            context, command.normalized_identifier
        )

    def _evaluate(
        self,
        context: RequestContext,
        user: User | None,
        command: LoginCommand,
    ) -> tuple[LoginFailureReason | None, PasswordVerificationResult | None]:
        """Evaluate credential and account state for the attempt.

        Password verification always runs, including for accounts in an
        ineligible state, so that the eligibility decision is not
        observable through response timing.
        """
        if user is None:
            self._verification.verify_absent_credential(context, command.password)
            return LoginFailureReason.UNKNOWN_IDENTITY, None

        verification = self._verification.verify_user_password(
            context, user.user_id, command.password
        )
        is_eligible = self._eligibility_policy.is_eligible(user)

        if not verification.is_match:
            reason = _REASON_BY_VERIFICATION_OUTCOME.get(
                verification.outcome, LoginFailureReason.INVALID_PASSWORD
            )
            return reason, verification

        if not is_eligible:
            return LoginFailureReason.INELIGIBLE_ACCOUNT_STATE, verification

        return None, verification

    def _validate_command(self, command: LoginCommand) -> None:
        """Enforce bounded identifier and password input before execution."""
        if not isinstance(command, LoginCommand):
            raise ValidationError("A login command is required", field="request")

        identifier = command.identifier.strip()
        if not identifier:
            raise ValidationError("Identifier is required", field="identifier")
        if len(identifier) < MIN_IDENTIFIER_LENGTH:
            raise ValidationError(
                f"Identifier must be at least {MIN_IDENTIFIER_LENGTH} characters",
                field="identifier",
            )
        if len(identifier) > self.max_identifier_length:
            raise ValidationError(
                f"Identifier must be at most {self.max_identifier_length} characters",
                field="identifier",
            )

        if command.password.is_empty:
            raise ValidationError("Password is required", field="password")
        if command.password.length > self.max_password_length:
            raise ValidationError(
                f"Password must be at most {self.max_password_length} characters",
                field="password",
            )

    def _log_internal_failure(
        self,
        context: RequestContext,
        reason: LoginFailureReason,
    ) -> None:
        """Log the internal failure reason for operators.

        The reason names a condition, never an identifier or credential.
        """
        self._logger.log_operation(
            context=context,
            operation=LOGIN_OPERATION,
            outcome=LogOutcome.FAILURE,
            message="Password login rejected",
            level=LogLevel.WARNING,
            failure_reason=reason.value,
            failure_category=reason.audit_category.value,
        )
