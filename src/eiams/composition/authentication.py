"""Composition wiring for the password authentication module.

Builds the login stack from configuration: hashing policy and adapters,
account eligibility policy, credential verification, audit recording, the
transaction scope, and the versioned REST endpoint. Every policy value is
injected from the supplied configuration provider.
"""

from dataclasses import dataclass

from eiams.shared.config import ConfigurationProvider
from eiams.shared.logging import SecretRedactor, StructuredLogger
from eiams.domain.audit.contracts import AuditEventRepository, AuditService
from eiams.domain.credentials.contracts import PasswordCredentialRepository
from eiams.domain.identity.contracts import UserRepository
from eiams.application.ports.security import PasswordHasher
from eiams.application.ports.transaction import UnitOfWorkFactory
from eiams.application.services.authentication import PasswordLoginService
from eiams.application.services.authentication_audit import (
    AuthenticationAuditRecorder,
)
from eiams.application.services.password_policy import (
    AccountEligibilityPolicy,
    PasswordHashingPolicy,
)
from eiams.application.services.password_verification import (
    PasswordVerificationService,
)
from eiams.infrastructure.adapters.audit_recording import RedactingAuditService
from eiams.infrastructure.adapters.http_api import ApiRouter
from eiams.infrastructure.adapters.login_api import (
    LoginEndpoint,
    create_login_endpoint,
)
from eiams.infrastructure.persistence.in_memory import (
    InMemoryAuditEventRepository,
    InMemoryUnitOfWorkFactory,
)
from eiams.infrastructure.security.password_hashing import create_password_hashers


@dataclass(frozen=True)
class AuthenticationComponents:
    """The wired password authentication stack."""

    hashing_policy: PasswordHashingPolicy
    eligibility_policy: AccountEligibilityPolicy
    password_hashers: tuple[PasswordHasher, ...]
    verification_service: PasswordVerificationService
    audit_service: AuditService
    audit_recorder: AuthenticationAuditRecorder
    login_service: PasswordLoginService
    login_endpoint: LoginEndpoint
    router: ApiRouter

    @property
    def primary_hasher(self) -> PasswordHasher:
        """The adapter for the configured algorithm."""
        return self.password_hashers[0]


def create_authentication_components(
    configuration: ConfigurationProvider,
    user_repository: UserRepository,
    credential_repository: PasswordCredentialRepository,
    audit_event_repository: AuditEventRepository | None = None,
    unit_of_work_factory: UnitOfWorkFactory | None = None,
    audit_service: AuditService | None = None,
    logger: StructuredLogger | None = None,
    redactor: SecretRedactor | None = None,
) -> AuthenticationComponents:
    """Wire the password authentication stack from configuration.

    Args:
        configuration: Provider supplying hashing and eligibility policy.
        user_repository: Repository resolving tenant identities.
        credential_repository: Repository of protected password credentials.
        audit_event_repository: Store for audit events. Defaults to the
            in-memory store.
        unit_of_work_factory: Transaction scope factory. Defaults to the
            in-memory scope.
        audit_service: Audit contract implementation. Defaults to the
            redacting service over ``audit_event_repository``.
        logger: Structured logger shared by the stack.
        redactor: Secret redactor shared by audit and logging.

    Returns:
        The wired components, including the versioned login endpoint.
    """
    hashing_policy = PasswordHashingPolicy.from_configuration(configuration)
    eligibility_policy = AccountEligibilityPolicy.from_configuration(configuration)
    hashers = create_password_hashers(hashing_policy)

    verification_service = PasswordVerificationService(
        credential_repository=credential_repository,
        hashers=hashers,
        policy=hashing_policy,
        logger=logger,
    )

    resolved_audit_service = audit_service or RedactingAuditService(
        repository=audit_event_repository or InMemoryAuditEventRepository(),
        redactor=redactor,
    )
    audit_recorder = AuthenticationAuditRecorder(
        audit_service=resolved_audit_service,
        logger=logger,
        redactor=redactor,
    )

    login_service = PasswordLoginService(
        user_repository=user_repository,
        password_verification_service=verification_service,
        eligibility_policy=eligibility_policy,
        audit_recorder=audit_recorder,
        unit_of_work_factory=unit_of_work_factory or InMemoryUnitOfWorkFactory(),
        logger=logger,
    )

    login_endpoint = create_login_endpoint(login_service, logger=logger)
    router = ApiRouter()
    router.register(login_endpoint)

    return AuthenticationComponents(
        hashing_policy=hashing_policy,
        eligibility_policy=eligibility_policy,
        password_hashers=tuple(hashers),
        verification_service=verification_service,
        audit_service=resolved_audit_service,
        audit_recorder=audit_recorder,
        login_service=login_service,
        login_endpoint=login_endpoint,
        router=router,
    )
