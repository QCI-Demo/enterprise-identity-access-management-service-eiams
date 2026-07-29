"""Shared fixtures for authentication tests.

Provides a fully wired password login stack with deliberately low
cryptographic work factors so tests stay fast while still exercising the
real hashing adapters.
"""

from dataclasses import dataclass

import pytest

from eiams.shared.config import MappingConfigurationProvider
from eiams.shared.context import RequestContext, RequestContextFactory
from eiams.shared.kernel import SecretString, TenantId, Timestamp
from eiams.shared.logging import StructuredLogger
from eiams.shared.logging.structured_logging import CaptureLogOutput
from eiams.domain.credentials.contracts import (
    PasswordCredentialId,
    PasswordHashAlgorithm,
    StoredPasswordCredential,
)
from eiams.domain.identity.contracts import User, UserId, UserStatus
from eiams.composition.authentication import (
    AuthenticationComponents,
    create_authentication_components,
)
from eiams.infrastructure.persistence.in_memory import (
    InMemoryAuditEventRepository,
    InMemoryPasswordCredentialRepository,
    InMemoryUnitOfWorkFactory,
    InMemoryUserRepository,
)


# Synthetic secret markers used by redaction regression scans. They are
# distinctive enough that a substring search proves nothing leaked.
KNOWN_PASSWORD = "SyntheticMarker-Password-9f3a7c"
WRONG_PASSWORD = "SyntheticMarker-WrongPassword-1b2d8e"

KNOWN_EMAIL = "ada.lovelace@example.com"
UNKNOWN_EMAIL = "nobody.here@example.com"

# Low work factors: correctness is what these tests assert, not cost.
FAST_HASHING_CONFIG: dict[str, str] = {
    "security.password.algorithm": "argon2id",
    "security.password.argon2.time_cost": "1",
    "security.password.argon2.memory_cost_kib": "8192",
    "security.password.argon2.parallelism": "1",
    "security.password.pbkdf2.iterations": "100000",
    "security.authentication.eligible_user_statuses": "active",
}


@pytest.fixture
def fast_configuration() -> MappingConfigurationProvider:
    """Configuration provider with fast hashing parameters."""
    return MappingConfigurationProvider(dict(FAST_HASHING_CONFIG))


@pytest.fixture
def tenant_id() -> TenantId:
    """A tenant scope for the test."""
    return TenantId.generate()


@pytest.fixture
def other_tenant_id() -> TenantId:
    """A second tenant scope, used for isolation checks."""
    return TenantId.generate()


def build_user(
    tenant_id: TenantId,
    email: str = KNOWN_EMAIL,
    status: UserStatus = UserStatus.ACTIVE,
) -> User:
    """Build a user in a given tenant and account state."""
    now = Timestamp.now()
    return User(
        user_id=UserId.generate(),
        tenant_id=tenant_id,
        email=email,
        display_name="Ada Lovelace",
        status=status,
        created_at=now,
        updated_at=now,
    )


def build_credential(
    tenant_id: TenantId,
    user_id: UserId,
    protected_value: str,
    algorithm: PasswordHashAlgorithm = PasswordHashAlgorithm.ARGON2ID,
    is_active: bool = True,
) -> StoredPasswordCredential:
    """Build a stored password credential."""
    now = Timestamp.now()
    return StoredPasswordCredential(
        credential_id=PasswordCredentialId.generate(),
        tenant_id=tenant_id,
        user_id=user_id,
        algorithm=algorithm,
        protected_value=protected_value,
        created_at=now,
        updated_at=now,
        is_active=is_active,
    )


def anonymous_context(
    tenant_id: TenantId | None = None,
    correlation_id: str = "test-correlation-id",
) -> RequestContext:
    """Build the unauthenticated context a login request arrives with."""
    return RequestContextFactory.create_anonymous(
        correlation_id=correlation_id,
        tenant_id=str(tenant_id) if tenant_id else None,
        source_ip="203.0.113.10",
        user_agent="pytest",
        request_path="/api/v1/auth/login",
        request_method="POST",
    )


# Sentinel distinguishing "use the stack's tenant" from "send no tenant".
DEFAULT_TENANT = object()


@dataclass
class AuthenticationStack:
    """A wired login stack plus the doubles it was built from."""

    components: AuthenticationComponents
    users: InMemoryUserRepository
    credentials: InMemoryPasswordCredentialRepository
    audit_events: InMemoryAuditEventRepository
    unit_of_work_factory: InMemoryUnitOfWorkFactory
    log_output: CaptureLogOutput
    tenant_id: TenantId
    user: User

    @property
    def endpoint(self):
        """The versioned login endpoint."""
        return self.components.login_endpoint

    @property
    def login_service(self):
        """The login application service."""
        return self.components.login_service

    def request(
        self,
        identifier: str | None = KNOWN_EMAIL,
        password: str | None = KNOWN_PASSWORD,
        tenant: TenantId | None | object = DEFAULT_TENANT,
        correlation_id: str = "login-correlation-id",
        body: object = None,
    ) -> dict:
        """Build a login HTTP request payload.

        Pass ``tenant=None`` to omit the tenant header entirely.
        """
        resolved_tenant = self.tenant_id if tenant is DEFAULT_TENANT else tenant
        payload: object
        if body is not None:
            payload = body
        else:
            payload = {}
            if identifier is not None:
                payload["identifier"] = identifier
            if password is not None:
                payload["password"] = password

        request: dict = {
            "method": "POST",
            "path": self.endpoint.path,
            "body": payload,
            "X-Correlation-ID": correlation_id,
            "client_ip": "203.0.113.10",
        }
        if resolved_tenant is not None:
            request["X-Tenant-ID"] = str(resolved_tenant)
        return request

    def add_user(
        self,
        email: str,
        status: UserStatus = UserStatus.ACTIVE,
        password: str | None = KNOWN_PASSWORD,
    ) -> User:
        """Add a user with an optional password credential."""
        context = anonymous_context(self.tenant_id)
        user = build_user(self.tenant_id, email=email, status=status)
        self.users.save(context, user)
        if password is not None:
            protected = self.components.primary_hasher.hash_password(
                SecretString(password)
            )
            self.credentials.save(
                context,
                build_credential(
                    self.tenant_id,
                    user.user_id,
                    protected,
                    algorithm=self.components.hashing_policy.algorithm,
                ),
            )
        return user

    def set_user_status(self, user: User, status: UserStatus) -> User:
        """Replace the stored user with one in a different account state."""
        context = anonymous_context(self.tenant_id)
        updated = User(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            email=user.email,
            display_name=user.display_name,
            status=status,
            created_at=user.created_at,
            updated_at=Timestamp.now(),
        )
        self.users.save(context, updated)
        return updated

    def captured_log_json(self) -> str:
        """All captured log events serialized as one JSON blob."""
        return "\n".join(event.to_json() for event in self.log_output.events)

    def audit_json(self) -> str:
        """All recorded audit events serialized as one JSON blob."""
        import json

        return json.dumps([event.to_dict() for event in self.audit_events.events])


def build_stack(
    configuration: MappingConfigurationProvider,
    tenant_id: TenantId,
    user_status: UserStatus = UserStatus.ACTIVE,
    password: str | None = KNOWN_PASSWORD,
) -> AuthenticationStack:
    """Wire a login stack around in-memory adapters."""
    user = build_user(tenant_id, status=user_status)
    users = InMemoryUserRepository([user])
    credentials = InMemoryPasswordCredentialRepository()
    audit_events = InMemoryAuditEventRepository()
    unit_of_work_factory = InMemoryUnitOfWorkFactory()
    log_output = CaptureLogOutput()
    logger = StructuredLogger(output=log_output, name="test")

    components = create_authentication_components(
        configuration=configuration,
        user_repository=users,
        credential_repository=credentials,
        audit_event_repository=audit_events,
        unit_of_work_factory=unit_of_work_factory,
        logger=logger,
    )

    if password is not None:
        protected = components.primary_hasher.hash_password(SecretString(password))
        credentials.save(
            anonymous_context(tenant_id),
            build_credential(
                tenant_id,
                user.user_id,
                protected,
                algorithm=components.hashing_policy.algorithm,
            ),
        )

    return AuthenticationStack(
        components=components,
        users=users,
        credentials=credentials,
        audit_events=audit_events,
        unit_of_work_factory=unit_of_work_factory,
        log_output=log_output,
        tenant_id=tenant_id,
        user=user,
    )


@pytest.fixture
def stack(
    fast_configuration: MappingConfigurationProvider,
    tenant_id: TenantId,
) -> AuthenticationStack:
    """A wired login stack with one active user holding a known password."""
    return build_stack(fast_configuration, tenant_id)
