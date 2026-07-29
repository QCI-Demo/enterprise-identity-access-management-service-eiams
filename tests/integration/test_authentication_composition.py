"""Integration tests for authentication composition and transactions."""

import pytest

from eiams.shared.config import MappingConfigurationProvider
from eiams.shared.errors import ConfigurationError
from eiams.shared.kernel import SecretString, TenantId
from eiams.domain.audit.contracts import AuditEventType
from eiams.domain.credentials.contracts import PasswordHashAlgorithm
from eiams.application.services.authentication import LoginCommand
from eiams.composition import create_authentication_components
from eiams.composition.container import create_container
from eiams.infrastructure.adapters.login_api import LOGIN_PATH
from eiams.infrastructure.config import create_configuration_provider
from eiams.infrastructure.persistence.in_memory import (
    InMemoryAuditEventRepository,
    InMemoryPasswordCredentialRepository,
    InMemoryUnitOfWorkFactory,
    InMemoryUserRepository,
)
from tests.conftest import (
    KNOWN_EMAIL,
    KNOWN_PASSWORD,
    anonymous_context,
    build_credential,
    build_user,
)


class FailingAuditService:
    """Audit service double that refuses to record events."""

    def record_event(self, *args, **kwargs):
        raise RuntimeError("audit store unavailable")

    def record_authentication_event(self, *args, **kwargs):
        raise RuntimeError("audit store unavailable")

    def record_authorization_event(self, *args, **kwargs):
        raise RuntimeError("audit store unavailable")

    def query_events(self, *args, **kwargs):
        return []


def wire(configuration, tenant_id, audit_service=None):
    """Wire an authentication stack with in-memory adapters."""
    user = build_user(tenant_id)
    users = InMemoryUserRepository([user])
    credentials = InMemoryPasswordCredentialRepository()
    unit_of_work_factory = InMemoryUnitOfWorkFactory()

    components = create_authentication_components(
        configuration=configuration,
        user_repository=users,
        credential_repository=credentials,
        audit_event_repository=InMemoryAuditEventRepository(),
        unit_of_work_factory=unit_of_work_factory,
        audit_service=audit_service,
    )

    credentials.save(
        anonymous_context(tenant_id),
        build_credential(
            tenant_id,
            user.user_id,
            components.primary_hasher.hash_password(SecretString(KNOWN_PASSWORD)),
            algorithm=components.hashing_policy.algorithm,
        ),
    )
    return components, user, unit_of_work_factory


class TestComposition:
    """Tests for wiring the authentication module."""

    def test_environment_configuration_drives_the_stack(self, tenant_id):
        """Policy comes from the environment-backed provider."""
        configuration = create_configuration_provider(
            environ={
                "EIAMS_SECURITY__PASSWORD__ALGORITHM": "pbkdf2_sha256",
                "EIAMS_SECURITY__PASSWORD__PBKDF2__ITERATIONS": "150000",
                "EIAMS_SECURITY__AUTHENTICATION__ELIGIBLE_USER_STATUSES": "active",
            }
        )
        components, user, _ = wire(configuration, tenant_id)

        assert components.hashing_policy.algorithm == (
            PasswordHashAlgorithm.PBKDF2_SHA256
        )
        assert components.hashing_policy.pbkdf2_iterations == 150000

        result = components.login_service.execute(
            anonymous_context(tenant_id),
            LoginCommand.from_raw(KNOWN_EMAIL, KNOWN_PASSWORD),
        )
        assert result.user_id == str(user.user_id)

    def test_router_exposes_only_the_versioned_login_route(self, tenant_id):
        """The wired router publishes the versioned login route."""
        components, _, _ = wire(MappingConfigurationProvider({}), tenant_id)
        assert components.router.routes == (("POST", LOGIN_PATH),)
        assert components.router.resolve("POST", LOGIN_PATH) is (
            components.login_endpoint
        )

    def test_verification_service_supports_stored_algorithms(self, tenant_id):
        """Both adapters are wired so stored credentials remain verifiable."""
        components, _, _ = wire(MappingConfigurationProvider({}), tenant_id)
        assert PasswordHashAlgorithm.ARGON2ID in (
            components.verification_service.supported_algorithms
        )

    def test_invalid_configuration_fails_wiring(self, tenant_id):
        """Bad policy configuration fails at wiring time, not at login."""
        configuration = MappingConfigurationProvider(
            {"security.password.argon2.time_cost": "0"}
        )
        with pytest.raises(ConfigurationError):
            wire(configuration, tenant_id)

    def test_existing_module_container_still_wires(self):
        """The foundation container remains instantiable."""
        results = create_container().verify_modules_instantiable()
        assert all(results.values())


class TestTransactionBoundary:
    """Tests for the transactional scope around a login attempt."""

    def test_successful_login_commits_once(self, tenant_id):
        """A success commits its scope exactly once."""
        components, _, factory = wire(MappingConfigurationProvider({}), tenant_id)

        components.login_service.execute(
            anonymous_context(tenant_id),
            LoginCommand.from_raw(KNOWN_EMAIL, KNOWN_PASSWORD),
        )

        assert [(s.committed, s.rolled_back) for s in factory.scopes] == [(True, False)]

    def test_audit_failure_rolls_back_and_does_not_authenticate(self, tenant_id):
        """If the outcome cannot be audited, the attempt does not succeed."""
        components, _, factory = wire(
            MappingConfigurationProvider({}),
            tenant_id,
            audit_service=FailingAuditService(),
        )

        with pytest.raises(RuntimeError):
            components.login_service.execute(
                anonymous_context(tenant_id),
                LoginCommand.from_raw(KNOWN_EMAIL, KNOWN_PASSWORD),
            )

        assert [(s.committed, s.rolled_back) for s in factory.scopes] == [(False, True)]

    def test_audit_failure_maps_to_an_internal_error_response(self, tenant_id):
        """The endpoint reports a generic internal error, not a login result."""
        components, _, _ = wire(
            MappingConfigurationProvider({}),
            tenant_id,
            audit_service=FailingAuditService(),
        )

        response = components.login_endpoint.handle(
            {
                "method": "POST",
                "path": LOGIN_PATH,
                "X-Tenant-ID": str(tenant_id),
                "body": {"identifier": KNOWN_EMAIL, "password": KNOWN_PASSWORD},
            }
        )

        assert response.status_code == 500
        assert response.body["error"]["code"] == "INTERNAL_ERROR"
        assert "audit store" not in response.to_json()
        assert KNOWN_PASSWORD not in response.to_json()

    def test_scope_is_not_reusable_after_commit(self):
        """A committed scope refuses further work."""
        factory = InMemoryUnitOfWorkFactory()
        scope = factory()
        scope.commit()

        assert scope.is_active is False
        with pytest.raises(RuntimeError):
            scope.commit()

    def test_abandoned_scope_rolls_back(self):
        """Leaving a scope without committing rolls it back."""
        factory = InMemoryUnitOfWorkFactory()
        with factory() as scope:
            pass
        assert scope.rolled_back is True


class TestTenantIsolationInAdapters:
    """Tests that in-memory adapters enforce tenant scope."""

    def test_credentials_are_not_visible_across_tenants(self, tenant_id):
        """A credential is invisible outside its tenant."""
        components, user, _ = wire(MappingConfigurationProvider({}), tenant_id)
        other_context = anonymous_context(TenantId.generate())

        found = components.verification_service.verify_user_password(
            other_context, user.user_id, SecretString(KNOWN_PASSWORD)
        )
        assert found.is_match is False

    def test_audit_events_record_the_requesting_tenant(self, tenant_id):
        """Audit events carry the tenant of the request."""
        repository = InMemoryAuditEventRepository()
        user = build_user(tenant_id)
        users = InMemoryUserRepository([user])
        credentials = InMemoryPasswordCredentialRepository()
        components = create_authentication_components(
            configuration=MappingConfigurationProvider({}),
            user_repository=users,
            credential_repository=credentials,
            audit_event_repository=repository,
        )
        credentials.save(
            anonymous_context(tenant_id),
            build_credential(
                tenant_id,
                user.user_id,
                components.primary_hasher.hash_password(SecretString(KNOWN_PASSWORD)),
                algorithm=components.hashing_policy.algorithm,
            ),
        )

        components.login_service.execute(
            anonymous_context(tenant_id),
            LoginCommand.from_raw(KNOWN_EMAIL, KNOWN_PASSWORD),
        )

        events = repository.find_by_tenant(tenant_id)
        assert len(events) == 1
        assert events[0].event_type == AuditEventType.LOGIN_SUCCESS
