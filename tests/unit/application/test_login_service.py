"""Tests for the tenant-aware password login service."""

import pytest

from eiams.shared.config import MappingConfigurationProvider
from eiams.shared.errors import (
    AuthenticationFailedError,
    TenantRequiredError,
    ValidationError,
)
from eiams.shared.kernel import SecretString, Timestamp
from eiams.domain.audit.contracts import AuditEventType
from eiams.domain.identity.contracts import UserStatus
from eiams.application.services.authentication import (
    LoginCommand,
    LoginFailureReason,
    LoginResult,
    PasswordLoginService,
)
from tests.conftest import (
    KNOWN_EMAIL,
    KNOWN_PASSWORD,
    UNKNOWN_EMAIL,
    WRONG_PASSWORD,
    anonymous_context,
    build_stack,
)


def command(identifier: str = KNOWN_EMAIL, password: str = KNOWN_PASSWORD):
    """Build a login command."""
    return LoginCommand.from_raw(identifier=identifier, password=password)


class TestSuccessfulLogin:
    """Tests for the successful authentication path."""

    def test_returns_safe_result_without_a_token(self, stack):
        """Success yields identity metadata and no token."""
        result = stack.login_service.execute(
            anonymous_context(stack.tenant_id), command()
        )

        assert isinstance(result, LoginResult)
        assert result.user_id == str(stack.user.user_id)
        assert result.tenant_id == str(stack.tenant_id)
        assert result.token_issued is False
        assert result.session_created is False
        assert result.to_dict()["authenticated"] is True
        assert "token" not in result.to_dict()

    def test_identifier_matching_is_case_and_space_insensitive(self, stack):
        """Identifiers are normalized before lookup."""
        result = stack.login_service.execute(
            anonymous_context(stack.tenant_id),
            command(identifier=f"  {KNOWN_EMAIL.upper()}  "),
        )
        assert result.user_id == str(stack.user.user_id)

    def test_success_commits_the_transaction(self, stack):
        """The transactional scope is committed exactly once."""
        stack.login_service.execute(anonymous_context(stack.tenant_id), command())

        scopes = stack.unit_of_work_factory.scopes
        assert len(scopes) == 1
        assert scopes[0].committed is True
        assert scopes[0].rolled_back is False

    def test_success_records_a_login_success_event(self, stack):
        """A success audit event is recorded for the resolved user."""
        stack.login_service.execute(anonymous_context(stack.tenant_id), command())

        events = stack.audit_events.events
        assert len(events) == 1
        assert events[0].event_type == AuditEventType.LOGIN_SUCCESS
        assert events[0].actor_id == str(stack.user.user_id)

    def test_authenticated_at_uses_injected_clock(self, fast_configuration, tenant_id):
        """The result timestamp comes from the injected clock."""
        stack = build_stack(fast_configuration, tenant_id)
        fixed = Timestamp.from_iso("2026-01-01T00:00:00.000Z")
        service = PasswordLoginService(
            user_repository=stack.users,
            password_verification_service=stack.components.verification_service,
            eligibility_policy=stack.components.eligibility_policy,
            audit_recorder=stack.components.audit_recorder,
            unit_of_work_factory=stack.unit_of_work_factory,
            clock=lambda: fixed,
        )

        result = service.execute(anonymous_context(tenant_id), command())
        assert result.authenticated_at == fixed


class TestUniformFailures:
    """Tests that every failure mode is externally identical."""

    @pytest.mark.parametrize(
        "identifier,password",
        [
            (UNKNOWN_EMAIL, KNOWN_PASSWORD),
            (KNOWN_EMAIL, WRONG_PASSWORD),
        ],
    )
    def test_unknown_identity_and_wrong_password_raise_the_same_error(
        self, stack, identifier, password
    ):
        """Both failures raise the identical uniform error."""
        with pytest.raises(AuthenticationFailedError) as exc_info:
            stack.login_service.execute(
                anonymous_context(stack.tenant_id), command(identifier, password)
            )

        assert exc_info.value.message == "Authentication failed"
        assert exc_info.value.details == {}

    @pytest.mark.parametrize(
        "status",
        [UserStatus.INACTIVE, UserStatus.SUSPENDED, UserStatus.PENDING_VERIFICATION],
    )
    def test_ineligible_account_state_is_rejected(self, stack, status):
        """An ineligible account cannot authenticate with a valid password."""
        stack.set_user_status(stack.user, status)

        with pytest.raises(AuthenticationFailedError) as exc_info:
            stack.login_service.execute(
                anonymous_context(stack.tenant_id), command()
            )

        assert exc_info.value.reason == (
            LoginFailureReason.INELIGIBLE_ACCOUNT_STATE.value
        )
        assert exc_info.value.details == {}

    def test_configured_state_becomes_eligible(self, tenant_id):
        """Configuration decides which states may authenticate."""
        configuration = MappingConfigurationProvider(
            {
                "security.password.algorithm": "argon2id",
                "security.password.argon2.time_cost": "1",
                "security.password.argon2.memory_cost_kib": "8192",
                "security.password.argon2.parallelism": "1",
                "security.authentication.eligible_user_statuses": (
                    "active,pending_verification"
                ),
            }
        )
        stack = build_stack(
            configuration, tenant_id, user_status=UserStatus.PENDING_VERIFICATION
        )

        result = stack.login_service.execute(
            anonymous_context(tenant_id), command()
        )
        assert result.user_id == str(stack.user.user_id)

    def test_missing_credential_is_rejected(self, fast_configuration, tenant_id):
        """A user without a stored credential cannot authenticate."""
        stack = build_stack(fast_configuration, tenant_id, password=None)

        with pytest.raises(AuthenticationFailedError) as exc_info:
            stack.login_service.execute(anonymous_context(tenant_id), command())

        assert exc_info.value.reason == LoginFailureReason.CREDENTIAL_MISSING.value

    def test_malformed_stored_credential_is_rejected(self, stack):
        """A credential stored unprotected cannot authenticate."""
        context = anonymous_context(stack.tenant_id)
        stored = stack.credentials.find_active_by_user(context, stack.user.user_id)
        from tests.conftest import build_credential

        stack.credentials.delete(context, stored.credential_id)
        stack.credentials.save(
            context,
            build_credential(stack.tenant_id, stack.user.user_id, KNOWN_PASSWORD),
        )

        with pytest.raises(AuthenticationFailedError) as exc_info:
            stack.login_service.execute(context, command())

        assert exc_info.value.reason == LoginFailureReason.CREDENTIAL_UNUSABLE.value

    def test_failures_record_a_login_failure_event(self, stack):
        """Failures are audited and the transaction is committed."""
        with pytest.raises(AuthenticationFailedError):
            stack.login_service.execute(
                anonymous_context(stack.tenant_id),
                command(password=WRONG_PASSWORD),
            )

        events = stack.audit_events.events
        assert len(events) == 1
        assert events[0].event_type == AuditEventType.LOGIN_FAILURE
        assert stack.unit_of_work_factory.scopes[0].committed is True

    def test_unknown_identity_failure_event_has_no_actor(self, stack):
        """An unresolved identifier yields an actorless audit event."""
        with pytest.raises(AuthenticationFailedError):
            stack.login_service.execute(
                anonymous_context(stack.tenant_id), command(identifier=UNKNOWN_EMAIL)
            )

        event = stack.audit_events.events[0]
        assert event.actor_id is None
        assert event.resource_id is None
        assert event.details["failure_category"] == "invalid_credentials"

    def test_ineligible_and_invalid_credentials_share_the_audit_outcome(self, stack):
        """Both categories record a failure outcome with no identifier."""
        stack.set_user_status(stack.user, UserStatus.SUSPENDED)
        with pytest.raises(AuthenticationFailedError):
            stack.login_service.execute(anonymous_context(stack.tenant_id), command())

        event = stack.audit_events.events[0]
        assert event.outcome == "failure"
        assert event.details["failure_category"] == "ineligible_account_state"
        assert KNOWN_EMAIL not in str(event.to_dict())


class TestTenantEnforcement:
    """Tests for tenant scope requirements."""

    def test_missing_tenant_context_is_refused(self, stack):
        """Login is refused without tenant context."""
        with pytest.raises(TenantRequiredError):
            stack.login_service.execute(anonymous_context(None), command())

        assert stack.audit_events.events == ()
        assert stack.unit_of_work_factory.scopes == ()

    def test_other_tenant_cannot_resolve_the_identity(
        self, stack, other_tenant_id
    ):
        """A different tenant cannot authenticate the same identifier."""
        with pytest.raises(AuthenticationFailedError) as exc_info:
            stack.login_service.execute(
                anonymous_context(other_tenant_id), command()
            )

        assert exc_info.value.reason == LoginFailureReason.UNKNOWN_IDENTITY.value


class TestBoundedInputValidation:
    """Tests for bounded field validation before execution."""

    def test_blank_identifier_is_a_validation_error(self, stack):
        """A blank identifier fails validation rather than authentication."""
        with pytest.raises(ValidationError) as exc_info:
            stack.login_service.execute(
                anonymous_context(stack.tenant_id), command(identifier="   ")
            )
        assert exc_info.value.field == "identifier"

    def test_short_identifier_is_a_validation_error(self, stack):
        """An identifier below the floor fails validation."""
        with pytest.raises(ValidationError):
            stack.login_service.execute(
                anonymous_context(stack.tenant_id), command(identifier="ab")
            )

    def test_oversized_identifier_is_a_validation_error(self, stack):
        """An identifier beyond the configured bound fails validation."""
        oversized = "a" * (stack.login_service.max_identifier_length + 1)
        with pytest.raises(ValidationError):
            stack.login_service.execute(
                anonymous_context(stack.tenant_id), command(identifier=oversized)
            )

    def test_empty_password_is_a_validation_error(self, stack):
        """An empty password fails validation."""
        with pytest.raises(ValidationError) as exc_info:
            stack.login_service.execute(
                anonymous_context(stack.tenant_id), command(password="")
            )
        assert exc_info.value.field == "password"

    def test_oversized_password_is_a_validation_error(self, stack):
        """A password beyond the configured bound fails validation."""
        oversized = "x" * (stack.login_service.max_password_length + 1)
        with pytest.raises(ValidationError):
            stack.login_service.execute(
                anonymous_context(stack.tenant_id), command(password=oversized)
            )

    def test_validation_failures_are_not_audited(self, stack):
        """Malformed input does not produce authentication audit events."""
        with pytest.raises(ValidationError):
            stack.login_service.execute(
                anonymous_context(stack.tenant_id), command(identifier="")
            )
        assert stack.audit_events.events == ()


class TestLoginCommand:
    """Tests for the login command value object."""

    def test_password_is_wrapped(self):
        """The command wraps the password in a secret value."""
        assert isinstance(command().password, SecretString)
        assert command().password.reveal() == KNOWN_PASSWORD

    def test_representation_omits_inputs(self):
        """repr and str never render the identifier or password."""
        rendered = f"{command()!r} {command()}"
        assert KNOWN_PASSWORD not in rendered
        assert KNOWN_EMAIL not in rendered

    def test_safe_dict_reports_lengths_only(self):
        """The safe view reports lengths, not values."""
        safe = command().to_safe_dict()
        assert safe["identifier_length"] == len(KNOWN_EMAIL)
        assert safe["password_length"] == len(KNOWN_PASSWORD)
        assert KNOWN_EMAIL not in str(safe)

    def test_non_string_inputs_are_rejected(self):
        """Non-string inputs are rejected at construction."""
        with pytest.raises(ValidationError):
            LoginCommand.from_raw(identifier=KNOWN_EMAIL, password=None)
        with pytest.raises(ValidationError):
            LoginCommand(identifier=123, password=SecretString(KNOWN_PASSWORD))
        with pytest.raises(ValidationError):
            LoginCommand(identifier=KNOWN_EMAIL, password=KNOWN_PASSWORD)

    def test_failure_reason_maps_to_audit_category(self):
        """Only ineligible state maps to its own audit category."""
        assert (
            LoginFailureReason.UNKNOWN_IDENTITY.audit_category.value
            == "invalid_credentials"
        )
        assert (
            LoginFailureReason.INVALID_PASSWORD.audit_category.value
            == "invalid_credentials"
        )
        assert (
            LoginFailureReason.CREDENTIAL_UNUSABLE.audit_category.value
            == "invalid_credentials"
        )
        assert (
            LoginFailureReason.INELIGIBLE_ACCOUNT_STATE.audit_category.value
            == "ineligible_account_state"
        )
