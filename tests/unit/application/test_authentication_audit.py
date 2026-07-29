"""Tests for safe authentication audit recording."""

import json

import pytest

from eiams.shared.context import RequestContextFactory
from eiams.shared.kernel import ActorId, TenantId
from eiams.shared.logging import StructuredLogger
from eiams.shared.logging.structured_logging import CaptureLogOutput
from eiams.domain.audit.contracts import AuditEventType, AuditSeverity
from eiams.domain.authentication.contracts import AuthenticationFailureCategory
from eiams.domain.identity.contracts import UserId
from eiams.application.services.authentication_audit import (
    AuthenticationAuditRecorder,
    SAFE_AUDIT_DETAIL_KEYS,
)
from eiams.infrastructure.adapters.audit_recording import RedactingAuditService
from eiams.infrastructure.persistence.in_memory import InMemoryAuditEventRepository
from tests.conftest import KNOWN_EMAIL, KNOWN_PASSWORD, anonymous_context


@pytest.fixture
def recorder_setup(tenant_id):
    """A recorder wired to in-memory audit storage and captured logs."""
    repository = InMemoryAuditEventRepository()
    log_output = CaptureLogOutput()
    recorder = AuthenticationAuditRecorder(
        audit_service=RedactingAuditService(repository),
        logger=StructuredLogger(output=log_output),
    )
    return recorder, repository, log_output


class TestSuccessEvents:
    """Tests for success event content."""

    def test_success_event_carries_required_fields(self, recorder_setup, tenant_id):
        """A success event records actor, tenant, outcome, time, and correlation."""
        recorder, repository, _ = recorder_setup
        user_id = UserId.generate()
        context = anonymous_context(tenant_id, correlation_id="corr-success-1")

        event = recorder.record_login_success(context, user_id)

        assert event.event_type == AuditEventType.LOGIN_SUCCESS
        assert event.severity == AuditSeverity.INFO
        assert event.outcome == "success"
        assert event.actor_id == str(user_id)
        assert event.tenant_id == tenant_id
        assert event.correlation_id == "corr-success-1"
        assert event.timestamp is not None
        assert event.resource_type == "user"
        assert event.resource_id == str(user_id)
        assert repository.events == (event,)

    def test_success_event_reports_no_token_or_session(self, recorder_setup, tenant_id):
        """The event states that no token or session was created."""
        recorder, _, _ = recorder_setup
        event = recorder.record_login_success(
            anonymous_context(tenant_id), UserId.generate()
        )
        assert event.details["token_issued"] is False
        assert event.details["session_created"] is False
        assert event.details["method"] == "password"

    def test_allow_listed_details_are_preserved(self, recorder_setup, tenant_id):
        """Approved metadata passes through."""
        recorder, _, _ = recorder_setup
        event = recorder.record_login_success(
            anonymous_context(tenant_id),
            UserId.generate(),
            details={"credential_algorithm": "argon2id", "needs_rehash": True},
        )
        assert event.details["credential_algorithm"] == "argon2id"
        assert event.details["needs_rehash"] is True


class TestFailureEvents:
    """Tests for failure event content."""

    def test_failure_event_carries_category_and_no_actor_when_unknown(
        self, recorder_setup, tenant_id
    ):
        """An unresolved identity produces an actorless failure event."""
        recorder, _, _ = recorder_setup
        event = recorder.record_login_failure(
            anonymous_context(tenant_id),
            AuthenticationFailureCategory.INVALID_CREDENTIALS,
        )

        assert event.event_type == AuditEventType.LOGIN_FAILURE
        assert event.severity == AuditSeverity.WARNING
        assert event.outcome == "failure"
        assert event.actor_id is None
        assert event.resource_id is None
        assert event.details["failure_category"] == "invalid_credentials"

    def test_failure_event_records_actor_when_known(self, recorder_setup, tenant_id):
        """A resolved identity becomes the actor and target."""
        recorder, _, _ = recorder_setup
        user_id = UserId.generate()

        event = recorder.record_login_failure(
            anonymous_context(tenant_id),
            AuthenticationFailureCategory.INELIGIBLE_ACCOUNT_STATE,
            user_id=user_id,
        )

        assert event.actor_id == str(user_id)
        assert event.resource_id == str(user_id)
        assert event.details["failure_category"] == "ineligible_account_state"


class TestMetadataFiltering:
    """Tests that unsafe metadata cannot reach the audit trail."""

    @pytest.mark.parametrize(
        "unsafe",
        [
            {"password": KNOWN_PASSWORD},
            {"identifier": KNOWN_EMAIL},
            {"email": KNOWN_EMAIL},
            {"protected_value": "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$ZGlnZXN0"},
            {"access_token": "at_synthetic_marker"},
            {"submitted_username": KNOWN_EMAIL},
        ],
    )
    def test_unapproved_keys_are_dropped(self, recorder_setup, tenant_id, unsafe):
        """Metadata outside the allow-list never reaches the event."""
        recorder, _, log_output = recorder_setup

        event = recorder.record_login_success(
            anonymous_context(tenant_id), UserId.generate(), details=unsafe
        )

        serialized = json.dumps(event.to_dict())
        for key, value in unsafe.items():
            assert key not in event.details
            assert value not in serialized

        log_serialized = "\n".join(e.to_json() for e in log_output.events)
        for value in unsafe.values():
            assert value not in log_serialized

    def test_core_fields_cannot_be_overridden(self, recorder_setup, tenant_id):
        """Caller metadata cannot rewrite the recorded outcome."""
        recorder, _, _ = recorder_setup
        event = recorder.record_login_success(
            anonymous_context(tenant_id),
            UserId.generate(),
            details={"outcome": "failure", "token_issued": True},
        )
        assert event.details["outcome"] == "success"
        assert event.details["token_issued"] is False

    def test_allow_list_is_explicit(self):
        """The allow-list contains no identifier or credential keys."""
        assert "identifier" not in SAFE_AUDIT_DETAIL_KEYS
        assert "email" not in SAFE_AUDIT_DETAIL_KEYS
        assert "password" not in SAFE_AUDIT_DETAIL_KEYS
        assert "protected_value" not in SAFE_AUDIT_DETAIL_KEYS


class TestAuditServiceAdapter:
    """Tests for the redacting audit service adapter."""

    def test_authenticated_actor_is_used_when_no_user_supplied(self, tenant_id):
        """A non-anonymous context actor is recorded."""
        repository = InMemoryAuditEventRepository()
        service = RedactingAuditService(repository)
        actor_id = ActorId.generate()
        context = RequestContextFactory.create(
            actor_id=str(actor_id), tenant_id=str(tenant_id)
        )

        event = service.record_authentication_event(
            context=context,
            event_type=AuditEventType.LOGIN_FAILURE,
            outcome="failure",
        )

        assert event.actor_id == str(actor_id)

    def test_details_are_redacted_by_the_service(self, tenant_id):
        """The service redacts sensitive details defensively."""
        repository = InMemoryAuditEventRepository()
        service = RedactingAuditService(repository)

        event = service.record_event(
            context=anonymous_context(tenant_id),
            event_type=AuditEventType.LOGIN_FAILURE,
            action="login",
            outcome="failure",
            details={"password": KNOWN_PASSWORD, "nested": {"secret": "s3cr3t"}},
        )

        serialized = json.dumps(event.to_dict())
        assert KNOWN_PASSWORD not in serialized
        assert "s3cr3t" not in serialized

    def test_events_are_queryable_by_correlation_id(self, tenant_id):
        """Recorded events can be retrieved by correlation ID."""
        repository = InMemoryAuditEventRepository()
        service = RedactingAuditService(repository)
        context = anonymous_context(tenant_id, correlation_id="corr-query-1")

        service.record_authentication_event(
            context=context,
            event_type=AuditEventType.LOGIN_SUCCESS,
            outcome="success",
            user_id=UserId.generate(),
        )

        found = service.query_events(context, {"correlation_id": "corr-query-1"})
        assert len(found) == 1

    def test_audit_events_cannot_be_deleted(self, tenant_id):
        """The append-only contract refuses deletion."""
        repository = InMemoryAuditEventRepository()
        with pytest.raises(NotImplementedError):
            repository.delete(anonymous_context(tenant_id), UserId.generate())
