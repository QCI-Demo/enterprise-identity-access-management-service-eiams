"""Integration tests for the versioned password login endpoint."""

import json

import pytest

from eiams.shared.config import MappingConfigurationProvider
from eiams.shared.kernel import TenantId
from eiams.domain.audit.contracts import AuditEventType
from eiams.domain.identity.contracts import UserStatus
from eiams.infrastructure.adapters.http_api import (
    API_VERSION,
    ApiRequest,
    ApiRouter,
)
from eiams.infrastructure.adapters.login_api import LOGIN_PATH
from tests.conftest import (
    KNOWN_EMAIL,
    KNOWN_PASSWORD,
    UNKNOWN_EMAIL,
    WRONG_PASSWORD,
    build_stack,
)


class TestVersionedRoute:
    """Tests for the endpoint's versioned surface."""

    def test_endpoint_is_registered_under_v1(self, stack):
        """The login route is versioned and served by POST."""
        assert stack.endpoint.path == "/api/v1/auth/login"
        assert stack.endpoint.method == "POST"
        assert stack.components.router.routes == (("POST", LOGIN_PATH),)

    def test_router_dispatches_to_the_endpoint(self, stack):
        """A routed request reaches the endpoint."""
        response = stack.components.router.dispatch(stack.request())
        assert response.status_code == 200

    def test_unknown_route_returns_not_found(self):
        """An unregistered route yields the standardized 404 payload."""
        response = ApiRouter().dispatch(
            {"method": "POST", "path": "/api/v1/auth/unknown", "body": {}}
        )
        assert response.status_code == 404
        assert response.body["error"]["code"] == "RESOURCE_NOT_FOUND"


class TestSuccessfulAuthentication:
    """Tests for the success response."""

    def test_success_returns_versioned_payload_without_a_token(self, stack):
        """A valid login returns identity metadata and no token."""
        response = stack.endpoint.handle(stack.request())

        assert response.status_code == 200
        assert response.body["api_version"] == API_VERSION
        data = response.body["data"]
        assert data["authenticated"] is True
        assert data["user_id"] == str(stack.user.user_id)
        assert data["tenant_id"] == str(stack.tenant_id)
        assert data["token_issued"] is False
        assert data["session_created"] is False

    def test_success_response_contains_no_token_material(self, stack):
        """No token, session, or credential value appears in the body."""
        serialized = stack.endpoint.handle(stack.request()).to_json()
        for forbidden in (
            "access_token",
            "refresh_token",
            "session_id",
            "argon2",
            KNOWN_PASSWORD,
            KNOWN_EMAIL,
        ):
            assert forbidden not in serialized

    def test_correlation_id_is_propagated(self, stack):
        """The request correlation ID is echoed in the response headers."""
        response = stack.endpoint.handle(
            stack.request(correlation_id="corr-login-echo")
        )
        assert response.headers["X-Correlation-ID"] == "corr-login-echo"

    def test_accepts_a_json_string_body(self, stack):
        """A JSON string body is parsed."""
        response = stack.endpoint.handle(
            stack.request(
                body=json.dumps(
                    {"identifier": KNOWN_EMAIL, "password": KNOWN_PASSWORD}
                )
            )
        )
        assert response.status_code == 200

    def test_accepts_a_typed_api_request(self, stack):
        """A typed ApiRequest is handled identically to a mapping."""
        response = stack.endpoint.handle(
            ApiRequest(
                method="POST",
                path=LOGIN_PATH,
                headers={"X-Tenant-ID": str(stack.tenant_id)},
                body={"identifier": KNOWN_EMAIL, "password": KNOWN_PASSWORD},
            )
        )
        assert response.status_code == 200

    def test_success_is_audited(self, stack):
        """A successful login records a success audit event."""
        stack.endpoint.handle(stack.request())
        assert stack.audit_events.events[0].event_type == (
            AuditEventType.LOGIN_SUCCESS
        )


class TestMalformedInput:
    """Tests for validation of malformed requests."""

    @pytest.mark.parametrize(
        "identifier,password,expected_fields",
        [
            (None, KNOWN_PASSWORD, {"identifier"}),
            (KNOWN_EMAIL, None, {"password"}),
            (None, None, {"identifier", "password"}),
            ("  ", KNOWN_PASSWORD, {"identifier"}),
            ("ab", KNOWN_PASSWORD, {"identifier"}),
            (KNOWN_EMAIL, "", {"password"}),
        ],
    )
    def test_missing_or_short_fields_are_rejected(
        self, stack, identifier, password, expected_fields
    ):
        """Missing and out-of-bounds fields yield field errors."""
        response = stack.endpoint.handle(
            stack.request(identifier=identifier, password=password)
        )

        assert response.status_code == 422
        assert response.body["error"]["code"] == "VALIDATION_FAILED"
        fields = {e["field"] for e in response.body["error"]["field_errors"]}
        assert fields == expected_fields

    def test_oversized_identifier_is_rejected(self, stack):
        """An identifier beyond the configured bound is rejected."""
        oversized = "a" * (stack.login_service.max_identifier_length + 1)
        response = stack.endpoint.handle(stack.request(identifier=oversized))

        assert response.status_code == 422
        assert response.body["error"]["field_errors"][0]["code"] == "too_long"

    def test_oversized_password_is_rejected(self, stack):
        """A password beyond the configured bound is rejected."""
        oversized = "x" * (stack.login_service.max_password_length + 1)
        response = stack.endpoint.handle(stack.request(password=oversized))

        assert response.status_code == 422
        assert response.body["error"]["field_errors"][0]["field"] == "password"

    def test_non_string_fields_are_rejected(self, stack):
        """Non-string field values are rejected."""
        response = stack.endpoint.handle(
            stack.request(body={"identifier": 42, "password": ["list"]})
        )

        assert response.status_code == 422
        codes = {e["code"] for e in response.body["error"]["field_errors"]}
        assert codes == {"invalid_type"}

    @pytest.mark.parametrize("body", ["not json", "[1, 2, 3]", None, 7])
    def test_unparsable_body_is_rejected(self, stack, body):
        """A body that is not a JSON object yields a format error."""
        request = stack.request()
        request["body"] = body
        response = stack.endpoint.handle(request)

        assert response.status_code == 400
        assert response.body["error"]["code"] == "INVALID_REQUEST_FORMAT"

    def test_validation_errors_do_not_echo_submitted_values(self, stack):
        """Validation responses never contain the submitted values."""
        response = stack.endpoint.handle(
            stack.request(identifier="ab", password=WRONG_PASSWORD)
        )
        serialized = response.to_json()
        assert WRONG_PASSWORD not in serialized
        assert "ab" not in serialized.replace("must be at least", "")

    def test_malformed_input_is_not_audited(self, stack):
        """Validation failures do not create authentication audit events."""
        stack.endpoint.handle(stack.request(identifier=None, password=None))
        assert stack.audit_events.events == ()


class TestMissingTenantContext:
    """Tests for tenant enforcement at the API edge."""

    def test_missing_tenant_header_is_refused(self, stack):
        """Login without tenant context is refused before authentication."""
        response = stack.endpoint.handle(stack.request(tenant=None))

        assert response.status_code == 403
        assert response.body["error"]["code"] == "TENANT_ACCESS_DENIED"

    def test_missing_tenant_does_not_authenticate(self, stack):
        """No authentication occurs and nothing is audited."""
        stack.endpoint.handle(stack.request(tenant=None))
        assert stack.audit_events.events == ()

    def test_malformed_tenant_header_is_refused(self, stack):
        """A malformed tenant identifier is refused safely."""
        request = stack.request()
        request["X-Tenant-ID"] = "not-a-uuid"
        response = stack.endpoint.handle(request)

        assert response.status_code == 403
        assert response.body["error"]["code"] == "TENANT_ACCESS_DENIED"
        assert KNOWN_PASSWORD not in response.to_json()

    def test_credentials_from_another_tenant_are_refused(self, stack):
        """A valid credential in another tenant does not authenticate."""
        response = stack.endpoint.handle(stack.request(tenant=TenantId.generate()))

        assert response.status_code == 401
        assert response.body["error"]["code"] == "CREDENTIALS_INVALID"


class TestNonEnumeratingFailures:
    """Tests that failure responses are indistinguishable."""

    def failure_responses(self, stack):
        """Collect responses for every enumeration-sensitive failure."""
        suspended = stack.add_user("suspended.user@example.com")
        stack.set_user_status(suspended, UserStatus.SUSPENDED)
        stack.add_user("no.credential@example.com", password=None)

        return {
            "unknown_identity": stack.endpoint.handle(
                stack.request(identifier=UNKNOWN_EMAIL, password=KNOWN_PASSWORD)
            ),
            "wrong_password": stack.endpoint.handle(
                stack.request(identifier=KNOWN_EMAIL, password=WRONG_PASSWORD)
            ),
            "ineligible_state": stack.endpoint.handle(
                stack.request(
                    identifier="suspended.user@example.com", password=KNOWN_PASSWORD
                )
            ),
            "missing_credential": stack.endpoint.handle(
                stack.request(
                    identifier="no.credential@example.com", password=KNOWN_PASSWORD
                )
            ),
        }

    def test_all_failures_share_the_same_status_and_body(self, stack):
        """Every failure returns one identical response."""
        responses = self.failure_responses(stack)

        bodies = {json.dumps(r.body, sort_keys=True) for r in responses.values()}
        statuses = {r.status_code for r in responses.values()}

        assert statuses == {401}
        assert len(bodies) == 1

    def test_failure_body_is_the_standardized_payload(self, stack):
        """The failure payload is the standardized credential error."""
        response = stack.endpoint.handle(
            stack.request(identifier=UNKNOWN_EMAIL, password=WRONG_PASSWORD)
        )

        assert response.status_code == 401
        assert response.body == {
            "error": {
                "code": "CREDENTIALS_INVALID",
                "message": "Invalid credentials",
                "correlation_id": "login-correlation-id",
            },
            "api_version": API_VERSION,
        }

    def test_failure_body_reveals_no_account_state(self, stack):
        """No response mentions account state or existence."""
        for response in self.failure_responses(stack).values():
            serialized = response.to_json().lower()
            for leak in (
                "suspended",
                "inactive",
                "pending",
                "not found",
                "unknown",
                "exists",
                "eligib",
                "password",
                "argon2",
            ):
                assert leak not in serialized

    def test_failure_responses_share_field_shape(self, stack):
        """Failure payloads carry no extra diagnostic fields."""
        for response in self.failure_responses(stack).values():
            assert set(response.body["error"]) == {
                "code",
                "message",
                "correlation_id",
            }

    def test_all_failures_are_audited_as_failures(self, stack):
        """Each failed attempt records exactly one failure event."""
        responses = self.failure_responses(stack)
        events = stack.audit_events.events

        assert len(events) == len(responses)
        assert all(e.event_type == AuditEventType.LOGIN_FAILURE for e in events)
        assert all(e.outcome == "failure" for e in events)


class TestConfiguredPolicyAtTheEdge:
    """Tests that injected policy changes endpoint behavior."""

    def test_configured_eligible_state_permits_login(self, tenant_id):
        """A configured additional state can authenticate."""
        configuration = MappingConfigurationProvider(
            {
                "security.password.algorithm": "pbkdf2_sha256",
                "security.password.pbkdf2.iterations": "100000",
                "security.authentication.eligible_user_statuses": (
                    "active,pending_verification"
                ),
            }
        )
        stack = build_stack(
            configuration, tenant_id, user_status=UserStatus.PENDING_VERIFICATION
        )

        response = stack.endpoint.handle(stack.request())
        assert response.status_code == 200

    def test_configured_bounds_apply_to_validation(self, tenant_id):
        """Configured maximum lengths drive the field errors."""
        configuration = MappingConfigurationProvider(
            {
                "security.password.algorithm": "pbkdf2_sha256",
                "security.password.pbkdf2.iterations": "100000",
                "security.password.max_length": "64",
                "security.authentication.max_identifier_length": "32",
            }
        )
        stack = build_stack(configuration, tenant_id)

        response = stack.endpoint.handle(stack.request(identifier="a" * 33))
        assert response.status_code == 422
        assert "32 characters" in response.body["error"]["field_errors"][0]["message"]

        response = stack.endpoint.handle(stack.request(password="x" * 65))
        assert response.status_code == 422
        assert "64 characters" in response.body["error"]["field_errors"][0]["message"]

    def test_pbkdf2_configuration_authenticates(self, tenant_id):
        """The stack authenticates under the PBKDF2 configuration."""
        configuration = MappingConfigurationProvider(
            {
                "security.password.algorithm": "pbkdf2_sha256",
                "security.password.pbkdf2.iterations": "100000",
            }
        )
        stack = build_stack(configuration, tenant_id)

        assert stack.endpoint.handle(stack.request()).status_code == 200
        assert (
            stack.endpoint.handle(stack.request(password=WRONG_PASSWORD)).status_code
            == 401
        )
