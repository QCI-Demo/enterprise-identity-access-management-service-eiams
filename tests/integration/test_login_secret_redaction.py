"""Regression tests that login never emits credential material.

Every scan below uses synthetic secret markers: distinctive strings that
are submitted as credentials and then searched for in captured logs, API
responses, audit events, and mapped errors.
"""

import json

import pytest

from eiams.shared.config import MappingConfigurationProvider
from eiams.shared.errors import AuthenticationFailedError
from eiams.shared.errors.exception_mapping import map_exception_to_response
from eiams.shared.kernel import SecretString
from eiams.shared.logging import SecretRedactor
from eiams.domain.identity.contracts import UserStatus
from tests.conftest import (
    KNOWN_EMAIL,
    KNOWN_PASSWORD,
    UNKNOWN_EMAIL,
    WRONG_PASSWORD,
    build_stack,
)


# Synthetic markers submitted as credentials during the scans.
MARKER_PASSWORD = "SyntheticMarker-Login-Password-a1b2c3d4"
MARKER_IDENTIFIER = "SyntheticMarker-Login-Identifier@example.com"


def all_emitted_output(stack) -> str:
    """Collect every observable output surface as one searchable blob."""
    return "\n".join([stack.captured_log_json(), stack.audit_json()])


def stored_protected_values(stack) -> list[str]:
    """Every protected credential value currently stored."""
    from tests.conftest import anonymous_context

    context = anonymous_context(stack.tenant_id)
    credential = stack.credentials.find_active_by_user(context, stack.user.user_id)
    return [credential.protected_value] if credential else []


class TestSuccessfulLoginObservability:
    """Scans for the successful path."""

    def test_no_credential_material_in_logs_or_audit(self, stack):
        """A successful login emits no password and no stored hash."""
        response = stack.endpoint.handle(stack.request())
        assert response.status_code == 200

        emitted = all_emitted_output(stack)
        assert KNOWN_PASSWORD not in emitted
        for protected in stored_protected_values(stack):
            assert protected not in emitted
            assert protected not in response.to_json()

    def test_submitted_identifier_is_not_emitted(self, stack):
        """The submitted identifier stays out of logs and audit events."""
        stack.endpoint.handle(stack.request())
        assert KNOWN_EMAIL not in all_emitted_output(stack)

    def test_logs_record_outcome_and_correlation(self, stack):
        """Safe observability is still present after redaction."""
        stack.endpoint.handle(stack.request(correlation_id="corr-safe-1"))

        emitted = stack.captured_log_json()
        assert "corr-safe-1" in emitted
        assert "password_login" in emitted
        assert '"outcome": "success"' in emitted


class TestFailedLoginObservability:
    """Scans for every failure path."""

    @pytest.mark.parametrize(
        "identifier,password",
        [
            (MARKER_IDENTIFIER, MARKER_PASSWORD),
            (KNOWN_EMAIL, MARKER_PASSWORD),
            (MARKER_IDENTIFIER, KNOWN_PASSWORD),
        ],
    )
    def test_markers_never_appear_anywhere(self, stack, identifier, password):
        """Submitted markers appear in no response, log, or audit event."""
        response = stack.endpoint.handle(
            stack.request(identifier=identifier, password=password)
        )

        surfaces = [response.to_json(), all_emitted_output(stack)]
        for surface in surfaces:
            assert MARKER_PASSWORD not in surface
            assert MARKER_IDENTIFIER not in surface

    def test_ineligible_state_scan(self, stack):
        """The ineligible path emits no marker and no account state."""
        stack.set_user_status(stack.user, UserStatus.SUSPENDED)

        response = stack.endpoint.handle(
            stack.request(identifier=KNOWN_EMAIL, password=MARKER_PASSWORD)
        )

        assert response.status_code == 401
        assert MARKER_PASSWORD not in response.to_json()
        assert MARKER_PASSWORD not in all_emitted_output(stack)
        assert "suspended" not in response.to_json().lower()

    def test_malformed_stored_credential_scan(self, stack):
        """A plaintext stored credential is never echoed back."""
        from tests.conftest import anonymous_context, build_credential

        context = anonymous_context(stack.tenant_id)
        existing = stack.credentials.find_active_by_user(context, stack.user.user_id)
        stack.credentials.delete(context, existing.credential_id)
        stack.credentials.save(
            context,
            build_credential(stack.tenant_id, stack.user.user_id, MARKER_PASSWORD),
        )

        response = stack.endpoint.handle(
            stack.request(identifier=KNOWN_EMAIL, password=MARKER_PASSWORD)
        )

        assert response.status_code == 401
        assert MARKER_PASSWORD not in response.to_json()
        assert MARKER_PASSWORD not in all_emitted_output(stack)

    def test_oversized_input_scan(self, stack):
        """A rejected oversized password is not echoed in field errors."""
        oversized = MARKER_PASSWORD * 40
        response = stack.endpoint.handle(stack.request(password=oversized))

        assert response.status_code == 422
        assert MARKER_PASSWORD not in response.to_json()
        assert MARKER_PASSWORD not in all_emitted_output(stack)

    def test_unparsable_body_scan(self, stack):
        """A malformed body containing a marker is not echoed."""
        response = stack.endpoint.handle(
            stack.request(body=f'{{"identifier": "x", "password": "{MARKER_PASSWORD}"')
        )

        assert response.status_code == 400
        assert MARKER_PASSWORD not in response.to_json()
        assert MARKER_PASSWORD not in all_emitted_output(stack)

    def test_missing_tenant_scan(self, stack):
        """A tenantless request containing a marker is not echoed."""
        response = stack.endpoint.handle(
            stack.request(password=MARKER_PASSWORD, tenant=None)
        )

        assert response.status_code == 403
        assert MARKER_PASSWORD not in response.to_json()
        assert MARKER_PASSWORD not in all_emitted_output(stack)


class TestErrorSurfaces:
    """Scans of the standardized error surfaces."""

    def test_authentication_failure_error_carries_no_details(self):
        """The uniform error exposes no internal reason externally."""
        error = AuthenticationFailedError(reason="unknown_identity")

        response = map_exception_to_response(error, "corr-error-1")

        assert response["error"]["code"] == "CREDENTIALS_INVALID"
        assert response["error"]["message"] == "Invalid credentials"
        assert "details" not in response["error"]
        assert "unknown_identity" not in json.dumps(response)
        assert "unknown_identity" not in repr(error)

    def test_configuration_errors_do_not_leak_outward(self):
        """Configuration problems map to a generic internal error."""
        from eiams.shared.errors import ConfigurationError

        error = ConfigurationError(
            "Bad work factor", key="security.password.argon2.time_cost"
        )
        response = map_exception_to_response(error, "corr-error-2")

        assert response["error"]["code"] == "INTERNAL_ERROR"
        assert "security.password" not in json.dumps(response)

    def test_secret_marker_in_exception_message_is_redacted(self):
        """A marker inside an unexpected error message is redacted."""
        redactor = SecretRedactor()
        redacted = redactor.redact(
            RuntimeError(f"failed for password={MARKER_PASSWORD}")
        )
        payload = json.dumps(redacted)
        assert MARKER_PASSWORD not in payload
        assert "[REDACTED]" in payload


class TestRedactionConfiguration:
    """Tests for redaction configuration used by authentication."""

    def test_credential_keys_are_redacted_by_default(self):
        """Credential-bearing keys are redacted without configuration."""
        redacted = SecretRedactor().redact_for_logging(
            {
                "password": MARKER_PASSWORD,
                "protected_value": "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$ZGlnZXN0",
                "nested": {"user_password": MARKER_PASSWORD},
            }
        )
        payload = json.dumps(redacted)
        assert MARKER_PASSWORD not in payload
        assert redacted["password"] == "[REDACTED]"
        assert redacted["nested"]["user_password"] == "[REDACTED]"

    def test_safe_keys_are_exempt_but_values_are_still_scanned(self):
        """Allow-listed flag keys keep their value; secrets still redact."""
        from eiams.shared.logging import RedactionConfig

        redactor = SecretRedactor(
            RedactionConfig().with_safe_keys("token_issued", "credential_algorithm")
        )
        redacted = redactor.redact_for_logging(
            {
                "token_issued": False,
                "credential_algorithm": "argon2id",
                "access_token": "at_marker",
                "nested": {"token_issued": True},
            }
        )

        assert redacted["token_issued"] is False
        assert redacted["credential_algorithm"] == "argon2id"
        assert redacted["access_token"] == "[REDACTED]"
        assert redacted["nested"]["token_issued"] is True

    def test_safe_key_value_matching_a_pattern_is_still_redacted(self):
        """A JWT stored under an allow-listed key is still redacted."""
        from eiams.shared.logging import RedactionConfig

        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        redactor = SecretRedactor(RedactionConfig().with_safe_keys("token_issued"))
        redacted = redactor.redact_for_logging({"token_issued": jwt})
        assert jwt not in json.dumps(redacted)


class TestRepeatedAttemptsScan:
    """A broader scan across many attempts and configurations."""

    @pytest.mark.parametrize("algorithm", ["argon2id", "pbkdf2_sha256"])
    def test_no_marker_survives_a_full_attempt_matrix(self, tenant_id, algorithm):
        """Across all outcomes and algorithms, no marker is emitted."""
        configuration = MappingConfigurationProvider(
            {
                "security.password.algorithm": algorithm,
                "security.password.argon2.time_cost": "1",
                "security.password.argon2.memory_cost_kib": "8192",
                "security.password.argon2.parallelism": "1",
                "security.password.pbkdf2.iterations": "100000",
            }
        )
        stack = build_stack(configuration, tenant_id, password=MARKER_PASSWORD)
        suspended = stack.add_user("suspended@example.com", password=MARKER_PASSWORD)
        stack.set_user_status(suspended, UserStatus.SUSPENDED)

        responses = [
            stack.endpoint.handle(stack.request(password=MARKER_PASSWORD)),
            stack.endpoint.handle(stack.request(password=WRONG_PASSWORD)),
            stack.endpoint.handle(
                stack.request(identifier=UNKNOWN_EMAIL, password=MARKER_PASSWORD)
            ),
            stack.endpoint.handle(
                stack.request(
                    identifier="suspended@example.com", password=MARKER_PASSWORD
                )
            ),
            stack.endpoint.handle(stack.request(identifier="", password="")),
        ]

        surfaces = [r.to_json() for r in responses] + [all_emitted_output(stack)]
        for surface in surfaces:
            assert MARKER_PASSWORD not in surface
            assert KNOWN_EMAIL not in surface

        for protected in stored_protected_values(stack):
            for surface in surfaces:
                assert protected not in surface

    def test_hashed_credential_never_reaches_observability(self, stack):
        """The stored hash appears nowhere, even on success."""
        protected = stored_protected_values(stack)[0]
        for _ in range(3):
            stack.endpoint.handle(stack.request())
            stack.endpoint.handle(stack.request(password=WRONG_PASSWORD))

        emitted = all_emitted_output(stack)
        assert protected not in emitted
        assert protected.split("$")[-1] not in emitted

    def test_secret_wrapper_prevents_accidental_formatting(self):
        """Formatting a wrapped secret cannot emit the marker."""
        secret = SecretString(MARKER_PASSWORD)
        rendered = f"attempt with {secret} and {secret!r}"
        assert MARKER_PASSWORD not in rendered
