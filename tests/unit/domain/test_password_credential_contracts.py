"""Tests for the password credential domain contracts."""

import json

import pytest

from eiams.shared.errors import ValidationError
from eiams.domain.credentials.contracts import (
    PasswordHashAlgorithm,
    PasswordVerificationOutcome,
    PasswordVerificationResult,
)
from eiams.domain.identity.contracts import UserId
from tests.conftest import KNOWN_PASSWORD, build_credential


ARGON2_VALUE = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$ZGlnZXN0ZGlnZXN0"
PBKDF2_VALUE = "$pbkdf2-sha256$i=100000$c2FsdHNhbHQ$ZGlnZXN0ZGlnZXN0"


class TestPasswordHashAlgorithm:
    """Tests for algorithm resolution and encoding identification."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("argon2id", PasswordHashAlgorithm.ARGON2ID),
            ("ARGON2ID", PasswordHashAlgorithm.ARGON2ID),
            ("pbkdf2_sha256", PasswordHashAlgorithm.PBKDF2_SHA256),
            ("pbkdf2-sha256", PasswordHashAlgorithm.PBKDF2_SHA256),
        ],
    )
    def test_resolves_configured_values(self, value, expected):
        """Configured spellings resolve to the algorithm."""
        assert PasswordHashAlgorithm.from_value(value) == expected

    @pytest.mark.parametrize("value", ["", "md5", "sha1", "plaintext"])
    def test_rejects_unsupported_values(self, value):
        """Unsupported algorithms are rejected."""
        with pytest.raises(ValidationError):
            PasswordHashAlgorithm.from_value(value)

    def test_encoding_prefix_identifies_representations(self):
        """Each algorithm recognizes only its own encoding."""
        assert PasswordHashAlgorithm.ARGON2ID.matches_encoding(ARGON2_VALUE) is True
        assert PasswordHashAlgorithm.ARGON2ID.matches_encoding(PBKDF2_VALUE) is False
        assert (
            PasswordHashAlgorithm.PBKDF2_SHA256.matches_encoding(PBKDF2_VALUE) is True
        )
        assert PasswordHashAlgorithm.PBKDF2_SHA256.matches_encoding("") is False


class TestStoredPasswordCredential:
    """Tests for the stored credential entity."""

    def test_recognizes_protected_representations(self, tenant_id):
        """A well-formed encoding is recognized as protected."""
        credential = build_credential(tenant_id, UserId.generate(), ARGON2_VALUE)
        assert credential.has_protected_representation is True

    @pytest.mark.parametrize(
        "protected_value",
        [
            "",
            KNOWN_PASSWORD,
            "$argon2id$",
            " $argon2id$v=19$m=8192,t=1,p=1$c2FsdA$ZGlnZXN0",
            "$argon2id$v=19$salt with space$ZGlnZXN0",
            PBKDF2_VALUE,
        ],
    )
    def test_rejects_unprotected_representations(self, tenant_id, protected_value):
        """Anything that is not this algorithm's encoding is rejected."""
        credential = build_credential(tenant_id, UserId.generate(), protected_value)
        assert credential.has_protected_representation is False

    def test_representation_omits_credential_material(self, tenant_id):
        """repr and str never render the protected value."""
        credential = build_credential(tenant_id, UserId.generate(), ARGON2_VALUE)
        assert ARGON2_VALUE not in repr(credential)
        assert ARGON2_VALUE not in str(credential)
        assert "[REDACTED]" in repr(credential)

    def test_safe_dict_omits_credential_material(self, tenant_id):
        """Serialization never includes the protected value."""
        credential = build_credential(tenant_id, UserId.generate(), ARGON2_VALUE)
        payload = json.dumps(credential.to_safe_dict())
        assert ARGON2_VALUE not in payload
        assert credential.to_safe_dict()["algorithm"] == "argon2id"

    def test_identity_semantics(self, tenant_id):
        """Credentials compare and hash by identity."""
        user_id = UserId.generate()
        credential = build_credential(tenant_id, user_id, ARGON2_VALUE)
        other = build_credential(tenant_id, user_id, ARGON2_VALUE)
        assert credential == credential
        assert credential != other
        assert credential.id == credential.credential_id
        assert len({credential, other}) == 2
        assert (credential == "not-a-credential") is False


class TestPasswordVerificationResult:
    """Tests for the internal verification result."""

    def test_match_result_reports_algorithm(self):
        """A match records the algorithm that verified it."""
        result = PasswordVerificationResult.match(
            PasswordHashAlgorithm.ARGON2ID, needs_rehash=True
        )
        assert result.is_match is True
        assert result.needs_rehash is True
        assert result.to_safe_dict() == {
            "outcome": "match",
            "algorithm": "argon2id",
            "needs_rehash": True,
        }

    def test_failure_result_is_not_a_match(self):
        """A failure never reports a match."""
        result = PasswordVerificationResult.failure(
            PasswordVerificationOutcome.NO_MATCH, PasswordHashAlgorithm.ARGON2ID
        )
        assert result.is_match is False
        assert result.needs_rehash is False

    def test_failure_factory_rejects_match(self):
        """MATCH cannot be produced through the failure factory."""
        with pytest.raises(ValidationError):
            PasswordVerificationResult.failure(PasswordVerificationOutcome.MATCH)
