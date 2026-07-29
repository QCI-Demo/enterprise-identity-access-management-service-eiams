"""Tests for the approved-library password hashing adapters."""

import pytest

from eiams.shared.errors import ConfigurationError
from eiams.shared.kernel import SecretString
from eiams.domain.credentials.contracts import PasswordHashAlgorithm
from eiams.application.ports.security import (
    MalformedProtectedCredentialError,
    UnsupportedAlgorithmError,
)
from eiams.application.services.password_policy import PasswordHashingPolicy
from eiams.infrastructure.security.password_hashing import (
    ARGON2_AVAILABLE,
    Argon2PasswordHasher,
    Pbkdf2PasswordHasher,
    create_password_hasher,
    create_password_hashers,
)
from tests.conftest import KNOWN_PASSWORD, WRONG_PASSWORD


FAST_ARGON2_POLICY = PasswordHashingPolicy(
    algorithm=PasswordHashAlgorithm.ARGON2ID,
    argon2_time_cost=1,
    argon2_memory_cost_kib=8192,
    argon2_parallelism=1,
)
FAST_PBKDF2_POLICY = PasswordHashingPolicy(
    algorithm=PasswordHashAlgorithm.PBKDF2_SHA256,
    pbkdf2_iterations=100_000,
)


def hashers():
    """Every adapter available on this host."""
    adapters = [Pbkdf2PasswordHasher(FAST_PBKDF2_POLICY)]
    if ARGON2_AVAILABLE:
        adapters.append(Argon2PasswordHasher(FAST_ARGON2_POLICY))
    return adapters


@pytest.fixture(params=hashers(), ids=lambda h: h.algorithm.value)
def hasher(request):
    """Parametrized adapter fixture covering each available algorithm."""
    return request.param


class TestProtectedRepresentation:
    """Tests for the produced protected representations."""

    def test_hash_is_a_protected_encoding(self, hasher):
        """The produced value declares its algorithm and parameters."""
        protected = hasher.hash_password(SecretString(KNOWN_PASSWORD))
        assert protected.startswith(hasher.algorithm.encoding_prefix)
        assert len([s for s in protected.split("$") if s]) >= 3

    def test_hash_never_contains_the_password(self, hasher):
        """The plaintext password does not appear in the encoding."""
        protected = hasher.hash_password(SecretString(KNOWN_PASSWORD))
        assert KNOWN_PASSWORD not in protected

    def test_hashes_are_salted(self, hasher):
        """Hashing the same password twice yields different encodings."""
        first = hasher.hash_password(SecretString(KNOWN_PASSWORD))
        second = hasher.hash_password(SecretString(KNOWN_PASSWORD))
        assert first != second


class TestVerification:
    """Tests for verification behavior."""

    def test_matching_password_verifies(self, hasher):
        """The original password verifies against its encoding."""
        protected = hasher.hash_password(SecretString(KNOWN_PASSWORD))
        assert hasher.verify(protected, SecretString(KNOWN_PASSWORD)) is True

    def test_wrong_password_does_not_verify(self, hasher):
        """A different password does not verify."""
        protected = hasher.hash_password(SecretString(KNOWN_PASSWORD))
        assert hasher.verify(protected, SecretString(WRONG_PASSWORD)) is False

    @pytest.mark.parametrize("protected_value", ["", "not-a-hash", KNOWN_PASSWORD])
    def test_malformed_value_raises_malformed_error(self, hasher, protected_value):
        """An unparsable stored value raises the malformed error."""
        with pytest.raises(MalformedProtectedCredentialError):
            hasher.verify(protected_value, SecretString(KNOWN_PASSWORD))

    def test_foreign_algorithm_raises_unsupported_error(self, hasher):
        """An encoding for another algorithm raises the unsupported error."""
        foreign = "$scrypt$ln=16,r=8,p=1$c2FsdHNhbHQ$ZGlnZXN0"
        with pytest.raises(UnsupportedAlgorithmError):
            hasher.verify(foreign, SecretString(KNOWN_PASSWORD))


class TestRehashDetection:
    """Tests for work-factor drift detection."""

    def test_current_policy_does_not_need_rehash(self, hasher):
        """A freshly produced encoding matches current policy."""
        protected = hasher.hash_password(SecretString(KNOWN_PASSWORD))
        assert hasher.needs_rehash(protected) is False

    def test_raised_pbkdf2_iterations_require_rehash(self):
        """An encoding below the configured iteration count needs rehashing."""
        weak = Pbkdf2PasswordHasher(FAST_PBKDF2_POLICY)
        protected = weak.hash_password(SecretString(KNOWN_PASSWORD))

        strict = Pbkdf2PasswordHasher(
            PasswordHashingPolicy(
                algorithm=PasswordHashAlgorithm.PBKDF2_SHA256,
                pbkdf2_iterations=200_000,
            )
        )
        assert strict.needs_rehash(protected) is True
        assert strict.verify(protected, SecretString(KNOWN_PASSWORD)) is True

    @pytest.mark.skipif(not ARGON2_AVAILABLE, reason="argon2-cffi is not installed")
    def test_raised_argon2_cost_requires_rehash(self):
        """An Argon2 encoding below configured cost needs rehashing."""
        weak = Argon2PasswordHasher(FAST_ARGON2_POLICY)
        protected = weak.hash_password(SecretString(KNOWN_PASSWORD))

        strict = Argon2PasswordHasher(
            PasswordHashingPolicy(
                algorithm=PasswordHashAlgorithm.ARGON2ID,
                argon2_time_cost=4,
                argon2_memory_cost_kib=65536,
                argon2_parallelism=2,
            )
        )
        assert strict.needs_rehash(protected) is True


class TestPolicyBinding:
    """Tests that adapters honour the configured work factors."""

    @pytest.mark.skipif(not ARGON2_AVAILABLE, reason="argon2-cffi is not installed")
    def test_argon2_encoding_reports_configured_parameters(self):
        """Configured Argon2 parameters appear in the encoding."""
        protected = Argon2PasswordHasher(
            PasswordHashingPolicy(
                algorithm=PasswordHashAlgorithm.ARGON2ID,
                argon2_time_cost=2,
                argon2_memory_cost_kib=16384,
                argon2_parallelism=1,
            )
        ).hash_password(SecretString(KNOWN_PASSWORD))
        assert "m=16384" in protected
        assert "t=2" in protected
        assert "p=1" in protected

    def test_pbkdf2_encoding_reports_configured_iterations(self):
        """The configured iteration count appears in the encoding."""
        protected = Pbkdf2PasswordHasher(FAST_PBKDF2_POLICY).hash_password(
            SecretString(KNOWN_PASSWORD)
        )
        assert "i=100000" in protected

    def test_pbkdf2_digest_length_follows_policy(self):
        """The configured hash length is honoured."""
        policy = PasswordHashingPolicy(
            algorithm=PasswordHashAlgorithm.PBKDF2_SHA256,
            pbkdf2_iterations=100_000,
            hash_length=64,
        )
        protected = Pbkdf2PasswordHasher(policy).hash_password(
            SecretString(KNOWN_PASSWORD)
        )
        iterations, _, digest = protected.split("$")[2:]
        assert iterations == "i=100000"
        assert len(digest) >= 80  # 64 bytes base64-encoded, unpadded


class TestAdapterFactory:
    """Tests for the adapter factory functions."""

    def test_factory_returns_adapter_for_configured_algorithm(self):
        """The factory honours the configured algorithm."""
        adapter = create_password_hasher(FAST_PBKDF2_POLICY)
        assert adapter.algorithm == PasswordHashAlgorithm.PBKDF2_SHA256

    def test_factory_lists_configured_adapter_first(self):
        """The configured algorithm leads the adapter list."""
        adapters = create_password_hashers(FAST_PBKDF2_POLICY)
        assert adapters[0].algorithm == PasswordHashAlgorithm.PBKDF2_SHA256
        assert len(adapters) == (2 if ARGON2_AVAILABLE else 1)

    def test_argon2_requires_the_library(self, monkeypatch):
        """Argon2 wiring fails clearly when the library is absent."""
        monkeypatch.setattr(
            "eiams.infrastructure.security.password_hashing.ARGON2_AVAILABLE",
            False,
        )
        with pytest.raises(ConfigurationError):
            create_password_hasher(FAST_ARGON2_POLICY)
