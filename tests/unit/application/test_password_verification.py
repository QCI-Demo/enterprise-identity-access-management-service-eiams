"""Tests for the application-layer password verification adapter."""

import json

import pytest

from eiams.shared.config import MappingConfigurationProvider
from eiams.shared.errors import ConfigurationError, ValidationError
from eiams.shared.kernel import SecretString, Timestamp
from eiams.shared.logging import StructuredLogger
from eiams.shared.logging.structured_logging import CaptureLogOutput
from eiams.domain.credentials.contracts import (
    PasswordHashAlgorithm,
    PasswordVerificationOutcome,
    PasswordVerificationResult,
)
from eiams.domain.identity.contracts import UserId
from eiams.application.ports.security import (
    MalformedProtectedCredentialError,
    PasswordHasher,
    UnsupportedAlgorithmError,
)
from eiams.application.services.password_policy import PasswordHashingPolicy
from eiams.application.services.password_verification import (
    PasswordVerificationService,
)
from eiams.infrastructure.persistence.in_memory import (
    InMemoryPasswordCredentialRepository,
)
from eiams.infrastructure.security.password_hashing import Pbkdf2PasswordHasher
from tests.conftest import (
    KNOWN_PASSWORD,
    WRONG_PASSWORD,
    anonymous_context,
    build_credential,
    build_user,
)


class StubArgon2Hasher(PasswordHasher):
    """Stub adapter that records calls and simulates library failures."""

    def __init__(
        self,
        matching_password: str = KNOWN_PASSWORD,
        raise_on_verify: Exception | None = None,
        needs_rehash: bool = False,
    ) -> None:
        self._matching_password = matching_password
        self._raise_on_verify = raise_on_verify
        self._needs_rehash = needs_rehash
        self.verify_calls: list[str] = []
        self.hash_calls = 0

    @property
    def algorithm(self) -> PasswordHashAlgorithm:
        return PasswordHashAlgorithm.ARGON2ID

    def hash_password(self, password: SecretString) -> str:
        self.hash_calls += 1
        return "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$ZGlnZXN0ZGlnZXN0"

    def verify(self, protected_value: str, password: SecretString) -> bool:
        self.verify_calls.append(protected_value)
        if self._raise_on_verify is not None:
            raise self._raise_on_verify
        return password.reveal() == self._matching_password

    def needs_rehash(self, protected_value: str) -> bool:
        return self._needs_rehash


ARGON2_PROTECTED_VALUE = (
    "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$ZGlnZXN0ZGlnZXN0ZGlnZXN0"
)


def build_service(
    hasher: PasswordHasher | list[PasswordHasher],
    policy: PasswordHashingPolicy | None = None,
    credentials: InMemoryPasswordCredentialRepository | None = None,
    log_output: CaptureLogOutput | None = None,
) -> PasswordVerificationService:
    """Build a verification service around the supplied doubles."""
    return PasswordVerificationService(
        credential_repository=credentials or InMemoryPasswordCredentialRepository(),
        hashers=hasher,
        policy=policy or PasswordHashingPolicy(),
        logger=StructuredLogger(output=log_output or CaptureLogOutput()),
    )


class TestMatchingCredential:
    """Tests for the matching path."""

    def test_matching_password_returns_match(self, tenant_id):
        """A matching password yields a MATCH outcome."""
        hasher = StubArgon2Hasher()
        service = build_service(hasher)
        credential = build_credential(
            tenant_id, UserId.generate(), ARGON2_PROTECTED_VALUE
        )

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(KNOWN_PASSWORD)
        )

        assert result.outcome == PasswordVerificationOutcome.MATCH
        assert result.is_match is True
        assert result.algorithm == PasswordHashAlgorithm.ARGON2ID
        assert hasher.verify_calls == [ARGON2_PROTECTED_VALUE]

    def test_match_flags_rehash_when_adapter_requests_it(self, tenant_id):
        """A stale work factor is reported through needs_rehash."""
        service = build_service(StubArgon2Hasher(needs_rehash=True))
        credential = build_credential(
            tenant_id, UserId.generate(), ARGON2_PROTECTED_VALUE
        )

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(KNOWN_PASSWORD)
        )

        assert result.is_match is True
        assert result.needs_rehash is True

    def test_match_flags_rehash_for_non_configured_algorithm(self, tenant_id):
        """A credential stored under another algorithm is marked for rehash."""
        policy = PasswordHashingPolicy(algorithm=PasswordHashAlgorithm.ARGON2ID)
        pbkdf2 = Pbkdf2PasswordHasher(
            PasswordHashingPolicy(
                algorithm=PasswordHashAlgorithm.PBKDF2_SHA256,
                pbkdf2_iterations=100_000,
            )
        )
        protected = pbkdf2.hash_password(SecretString(KNOWN_PASSWORD))
        service = build_service([StubArgon2Hasher(), pbkdf2], policy=policy)

        credential = build_credential(
            tenant_id,
            UserId.generate(),
            protected,
            algorithm=PasswordHashAlgorithm.PBKDF2_SHA256,
        )

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(KNOWN_PASSWORD)
        )

        assert result.is_match is True
        assert result.needs_rehash is True

    def test_repository_lookup_resolves_active_credential(self, tenant_id):
        """Verification through the repository finds the active credential."""
        context = anonymous_context(tenant_id)
        user = build_user(tenant_id)
        credentials = InMemoryPasswordCredentialRepository()
        credentials.save(
            context,
            build_credential(tenant_id, user.user_id, ARGON2_PROTECTED_VALUE),
        )
        service = build_service(StubArgon2Hasher(), credentials=credentials)

        result = service.verify_user_password(
            context, user.user_id, SecretString(KNOWN_PASSWORD)
        )

        assert result.is_match is True


class TestNonMatchingCredential:
    """Tests for the non-matching path."""

    def test_wrong_password_returns_no_match(self, tenant_id):
        """A wrong password yields NO_MATCH."""
        service = build_service(StubArgon2Hasher())
        credential = build_credential(
            tenant_id, UserId.generate(), ARGON2_PROTECTED_VALUE
        )

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(WRONG_PASSWORD)
        )

        assert result.outcome == PasswordVerificationOutcome.NO_MATCH
        assert result.is_match is False

    def test_empty_password_is_not_sent_to_the_verifier(self, tenant_id):
        """An empty password short-circuits to NO_MATCH."""
        hasher = StubArgon2Hasher()
        service = build_service(hasher)
        credential = build_credential(
            tenant_id, UserId.generate(), ARGON2_PROTECTED_VALUE
        )

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString.empty()
        )

        assert result.outcome == PasswordVerificationOutcome.NO_MATCH
        assert hasher.verify_calls == []

    def test_oversized_password_is_not_sent_to_the_verifier(self, tenant_id):
        """A password beyond the configured bound short-circuits."""
        hasher = StubArgon2Hasher()
        service = build_service(
            hasher, policy=PasswordHashingPolicy(max_password_length=64)
        )
        credential = build_credential(
            tenant_id, UserId.generate(), ARGON2_PROTECTED_VALUE
        )

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString("x" * 65)
        )

        assert result.outcome == PasswordVerificationOutcome.NO_MATCH
        assert hasher.verify_calls == []

    def test_missing_credential_reports_missing_after_equalizing(self, tenant_id):
        """An absent credential still performs comparable work."""
        hasher = StubArgon2Hasher()
        service = build_service(hasher)

        result = service.verify_user_password(
            anonymous_context(tenant_id),
            UserId.generate(),
            SecretString(KNOWN_PASSWORD),
        )

        assert result.outcome == PasswordVerificationOutcome.CREDENTIAL_MISSING
        assert hasher.hash_calls == 1
        assert len(hasher.verify_calls) == 1

    def test_absent_identity_path_equalizes_work(self, tenant_id):
        """The unresolved-identity path also exercises the verifier."""
        hasher = StubArgon2Hasher()
        service = build_service(hasher)

        result = service.verify_absent_credential(
            anonymous_context(tenant_id), SecretString(WRONG_PASSWORD)
        )

        assert result.outcome == PasswordVerificationOutcome.CREDENTIAL_MISSING
        assert len(hasher.verify_calls) == 1

    def test_disabled_credential_is_rejected(self, tenant_id):
        """An inactive credential never verifies."""
        hasher = StubArgon2Hasher()
        service = build_service(hasher)
        credential = build_credential(
            tenant_id,
            UserId.generate(),
            ARGON2_PROTECTED_VALUE,
            is_active=False,
        )

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(KNOWN_PASSWORD)
        )

        assert result.outcome == PasswordVerificationOutcome.CREDENTIAL_DISABLED
        assert hasher.verify_calls == []


class TestMalformedCredential:
    """Tests that malformed stored credentials fail safely."""

    @pytest.mark.parametrize(
        "protected_value",
        [
            "",
            KNOWN_PASSWORD,
            "argon2id$v=19$m=8192,t=1,p=1$c2FsdA$ZGlnZXN0",
            "$argon2id$",
            "$argon2id$v=19$ salt with spaces $digest",
            "0123456789abcdef0123456789abcdef",
        ],
    )
    def test_unprotected_stored_values_never_match(self, tenant_id, protected_value):
        """A value that is not a protected representation cannot match."""
        hasher = StubArgon2Hasher(matching_password=KNOWN_PASSWORD)
        service = build_service(hasher)
        credential = build_credential(tenant_id, UserId.generate(), protected_value)

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(KNOWN_PASSWORD)
        )

        assert result.outcome == PasswordVerificationOutcome.CREDENTIAL_MALFORMED
        assert result.is_match is False
        # The unprotected value is never handed to the verifier; only the
        # throwaway equalization credential is.
        assert protected_value not in hasher.verify_calls

    def test_plaintext_stored_password_is_not_accepted(self, tenant_id):
        """A stored plaintext password is treated as malformed, not a match."""
        service = build_service(StubArgon2Hasher())
        credential = build_credential(tenant_id, UserId.generate(), KNOWN_PASSWORD)

        assert credential.has_protected_representation is False
        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(KNOWN_PASSWORD)
        )
        assert result.is_match is False

    def test_verifier_malformed_error_is_normalized(self, tenant_id):
        """A library parse failure becomes a safe malformed outcome."""
        service = build_service(
            StubArgon2Hasher(raise_on_verify=MalformedProtectedCredentialError())
        )
        credential = build_credential(
            tenant_id, UserId.generate(), ARGON2_PROTECTED_VALUE
        )

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(KNOWN_PASSWORD)
        )

        assert result.outcome == PasswordVerificationOutcome.CREDENTIAL_MALFORMED

    def test_verifier_unsupported_error_is_normalized(self, tenant_id):
        """An unsupported encoding becomes a safe unsupported outcome."""
        service = build_service(
            StubArgon2Hasher(raise_on_verify=UnsupportedAlgorithmError())
        )
        credential = build_credential(
            tenant_id, UserId.generate(), ARGON2_PROTECTED_VALUE
        )

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(KNOWN_PASSWORD)
        )

        assert result.outcome == PasswordVerificationOutcome.ALGORITHM_UNSUPPORTED

    def test_unexpected_verifier_error_is_normalized(self, tenant_id):
        """An unexpected adapter error never propagates to the caller."""
        service = build_service(
            StubArgon2Hasher(raise_on_verify=RuntimeError("library exploded"))
        )
        credential = build_credential(
            tenant_id, UserId.generate(), ARGON2_PROTECTED_VALUE
        )

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(KNOWN_PASSWORD)
        )

        assert result.outcome == PasswordVerificationOutcome.CREDENTIAL_MALFORMED

    def test_credential_for_unavailable_algorithm_is_rejected(self, tenant_id):
        """A credential with no matching adapter cannot verify."""
        service = build_service(StubArgon2Hasher())
        credential = build_credential(
            tenant_id,
            UserId.generate(),
            "$pbkdf2-sha256$i=100000$c2FsdHNhbHQ$ZGlnZXN0",
            algorithm=PasswordHashAlgorithm.PBKDF2_SHA256,
        )

        result = service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(KNOWN_PASSWORD)
        )

        assert result.outcome == PasswordVerificationOutcome.ALGORITHM_UNSUPPORTED


class TestInputContracts:
    """Tests for the accepted input types and required context."""

    def test_only_protected_credential_entities_are_accepted(self, tenant_id):
        """A raw string is rejected as a programming error."""
        service = build_service(StubArgon2Hasher())
        with pytest.raises(ValidationError):
            service.verify_credential(
                anonymous_context(tenant_id),
                ARGON2_PROTECTED_VALUE,  # type: ignore[arg-type]
                SecretString(KNOWN_PASSWORD),
            )

    def test_password_must_be_wrapped(self, tenant_id):
        """An unwrapped password is rejected as a programming error."""
        service = build_service(StubArgon2Hasher())
        credential = build_credential(
            tenant_id, UserId.generate(), ARGON2_PROTECTED_VALUE
        )
        with pytest.raises(ValidationError):
            service.verify_credential(
                anonymous_context(tenant_id),
                credential,
                KNOWN_PASSWORD,  # type: ignore[arg-type]
            )

    def test_repository_lookup_requires_tenant_context(self):
        """Credential lookup is refused without tenant scope."""
        from eiams.shared.errors import TenantRequiredError

        service = build_service(StubArgon2Hasher())
        with pytest.raises(TenantRequiredError):
            service.verify_user_password(
                anonymous_context(None),
                UserId.generate(),
                SecretString(KNOWN_PASSWORD),
            )

    def test_adapter_for_configured_algorithm_is_required(self):
        """Wiring fails when no adapter serves the configured algorithm."""
        with pytest.raises(ConfigurationError):
            PasswordVerificationService(
                credential_repository=InMemoryPasswordCredentialRepository(),
                hashers=[StubArgon2Hasher()],
                policy=PasswordHashingPolicy(
                    algorithm=PasswordHashAlgorithm.PBKDF2_SHA256
                ),
            )

    def test_at_least_one_adapter_is_required(self):
        """Wiring fails when no adapter is supplied at all."""
        with pytest.raises(ConfigurationError):
            PasswordVerificationService(
                credential_repository=InMemoryPasswordCredentialRepository(),
                hashers=[],
                policy=PasswordHashingPolicy(),
            )


class TestVerificationObservability:
    """Tests that verification emits no credential material."""

    def test_logs_contain_outcome_but_no_credential_material(self, tenant_id):
        """Verification logs carry the outcome only."""
        log_output = CaptureLogOutput()
        service = build_service(StubArgon2Hasher(), log_output=log_output)
        credential = build_credential(
            tenant_id, UserId.generate(), ARGON2_PROTECTED_VALUE
        )

        service.verify_credential(
            anonymous_context(tenant_id), credential, SecretString(WRONG_PASSWORD)
        )

        serialized = "\n".join(e.to_json() for e in log_output.events)
        assert "no_match" in serialized
        assert WRONG_PASSWORD not in serialized
        assert ARGON2_PROTECTED_VALUE not in serialized

    def test_result_representation_omits_credential_material(self):
        """The result value object never renders credential material."""
        result = PasswordVerificationResult.match(PasswordHashAlgorithm.ARGON2ID)
        assert "argon2id" in repr(result)
        assert json.dumps(result.to_safe_dict())

    def test_failure_factory_rejects_match_outcome(self):
        """MATCH cannot be constructed through the failure factory."""
        with pytest.raises(ValidationError):
            PasswordVerificationResult.failure(PasswordVerificationOutcome.MATCH)

    def test_supported_algorithms_reflect_wired_adapters(self):
        """The service reports the algorithms it can verify."""
        pbkdf2 = Pbkdf2PasswordHasher(
            PasswordHashingPolicy(
                algorithm=PasswordHashAlgorithm.PBKDF2_SHA256,
                pbkdf2_iterations=100_000,
            )
        )
        service = build_service([StubArgon2Hasher(), pbkdf2])
        assert set(service.supported_algorithms) == {
            PasswordHashAlgorithm.ARGON2ID,
            PasswordHashAlgorithm.PBKDF2_SHA256,
        }
