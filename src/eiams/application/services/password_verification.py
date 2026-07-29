"""Application-layer password verification.

Loads protected password credentials through the credential repository
and delegates comparison to an approved cryptographic adapter. Every
abnormal condition (absent, disabled, malformed, or unsupported stored
credential) is normalized to an internal failure outcome that carries no
credential material.
"""

from typing import Iterable, Sequence

from eiams.shared.context import RequestContext, require_tenant
from eiams.shared.errors import ConfigurationError, ValidationError
from eiams.shared.kernel import SecretString
from eiams.shared.logging import (
    LogLevel,
    LogOutcome,
    StructuredLogger,
    get_logger,
)
from eiams.domain.credentials.contracts import (
    PasswordCredentialRepository,
    PasswordHashAlgorithm,
    PasswordVerificationOutcome,
    PasswordVerificationResult,
    StoredPasswordCredential,
)
from eiams.domain.identity.contracts import UserId
from eiams.application.ports.security import (
    MalformedProtectedCredentialError,
    PasswordHasher,
    ProtectedCredentialError,
    UnsupportedAlgorithmError,
)
from eiams.application.services.base import ApplicationService
from eiams.application.services.password_policy import PasswordHashingPolicy


VERIFICATION_OPERATION = "password_verification"

# Presented to the hasher when no stored credential exists, so that the
# absent-credential path performs comparable work to the normal path.
_EQUALIZATION_PASSWORD = "credential-absent-equalization"


class PasswordVerificationService(ApplicationService):
    """Verifies presented passwords against protected stored credentials.

    The service accepts only protected representations, performs no
    cryptography of its own, and returns internal outcomes that never
    include the presented password or the stored hash.
    """

    def __init__(
        self,
        credential_repository: PasswordCredentialRepository,
        hashers: PasswordHasher | Sequence[PasswordHasher],
        policy: PasswordHashingPolicy,
        logger: StructuredLogger | None = None,
    ) -> None:
        """Initialize the verification service.

        Args:
            credential_repository: Repository for protected credentials.
            hashers: One or more approved hashing adapters. The adapter
                matching the configured algorithm is used for new hashes
                and for equalizing the absent-credential path; additional
                adapters allow verifying credentials stored under a
                previously configured algorithm.
            policy: Configuration-bound hashing policy.
            logger: Structured logger for safe verification events.

        Raises:
            ConfigurationError: If no adapter satisfies the configured
                algorithm.
        """
        self._credential_repository = credential_repository
        self._policy = policy
        self._logger = logger or get_logger("credentials")
        self._hashers = self._index_hashers(
            [hashers] if isinstance(hashers, PasswordHasher) else list(hashers)
        )

        primary = self._hashers.get(policy.algorithm)
        if primary is None:
            raise ConfigurationError(
                "No password hashing adapter is available for the configured algorithm",
                details={"algorithm": policy.algorithm.value},
            )
        self._primary_hasher = primary
        self._equalization_value: str | None = None

    @property
    def policy(self) -> PasswordHashingPolicy:
        """The configuration-bound hashing policy in effect."""
        return self._policy

    @property
    def supported_algorithms(self) -> tuple[PasswordHashAlgorithm, ...]:
        """Algorithms this service can verify."""
        return tuple(self._hashers)

    def verify_user_password(
        self,
        context: RequestContext,
        user_id: UserId,
        presented_password: SecretString,
    ) -> PasswordVerificationResult:
        """Verify a presented password for a user within tenant scope.

        Returns an internal outcome; a missing credential is reported as
        ``CREDENTIAL_MISSING`` only after equalizing work so that callers
        cannot distinguish it by timing.
        """
        self._validate_context(context)
        require_tenant(context)

        credential = self._credential_repository.find_active_by_user(
            context, user_id
        )
        if credential is None:
            self._equalize(presented_password)
            return self._record(
                context,
                PasswordVerificationResult.failure(
                    PasswordVerificationOutcome.CREDENTIAL_MISSING
                ),
            )

        return self.verify_credential(context, credential, presented_password)

    def verify_absent_credential(
        self,
        context: RequestContext,
        presented_password: SecretString,
    ) -> PasswordVerificationResult:
        """Equalize work when there is no credential to verify at all.

        Called when identity resolution itself failed, so that an
        unresolved identifier costs approximately the same as a resolved
        identifier with a wrong password.
        """
        self._validate_context(context)
        self._equalize(presented_password)
        return self._record(
            context,
            PasswordVerificationResult.failure(
                PasswordVerificationOutcome.CREDENTIAL_MISSING
            ),
        )

    def verify_credential(
        self,
        context: RequestContext,
        credential: StoredPasswordCredential,
        presented_password: SecretString,
    ) -> PasswordVerificationResult:
        """Verify a presented password against a protected credential.

        Raises:
            ValidationError: If the inputs are not the expected protected
                credential and wrapped secret types. This signals a
                programming error rather than a failed login.
        """
        self._validate_context(context)

        if not isinstance(credential, StoredPasswordCredential):
            raise ValidationError(
                "Only protected stored credential representations are accepted",
                field="credential",
            )
        if not isinstance(presented_password, SecretString):
            raise ValidationError(
                "Presented password must be a wrapped secret value",
                field="password",
            )

        if not credential.is_active:
            return self._record(
                context,
                PasswordVerificationResult.failure(
                    PasswordVerificationOutcome.CREDENTIAL_DISABLED,
                    credential.algorithm,
                ),
            )

        if not credential.has_protected_representation:
            self._equalize(presented_password)
            return self._record(
                context,
                PasswordVerificationResult.failure(
                    PasswordVerificationOutcome.CREDENTIAL_MALFORMED,
                    credential.algorithm,
                ),
            )

        if self._is_outside_accepted_bounds(presented_password):
            return self._record(
                context,
                PasswordVerificationResult.failure(
                    PasswordVerificationOutcome.NO_MATCH,
                    credential.algorithm,
                ),
            )

        hasher = self._hashers.get(credential.algorithm)
        if hasher is None:
            self._equalize(presented_password)
            return self._record(
                context,
                PasswordVerificationResult.failure(
                    PasswordVerificationOutcome.ALGORITHM_UNSUPPORTED,
                    credential.algorithm,
                ),
            )

        try:
            matched = hasher.verify(credential.protected_value, presented_password)
        except MalformedProtectedCredentialError:
            return self._record(
                context,
                PasswordVerificationResult.failure(
                    PasswordVerificationOutcome.CREDENTIAL_MALFORMED,
                    credential.algorithm,
                ),
            )
        except UnsupportedAlgorithmError:
            return self._record(
                context,
                PasswordVerificationResult.failure(
                    PasswordVerificationOutcome.ALGORITHM_UNSUPPORTED,
                    credential.algorithm,
                ),
            )
        except ProtectedCredentialError:
            return self._record(
                context,
                PasswordVerificationResult.failure(
                    PasswordVerificationOutcome.CREDENTIAL_MALFORMED,
                    credential.algorithm,
                ),
            )
        except Exception:
            # Any unexpected verifier failure is normalized to a safe
            # non-match; no credential material is logged or re-raised.
            self._logger.log_operation(
                context=context,
                operation=VERIFICATION_OPERATION,
                outcome=LogOutcome.ERROR,
                message="Password verification adapter raised an unexpected error",
                level=LogLevel.ERROR,
                algorithm=credential.algorithm.value,
            )
            return self._record(
                context,
                PasswordVerificationResult.failure(
                    PasswordVerificationOutcome.CREDENTIAL_MALFORMED,
                    credential.algorithm,
                ),
            )

        if not matched:
            return self._record(
                context,
                PasswordVerificationResult.failure(
                    PasswordVerificationOutcome.NO_MATCH,
                    credential.algorithm,
                ),
            )

        return self._record(
            context,
            PasswordVerificationResult.match(
                credential.algorithm,
                needs_rehash=self._needs_rehash(hasher, credential),
            ),
        )

    def _needs_rehash(
        self,
        hasher: PasswordHasher,
        credential: StoredPasswordCredential,
    ) -> bool:
        """Whether a matched credential no longer meets configured policy."""
        if credential.algorithm != self._policy.algorithm:
            return True
        try:
            return hasher.needs_rehash(credential.protected_value)
        except Exception:
            return False

    def _is_outside_accepted_bounds(self, presented_password: SecretString) -> bool:
        """Whether the presented password is empty or exceeds the input bound."""
        return (
            presented_password.is_empty
            or presented_password.length > self._policy.max_password_length
        )

    def _equalize(self, presented_password: SecretString) -> None:
        """Perform comparable verification work on a throwaway credential.

        Used when there is nothing legitimate to compare against, so the
        absent, malformed, and unsupported paths cost roughly the same as
        a real mismatch.
        """
        if self._is_outside_accepted_bounds(presented_password):
            return
        try:
            if self._equalization_value is None:
                self._equalization_value = self._primary_hasher.hash_password(
                    SecretString(_EQUALIZATION_PASSWORD)
                )
            self._primary_hasher.verify(self._equalization_value, presented_password)
        except Exception:
            return

    def _record(
        self,
        context: RequestContext,
        result: PasswordVerificationResult,
    ) -> PasswordVerificationResult:
        """Log a safe verification event and return the result unchanged."""
        self._logger.log_operation(
            context=context,
            operation=VERIFICATION_OPERATION,
            outcome=LogOutcome.SUCCESS if result.is_match else LogOutcome.FAILURE,
            message="Password verification completed",
            level=LogLevel.INFO if result.is_match else LogLevel.WARNING,
            verification_outcome=result.outcome.value,
            algorithm=result.algorithm.value if result.algorithm else None,
            needs_rehash=result.needs_rehash,
        )
        return result

    @staticmethod
    def _index_hashers(
        hashers: Iterable[PasswordHasher],
    ) -> dict[PasswordHashAlgorithm, PasswordHasher]:
        """Index hashing adapters by the algorithm they implement."""
        indexed: dict[PasswordHashAlgorithm, PasswordHasher] = {}
        for hasher in hashers:
            if not isinstance(hasher, PasswordHasher):
                raise ConfigurationError(
                    "Password hashing adapters must implement the PasswordHasher port"
                )
            indexed[hasher.algorithm] = hasher
        if not indexed:
            raise ConfigurationError(
                "At least one password hashing adapter is required"
            )
        return indexed
