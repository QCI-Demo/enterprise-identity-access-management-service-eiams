"""Password hashing adapters backed by approved cryptographic libraries.

These adapters contain no bespoke cryptography: Argon2id delegates to
argon2-cffi (libargon2) and PBKDF2-HMAC-SHA256 delegates to the standard
library ``hashlib`` and ``hmac`` primitives. Work factors always come from
the configuration-bound policy.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from eiams.shared.errors import ConfigurationError
from eiams.shared.kernel import SecretString
from eiams.domain.credentials.contracts import PasswordHashAlgorithm
from eiams.application.ports.security import (
    MalformedProtectedCredentialError,
    PasswordHasher,
    UnsupportedAlgorithmError,
)
from eiams.application.services.password_policy import PasswordHashingPolicy

try:  # pragma: no cover - exercised by whichever branch the host supports
    import argon2 as _argon2
    from argon2.exceptions import (
        InvalidHashError as _Argon2InvalidHashError,
        VerificationError as _Argon2VerificationError,
        VerifyMismatchError as _Argon2VerifyMismatchError,
    )

    ARGON2_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on host packages
    _argon2 = None
    ARGON2_AVAILABLE = False


class Argon2PasswordHasher(PasswordHasher):
    """Argon2id adapter delegating to the argon2-cffi library."""

    def __init__(self, policy: PasswordHashingPolicy) -> None:
        """Initialize the adapter with configuration-bound work factors.

        Raises:
            ConfigurationError: If argon2-cffi is not installed.
        """
        if not ARGON2_AVAILABLE:
            raise ConfigurationError(
                "Argon2id hashing requires the argon2-cffi package",
                details={"algorithm": PasswordHashAlgorithm.ARGON2ID.value},
            )
        self._policy = policy
        self._library = _argon2.PasswordHasher(
            time_cost=policy.argon2_time_cost,
            memory_cost=policy.argon2_memory_cost_kib,
            parallelism=policy.argon2_parallelism,
            hash_len=policy.hash_length,
            salt_len=policy.salt_length,
            type=_argon2.Type.ID,
        )

    @property
    def algorithm(self) -> PasswordHashAlgorithm:
        return PasswordHashAlgorithm.ARGON2ID

    def hash_password(self, password: SecretString) -> str:
        """Produce an Argon2id protected representation."""
        return self._library.hash(password.reveal())

    def verify(self, protected_value: str, password: SecretString) -> bool:
        """Verify a password against an Argon2id protected representation."""
        self._require_supported_encoding(protected_value)
        try:
            return bool(self._library.verify(protected_value, password.reveal()))
        except _Argon2VerifyMismatchError:
            return False
        except _Argon2InvalidHashError:
            raise MalformedProtectedCredentialError()
        except _Argon2VerificationError:
            # The library reports both mismatches and unusable encodings
            # through this base type; treat the residual case as a mismatch.
            return False

    def needs_rehash(self, protected_value: str) -> bool:
        """Whether the stored parameters differ from configured policy."""
        self._require_supported_encoding(protected_value)
        try:
            return bool(self._library.check_needs_rehash(protected_value))
        except _Argon2InvalidHashError:
            raise MalformedProtectedCredentialError()

    def _require_supported_encoding(self, protected_value: str) -> None:
        """Reject values that are not Argon2id encodings.

        A value carrying another algorithm's identifier is unsupported;
        anything that is not a protected encoding at all is malformed.
        """
        if not protected_value or not isinstance(protected_value, str):
            raise MalformedProtectedCredentialError()
        if not PasswordHashAlgorithm.ARGON2ID.matches_encoding(protected_value):
            if protected_value.startswith("$"):
                raise UnsupportedAlgorithmError()
            raise MalformedProtectedCredentialError()


class Pbkdf2PasswordHasher(PasswordHasher):
    """PBKDF2-HMAC-SHA256 adapter delegating to standard library primitives.

    Produces a PHC-style encoding: ``$pbkdf2-sha256$i=<iterations>$<salt>$<digest>``
    with base64 (unpadded) salt and digest.
    """

    _ITERATION_PREFIX = "i="

    def __init__(self, policy: PasswordHashingPolicy) -> None:
        """Initialize the adapter with configuration-bound work factors."""
        self._policy = policy

    @property
    def algorithm(self) -> PasswordHashAlgorithm:
        return PasswordHashAlgorithm.PBKDF2_SHA256

    def hash_password(self, password: SecretString) -> str:
        """Produce a PBKDF2-HMAC-SHA256 protected representation."""
        salt = secrets.token_bytes(self._policy.salt_length)
        digest = self._derive(
            password, salt, self._policy.pbkdf2_iterations, self._policy.hash_length
        )
        return (
            f"{self.algorithm.encoding_prefix}"
            f"{self._ITERATION_PREFIX}{self._policy.pbkdf2_iterations}$"
            f"{_b64_encode(salt)}${_b64_encode(digest)}"
        )

    def verify(self, protected_value: str, password: SecretString) -> bool:
        """Verify a password against a PBKDF2 protected representation."""
        iterations, salt, expected = self._parse(protected_value)
        candidate = self._derive(password, salt, iterations, len(expected))
        return hmac.compare_digest(candidate, expected)

    def needs_rehash(self, protected_value: str) -> bool:
        """Whether the stored iteration count or length is below policy."""
        iterations, _salt, expected = self._parse(protected_value)
        return (
            iterations < self._policy.pbkdf2_iterations
            or len(expected) < self._policy.hash_length
        )

    def _parse(self, protected_value: str) -> tuple[int, bytes, bytes]:
        """Parse a protected representation into its components.

        Raises:
            UnsupportedAlgorithmError: If the encoding is for another algorithm.
            MalformedProtectedCredentialError: If the encoding is unusable.
        """
        if not protected_value or not isinstance(protected_value, str):
            raise MalformedProtectedCredentialError()
        if not self.algorithm.matches_encoding(protected_value):
            if protected_value.startswith("$"):
                raise UnsupportedAlgorithmError()
            raise MalformedProtectedCredentialError()

        parts = protected_value.split("$")
        # ["", "pbkdf2-sha256", "i=<iterations>", "<salt>", "<digest>"]
        if len(parts) != 5:
            raise MalformedProtectedCredentialError()

        iteration_part = parts[2]
        if not iteration_part.startswith(self._ITERATION_PREFIX):
            raise MalformedProtectedCredentialError()
        try:
            iterations = int(iteration_part[len(self._ITERATION_PREFIX) :])
            salt = _b64_decode(parts[3])
            expected = _b64_decode(parts[4])
        except (ValueError, TypeError):
            raise MalformedProtectedCredentialError()

        if iterations < 1 or not salt or not expected:
            raise MalformedProtectedCredentialError()

        return iterations, salt, expected

    @staticmethod
    def _derive(
        password: SecretString,
        salt: bytes,
        iterations: int,
        length: int,
    ) -> bytes:
        """Derive a digest using the standard library PBKDF2 implementation."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.reveal().encode("utf-8"),
            salt,
            iterations,
            dklen=length,
        )


def _b64_encode(value: bytes) -> str:
    """Encode bytes as unpadded URL-safe base64."""
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64_decode(value: str) -> bytes:
    """Decode unpadded URL-safe base64 into bytes."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_password_hasher(policy: PasswordHashingPolicy) -> PasswordHasher:
    """Create the hashing adapter for the configured algorithm.

    Raises:
        ConfigurationError: If no adapter supports the configured algorithm.
    """
    if policy.algorithm == PasswordHashAlgorithm.ARGON2ID:
        return Argon2PasswordHasher(policy)
    if policy.algorithm == PasswordHashAlgorithm.PBKDF2_SHA256:
        return Pbkdf2PasswordHasher(policy)
    raise ConfigurationError(
        "No password hashing adapter is available for the configured algorithm",
        details={"algorithm": policy.algorithm.value},
    )


def create_password_hashers(
    policy: PasswordHashingPolicy,
) -> tuple[PasswordHasher, ...]:
    """Create every available adapter, with the configured one first.

    Additional adapters let the service verify credentials that were
    stored under a previously configured algorithm and mark them for
    rehashing.
    """
    primary = create_password_hasher(policy)
    adapters: list[PasswordHasher] = [primary]

    for candidate in (Argon2PasswordHasher, Pbkdf2PasswordHasher):
        if isinstance(primary, candidate):
            continue
        try:
            adapters.append(candidate(policy))
        except ConfigurationError:
            continue

    return tuple(adapters)
