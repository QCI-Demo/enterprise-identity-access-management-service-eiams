"""Ports for cryptographic operations performed by approved adapters.

The application layer never implements hashing itself. It depends on this
port, which infrastructure adapters satisfy by delegating to an approved
cryptographic library.
"""

from abc import ABC, abstractmethod

from eiams.shared.kernel import SecretString
from eiams.domain.credentials.contracts import PasswordHashAlgorithm


class ProtectedCredentialError(Exception):
    """Base error for protected credential handling failures."""


class MalformedProtectedCredentialError(ProtectedCredentialError):
    """Raised when a stored credential cannot be parsed by the verifier.

    The offending value is never attached to the error.
    """

    def __init__(self, message: str = "Stored credential is malformed") -> None:
        super().__init__(message)


class UnsupportedAlgorithmError(ProtectedCredentialError):
    """Raised when a stored credential uses an algorithm the adapter cannot verify."""

    def __init__(self, message: str = "Stored credential algorithm is unsupported") -> None:
        super().__init__(message)


class PasswordHasher(ABC):
    """Port for password hashing and verification.

    Implementations wrap an approved cryptographic library. They must not
    contain bespoke hashing, salting, or comparison logic, and must never
    return or log credential material.
    """

    @property
    @abstractmethod
    def algorithm(self) -> PasswordHashAlgorithm:
        """The algorithm this adapter produces and verifies."""
        ...

    @abstractmethod
    def hash_password(self, password: SecretString) -> str:
        """Produce a protected representation of a password.

        Args:
            password: The plaintext password, wrapped for safety.

        Returns:
            The protected (encoded hash) representation.
        """
        ...

    @abstractmethod
    def verify(self, protected_value: str, password: SecretString) -> bool:
        """Verify a password against a protected representation.

        Args:
            protected_value: The stored protected credential representation.
            password: The presented plaintext password, wrapped for safety.

        Returns:
            True when the password matches, False when it does not.

        Raises:
            MalformedProtectedCredentialError: If the stored value cannot
                be parsed as a protected representation.
            UnsupportedAlgorithmError: If the stored value uses another
                algorithm than this adapter supports.
        """
        ...

    @abstractmethod
    def needs_rehash(self, protected_value: str) -> bool:
        """Whether the stored credential predates the configured work factors."""
        ...
