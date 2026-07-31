"""Cryptographic abstractions for credential management.

Provides secure credential generation, hashing, and verification
without exposing raw secret material beyond the creation response path.
"""

from .credential_generator import (
    CredentialGenerator,
    GeneratedCredential,
    CredentialConfig,
)
from .secret_hasher import (
    SecretHasher,
    HashConfig,
    HashedSecret,
)

__all__ = [
    "CredentialGenerator",
    "GeneratedCredential",
    "CredentialConfig",
    "SecretHasher",
    "HashConfig",
    "HashedSecret",
]
