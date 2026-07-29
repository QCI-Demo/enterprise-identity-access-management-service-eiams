"""Infrastructure security adapters.

Wrappers around approved cryptographic libraries. No cryptographic
primitive is implemented here; adapters only translate between the
application ports and the library APIs.
"""

from .password_hashing import (
    ARGON2_AVAILABLE,
    Argon2PasswordHasher,
    Pbkdf2PasswordHasher,
    create_password_hasher,
    create_password_hashers,
)

__all__ = [
    "ARGON2_AVAILABLE",
    "Argon2PasswordHasher",
    "Pbkdf2PasswordHasher",
    "create_password_hasher",
    "create_password_hashers",
]
