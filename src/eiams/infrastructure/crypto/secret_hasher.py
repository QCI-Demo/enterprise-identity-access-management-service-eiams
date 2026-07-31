"""Secure secret hashing for credential verification.

Provides one-way hashing for API keys and OAuth client secrets
using approved cryptographic algorithms (SHA-256 with salt).
The raw secret is never stored - only its hash is persisted.
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class HashConfig:
    """Configuration for secret hashing.
    
    Attributes:
        salt_length: Length of random salt in bytes.
        iterations: Number of hash iterations (for PBKDF2-style hardening).
        algorithm: Hash algorithm to use.
    """
    salt_length: int = 16
    iterations: int = 100000
    algorithm: str = "sha256"
    
    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.salt_length < 8:
            raise ValueError("salt_length must be at least 8 bytes")
        if self.iterations < 10000:
            raise ValueError("iterations must be at least 10000")
        if self.algorithm not in ("sha256", "sha384", "sha512"):
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")


@dataclass(frozen=True)
class HashedSecret:
    """A hashed secret with its salt for verification.
    
    This structure is safe to store - it contains no plaintext secrets.
    
    Attributes:
        hash_value: The hex-encoded hash of the secret.
        salt: The hex-encoded salt used in hashing.
        algorithm: The algorithm used for hashing.
        iterations: Number of iterations used.
    """
    hash_value: str
    salt: str
    algorithm: str
    iterations: int
    
    def to_storage_string(self) -> str:
        """Serialize to a storage-safe string format.
        
        Format: $algorithm$iterations$salt$hash
        """
        return f"${self.algorithm}${self.iterations}${self.salt}${self.hash_value}"
    
    @classmethod
    def from_storage_string(cls, storage: str) -> "HashedSecret":
        """Deserialize from storage string format.
        
        Args:
            storage: String in format $algorithm$iterations$salt$hash
            
        Returns:
            HashedSecret instance.
            
        Raises:
            ValueError: If format is invalid.
        """
        parts = storage.split('$')
        if len(parts) != 5 or parts[0] != '':
            raise ValueError("Invalid hash storage format")
        
        _, algorithm, iterations_str, salt, hash_value = parts
        try:
            iterations = int(iterations_str)
        except ValueError:
            raise ValueError("Invalid iterations value in hash storage")
        
        return cls(
            hash_value=hash_value,
            salt=salt,
            algorithm=algorithm,
            iterations=iterations,
        )
    
    def __repr__(self) -> str:
        """Safe repr that doesn't expose hash internals."""
        return f"HashedSecret(algorithm='{self.algorithm}', iterations={self.iterations})"


class SecretHasher:
    """Secure hasher for credential verification.
    
    Uses PBKDF2-HMAC for key derivation with configurable iterations
    to provide computational resistance against brute-force attacks.
    """
    
    def __init__(self, config: HashConfig | None = None) -> None:
        """Initialize the hasher.
        
        Args:
            config: Optional hash configuration. Uses defaults if not provided.
        """
        self._config = config or HashConfig()
    
    @property
    def config(self) -> HashConfig:
        """The current hash configuration."""
        return self._config
    
    def hash_secret(self, secret: str) -> HashedSecret:
        """Hash a secret for secure storage.
        
        Args:
            secret: The plaintext secret to hash.
            
        Returns:
            HashedSecret containing the hash and salt for verification.
        """
        if not secret:
            raise ValueError("Secret cannot be empty")
        
        # Generate random salt
        salt_bytes = secrets.token_bytes(self._config.salt_length)
        salt_hex = salt_bytes.hex()
        
        # Derive key using PBKDF2
        hash_bytes = hashlib.pbkdf2_hmac(
            hash_name=self._config.algorithm,
            password=secret.encode('utf-8'),
            salt=salt_bytes,
            iterations=self._config.iterations,
        )
        
        return HashedSecret(
            hash_value=hash_bytes.hex(),
            salt=salt_hex,
            algorithm=self._config.algorithm,
            iterations=self._config.iterations,
        )
    
    def verify_secret(self, secret: str, hashed: HashedSecret) -> bool:
        """Verify a secret against its hash.
        
        Uses constant-time comparison to prevent timing attacks.
        
        Args:
            secret: The plaintext secret to verify.
            hashed: The stored hash to verify against.
            
        Returns:
            True if the secret matches, False otherwise.
        """
        if not secret:
            return False
        
        try:
            salt_bytes = bytes.fromhex(hashed.salt)
        except ValueError:
            return False
        
        # Derive key using same parameters
        computed_bytes = hashlib.pbkdf2_hmac(
            hash_name=hashed.algorithm,
            password=secret.encode('utf-8'),
            salt=salt_bytes,
            iterations=hashed.iterations,
        )
        
        try:
            stored_bytes = bytes.fromhex(hashed.hash_value)
        except ValueError:
            return False
        
        # Constant-time comparison
        return hmac.compare_digest(computed_bytes, stored_bytes)
    
    def verify_from_storage(self, secret: str, storage_string: str) -> bool:
        """Verify a secret against a storage string.
        
        Convenience method combining parsing and verification.
        
        Args:
            secret: The plaintext secret to verify.
            storage_string: The stored hash in string format.
            
        Returns:
            True if the secret matches, False otherwise.
        """
        try:
            hashed = HashedSecret.from_storage_string(storage_string)
            return self.verify_secret(secret, hashed)
        except ValueError:
            return False
