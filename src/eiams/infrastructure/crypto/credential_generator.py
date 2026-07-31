"""Secure credential generation for OAuth clients and API keys.

Generates cryptographically strong credentials suitable for machine
authentication. The raw credential is only returned once during creation
or rotation and must not be stored or logged.
"""

import secrets
import string
from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class CredentialConfig:
    """Configuration for credential generation.
    
    Attributes:
        api_key_length: Length of generated API keys (bytes of randomness).
        api_key_prefix: Prefix for API key identification (e.g., "eiams_").
        client_secret_length: Length of OAuth client secrets (bytes).
        display_prefix_length: Characters to store for display purposes.
    """
    api_key_length: int = 32
    api_key_prefix: str = "eiams_"
    client_secret_length: int = 32
    display_prefix_length: int = 8
    
    # Validation limits
    MIN_KEY_LENGTH: ClassVar[int] = 16
    MAX_KEY_LENGTH: ClassVar[int] = 64
    MAX_PREFIX_LENGTH: ClassVar[int] = 16
    
    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if not (self.MIN_KEY_LENGTH <= self.api_key_length <= self.MAX_KEY_LENGTH):
            raise ValueError(
                f"api_key_length must be between {self.MIN_KEY_LENGTH} and {self.MAX_KEY_LENGTH}"
            )
        if not (self.MIN_KEY_LENGTH <= self.client_secret_length <= self.MAX_KEY_LENGTH):
            raise ValueError(
                f"client_secret_length must be between {self.MIN_KEY_LENGTH} and {self.MAX_KEY_LENGTH}"
            )
        if len(self.api_key_prefix) > self.MAX_PREFIX_LENGTH:
            raise ValueError(
                f"api_key_prefix must not exceed {self.MAX_PREFIX_LENGTH} characters"
            )
        if not (1 <= self.display_prefix_length <= 16):
            raise ValueError("display_prefix_length must be between 1 and 16")


@dataclass(frozen=True)
class GeneratedCredential:
    """A newly generated credential with raw secret and safe metadata.
    
    The raw_secret field contains the plaintext credential that must
    be returned to the caller exactly once. After this, only the
    display_prefix and hash should be retained.
    
    Attributes:
        raw_secret: The plaintext credential (ONE-TIME ACCESS ONLY).
        display_prefix: Safe prefix for credential identification.
        full_prefix: Complete prefix including any configured prefix.
    """
    raw_secret: str
    display_prefix: str
    full_prefix: str
    
    def __repr__(self) -> str:
        """Prevent secret from appearing in repr output."""
        return f"GeneratedCredential(display_prefix='{self.display_prefix}', full_prefix='{self.full_prefix}')"
    
    def __str__(self) -> str:
        """Prevent secret from appearing in str output."""
        return f"GeneratedCredential({self.display_prefix}...)"


class CredentialGenerator:
    """Generates cryptographically secure credentials.
    
    Uses the secrets module to generate cryptographically strong
    random values suitable for authentication credentials.
    """
    
    # Characters allowed in generated credentials
    CREDENTIAL_ALPHABET: ClassVar[str] = string.ascii_letters + string.digits
    
    def __init__(self, config: CredentialConfig | None = None) -> None:
        """Initialize the credential generator.
        
        Args:
            config: Optional configuration. Uses defaults if not provided.
        """
        self._config = config or CredentialConfig()
    
    @property
    def config(self) -> CredentialConfig:
        """The current generator configuration."""
        return self._config
    
    def generate_api_key(self) -> GeneratedCredential:
        """Generate a new API key.
        
        Returns:
            GeneratedCredential containing the raw key and safe metadata.
            The raw_secret must be returned to the caller once and never stored.
        """
        # Generate random bytes and encode as URL-safe string
        random_part = self._generate_random_string(self._config.api_key_length)
        
        # Construct full key with prefix
        full_key = f"{self._config.api_key_prefix}{random_part}"
        
        # Extract display prefix (characters after the configured prefix)
        display_prefix = full_key[:self._config.display_prefix_length]
        
        return GeneratedCredential(
            raw_secret=full_key,
            display_prefix=display_prefix,
            full_prefix=self._config.api_key_prefix,
        )
    
    def generate_client_secret(self) -> GeneratedCredential:
        """Generate a new OAuth client secret.
        
        Returns:
            GeneratedCredential containing the raw secret and safe metadata.
            The raw_secret must be returned to the caller once and never stored.
        """
        # Generate random bytes for client secret
        secret = self._generate_random_string(self._config.client_secret_length)
        
        # Display prefix for client secrets (first N characters)
        display_prefix = secret[:self._config.display_prefix_length]
        
        return GeneratedCredential(
            raw_secret=secret,
            display_prefix=display_prefix,
            full_prefix="",  # No prefix for client secrets
        )
    
    def _generate_random_string(self, length: int) -> str:
        """Generate a cryptographically secure random string.
        
        Args:
            length: Number of random characters to generate.
            
        Returns:
            Random string of the specified length.
        """
        return ''.join(
            secrets.choice(self.CREDENTIAL_ALPHABET)
            for _ in range(length)
        )
    
    @staticmethod
    def extract_prefix(credential: str, prefix_length: int = 8) -> str:
        """Extract the safe display prefix from a credential.
        
        Args:
            credential: The full credential string.
            prefix_length: Number of characters to extract.
            
        Returns:
            The prefix portion safe for display/storage.
        """
        if len(credential) < prefix_length:
            return credential
        return credential[:prefix_length]
