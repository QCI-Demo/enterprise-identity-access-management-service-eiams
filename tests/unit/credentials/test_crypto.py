"""Tests for cryptographic credential generation and hashing.

Verifies that:
1. Generated credentials are cryptographically strong
2. Secret hashing produces verifiable hashes
3. Raw secrets are not exposed in repr/str output
4. Verification correctly accepts/rejects credentials
"""

import pytest
import re

from eiams.infrastructure.crypto import (
    CredentialGenerator,
    GeneratedCredential,
    CredentialConfig,
    SecretHasher,
    HashConfig,
    HashedSecret,
)


class TestCredentialGenerator:
    """Tests for credential generation."""
    
    def test_generate_api_key_returns_credential(self) -> None:
        """Verify API key generation returns a valid credential."""
        generator = CredentialGenerator()
        credential = generator.generate_api_key()
        
        assert isinstance(credential, GeneratedCredential)
        assert credential.raw_secret is not None
        assert len(credential.raw_secret) > 0
    
    def test_generate_api_key_includes_prefix(self) -> None:
        """Verify API key includes configured prefix."""
        config = CredentialConfig(api_key_prefix="test_")
        generator = CredentialGenerator(config)
        credential = generator.generate_api_key()
        
        assert credential.raw_secret.startswith("test_")
        assert credential.full_prefix == "test_"
    
    def test_generate_api_key_correct_length(self) -> None:
        """Verify API key has correct length."""
        config = CredentialConfig(api_key_length=32, api_key_prefix="eiams_")
        generator = CredentialGenerator(config)
        credential = generator.generate_api_key()
        
        # Key = prefix + random part
        assert len(credential.raw_secret) == 32 + len("eiams_")
    
    def test_generate_api_key_unique(self) -> None:
        """Verify each generated API key is unique."""
        generator = CredentialGenerator()
        keys = [generator.generate_api_key().raw_secret for _ in range(100)]
        
        assert len(set(keys)) == 100
    
    def test_generate_api_key_safe_characters(self) -> None:
        """Verify API key uses only safe characters."""
        generator = CredentialGenerator()
        credential = generator.generate_api_key()
        
        # Remove prefix and check random part
        random_part = credential.raw_secret[len(credential.full_prefix):]
        assert re.match(r'^[a-zA-Z0-9]+$', random_part)
    
    def test_generate_client_secret_returns_credential(self) -> None:
        """Verify client secret generation returns a valid credential."""
        generator = CredentialGenerator()
        credential = generator.generate_client_secret()
        
        assert isinstance(credential, GeneratedCredential)
        assert credential.raw_secret is not None
        assert len(credential.raw_secret) > 0
    
    def test_generate_client_secret_no_prefix(self) -> None:
        """Verify client secret has no prefix."""
        generator = CredentialGenerator()
        credential = generator.generate_client_secret()
        
        assert credential.full_prefix == ""
    
    def test_generate_client_secret_correct_length(self) -> None:
        """Verify client secret has correct length."""
        config = CredentialConfig(client_secret_length=48)
        generator = CredentialGenerator(config)
        credential = generator.generate_client_secret()
        
        assert len(credential.raw_secret) == 48
    
    def test_credential_repr_hides_secret(self) -> None:
        """Verify repr does not expose the raw secret."""
        generator = CredentialGenerator()
        credential = generator.generate_api_key()
        
        repr_str = repr(credential)
        str_str = str(credential)
        
        assert credential.raw_secret not in repr_str
        assert credential.raw_secret not in str_str
        assert "display_prefix" in repr_str
    
    def test_display_prefix_is_prefix_of_secret(self) -> None:
        """Verify display_prefix is a prefix of the raw secret."""
        config = CredentialConfig(display_prefix_length=8)
        generator = CredentialGenerator(config)
        credential = generator.generate_api_key()
        
        assert credential.raw_secret.startswith(credential.display_prefix)
        assert len(credential.display_prefix) == 8
    
    def test_config_validation_rejects_short_key_length(self) -> None:
        """Verify config rejects key length below minimum."""
        with pytest.raises(ValueError, match="api_key_length"):
            CredentialConfig(api_key_length=8)
    
    def test_config_validation_rejects_long_key_length(self) -> None:
        """Verify config rejects key length above maximum."""
        with pytest.raises(ValueError, match="api_key_length"):
            CredentialConfig(api_key_length=128)
    
    def test_extract_prefix_static_method(self) -> None:
        """Verify prefix extraction works correctly."""
        assert CredentialGenerator.extract_prefix("abc123xyz", 3) == "abc"
        assert CredentialGenerator.extract_prefix("ab", 5) == "ab"


class TestSecretHasher:
    """Tests for secret hashing and verification."""
    
    def test_hash_secret_returns_hashed_secret(self) -> None:
        """Verify hashing returns a HashedSecret."""
        hasher = SecretHasher()
        result = hasher.hash_secret("my_secret")
        
        assert isinstance(result, HashedSecret)
        assert result.hash_value is not None
        assert result.salt is not None
    
    def test_hash_secret_produces_different_hashes(self) -> None:
        """Verify same secret produces different hashes (due to salt)."""
        hasher = SecretHasher()
        hash1 = hasher.hash_secret("same_secret")
        hash2 = hasher.hash_secret("same_secret")
        
        # Hashes should differ due to random salt
        assert hash1.hash_value != hash2.hash_value
        assert hash1.salt != hash2.salt
    
    def test_verify_secret_accepts_correct_secret(self) -> None:
        """Verify verification accepts the correct secret."""
        hasher = SecretHasher()
        secret = "my_test_secret"
        hashed = hasher.hash_secret(secret)
        
        assert hasher.verify_secret(secret, hashed) is True
    
    def test_verify_secret_rejects_wrong_secret(self) -> None:
        """Verify verification rejects wrong secrets."""
        hasher = SecretHasher()
        secret = "my_test_secret"
        hashed = hasher.hash_secret(secret)
        
        assert hasher.verify_secret("wrong_secret", hashed) is False
        assert hasher.verify_secret("", hashed) is False
        assert hasher.verify_secret("my_test_secrets", hashed) is False
    
    def test_verify_secret_timing_safe(self) -> None:
        """Verify that verification uses constant-time comparison.
        
        Note: This test can't truly verify timing safety, but it
        ensures the code path is exercised.
        """
        hasher = SecretHasher()
        hashed = hasher.hash_secret("secret")
        
        # Multiple verifications should all work consistently
        results = [
            hasher.verify_secret("secret", hashed)
            for _ in range(10)
        ]
        assert all(results)
    
    def test_hash_storage_string_format(self) -> None:
        """Verify storage string has correct format."""
        hasher = SecretHasher()
        hashed = hasher.hash_secret("test")
        storage = hashed.to_storage_string()
        
        # Format: $algorithm$iterations$salt$hash
        parts = storage.split("$")
        assert len(parts) == 5
        assert parts[0] == ""
        assert parts[1] == "sha256"  # Default algorithm
        assert int(parts[2]) == 100000  # Default iterations
        # Salt and hash are hex strings
        assert re.match(r'^[a-f0-9]+$', parts[3])
        assert re.match(r'^[a-f0-9]+$', parts[4])
    
    def test_hash_from_storage_string(self) -> None:
        """Verify HashedSecret can be deserialized from storage."""
        original = HashedSecret(
            hash_value="abcd1234",
            salt="efgh5678",
            algorithm="sha256",
            iterations=100000,
        )
        storage = original.to_storage_string()
        restored = HashedSecret.from_storage_string(storage)
        
        assert restored.hash_value == original.hash_value
        assert restored.salt == original.salt
        assert restored.algorithm == original.algorithm
        assert restored.iterations == original.iterations
    
    def test_verify_from_storage_string(self) -> None:
        """Verify verification works with storage string."""
        hasher = SecretHasher()
        secret = "test_secret"
        hashed = hasher.hash_secret(secret)
        storage = hashed.to_storage_string()
        
        assert hasher.verify_from_storage(secret, storage) is True
        assert hasher.verify_from_storage("wrong", storage) is False
    
    def test_hashed_secret_repr_is_safe(self) -> None:
        """Verify HashedSecret repr doesn't expose hash values."""
        hashed = HashedSecret(
            hash_value="sensitive_hash",
            salt="sensitive_salt",
            algorithm="sha256",
            iterations=100000,
        )
        repr_str = repr(hashed)
        
        assert "sensitive_hash" not in repr_str
        assert "sensitive_salt" not in repr_str
        assert "sha256" in repr_str
    
    def test_config_validation_rejects_weak_iterations(self) -> None:
        """Verify config rejects iteration count below minimum."""
        with pytest.raises(ValueError, match="iterations"):
            HashConfig(iterations=100)
    
    def test_config_validation_rejects_unsupported_algorithm(self) -> None:
        """Verify config rejects unsupported algorithm."""
        with pytest.raises(ValueError, match="algorithm"):
            HashConfig(algorithm="md5")
    
    def test_hash_empty_secret_raises(self) -> None:
        """Verify hashing empty secret raises error."""
        hasher = SecretHasher()
        with pytest.raises(ValueError, match="empty"):
            hasher.hash_secret("")


class TestCredentialSecurityProperties:
    """Tests for security properties of credential handling."""
    
    def test_generated_credentials_are_cryptographically_random(self) -> None:
        """Verify generated credentials have sufficient entropy."""
        generator = CredentialGenerator()
        
        # Generate many credentials and check uniqueness
        credentials = [generator.generate_api_key().raw_secret for _ in range(1000)]
        unique = set(credentials)
        
        # All should be unique
        assert len(unique) == 1000
    
    def test_hash_salt_is_random(self) -> None:
        """Verify hash salt is randomly generated."""
        hasher = SecretHasher()
        
        salts = [hasher.hash_secret("same").salt for _ in range(100)]
        unique = set(salts)
        
        # All salts should be unique
        assert len(unique) == 100
    
    def test_credential_not_in_any_string_output(self) -> None:
        """Verify raw credential doesn't appear in any string representation."""
        generator = CredentialGenerator()
        credential = generator.generate_api_key()
        
        outputs = [
            str(credential),
            repr(credential),
            f"{credential}",
        ]
        
        for output in outputs:
            assert credential.raw_secret not in output
    
    def test_hashed_secret_safe_for_logging(self) -> None:
        """Verify HashedSecret can be safely included in logs."""
        hasher = SecretHasher()
        hashed = hasher.hash_secret("secret_value")
        
        # The storage string contains only derived data, not the original
        storage = hashed.to_storage_string()
        assert "secret_value" not in storage
        
        # repr is also safe
        repr_str = repr(hashed)
        assert "secret_value" not in repr_str
