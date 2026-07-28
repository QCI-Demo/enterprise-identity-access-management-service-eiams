"""Tests for secret redaction functionality."""

import pytest

from eiams.shared.logging.redaction import (
    SecretRedactor,
    RedactionConfig,
    DEFAULT_SENSITIVE_KEYS,
    REDACTED_VALUE,
)


class TestSecretRedactor:
    """Tests for SecretRedactor."""

    def test_redacts_password_field(self):
        """Password fields should be redacted."""
        redactor = SecretRedactor()
        data = {"username": "john", "password": "supersecret123"}

        result = redactor.redact(data)

        assert result["username"] == "john"
        assert result["password"] == REDACTED_VALUE

    def test_redacts_api_key_field(self):
        """API key fields should be redacted."""
        redactor = SecretRedactor()
        data = {"api_key": "sk-1234567890abcdef"}

        result = redactor.redact(data)

        assert result["api_key"] == REDACTED_VALUE

    def test_redacts_client_secret_field(self):
        """Client secret fields should be redacted."""
        redactor = SecretRedactor()
        data = {"client_secret": "my-super-secret-client-secret"}

        result = redactor.redact(data)

        assert result["client_secret"] == REDACTED_VALUE

    def test_redacts_refresh_token_field(self):
        """Refresh token fields should be redacted."""
        redactor = SecretRedactor()
        data = {"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}

        result = redactor.redact(data)

        assert result["refresh_token"] == REDACTED_VALUE

    def test_redacts_jwt_pattern_in_string(self):
        """JWT patterns in strings should be redacted."""
        redactor = SecretRedactor()
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        message = f"Token received: {jwt}"

        result = redactor.redact(message)

        assert jwt not in result
        assert REDACTED_VALUE in result

    def test_redacts_bearer_token_in_string(self):
        """Bearer token patterns should be redacted."""
        redactor = SecretRedactor()
        data = "Authorization: Bearer abc123token456"

        result = redactor.redact(data)

        assert "Bearer abc123token456" not in result
        assert REDACTED_VALUE in result

    def test_redacts_nested_dict(self):
        """Should redact sensitive values in nested dictionaries."""
        redactor = SecretRedactor()
        data = {
            "user": {
                "name": "john",
                "security": {
                    "password": "secret123",
                    "api_key": "key123",
                }
            }
        }

        result = redactor.redact(data)

        assert result["user"]["name"] == "john"
        assert result["user"]["security"]["password"] == REDACTED_VALUE
        assert result["user"]["security"]["api_key"] == REDACTED_VALUE

    def test_redacts_list_items(self):
        """Should redact sensitive values in lists."""
        redactor = SecretRedactor()
        data = {
            "items": [
                {"api_key": "secret1"},
                {"api_key": "secret2"},
            ]
        }

        result = redactor.redact(data)

        assert result["items"][0]["api_key"] == REDACTED_VALUE
        assert result["items"][1]["api_key"] == REDACTED_VALUE

    def test_redacts_partial_key_match(self):
        """Should redact keys containing sensitive words."""
        redactor = SecretRedactor()
        data = {
            "user_password_hash": "hashed123",
            "api_secret_key": "secret456",
        }

        result = redactor.redact(data)

        assert result["user_password_hash"] == REDACTED_VALUE
        assert result["api_secret_key"] == REDACTED_VALUE

    def test_preserves_non_sensitive_fields(self):
        """Non-sensitive fields should be preserved."""
        redactor = SecretRedactor()
        data = {
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30,
            "active": True,
        }

        result = redactor.redact(data)

        assert result == data

    def test_handles_none_values(self):
        """Should handle None values gracefully."""
        redactor = SecretRedactor()
        data = {"password": None, "name": "test"}

        result = redactor.redact(data)

        assert result["password"] == REDACTED_VALUE  # Key match triggers redaction
        assert result["name"] == "test"

    def test_handles_tuples(self):
        """Should handle tuples and preserve type."""
        redactor = SecretRedactor()
        data = ("safe", {"password": "secret"})

        result = redactor.redact(data)

        assert isinstance(result, tuple)
        assert result[0] == "safe"
        assert result[1]["password"] == REDACTED_VALUE

    def test_max_depth_protection(self):
        """Should stop recursion at max depth."""
        config = RedactionConfig(max_depth=2)
        redactor = SecretRedactor(config)

        # Create deeply nested structure
        deep = {"level1": {"level2": {"level3": {"password": "secret"}}}}

        result = redactor.redact(deep)

        # At depth 2, the entire nested structure gets redacted
        assert result["level1"]["level2"]["level3"] == REDACTED_VALUE

    def test_case_insensitive_key_match(self):
        """Key matching should be case-insensitive."""
        redactor = SecretRedactor()
        data = {
            "PASSWORD": "secret1",
            "Password": "secret2",
            "API_KEY": "key1",
        }

        result = redactor.redact(data)

        assert result["PASSWORD"] == REDACTED_VALUE
        assert result["Password"] == REDACTED_VALUE
        assert result["API_KEY"] == REDACTED_VALUE

    def test_custom_sensitive_keys(self):
        """Should support custom sensitive keys."""
        config = RedactionConfig(
            sensitive_keys=frozenset({"custom_field", "my_secret"})
        )
        redactor = SecretRedactor(config)

        data = {
            "custom_field": "value1",
            "my_secret": "value2",
            "password": "notredacted",  # Not in custom keys
        }

        result = redactor.redact(data)

        assert result["custom_field"] == REDACTED_VALUE
        assert result["my_secret"] == REDACTED_VALUE
        assert result["password"] == "notredacted"

    def test_with_additional_keys(self):
        """Should support adding keys to existing config."""
        config = RedactionConfig().with_additional_keys("my_field")
        redactor = SecretRedactor(config)

        data = {
            "my_field": "secret",
            "password": "also_secret",
        }

        result = redactor.redact(data)

        assert result["my_field"] == REDACTED_VALUE
        assert result["password"] == REDACTED_VALUE


class TestRedactionWithExceptions:
    """Tests for exception redaction."""

    def test_redacts_exception_message(self):
        """Should redact sensitive data in exception messages."""
        redactor = SecretRedactor()
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        exc = ValueError(f"Invalid token: {jwt}")

        result = redactor.redact(exc)

        assert jwt not in result["message"]
        assert REDACTED_VALUE in result["message"]

    def test_redacts_domain_error_details(self):
        """Should redact sensitive data in DomainError details."""
        from eiams.shared.errors import DomainError

        redactor = SecretRedactor()
        exc = DomainError(
            "Auth failed",
            details={"password": "secret123", "user": "john"},
        )

        result = redactor.redact(exc)

        assert result["details"]["password"] == REDACTED_VALUE
        assert result["details"]["user"] == "john"


class TestRedactionForLogging:
    """Tests for logging-specific redaction."""

    def test_redact_for_logging_returns_dict(self):
        """redact_for_logging should always return a dict."""
        redactor = SecretRedactor()
        data = {"level": "info", "password": "secret"}

        result = redactor.redact_for_logging(data)

        assert isinstance(result, dict)
        assert result["level"] == "info"
        assert result["password"] == REDACTED_VALUE


class TestCorrelationPreservation:
    """Tests ensuring correlation metadata is preserved during redaction."""

    def test_preserves_correlation_id(self):
        """Correlation ID should not be redacted."""
        redactor = SecretRedactor()
        data = {
            "correlation_id": "abc-123-def-456",
            "password": "secret",
        }

        result = redactor.redact(data)

        assert result["correlation_id"] == "abc-123-def-456"
        assert result["password"] == REDACTED_VALUE

    def test_preserves_actor_id(self):
        """Actor ID should not be redacted."""
        redactor = SecretRedactor()
        data = {
            "actor_id": "user-123",
            "api_key": "secret",
        }

        result = redactor.redact(data)

        assert result["actor_id"] == "user-123"
        assert result["api_key"] == REDACTED_VALUE

    def test_preserves_tenant_id(self):
        """Tenant ID should not be redacted."""
        redactor = SecretRedactor()
        data = {
            "tenant_id": "tenant-abc",
            "secret": "hidden",
        }

        result = redactor.redact(data)

        assert result["tenant_id"] == "tenant-abc"
        assert result["secret"] == REDACTED_VALUE
