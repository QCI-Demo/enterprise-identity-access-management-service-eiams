"""Secret redaction for safe structured logging.

Provides recursive redaction of sensitive values including passwords,
client secrets, API keys, refresh tokens, JWTs, and configured sensitive
field names. Ensures raw secrets are never emitted in logs or error responses.
"""

import re
from dataclasses import dataclass, field
from typing import Any

# Default sensitive keys that will trigger redaction (case-insensitive)
DEFAULT_SENSITIVE_KEYS: frozenset[str] = frozenset({
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "clientsecret",
    "api_key",
    "apikey",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "token",
    "bearer",
    "authorization",
    "auth",
    "credential",
    "credentials",
    "private_key",
    "privatekey",
    "secret_key",
    "secretkey",
    "session_id",
    "sessionid",
    "csrf",
    "csrf_token",
    "x-api-key",
    "x-auth-token",
})

# Patterns that detect sensitive values in content
DEFAULT_SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # JWT pattern (header.payload.signature)
    re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    # Bearer token pattern
    re.compile(r"Bearer\s+[A-Za-z0-9_-]+", re.IGNORECASE),
    # Basic auth pattern
    re.compile(r"Basic\s+[A-Za-z0-9+/=]+", re.IGNORECASE),
    # Generic API key pattern (32+ hex chars)
    re.compile(r"[a-fA-F0-9]{32,}"),
    # AWS-style keys
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # Private key markers
    re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
)

REDACTED_VALUE = "[REDACTED]"


@dataclass(frozen=True)
class RedactionConfig:
    """Configuration for secret redaction.

    Attributes:
        sensitive_keys: Set of key names to redact (case-insensitive).
        sensitive_patterns: Regex patterns to detect sensitive content.
        redacted_placeholder: String to replace sensitive values with.
        max_depth: Maximum recursion depth for nested structures.
    """

    sensitive_keys: frozenset[str] = DEFAULT_SENSITIVE_KEYS
    sensitive_patterns: tuple[re.Pattern[str], ...] = DEFAULT_SENSITIVE_PATTERNS
    redacted_placeholder: str = REDACTED_VALUE
    max_depth: int = 20

    def with_additional_keys(self, *keys: str) -> "RedactionConfig":
        """Create a new config with additional sensitive keys."""
        return RedactionConfig(
            sensitive_keys=self.sensitive_keys | frozenset(k.lower() for k in keys),
            sensitive_patterns=self.sensitive_patterns,
            redacted_placeholder=self.redacted_placeholder,
            max_depth=self.max_depth,
        )


class SecretRedactor:
    """Recursively redacts sensitive values from structured data.

    Applies redaction to:
    - Dictionary keys matching sensitive key patterns
    - String values matching sensitive content patterns
    - Nested dictionaries, lists, and tuples
    - Exception messages and details
    """

    def __init__(self, config: RedactionConfig | None = None) -> None:
        """Initialize the redactor with optional configuration.

        Args:
            config: Redaction configuration. Uses defaults if not provided.
        """
        self._config = config or RedactionConfig()
        self._sensitive_keys_lower = frozenset(
            k.lower() for k in self._config.sensitive_keys
        )

    @property
    def config(self) -> RedactionConfig:
        """The current redaction configuration."""
        return self._config

    def redact(self, value: Any, depth: int = 0) -> Any:
        """Recursively redact sensitive values from structured data.

        Args:
            value: The value to redact. Can be dict, list, tuple, str, or scalar.
            depth: Current recursion depth (internal use).

        Returns:
            A copy of the value with sensitive data redacted.
        """
        if depth > self._config.max_depth:
            return self._config.redacted_placeholder

        if isinstance(value, dict):
            return self._redact_dict(value, depth)
        elif isinstance(value, (list, tuple)):
            return self._redact_sequence(value, depth)
        elif isinstance(value, str):
            return self._redact_string(value)
        elif isinstance(value, Exception):
            return self._redact_exception(value, depth)
        else:
            return value

    def _redact_dict(self, data: dict[str, Any], depth: int) -> dict[str, Any]:
        """Redact sensitive keys and values in a dictionary."""
        result: dict[str, Any] = {}
        for key, val in data.items():
            key_lower = str(key).lower()
            # Check if key matches sensitive patterns
            if self._is_sensitive_key(key_lower):
                result[key] = self._config.redacted_placeholder
            else:
                result[key] = self.redact(val, depth + 1)
        return result

    def _redact_sequence(self, data: list | tuple, depth: int) -> list | tuple:
        """Redact sensitive values in a sequence."""
        redacted = [self.redact(item, depth + 1) for item in data]
        return tuple(redacted) if isinstance(data, tuple) else redacted

    def _redact_string(self, value: str) -> str:
        """Redact sensitive patterns in a string value."""
        result = value
        for pattern in self._config.sensitive_patterns:
            result = pattern.sub(self._config.redacted_placeholder, result)
        return result

    def _redact_exception(self, exc: Exception, depth: int) -> dict[str, Any]:
        """Redact sensitive data from exception details."""
        result: dict[str, Any] = {
            "type": type(exc).__name__,
            "message": self._redact_string(str(exc)),
        }

        # Handle DomainError-style exceptions with details
        if hasattr(exc, "details") and callable(getattr(exc, "details", None)):
            # It's a property, not a method
            pass
        if hasattr(exc, "_details"):
            result["details"] = self.redact(exc._details, depth + 1)
        elif hasattr(exc, "details"):
            details = exc.details
            if isinstance(details, dict):
                result["details"] = self.redact(details, depth + 1)

        return result

    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a key matches sensitive patterns."""
        key_lower = key.lower()

        # Direct match
        if key_lower in self._sensitive_keys_lower:
            return True

        # Partial match (e.g., "user_password" contains "password")
        for sensitive_key in self._sensitive_keys_lower:
            if sensitive_key in key_lower:
                return True

        return False

    def redact_for_logging(self, data: dict[str, Any]) -> dict[str, Any]:
        """Convenience method specifically for log event payloads.

        Ensures the result is always a dictionary suitable for structured logging.

        Args:
            data: Log event data dictionary.

        Returns:
            Redacted dictionary safe for logging.
        """
        return self._redact_dict(data, 0)
