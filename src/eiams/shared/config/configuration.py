"""Framework-isolated configuration abstraction.

Security and policy values (hashing parameters, account eligibility,
bounds) must be supplied by configuration rather than hard-coded. This
module defines the provider contract plus pure in-process providers.
Environment-backed and file-backed providers live in the infrastructure
layer so the shared kernel stays dependency-free.
"""

from abc import ABC, abstractmethod
from typing import Any, Iterable, Mapping

from eiams.shared.errors import (
    ConfigurationError,
    MissingConfigurationError,
)


TRUE_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on", "enabled"})
FALSE_VALUES: frozenset[str] = frozenset({"0", "false", "no", "off", "disabled"})


def normalize_key(key: str) -> str:
    """Normalize a configuration key to its canonical form.

    Keys are case-insensitive and treat ``.``, ``__``, and ``_`` as
    equivalent separators so the same logical key can be expressed as
    ``security.password.algorithm`` or ``SECURITY__PASSWORD__ALGORITHM``.
    """
    if not key or not isinstance(key, str):
        raise ConfigurationError("Configuration key must be a non-empty string")
    return key.strip().lower().replace("__", ".").replace("_", ".")


class ConfigurationProvider(ABC):
    """Contract for reading configuration values.

    Implementations only need to resolve raw string values; typed
    accessors and validation are provided here so every provider
    behaves identically.
    """

    @abstractmethod
    def get_raw(self, key: str) -> str | None:
        """Resolve the raw string value for a key, or None if absent."""
        ...

    def has(self, key: str) -> bool:
        """Whether a value is present for the key."""
        return self.get_raw(key) is not None

    def get_str(self, key: str, default: str | None = None) -> str | None:
        """Read a string value, falling back to a default."""
        value = self.get_raw(key)
        if value is None:
            return default
        stripped = value.strip()
        return stripped if stripped else default

    def require_str(self, key: str) -> str:
        """Read a required string value.

        Raises:
            MissingConfigurationError: If the key has no value.
        """
        value = self.get_str(key)
        if value is None:
            raise MissingConfigurationError(key)
        return value

    def get_int(
        self,
        key: str,
        default: int | None = None,
        *,
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> int | None:
        """Read an integer value with optional inclusive bounds.

        Raises:
            ConfigurationError: If the value is not an integer or is out
                of the permitted range.
        """
        raw = self.get_str(key)
        if raw is None:
            value = default
        else:
            try:
                value = int(raw)
            except ValueError:
                raise ConfigurationError(
                    f"Configuration value for {key} must be an integer",
                    key=key,
                )
        if value is None:
            return None
        self._check_bounds(key, value, minimum, maximum)
        return value

    def require_int(
        self,
        key: str,
        *,
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> int:
        """Read a required integer value with optional inclusive bounds."""
        value = self.get_int(key, minimum=minimum, maximum=maximum)
        if value is None:
            raise MissingConfigurationError(key)
        return value

    def get_bool(self, key: str, default: bool | None = None) -> bool | None:
        """Read a boolean value.

        Raises:
            ConfigurationError: If the value is not a recognized boolean.
        """
        raw = self.get_str(key)
        if raw is None:
            return default
        lowered = raw.lower()
        if lowered in TRUE_VALUES:
            return True
        if lowered in FALSE_VALUES:
            return False
        raise ConfigurationError(
            f"Configuration value for {key} must be a boolean",
            key=key,
        )

    def get_str_tuple(
        self,
        key: str,
        default: tuple[str, ...] | None = None,
        *,
        separator: str = ",",
    ) -> tuple[str, ...]:
        """Read a separated list of strings.

        Empty entries are dropped and surrounding whitespace is removed.
        """
        raw = self.get_str(key)
        if raw is None:
            return default if default is not None else ()
        parts = tuple(part.strip() for part in raw.split(separator))
        values = tuple(part for part in parts if part)
        if not values:
            return default if default is not None else ()
        return values

    def require_str_tuple(
        self,
        key: str,
        *,
        separator: str = ",",
    ) -> tuple[str, ...]:
        """Read a required non-empty separated list of strings."""
        values = self.get_str_tuple(key, separator=separator)
        if not values:
            raise MissingConfigurationError(key)
        return values

    @staticmethod
    def _check_bounds(
        key: str,
        value: int,
        minimum: int | None,
        maximum: int | None,
    ) -> None:
        """Validate an integer value against inclusive bounds."""
        if minimum is not None and value < minimum:
            raise ConfigurationError(
                f"Configuration value for {key} must be at least {minimum}",
                key=key,
            )
        if maximum is not None and value > maximum:
            raise ConfigurationError(
                f"Configuration value for {key} must be at most {maximum}",
                key=key,
            )


class MappingConfigurationProvider(ConfigurationProvider):
    """Configuration provider backed by an in-memory mapping.

    Keys are normalized so callers can mix separator and casing styles.
    Values are copied at construction time to keep the provider immutable
    from the caller's perspective.
    """

    def __init__(
        self,
        values: Mapping[str, Any] | None = None,
        *,
        prefix: str | None = None,
    ) -> None:
        """Initialize the provider.

        Args:
            values: Raw configuration mapping.
            prefix: Optional prefix stripped from mapping keys, allowing
                namespaced sources (for example ``EIAMS_``) to be used
                with unprefixed logical keys.
        """
        self._prefix = normalize_key(prefix) if prefix else None
        self._values: dict[str, str] = {}
        for raw_key, raw_value in (values or {}).items():
            if raw_value is None:
                continue
            key = normalize_key(str(raw_key))
            if self._prefix:
                if not key.startswith(self._prefix):
                    continue
                key = key[len(self._prefix) :].lstrip(".")
                if not key:
                    continue
            self._values[key] = str(raw_value)

    @property
    def keys(self) -> tuple[str, ...]:
        """All normalized keys held by this provider."""
        return tuple(sorted(self._values))

    def get_raw(self, key: str) -> str | None:
        """Resolve the raw string value for a normalized key."""
        return self._values.get(normalize_key(key))


class LayeredConfigurationProvider(ConfigurationProvider):
    """Configuration provider that resolves through ordered layers.

    The first layer that holds a value wins, which lets deployment
    overrides sit in front of packaged defaults.
    """

    def __init__(self, providers: Iterable[ConfigurationProvider]) -> None:
        """Initialize with providers in precedence order."""
        self._providers = tuple(providers)
        if not self._providers:
            raise ConfigurationError(
                "At least one configuration provider is required"
            )

    @property
    def providers(self) -> tuple[ConfigurationProvider, ...]:
        """The layered providers in precedence order."""
        return self._providers

    def get_raw(self, key: str) -> str | None:
        """Resolve the first available value across layers."""
        for provider in self._providers:
            value = provider.get_raw(key)
            if value is not None:
                return value
        return None
