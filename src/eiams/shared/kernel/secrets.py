"""Secret-carrying value objects for the shared kernel.

Secrets are wrapped so that accidental logging, string formatting, or
serialization of a credential value cannot emit the raw material. The
wrapped value is only accessible through an explicit reveal call.
"""

from typing import Any

from eiams.shared.errors import ValidationError


REDACTED_REPRESENTATION = "[REDACTED]"


class SecretString:
    """Immutable wrapper around a sensitive string value.

    ``str()``, ``repr()``, and ``to_dict()`` always yield a redacted
    placeholder so the wrapped value cannot leak through logs, error
    messages, or serialized payloads. Use :meth:`reveal` at the single
    point where the raw value is genuinely required (for example, when
    calling a cryptographic verifier).
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        """Wrap a sensitive string value.

        Args:
            value: The sensitive value. Must be a string.

        Raises:
            ValidationError: If the value is not a string.
        """
        if not isinstance(value, str):
            raise ValidationError("Secret value must be a string", field="secret")
        self._value = value

    @classmethod
    def empty(cls) -> "SecretString":
        """Create an empty secret, useful for equalizing failure paths."""
        return cls("")

    def reveal(self) -> str:
        """Return the raw wrapped value.

        Callers must never log, store, or serialize the returned value.
        """
        return self._value

    @property
    def length(self) -> int:
        """Length of the wrapped value (safe to log)."""
        return len(self._value)

    @property
    def is_empty(self) -> bool:
        """Whether the wrapped value is empty."""
        return not self._value

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretString):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        raise TypeError("SecretString is not hashable to avoid secret leakage")

    def __str__(self) -> str:
        return REDACTED_REPRESENTATION

    def __repr__(self) -> str:
        return f"SecretString({REDACTED_REPRESENTATION})"

    def __format__(self, format_spec: str) -> str:
        return REDACTED_REPRESENTATION

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a redacted dictionary for safe logging."""
        return {"secret": REDACTED_REPRESENTATION}
