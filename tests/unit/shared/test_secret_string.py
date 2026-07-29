"""Tests for the secret-carrying value object."""

import json

import pytest

from eiams.shared.errors import ValidationError
from eiams.shared.kernel import SecretString
from eiams.shared.logging import SecretRedactor


SYNTHETIC_SECRET = "SyntheticMarker-Secret-4d1f"


class TestSecretString:
    """Tests for SecretString containment guarantees."""

    def test_reveal_returns_the_wrapped_value(self):
        """The raw value is available through an explicit call."""
        assert SecretString(SYNTHETIC_SECRET).reveal() == SYNTHETIC_SECRET

    def test_string_conversions_are_redacted(self):
        """str, repr, and format never expose the value."""
        secret = SecretString(SYNTHETIC_SECRET)
        assert SYNTHETIC_SECRET not in str(secret)
        assert SYNTHETIC_SECRET not in repr(secret)
        assert SYNTHETIC_SECRET not in f"{secret}"
        assert SYNTHETIC_SECRET not in "{}".format(secret)

    def test_serialization_is_redacted(self):
        """Dictionary serialization never exposes the value."""
        payload = json.dumps(SecretString(SYNTHETIC_SECRET).to_dict())
        assert SYNTHETIC_SECRET not in payload

    def test_length_and_emptiness_are_available(self):
        """Safe metadata about the secret is exposed."""
        secret = SecretString(SYNTHETIC_SECRET)
        assert secret.length == len(SYNTHETIC_SECRET)
        assert len(secret) == len(SYNTHETIC_SECRET)
        assert secret.is_empty is False
        assert bool(secret) is True
        assert SecretString.empty().is_empty is True

    def test_equality_compares_wrapped_values(self):
        """Two wrappers around the same value are equal."""
        assert SecretString("a") == SecretString("a")
        assert SecretString("a") != SecretString("b")
        assert (SecretString("a") == "a") is False

    def test_is_not_hashable(self):
        """Hashing is refused so secrets cannot become dict keys."""
        with pytest.raises(TypeError):
            hash(SecretString(SYNTHETIC_SECRET))

    def test_non_string_values_are_rejected(self):
        """Only strings may be wrapped."""
        with pytest.raises(ValidationError):
            SecretString(12345)  # type: ignore[arg-type]

    def test_redactor_does_not_expose_wrapped_value(self):
        """Redacting a structure containing a secret emits no raw value."""
        redacted = SecretRedactor().redact({"nested": {"value": SecretString(SYNTHETIC_SECRET)}})
        assert SYNTHETIC_SECRET not in json.dumps(redacted, default=str)
