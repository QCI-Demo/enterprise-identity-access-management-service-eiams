"""Tests for the configuration abstraction."""

import pytest

from eiams.shared.config import (
    LayeredConfigurationProvider,
    MappingConfigurationProvider,
    normalize_key,
)
from eiams.shared.errors import ConfigurationError, MissingConfigurationError
from eiams.infrastructure.config import (
    EnvironmentConfigurationProvider,
    create_configuration_provider,
)


class TestKeyNormalization:
    """Tests for configuration key normalization."""

    def test_separators_and_case_are_equivalent(self):
        """Dots, underscores, and casing resolve to the same key."""
        assert normalize_key("security.password.algorithm") == (
            normalize_key("SECURITY__PASSWORD__ALGORITHM")
        )
        assert normalize_key("Security_Password_Algorithm") == (
            "security.password.algorithm"
        )

    def test_empty_key_is_rejected(self):
        """An empty key is a configuration error."""
        with pytest.raises(ConfigurationError):
            normalize_key("")


class TestMappingConfigurationProvider:
    """Tests for the in-memory configuration provider."""

    def test_reads_values_regardless_of_key_style(self):
        """Values are readable through any equivalent key style."""
        provider = MappingConfigurationProvider(
            {"SECURITY__PASSWORD__ALGORITHM": "pbkdf2_sha256"}
        )
        assert provider.get_str("security.password.algorithm") == "pbkdf2_sha256"

    def test_missing_value_falls_back_to_default(self):
        """A default is returned when the key is absent."""
        provider = MappingConfigurationProvider({})
        assert provider.get_str("security.password.algorithm", "argon2id") == "argon2id"
        assert provider.has("security.password.algorithm") is False

    def test_prefix_is_stripped(self):
        """A namespace prefix is removed from source keys."""
        provider = MappingConfigurationProvider(
            {"EIAMS_SECURITY__PASSWORD__MAX_LENGTH": "512", "OTHER_KEY": "ignored"},
            prefix="EIAMS",
        )
        assert provider.get_int("security.password.max_length") == 512
        assert provider.has("other.key") is False

    def test_integer_bounds_are_enforced(self):
        """Out-of-range integers raise a configuration error."""
        provider = MappingConfigurationProvider({"work.factor": "2"})
        with pytest.raises(ConfigurationError) as exc_info:
            provider.get_int("work.factor", minimum=4)
        assert exc_info.value.key == "work.factor"

    def test_non_integer_value_is_rejected(self):
        """A non-numeric value for an integer key is rejected."""
        provider = MappingConfigurationProvider({"work.factor": "high"})
        with pytest.raises(ConfigurationError):
            provider.get_int("work.factor")

    def test_boolean_parsing(self):
        """Recognized boolean spellings parse; others are rejected."""
        provider = MappingConfigurationProvider(
            {"flag.on": "yes", "flag.off": "disabled", "flag.bad": "perhaps"}
        )
        assert provider.get_bool("flag.on") is True
        assert provider.get_bool("flag.off") is False
        assert provider.get_bool("flag.absent", True) is True
        with pytest.raises(ConfigurationError):
            provider.get_bool("flag.bad")

    def test_string_tuple_parsing(self):
        """Separated lists drop blanks and trim whitespace."""
        provider = MappingConfigurationProvider({"states": " active , ,pending "})
        assert provider.get_str_tuple("states") == ("active", "pending")
        assert provider.get_str_tuple("absent", ("active",)) == ("active",)

    def test_required_values_raise_when_absent(self):
        """Required accessors raise a missing-configuration error."""
        provider = MappingConfigurationProvider({})
        with pytest.raises(MissingConfigurationError):
            provider.require_str("security.password.algorithm")
        with pytest.raises(MissingConfigurationError):
            provider.require_int("security.password.max_length")
        with pytest.raises(MissingConfigurationError):
            provider.require_str_tuple("security.authentication.eligible_user_statuses")


class TestLayeredConfigurationProvider:
    """Tests for layered configuration precedence."""

    def test_first_layer_with_a_value_wins(self):
        """Earlier layers override later ones."""
        provider = LayeredConfigurationProvider(
            [
                MappingConfigurationProvider({"security.password.algorithm": "argon2id"}),
                MappingConfigurationProvider(
                    {
                        "security.password.algorithm": "pbkdf2_sha256",
                        "security.password.max_length": "128",
                    }
                ),
            ]
        )
        assert provider.get_str("security.password.algorithm") == "argon2id"
        assert provider.get_int("security.password.max_length") == 128

    def test_at_least_one_layer_is_required(self):
        """An empty layer list is a configuration error."""
        with pytest.raises(ConfigurationError):
            LayeredConfigurationProvider([])


class TestEnvironmentConfigurationProvider:
    """Tests for the environment-backed provider."""

    def test_reads_prefixed_environment_variables(self):
        """Prefixed variables resolve to logical keys."""
        provider = EnvironmentConfigurationProvider(
            {"EIAMS_SECURITY__PASSWORD__ARGON2__TIME_COST": "5"}
        )
        assert provider.get_int("security.password.argon2.time_cost") == 5

    def test_unprefixed_variables_are_ignored(self):
        """Variables outside the namespace are not visible."""
        provider = EnvironmentConfigurationProvider({"PATH": "/usr/bin"})
        assert provider.has("path") is False

    def test_overrides_take_precedence_over_environment(self):
        """Explicit overrides beat the environment, which beats defaults."""
        provider = create_configuration_provider(
            overrides={"security.password.algorithm": "argon2id"},
            defaults={"security.password.max_length": "256"},
            environ={
                "EIAMS_SECURITY__PASSWORD__ALGORITHM": "pbkdf2_sha256",
                "EIAMS_SECURITY__PASSWORD__MAX_LENGTH": "512",
            },
        )
        assert provider.get_str("security.password.algorithm") == "argon2id"
        assert provider.get_int("security.password.max_length") == 512
