"""Tests for configuration-bound password and eligibility policy."""

import pytest

from eiams.shared.config import MappingConfigurationProvider
from eiams.shared.errors import ConfigurationError
from eiams.domain.credentials.contracts import PasswordHashAlgorithm
from eiams.domain.identity.contracts import UserStatus
from eiams.application.services.password_policy import (
    AccountEligibilityPolicy,
    PasswordHashingPolicy,
    DEFAULT_ALGORITHM,
    DEFAULT_ARGON2_MEMORY_COST_KIB,
    DEFAULT_ARGON2_TIME_COST,
    DEFAULT_MAX_PASSWORD_LENGTH,
)
from tests.conftest import build_stack, build_user


class TestPasswordHashingPolicyBinding:
    """Tests for binding hashing parameters from configuration."""

    def test_defaults_apply_when_configuration_is_empty(self):
        """An empty provider yields the packaged defaults."""
        policy = PasswordHashingPolicy.from_configuration(
            MappingConfigurationProvider({})
        )
        assert policy.algorithm == DEFAULT_ALGORITHM
        assert policy.argon2_time_cost == DEFAULT_ARGON2_TIME_COST
        assert policy.argon2_memory_cost_kib == DEFAULT_ARGON2_MEMORY_COST_KIB
        assert policy.max_password_length == DEFAULT_MAX_PASSWORD_LENGTH

    def test_values_are_injected_from_configuration(self):
        """Configured work factors override the defaults."""
        policy = PasswordHashingPolicy.from_configuration(
            MappingConfigurationProvider(
                {
                    "security.password.algorithm": "pbkdf2_sha256",
                    "security.password.argon2.time_cost": "7",
                    "security.password.argon2.memory_cost_kib": "131072",
                    "security.password.argon2.parallelism": "8",
                    "security.password.pbkdf2.iterations": "750000",
                    "security.password.salt_length": "32",
                    "security.password.hash_length": "64",
                    "security.password.min_length": "16",
                    "security.password.max_length": "512",
                }
            )
        )
        assert policy.algorithm == PasswordHashAlgorithm.PBKDF2_SHA256
        assert policy.argon2_time_cost == 7
        assert policy.argon2_memory_cost_kib == 131072
        assert policy.argon2_parallelism == 8
        assert policy.pbkdf2_iterations == 750000
        assert policy.salt_length == 32
        assert policy.hash_length == 64
        assert policy.min_password_length == 16
        assert policy.max_password_length == 512

    def test_environment_style_keys_are_accepted(self):
        """Environment-style key spelling binds the same values."""
        policy = PasswordHashingPolicy.from_configuration(
            MappingConfigurationProvider(
                {"SECURITY__PASSWORD__ARGON2__TIME_COST": "4"}
            )
        )
        assert policy.argon2_time_cost == 4

    def test_unsupported_algorithm_is_rejected(self):
        """An unknown algorithm fails fast as a configuration error."""
        with pytest.raises(ConfigurationError) as exc_info:
            PasswordHashingPolicy.from_configuration(
                MappingConfigurationProvider({"security.password.algorithm": "md5"})
            )
        assert exc_info.value.key == "security.password.algorithm"

    def test_work_factor_below_floor_is_rejected(self):
        """A work factor under the safe floor fails fast."""
        with pytest.raises(ConfigurationError):
            PasswordHashingPolicy.from_configuration(
                MappingConfigurationProvider(
                    {"security.password.argon2.memory_cost_kib": "16"}
                )
            )

    def test_iteration_count_below_floor_is_rejected(self):
        """A PBKDF2 iteration count under the floor fails fast."""
        with pytest.raises(ConfigurationError):
            PasswordHashingPolicy.from_configuration(
                MappingConfigurationProvider(
                    {"security.password.pbkdf2.iterations": "1000"}
                )
            )

    def test_inconsistent_length_bounds_are_rejected(self):
        """A minimum above the maximum is rejected."""
        with pytest.raises(ConfigurationError):
            PasswordHashingPolicy(min_password_length=200, max_password_length=100)

    def test_safe_dict_contains_no_secrets(self):
        """The diagnostic view exposes only parameters."""
        policy = PasswordHashingPolicy()
        assert policy.to_safe_dict()["algorithm"] == DEFAULT_ALGORITHM.value
        assert "protected_value" not in policy.to_safe_dict()


class TestAccountEligibilityPolicyBinding:
    """Tests for binding account eligibility from configuration."""

    def test_default_allows_only_active_accounts(self):
        """Only active accounts may authenticate by default."""
        policy = AccountEligibilityPolicy.from_configuration(
            MappingConfigurationProvider({})
        )
        assert policy.eligible_statuses == (UserStatus.ACTIVE,)
        assert policy.is_status_eligible(UserStatus.ACTIVE) is True
        assert policy.is_status_eligible(UserStatus.SUSPENDED) is False

    def test_configured_states_are_injected(self):
        """Configured states replace the default set."""
        policy = AccountEligibilityPolicy.from_configuration(
            MappingConfigurationProvider(
                {
                    "security.authentication.eligible_user_statuses": (
                        "active, pending_verification"
                    ),
                    "security.authentication.max_identifier_length": "128",
                }
            )
        )
        assert policy.eligible_statuses == (
            UserStatus.ACTIVE,
            UserStatus.PENDING_VERIFICATION,
        )
        assert policy.max_identifier_length == 128
        assert policy.is_status_eligible(UserStatus.PENDING_VERIFICATION) is True
        assert policy.is_status_eligible(UserStatus.INACTIVE) is False

    def test_duplicate_states_are_collapsed(self):
        """Repeated states are de-duplicated."""
        policy = AccountEligibilityPolicy.from_configuration(
            MappingConfigurationProvider(
                {"security.authentication.eligible_user_statuses": "active,active"}
            )
        )
        assert policy.eligible_statuses == (UserStatus.ACTIVE,)

    def test_unknown_state_is_rejected(self):
        """An unrecognized account state fails fast."""
        with pytest.raises(ConfigurationError):
            AccountEligibilityPolicy.from_configuration(
                MappingConfigurationProvider(
                    {"security.authentication.eligible_user_statuses": "zombie"}
                )
            )

    def test_empty_state_set_is_rejected(self):
        """An empty eligible set is rejected."""
        with pytest.raises(ConfigurationError):
            AccountEligibilityPolicy(eligible_statuses=())

    def test_is_eligible_uses_user_status(self, tenant_id):
        """User eligibility follows the configured states."""
        policy = AccountEligibilityPolicy()
        assert policy.is_eligible(build_user(tenant_id)) is True
        assert (
            policy.is_eligible(build_user(tenant_id, status=UserStatus.SUSPENDED))
            is False
        )


class TestPolicyInjectionThroughComposition:
    """Tests that the wired stack honours injected policy values."""

    def test_login_bounds_come_from_configuration(self, tenant_id):
        """Endpoint and service bounds derive from configuration."""
        configuration = MappingConfigurationProvider(
            {
                "security.password.algorithm": "pbkdf2_sha256",
                "security.password.pbkdf2.iterations": "100000",
                "security.password.max_length": "72",
                "security.authentication.max_identifier_length": "64",
                "security.authentication.eligible_user_statuses": "active,inactive",
            }
        )
        stack = build_stack(configuration, tenant_id)

        assert stack.login_service.max_password_length == 72
        assert stack.login_service.max_identifier_length == 64
        assert stack.components.hashing_policy.algorithm == (
            PasswordHashAlgorithm.PBKDF2_SHA256
        )
        assert stack.components.eligibility_policy.eligible_statuses == (
            UserStatus.ACTIVE,
            UserStatus.INACTIVE,
        )
