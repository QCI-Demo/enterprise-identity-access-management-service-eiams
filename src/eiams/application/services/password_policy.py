"""Configuration-bound password hashing and account eligibility policy.

Every cryptographic work factor and account-state decision used by
authentication is resolved here from the configuration abstraction, so
supplied security policy can change per environment without code edits.
"""

from dataclasses import dataclass

from eiams.shared.config import ConfigurationProvider
from eiams.shared.errors import ConfigurationError, ValidationError
from eiams.domain.credentials.contracts import PasswordHashAlgorithm
from eiams.domain.identity.contracts import User, UserStatus


# Configuration keys for password hashing policy
KEY_ALGORITHM = "security.password.algorithm"
KEY_ARGON2_TIME_COST = "security.password.argon2.time_cost"
KEY_ARGON2_MEMORY_COST_KIB = "security.password.argon2.memory_cost_kib"
KEY_ARGON2_PARALLELISM = "security.password.argon2.parallelism"
KEY_PBKDF2_ITERATIONS = "security.password.pbkdf2.iterations"
KEY_SALT_LENGTH = "security.password.salt_length"
KEY_HASH_LENGTH = "security.password.hash_length"
KEY_MIN_LENGTH = "security.password.min_length"
KEY_MAX_LENGTH = "security.password.max_length"

# Configuration keys for account eligibility policy
KEY_ELIGIBLE_USER_STATUSES = "security.authentication.eligible_user_statuses"
KEY_MAX_IDENTIFIER_LENGTH = "security.authentication.max_identifier_length"

# Defaults follow current OWASP guidance for Argon2id and PBKDF2-HMAC-SHA256.
DEFAULT_ALGORITHM = PasswordHashAlgorithm.ARGON2ID
DEFAULT_ARGON2_TIME_COST = 3
DEFAULT_ARGON2_MEMORY_COST_KIB = 65536
DEFAULT_ARGON2_PARALLELISM = 4
DEFAULT_PBKDF2_ITERATIONS = 600_000
DEFAULT_SALT_LENGTH = 16
DEFAULT_HASH_LENGTH = 32
DEFAULT_MIN_PASSWORD_LENGTH = 12
DEFAULT_MAX_PASSWORD_LENGTH = 256
DEFAULT_ELIGIBLE_USER_STATUSES: tuple[UserStatus, ...] = (UserStatus.ACTIVE,)
DEFAULT_MAX_IDENTIFIER_LENGTH = 320


@dataclass(frozen=True)
class PasswordHashingPolicy:
    """Password hashing parameters resolved from configuration.

    The policy also carries the accepted input bounds for presented
    passwords, which cap work for oversized submissions.
    """

    algorithm: PasswordHashAlgorithm = DEFAULT_ALGORITHM
    argon2_time_cost: int = DEFAULT_ARGON2_TIME_COST
    argon2_memory_cost_kib: int = DEFAULT_ARGON2_MEMORY_COST_KIB
    argon2_parallelism: int = DEFAULT_ARGON2_PARALLELISM
    pbkdf2_iterations: int = DEFAULT_PBKDF2_ITERATIONS
    salt_length: int = DEFAULT_SALT_LENGTH
    hash_length: int = DEFAULT_HASH_LENGTH
    min_password_length: int = DEFAULT_MIN_PASSWORD_LENGTH
    max_password_length: int = DEFAULT_MAX_PASSWORD_LENGTH

    def __post_init__(self) -> None:
        """Validate that the resolved policy is internally consistent."""
        if self.min_password_length > self.max_password_length:
            raise ConfigurationError(
                "Minimum password length cannot exceed the maximum",
                key=KEY_MIN_LENGTH,
            )

    @classmethod
    def from_configuration(
        cls,
        configuration: ConfigurationProvider,
    ) -> "PasswordHashingPolicy":
        """Bind the hashing policy from a configuration provider.

        Raises:
            ConfigurationError: If a value is malformed or out of range.
        """
        algorithm_value = configuration.get_str(
            KEY_ALGORITHM, DEFAULT_ALGORITHM.value
        )
        try:
            algorithm = PasswordHashAlgorithm.from_value(algorithm_value or "")
        except ValidationError as exc:
            raise ConfigurationError(
                "Configured password hash algorithm is not supported",
                key=KEY_ALGORITHM,
                details=exc.details,
            )

        return cls(
            algorithm=algorithm,
            argon2_time_cost=configuration.get_int(
                KEY_ARGON2_TIME_COST,
                DEFAULT_ARGON2_TIME_COST,
                minimum=1,
                maximum=64,
            ),
            argon2_memory_cost_kib=configuration.get_int(
                KEY_ARGON2_MEMORY_COST_KIB,
                DEFAULT_ARGON2_MEMORY_COST_KIB,
                minimum=8192,
                maximum=4_194_304,
            ),
            argon2_parallelism=configuration.get_int(
                KEY_ARGON2_PARALLELISM,
                DEFAULT_ARGON2_PARALLELISM,
                minimum=1,
                maximum=64,
            ),
            pbkdf2_iterations=configuration.get_int(
                KEY_PBKDF2_ITERATIONS,
                DEFAULT_PBKDF2_ITERATIONS,
                minimum=100_000,
                maximum=10_000_000,
            ),
            salt_length=configuration.get_int(
                KEY_SALT_LENGTH,
                DEFAULT_SALT_LENGTH,
                minimum=16,
                maximum=64,
            ),
            hash_length=configuration.get_int(
                KEY_HASH_LENGTH,
                DEFAULT_HASH_LENGTH,
                minimum=32,
                maximum=128,
            ),
            min_password_length=configuration.get_int(
                KEY_MIN_LENGTH,
                DEFAULT_MIN_PASSWORD_LENGTH,
                minimum=8,
                maximum=1024,
            ),
            max_password_length=configuration.get_int(
                KEY_MAX_LENGTH,
                DEFAULT_MAX_PASSWORD_LENGTH,
                minimum=64,
                maximum=4096,
            ),
        )

    def to_safe_dict(self) -> dict[str, int | str]:
        """Serialize the policy for diagnostics; contains no secrets."""
        return {
            "algorithm": self.algorithm.value,
            "argon2_time_cost": self.argon2_time_cost,
            "argon2_memory_cost_kib": self.argon2_memory_cost_kib,
            "argon2_parallelism": self.argon2_parallelism,
            "pbkdf2_iterations": self.pbkdf2_iterations,
            "salt_length": self.salt_length,
            "hash_length": self.hash_length,
            "min_password_length": self.min_password_length,
            "max_password_length": self.max_password_length,
        }


@dataclass(frozen=True)
class AccountEligibilityPolicy:
    """Account states that are permitted to authenticate.

    Eligibility is configured rather than hard-coded so deployments can
    decide, for example, whether accounts pending verification may log in.
    """

    eligible_statuses: tuple[UserStatus, ...] = DEFAULT_ELIGIBLE_USER_STATUSES
    max_identifier_length: int = DEFAULT_MAX_IDENTIFIER_LENGTH

    def __post_init__(self) -> None:
        """Validate that at least one eligible state is configured."""
        if not self.eligible_statuses:
            raise ConfigurationError(
                "At least one eligible account state must be configured",
                key=KEY_ELIGIBLE_USER_STATUSES,
            )

    @classmethod
    def from_configuration(
        cls,
        configuration: ConfigurationProvider,
    ) -> "AccountEligibilityPolicy":
        """Bind the eligibility policy from a configuration provider.

        Raises:
            ConfigurationError: If a configured state is not a known
                account status.
        """
        configured = configuration.get_str_tuple(
            KEY_ELIGIBLE_USER_STATUSES,
            tuple(status.value for status in DEFAULT_ELIGIBLE_USER_STATUSES),
        )

        statuses: list[UserStatus] = []
        for value in configured:
            normalized = value.strip().lower()
            try:
                status = UserStatus(normalized)
            except ValueError:
                raise ConfigurationError(
                    "Configured eligible account state is not a known user status",
                    key=KEY_ELIGIBLE_USER_STATUSES,
                    details={"supported": [s.value for s in UserStatus]},
                )
            if status not in statuses:
                statuses.append(status)

        return cls(
            eligible_statuses=tuple(statuses),
            max_identifier_length=configuration.get_int(
                KEY_MAX_IDENTIFIER_LENGTH,
                DEFAULT_MAX_IDENTIFIER_LENGTH,
                minimum=8,
                maximum=1024,
            ),
        )

    def is_status_eligible(self, status: UserStatus) -> bool:
        """Whether an account status may authenticate."""
        return status in self.eligible_statuses

    def is_eligible(self, user: User) -> bool:
        """Whether a resolved user may authenticate."""
        if user is None:
            return False
        return self.is_status_eligible(user.status)

    def to_safe_dict(self) -> dict[str, object]:
        """Serialize the policy for diagnostics; contains no secrets."""
        return {
            "eligible_statuses": [status.value for status in self.eligible_statuses],
            "max_identifier_length": self.max_identifier_length,
        }
