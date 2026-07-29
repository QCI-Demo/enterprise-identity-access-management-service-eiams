"""Credentials domain contracts.

Framework-isolated interfaces for credential management.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

from eiams.shared.kernel import EntityId, TenantId, Timestamp
from eiams.shared.context import RequestContext
from eiams.shared.errors import ValidationError
from eiams.domain.base import DomainEntity, Repository, DomainService
from eiams.domain.identity.contracts import UserId


class ApiKeyId(EntityId):
    """Unique identifier for an API key."""
    pass


class PasswordCredentialId(EntityId):
    """Unique identifier for a stored password credential."""
    pass


class OAuthClientId(EntityId):
    """Unique identifier for an OAuth client."""
    pass


class ApiKeyStatus(str, Enum):
    """Status of an API key."""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class OAuthClientType(str, Enum):
    """Type of OAuth client."""
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


class PasswordHashAlgorithm(str, Enum):
    """Supported password hashing algorithms.

    Values are resolved from configuration; the service never selects an
    algorithm implicitly. Each member maps to the identifier used inside
    the protected (PHC-style) credential encoding.
    """

    ARGON2ID = "argon2id"
    PBKDF2_SHA256 = "pbkdf2_sha256"

    @property
    def encoded_identifier(self) -> str:
        """Identifier that appears in the protected credential encoding."""
        return _ENCODED_IDENTIFIERS[self]

    @property
    def encoding_prefix(self) -> str:
        """Prefix that a protected credential of this algorithm starts with."""
        return f"${self.encoded_identifier}$"

    def matches_encoding(self, protected_value: str) -> bool:
        """Whether a protected value is encoded with this algorithm."""
        if not protected_value:
            return False
        return protected_value.startswith(self.encoding_prefix)

    @classmethod
    def from_value(cls, value: str) -> "PasswordHashAlgorithm":
        """Resolve an algorithm from its configured value.

        Raises:
            ValidationError: If the value is not a supported algorithm.
        """
        normalized = (value or "").strip().lower().replace("-", "_")
        for member in cls:
            if member.value == normalized:
                return member
        raise ValidationError(
            f"Unsupported password hash algorithm: {value}",
            field="algorithm",
            details={"supported": [m.value for m in cls]},
        )


_ENCODED_IDENTIFIERS: dict[PasswordHashAlgorithm, str] = {
    PasswordHashAlgorithm.ARGON2ID: "argon2id",
    PasswordHashAlgorithm.PBKDF2_SHA256: "pbkdf2-sha256",
}


class PasswordVerificationOutcome(str, Enum):
    """Internal outcome of a password verification attempt.

    These outcomes stay inside the service boundary. External callers
    only ever observe a single generic authentication failure.
    """

    MATCH = "match"
    NO_MATCH = "no_match"
    CREDENTIAL_MISSING = "credential_missing"
    CREDENTIAL_DISABLED = "credential_disabled"
    CREDENTIAL_MALFORMED = "credential_malformed"
    ALGORITHM_UNSUPPORTED = "algorithm_unsupported"


@dataclass(frozen=True, repr=False)
class PasswordVerificationResult:
    """Internal result of a password verification attempt.

    Carries no credential material: only the outcome, the algorithm that
    was evaluated, and whether the stored credential should be rehashed
    under the currently configured work factors.
    """

    outcome: PasswordVerificationOutcome
    algorithm: PasswordHashAlgorithm | None = None
    needs_rehash: bool = False

    @classmethod
    def match(
        cls,
        algorithm: PasswordHashAlgorithm,
        needs_rehash: bool = False,
    ) -> "PasswordVerificationResult":
        """Create a successful verification result."""
        return cls(
            outcome=PasswordVerificationOutcome.MATCH,
            algorithm=algorithm,
            needs_rehash=needs_rehash,
        )

    @classmethod
    def failure(
        cls,
        outcome: PasswordVerificationOutcome,
        algorithm: PasswordHashAlgorithm | None = None,
    ) -> "PasswordVerificationResult":
        """Create a failed verification result."""
        if outcome == PasswordVerificationOutcome.MATCH:
            raise ValidationError(
                "MATCH is not a failure outcome",
                field="outcome",
            )
        return cls(outcome=outcome, algorithm=algorithm)

    @property
    def is_match(self) -> bool:
        """Whether the presented password matched the stored credential."""
        return self.outcome == PasswordVerificationOutcome.MATCH

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize for internal logging without credential material."""
        return {
            "outcome": self.outcome.value,
            "algorithm": self.algorithm.value if self.algorithm else None,
            "needs_rehash": self.needs_rehash,
        }

    def __repr__(self) -> str:
        return (
            f"PasswordVerificationResult(outcome={self.outcome.value}, "
            f"algorithm={self.algorithm.value if self.algorithm else None})"
        )


@dataclass(frozen=True, repr=False)
class StoredPasswordCredential(DomainEntity):
    """A user's password credential in protected (hashed) form.

    The ``protected_value`` is always an encoded hash produced by an
    approved hashing library; plaintext passwords are never represented
    by this entity. Serialization and representation helpers deliberately
    omit the protected value so it cannot reach logs or responses.
    """

    credential_id: PasswordCredentialId
    tenant_id: TenantId
    user_id: UserId
    algorithm: PasswordHashAlgorithm
    protected_value: str
    created_at: Timestamp
    updated_at: Timestamp
    is_active: bool = True

    @property
    def id(self) -> EntityId:
        return self.credential_id

    @property
    def has_protected_representation(self) -> bool:
        """Whether the stored value is a well-formed protected encoding.

        A protected representation is a PHC-style string that declares the
        algorithm and its parameters. Anything else (empty value, raw
        plaintext, a bare digest, or an encoding for a different
        algorithm) is rejected so an unprotected value can never be
        treated as a comparable credential.
        """
        value = self.protected_value
        if not value or not isinstance(value, str):
            return False
        if value != value.strip() or any(c.isspace() for c in value):
            return False
        if not self.algorithm.matches_encoding(value):
            return False
        # "$<algorithm>$<parameters>$<salt>$<digest>" style encodings always
        # carry at least the algorithm plus two further segments.
        segments = [segment for segment in value.split("$") if segment]
        return len(segments) >= 3

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize without any credential material."""
        return {
            "credential_id": str(self.credential_id),
            "tenant_id": str(self.tenant_id),
            "user_id": str(self.user_id),
            "algorithm": self.algorithm.value,
            "is_active": self.is_active,
            "created_at": self.created_at.to_iso(),
            "updated_at": self.updated_at.to_iso(),
        }

    def __repr__(self) -> str:
        return (
            f"StoredPasswordCredential(credential_id={self.credential_id!s}, "
            f"algorithm={self.algorithm.value}, protected_value=[REDACTED])"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, StoredPasswordCredential):
            return NotImplemented
        return self.credential_id == other.credential_id

    def __hash__(self) -> int:
        return hash(self.credential_id)


@dataclass(frozen=True)
class ApiKey(DomainEntity):
    """API key entity contract.

    Represents an API key for programmatic access.
    Note: The actual key value is only available at creation time.
    """

    api_key_id: ApiKeyId
    tenant_id: TenantId
    user_id: UserId | None  # None for service-level keys
    name: str
    key_prefix: str  # First few characters for identification
    key_hash: str  # Hashed key value for validation
    scopes: tuple[str, ...]
    status: ApiKeyStatus
    created_at: Timestamp
    expires_at: Timestamp | None
    last_used_at: Timestamp | None

    @property
    def id(self) -> EntityId:
        return self.api_key_id

    @property
    def is_active(self) -> bool:
        """Check if the API key is currently usable."""
        if self.status != ApiKeyStatus.ACTIVE:
            return False
        if self.expires_at and Timestamp.now() > self.expires_at:
            return False
        return True

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ApiKey):
            return NotImplemented
        return self.api_key_id == other.api_key_id

    def __hash__(self) -> int:
        return hash(self.api_key_id)


@dataclass(frozen=True)
class OAuthClient(DomainEntity):
    """OAuth client entity contract.

    Represents an OAuth 2.0 client application.
    """

    client_id: OAuthClientId
    tenant_id: TenantId
    name: str
    description: str | None
    client_type: OAuthClientType
    client_secret_hash: str | None  # None for public clients
    redirect_uris: tuple[str, ...]
    scopes: tuple[str, ...]
    is_active: bool
    created_at: Timestamp
    updated_at: Timestamp

    @property
    def id(self) -> EntityId:
        return self.client_id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OAuthClient):
            return NotImplemented
        return self.client_id == other.client_id

    def __hash__(self) -> int:
        return hash(self.client_id)


class PasswordCredentialRepository(
    Repository[StoredPasswordCredential, PasswordCredentialId], ABC
):
    """Repository contract for protected password credential persistence."""

    @abstractmethod
    def find_active_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> StoredPasswordCredential | None:
        """Find the active password credential for a user within tenant scope.

        Returns None when the user has no active password credential.
        """
        ...


class ApiKeyRepository(Repository[ApiKey, ApiKeyId], ABC):
    """Repository contract for API key persistence operations."""

    @abstractmethod
    def find_by_prefix(
        self, context: RequestContext, prefix: str
    ) -> ApiKey | None:
        """Find an API key by its prefix."""
        ...

    @abstractmethod
    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[ApiKey]:
        """Find all API keys for a user."""
        ...

    @abstractmethod
    def find_active(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[ApiKey]:
        """Find all active API keys with pagination."""
        ...


class OAuthClientRepository(Repository[OAuthClient, OAuthClientId], ABC):
    """Repository contract for OAuth client persistence operations."""

    @abstractmethod
    def find_by_name(
        self, context: RequestContext, name: str
    ) -> OAuthClient | None:
        """Find an OAuth client by name."""
        ...

    @abstractmethod
    def find_active(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[OAuthClient]:
        """Find all active OAuth clients with pagination."""
        ...


class CredentialService(DomainService, ABC):
    """Domain service contract for credential operations.

    Note: This is an extension point. Actual credential validation
    and secure storage will be implemented in later epics.
    """

    @abstractmethod
    def create_api_key(
        self,
        context: RequestContext,
        name: str,
        scopes: list[str],
        user_id: UserId | None = None,
        expires_at: Timestamp | None = None,
    ) -> tuple[ApiKey, str]:
        """Create a new API key. Returns the key entity and the raw key value."""
        ...

    @abstractmethod
    def validate_api_key(
        self,
        context: RequestContext,
        raw_key: str,
    ) -> ApiKey | None:
        """Validate an API key and return it if valid."""
        ...

    @abstractmethod
    def revoke_api_key(
        self,
        context: RequestContext,
        api_key_id: ApiKeyId,
    ) -> bool:
        """Revoke an API key."""
        ...

    @abstractmethod
    def create_oauth_client(
        self,
        context: RequestContext,
        name: str,
        client_type: OAuthClientType,
        redirect_uris: list[str],
        scopes: list[str],
        description: str | None = None,
    ) -> tuple[OAuthClient, str | None]:
        """Create an OAuth client. Returns client and secret for confidential clients."""
        ...

    @abstractmethod
    def rotate_client_secret(
        self,
        context: RequestContext,
        client_id: OAuthClientId,
    ) -> str:
        """Rotate an OAuth client's secret. Returns the new secret."""
        ...
