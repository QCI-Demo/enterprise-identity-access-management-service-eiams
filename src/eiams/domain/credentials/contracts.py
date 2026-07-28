"""Credentials domain contracts.

Framework-isolated interfaces for credential management.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

from eiams.shared.kernel import EntityId, TenantId, Timestamp
from eiams.shared.context import RequestContext
from eiams.domain.base import DomainEntity, TenantScopedRepository, DomainService
from eiams.domain.identity.contracts import UserId


class ApiKeyId(EntityId):
    """Unique identifier for an API key."""
    pass


class OAuthClientId(EntityId):
    """Unique identifier for an OAuth client."""
    pass


class CredentialId(EntityId):
    """Unique identifier for a stored user credential."""
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


class CredentialType(str, Enum):
    """Type of stored user credential."""
    PASSWORD = "password"
    TOTP = "totp"
    WEBAUTHN = "webauthn"
    RECOVERY_CODE = "recovery_code"


@dataclass(frozen=True)
class UserCredential(DomainEntity):
    """Stored authentication credential for a user.

    Only verifier material is represented: ``credential_hash`` holds a hash
    or an encrypted secret, never a raw password, seed, or recovery code.
    """

    credential_id: CredentialId
    tenant_id: TenantId
    user_id: UserId
    credential_type: CredentialType
    credential_hash: str
    hash_algorithm: str
    is_active: bool
    requires_reset: bool
    failed_attempts: int
    created_at: Timestamp
    updated_at: Timestamp
    locked_until: Timestamp | None = None
    last_used_at: Timestamp | None = None

    @property
    def id(self) -> EntityId:
        return self.credential_id

    @property
    def is_locked(self) -> bool:
        """Check whether the credential is currently locked out."""
        if self.locked_until is None:
            return False
        return Timestamp.now() < self.locked_until

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UserCredential):
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


class UserCredentialRepository(
    TenantScopedRepository[UserCredential, CredentialId], ABC
):
    """Repository contract for user credential persistence operations."""

    @abstractmethod
    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[UserCredential]:
        """Find all credentials belonging to a user."""
        ...

    @abstractmethod
    def find_by_user_and_type(
        self,
        context: RequestContext,
        user_id: UserId,
        credential_type: CredentialType,
    ) -> UserCredential | None:
        """Find a user's credential of a specific type."""
        ...


class ApiKeyRepository(TenantScopedRepository[ApiKey, ApiKeyId], ABC):
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


class OAuthClientRepository(
    TenantScopedRepository[OAuthClient, OAuthClientId], ABC
):
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
