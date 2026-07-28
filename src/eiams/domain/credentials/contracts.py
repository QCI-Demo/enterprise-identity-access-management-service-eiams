"""Credentials domain contracts.

Framework-isolated interfaces for credential management.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

from eiams.shared.kernel import EntityId, TenantId, Timestamp
from eiams.shared.context import RequestContext
from eiams.domain.base import DomainEntity, Repository, DomainService
from eiams.domain.identity.contracts import UserId


class ApiKeyId(EntityId):
    """Unique identifier for an API key."""
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
