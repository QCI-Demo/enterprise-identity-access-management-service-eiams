"""Authentication domain contracts.

Framework-isolated interfaces for authentication and session management.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

from eiams.shared.kernel import EntityId, TenantId, Timestamp
from eiams.shared.context import RequestContext
from eiams.domain.base import DomainEntity, TenantScopedRepository, DomainService
from eiams.domain.identity.contracts import UserId


class SessionId(EntityId):
    """Unique identifier for a session."""
    pass


class RefreshTokenId(EntityId):
    """Unique identifier for a refresh token."""
    pass


class SessionStatus(str, Enum):
    """Status of an authentication session."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    LOGGED_OUT = "logged_out"


@dataclass(frozen=True)
class TokenClaims:
    """JWT token claims value object.

    Represents the claims encoded in an access token.
    This is a pure value object with no persistence identity.
    """

    subject: str  # User ID
    tenant_id: str
    session_id: str
    issued_at: Timestamp
    expires_at: Timestamp
    roles: tuple[str, ...]
    permissions: tuple[str, ...]

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        return Timestamp.now() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Serialize claims for token encoding."""
        return {
            "sub": self.subject,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "iat": self.issued_at.to_iso(),
            "exp": self.expires_at.to_iso(),
            "roles": list(self.roles),
            "permissions": list(self.permissions),
        }


@dataclass(frozen=True)
class Session(DomainEntity):
    """Authentication session entity contract.

    Represents an active authentication session for a user.
    """

    session_id: SessionId
    tenant_id: TenantId
    user_id: UserId
    status: SessionStatus
    created_at: Timestamp
    expires_at: Timestamp
    last_activity_at: Timestamp
    ip_address: str | None
    user_agent: str | None
    device_fingerprint: str | None = None
    revoked_at: Timestamp | None = None

    @property
    def id(self) -> EntityId:
        return self.session_id

    @property
    def is_active(self) -> bool:
        """Check if the session is currently active."""
        return (
            self.status == SessionStatus.ACTIVE
            and Timestamp.now() <= self.expires_at
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Session):
            return NotImplemented
        return self.session_id == other.session_id

    def __hash__(self) -> int:
        return hash(self.session_id)


@dataclass(frozen=True)
class RefreshToken(DomainEntity):
    """Refresh token entity contract.

    Only the token verifier is represented: ``token_hash`` holds a hash of
    the issued token, never the token itself. ``token_family`` links the
    tokens of one rotation chain so that replay of a superseded token can be
    detected.
    """

    refresh_token_id: RefreshTokenId
    tenant_id: TenantId
    session_id: SessionId
    user_id: UserId
    token_hash: str
    token_family: str
    is_revoked: bool
    created_at: Timestamp
    expires_at: Timestamp
    previous_token_id: RefreshTokenId | None = None
    used_at: Timestamp | None = None
    revoked_at: Timestamp | None = None

    @property
    def id(self) -> EntityId:
        return self.refresh_token_id

    @property
    def is_usable(self) -> bool:
        """Check whether the token can still be exchanged."""
        return (
            not self.is_revoked
            and self.used_at is None
            and Timestamp.now() <= self.expires_at
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RefreshToken):
            return NotImplemented
        return self.refresh_token_id == other.refresh_token_id

    def __hash__(self) -> int:
        return hash(self.refresh_token_id)


class SessionRepository(TenantScopedRepository[Session, SessionId], ABC):
    """Repository contract for session persistence operations."""

    @abstractmethod
    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[Session]:
        """Find all sessions for a user."""
        ...

    @abstractmethod
    def find_active_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[Session]:
        """Find all active sessions for a user."""
        ...

    @abstractmethod
    def revoke_all_for_user(
        self, context: RequestContext, user_id: UserId
    ) -> int:
        """Revoke all sessions for a user. Returns count of revoked sessions."""
        ...

    @abstractmethod
    def cleanup_expired(self, context: RequestContext) -> int:
        """Clean up expired sessions. Returns count of cleaned sessions."""
        ...


class RefreshTokenRepository(
    TenantScopedRepository[RefreshToken, RefreshTokenId], ABC
):
    """Repository contract for refresh token persistence operations."""

    @abstractmethod
    def find_by_token_hash(
        self, context: RequestContext, token_hash: str
    ) -> RefreshToken | None:
        """Find a refresh token by its stored hash within the tenant scope."""
        ...

    @abstractmethod
    def find_by_session(
        self, context: RequestContext, session_id: SessionId
    ) -> list[RefreshToken]:
        """Find all refresh tokens issued for a session."""
        ...

    @abstractmethod
    def find_by_family(
        self, context: RequestContext, token_family: str
    ) -> list[RefreshToken]:
        """Find every token in a rotation chain."""
        ...

    @abstractmethod
    def revoke_family(
        self, context: RequestContext, token_family: str
    ) -> int:
        """Revoke a whole rotation chain. Returns count of revoked tokens."""
        ...


class AuthenticationService(DomainService, ABC):
    """Domain service contract for authentication operations.

    Note: This is an extension point. Actual authentication logic
    (password validation, MFA, etc.) will be implemented in later epics.
    """

    @abstractmethod
    def create_session(
        self,
        context: RequestContext,
        user_id: UserId,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Session:
        """Create a new authentication session for a user."""
        ...

    @abstractmethod
    def validate_session(
        self,
        context: RequestContext,
        session_id: SessionId,
    ) -> Session | None:
        """Validate and return a session if active."""
        ...

    @abstractmethod
    def revoke_session(
        self,
        context: RequestContext,
        session_id: SessionId,
    ) -> bool:
        """Revoke a session. Returns True if revoked."""
        ...

    @abstractmethod
    def refresh_session(
        self,
        context: RequestContext,
        session_id: SessionId,
    ) -> Session | None:
        """Extend session expiration if valid."""
        ...
