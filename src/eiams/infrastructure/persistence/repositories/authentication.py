"""Tenant-scoped repositories for the authentication entity group."""

from datetime import datetime, timezone

from eiams.domain.authentication.contracts import (
    RefreshToken,
    RefreshTokenId,
    RefreshTokenRepository,
    Session,
    SessionId,
    SessionRepository,
)
from eiams.domain.identity.contracts import UserId
from eiams.infrastructure.persistence.models import (
    authentication as authentication_models,
)
from eiams.shared.context import RequestContext

from ..mappers import RefreshTokenMapper, SessionMapper
from ..mappers.base import identifier, utc_now
from .base import TenantScopedSqlRepository


class SqlAlchemySessionRepository(
    TenantScopedSqlRepository[
        Session, SessionId, authentication_models.Session
    ],
    SessionRepository,
):
    """Authentication sessions within one tenant."""

    __model__ = authentication_models.Session
    __mapper__ = SessionMapper()
    __entity_name__ = "session"

    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[Session]:
        statement = self._scoped_select(context).where(
            authentication_models.Session.user_id == identifier(user_id)
        )
        return self._entities(self._rows(self._ordered(statement)))

    def find_active_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[Session]:
        now = datetime.now(timezone.utc)
        statement = (
            self._scoped_select(context)
            .where(authentication_models.Session.user_id == identifier(user_id))
            .where(
                authentication_models.Session.status
                == authentication_models.SessionStatus.ACTIVE
            )
            .where(authentication_models.Session.expires_at > now)
        )
        return self._entities(self._rows(self._ordered(statement)))

    def revoke_all_for_user(
        self, context: RequestContext, user_id: UserId
    ) -> int:
        """Revoke every active session of a user inside the tenant scope."""
        statement = (
            self._scoped_select(context, for_write=True)
            .where(authentication_models.Session.user_id == identifier(user_id))
            .where(
                authentication_models.Session.status
                == authentication_models.SessionStatus.ACTIVE
            )
        )
        revoked_at = utc_now()
        rows = self._rows(statement)
        for row in rows:
            row.status = authentication_models.SessionStatus.REVOKED
            row.revoked_at = revoked_at
        self._flush()
        return len(rows)

    def cleanup_expired(self, context: RequestContext) -> int:
        """Mark elapsed sessions of the tenant as expired."""
        now = datetime.now(timezone.utc)
        statement = (
            self._scoped_select(context, for_write=True)
            .where(
                authentication_models.Session.status
                == authentication_models.SessionStatus.ACTIVE
            )
            .where(authentication_models.Session.expires_at <= now)
        )
        rows = self._rows(statement)
        for row in rows:
            row.status = authentication_models.SessionStatus.EXPIRED
        self._flush()
        return len(rows)


class SqlAlchemyRefreshTokenRepository(
    TenantScopedSqlRepository[
        RefreshToken, RefreshTokenId, authentication_models.RefreshToken
    ],
    RefreshTokenRepository,
):
    """Refresh tokens within one tenant.

    Token hashes are unique across the platform, but a lookup by hash still
    runs inside the tenant predicate, so a token issued to another tenant
    reads back as absent instead of being exchangeable.
    """

    __model__ = authentication_models.RefreshToken
    __mapper__ = RefreshTokenMapper()
    __entity_name__ = "refresh token"

    def find_by_token_hash(
        self, context: RequestContext, token_hash: str
    ) -> RefreshToken | None:
        statement = self._scoped_select(context).where(
            authentication_models.RefreshToken.token_hash == token_hash
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)

    def find_by_session(
        self, context: RequestContext, session_id: SessionId
    ) -> list[RefreshToken]:
        statement = self._scoped_select(context).where(
            authentication_models.RefreshToken.session_id
            == identifier(session_id)
        )
        return self._entities(self._rows(self._ordered(statement)))

    def find_by_family(
        self, context: RequestContext, token_family: str
    ) -> list[RefreshToken]:
        statement = self._scoped_select(context).where(
            authentication_models.RefreshToken.token_family == token_family
        )
        return self._entities(self._rows(self._ordered(statement)))

    def revoke_family(
        self, context: RequestContext, token_family: str
    ) -> int:
        """Revoke a whole rotation chain, used when replay is detected."""
        statement = (
            self._scoped_select(context, for_write=True)
            .where(
                authentication_models.RefreshToken.token_family == token_family
            )
            .where(authentication_models.RefreshToken.is_revoked.is_(False))
        )
        revoked_at = utc_now()
        rows = self._rows(statement)
        for row in rows:
            row.is_revoked = True
            row.revoked_at = revoked_at
        self._flush()
        return len(rows)
