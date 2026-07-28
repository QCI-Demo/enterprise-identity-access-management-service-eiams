"""Mapping for the authentication entity group."""

from eiams.domain.authentication.contracts import (
    RefreshToken,
    RefreshTokenId,
    Session,
    SessionId,
    SessionStatus,
)
from eiams.domain.identity.contracts import UserId
from eiams.infrastructure.persistence.models import (
    authentication as authentication_models,
)
from eiams.shared.kernel import TenantId

from .base import (
    EntityMapper,
    from_timestamp,
    identifier,
    optional_identifier,
    require_timestamp,
    to_timestamp,
    utc_now,
)


class SessionMapper(EntityMapper[Session, authentication_models.Session]):
    """Maps session rows to and from the session entity."""

    entity_name = "session"

    def to_entity(self, row: authentication_models.Session) -> Session:
        return Session(
            session_id=SessionId(row.id),
            tenant_id=TenantId(row.tenant_id),
            user_id=UserId(row.user_id),
            status=SessionStatus(row.status.value),
            created_at=require_timestamp(row.created_at),
            expires_at=require_timestamp(row.expires_at),
            last_activity_at=require_timestamp(row.last_activity_at),
            ip_address=row.ip_address,
            user_agent=row.user_agent,
            device_fingerprint=row.device_fingerprint,
            revoked_at=to_timestamp(row.revoked_at),
        )

    def to_model(self, entity: Session) -> authentication_models.Session:
        row = authentication_models.Session(
            id=identifier(entity.session_id),
            tenant_id=identifier(entity.tenant_id),
            user_id=identifier(entity.user_id),
            status=authentication_models.SessionStatus(entity.status.value),
            ip_address=entity.ip_address,
            user_agent=entity.user_agent,
            device_fingerprint=entity.device_fingerprint,
            expires_at=from_timestamp(entity.expires_at),
            revoked_at=from_timestamp(entity.revoked_at),
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
        if entity.last_activity_at is not None:
            row.last_activity_at = from_timestamp(entity.last_activity_at)
        return row

    def apply(self, entity: Session, row: authentication_models.Session) -> None:
        row.status = authentication_models.SessionStatus(entity.status.value)
        row.expires_at = from_timestamp(entity.expires_at)
        row.last_activity_at = from_timestamp(entity.last_activity_at)
        row.ip_address = entity.ip_address
        row.user_agent = entity.user_agent
        row.device_fingerprint = entity.device_fingerprint
        row.revoked_at = from_timestamp(entity.revoked_at)
        if (
            entity.status
            in (SessionStatus.REVOKED, SessionStatus.LOGGED_OUT)
            and row.revoked_at is None
        ):
            row.revoked_at = utc_now()


class RefreshTokenMapper(
    EntityMapper[RefreshToken, authentication_models.RefreshToken]
):
    """Maps refresh token rows to and from the refresh token entity."""

    entity_name = "refresh token"

    def to_entity(
        self, row: authentication_models.RefreshToken
    ) -> RefreshToken:
        return RefreshToken(
            refresh_token_id=RefreshTokenId(row.id),
            tenant_id=TenantId(row.tenant_id),
            session_id=SessionId(row.session_id),
            user_id=UserId(row.user_id),
            token_hash=row.token_hash,
            token_family=row.token_family,
            is_revoked=row.is_revoked,
            created_at=require_timestamp(row.created_at),
            expires_at=require_timestamp(row.expires_at),
            previous_token_id=(
                RefreshTokenId(row.previous_token_id)
                if row.previous_token_id
                else None
            ),
            used_at=to_timestamp(row.used_at),
            revoked_at=to_timestamp(row.revoked_at),
        )

    def to_model(
        self, entity: RefreshToken
    ) -> authentication_models.RefreshToken:
        row = authentication_models.RefreshToken(
            id=identifier(entity.refresh_token_id),
            tenant_id=identifier(entity.tenant_id),
            session_id=identifier(entity.session_id),
            user_id=identifier(entity.user_id),
            token_hash=entity.token_hash,
            token_family=entity.token_family,
            previous_token_id=optional_identifier(entity.previous_token_id),
            is_revoked=entity.is_revoked,
            expires_at=from_timestamp(entity.expires_at),
            used_at=from_timestamp(entity.used_at),
            revoked_at=from_timestamp(entity.revoked_at),
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
        return row

    def apply(
        self, entity: RefreshToken, row: authentication_models.RefreshToken
    ) -> None:
        row.is_revoked = entity.is_revoked
        row.used_at = from_timestamp(entity.used_at)
        row.revoked_at = from_timestamp(entity.revoked_at)
        row.expires_at = from_timestamp(entity.expires_at)
        if entity.is_revoked and row.revoked_at is None:
            row.revoked_at = utc_now()
