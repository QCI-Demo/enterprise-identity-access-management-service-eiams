"""Tenant-scoped repositories for the credential entity group."""

from datetime import datetime, timezone

from sqlalchemy import or_

from eiams.domain.credentials.contracts import (
    ApiKey,
    ApiKeyId,
    ApiKeyRepository,
    CredentialId,
    CredentialType,
    OAuthClient,
    OAuthClientId,
    OAuthClientRepository,
    UserCredential,
    UserCredentialRepository,
)
from eiams.domain.identity.contracts import UserId
from eiams.infrastructure.persistence.models import (
    credentials as credential_models,
)
from eiams.shared.context import RequestContext

from ..mappers import ApiKeyMapper, OAuthClientMapper, UserCredentialMapper
from ..mappers.base import identifier
from .base import TenantScopedSqlRepository


class SqlAlchemyUserCredentialRepository(
    TenantScopedSqlRepository[
        UserCredential, CredentialId, credential_models.UserCredential
    ],
    UserCredentialRepository,
):
    """Authentication credentials of users within one tenant."""

    __model__ = credential_models.UserCredential
    __mapper__ = UserCredentialMapper()
    __entity_name__ = "credential"

    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[UserCredential]:
        statement = self._scoped_select(context).where(
            credential_models.UserCredential.user_id == identifier(user_id)
        )
        return self._entities(self._rows(self._ordered(statement)))

    def find_by_user_and_type(
        self,
        context: RequestContext,
        user_id: UserId,
        credential_type: CredentialType,
    ) -> UserCredential | None:
        statement = (
            self._scoped_select(context)
            .where(
                credential_models.UserCredential.user_id == identifier(user_id)
            )
            .where(
                credential_models.UserCredential.credential_type
                == credential_models.CredentialType(credential_type.value)
            )
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)


class SqlAlchemyApiKeyRepository(
    TenantScopedSqlRepository[ApiKey, ApiKeyId, credential_models.ApiKey],
    ApiKeyRepository,
):
    """API keys within one tenant.

    Key prefixes are unique across the whole platform, but a lookup by
    prefix still runs inside the tenant predicate: a key belonging to
    another tenant reads back as absent.
    """

    __model__ = credential_models.ApiKey
    __mapper__ = ApiKeyMapper()
    __entity_name__ = "API key"

    def find_by_prefix(
        self, context: RequestContext, prefix: str
    ) -> ApiKey | None:
        statement = self._scoped_select(context).where(
            credential_models.ApiKey.key_prefix == prefix
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)

    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[ApiKey]:
        statement = self._scoped_select(context).where(
            credential_models.ApiKey.user_id == identifier(user_id)
        )
        return self._entities(self._rows(self._ordered(statement)))

    def find_active(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[ApiKey]:
        now = datetime.now(timezone.utc)
        statement = (
            self._scoped_select(context)
            .where(
                credential_models.ApiKey.status
                == credential_models.ApiKeyStatus.ACTIVE
            )
            .where(
                or_(
                    credential_models.ApiKey.expires_at.is_(None),
                    credential_models.ApiKey.expires_at > now,
                )
            )
        )
        return self._entities(
            self._rows(self._paginated(self._ordered(statement), offset, limit))
        )


class SqlAlchemyOAuthClientRepository(
    TenantScopedSqlRepository[
        OAuthClient, OAuthClientId, credential_models.OAuthClient
    ],
    OAuthClientRepository,
):
    """OAuth clients within one tenant."""

    __model__ = credential_models.OAuthClient
    __mapper__ = OAuthClientMapper()
    __entity_name__ = "OAuth client"

    def find_by_name(
        self, context: RequestContext, name: str
    ) -> OAuthClient | None:
        statement = self._scoped_select(context).where(
            credential_models.OAuthClient.name == name
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)

    def find_active(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[OAuthClient]:
        statement = self._scoped_select(context).where(
            credential_models.OAuthClient.is_active.is_(True)
        )
        return self._entities(
            self._rows(self._paginated(self._ordered(statement), offset, limit))
        )
