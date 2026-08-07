"""Mapping for the credential entity group."""

from eiams.domain.credentials.contracts import (
    ApiKey,
    ApiKeyId,
    ApiKeyStatus,
    CredentialId,
    CredentialType,
    OAuthClient,
    OAuthClientId,
    OAuthClientType,
    UserCredential,
)
from eiams.domain.identity.contracts import UserId
from eiams.infrastructure.persistence.models import (
    credentials as credential_models,
)
from eiams.shared.kernel import TenantId

from .base import (
    EntityMapper,
    from_timestamp,
    from_tuple,
    identifier,
    optional_identifier,
    require_timestamp,
    to_timestamp,
    to_tuple,
    utc_now,
)


class UserCredentialMapper(
    EntityMapper[UserCredential, credential_models.UserCredential]
):
    """Maps credential rows to and from the credential entity."""

    entity_name = "credential"

    def to_entity(
        self, row: credential_models.UserCredential
    ) -> UserCredential:
        return UserCredential(
            credential_id=CredentialId(row.id),
            tenant_id=TenantId(row.tenant_id),
            user_id=UserId(row.user_id),
            credential_type=CredentialType(row.credential_type.value),
            credential_hash=row.credential_hash,
            hash_algorithm=row.hash_algorithm,
            is_active=row.is_active,
            requires_reset=row.requires_reset,
            failed_attempts=row.failed_attempts,
            created_at=require_timestamp(row.created_at),
            updated_at=require_timestamp(row.updated_at),
            locked_until=to_timestamp(row.locked_until),
            last_used_at=to_timestamp(row.last_used_at),
        )

    def to_model(
        self, entity: UserCredential
    ) -> credential_models.UserCredential:
        row = credential_models.UserCredential(
            id=identifier(entity.credential_id),
            tenant_id=identifier(entity.tenant_id),
            user_id=identifier(entity.user_id),
            credential_type=credential_models.CredentialType(
                entity.credential_type.value
            ),
            credential_hash=entity.credential_hash,
            hash_algorithm=entity.hash_algorithm,
            is_active=entity.is_active,
            requires_reset=entity.requires_reset,
            failed_attempts=entity.failed_attempts,
            locked_until=from_timestamp(entity.locked_until),
            last_used_at=from_timestamp(entity.last_used_at),
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
            row.updated_at = from_timestamp(entity.updated_at or entity.created_at)
        return row

    def apply(
        self, entity: UserCredential, row: credential_models.UserCredential
    ) -> None:
        row.credential_hash = entity.credential_hash
        row.hash_algorithm = entity.hash_algorithm
        row.is_active = entity.is_active
        row.requires_reset = entity.requires_reset
        row.failed_attempts = entity.failed_attempts
        row.locked_until = from_timestamp(entity.locked_until)
        row.last_used_at = from_timestamp(entity.last_used_at)


class ApiKeyMapper(EntityMapper[ApiKey, credential_models.ApiKey]):
    """Maps API key rows to and from the API key entity."""

    entity_name = "API key"

    def to_entity(self, row: credential_models.ApiKey) -> ApiKey:
        return ApiKey(
            api_key_id=ApiKeyId(row.id),
            tenant_id=TenantId(row.tenant_id),
            user_id=UserId(row.user_id) if row.user_id else None,
            name=row.name,
            key_prefix=row.key_prefix,
            key_hash=row.key_hash,
            scopes=to_tuple(row.scopes),
            status=ApiKeyStatus(row.status.value),
            created_at=require_timestamp(row.created_at),
            expires_at=to_timestamp(row.expires_at),
            last_used_at=to_timestamp(row.last_used_at),
        )

    def to_model(self, entity: ApiKey) -> credential_models.ApiKey:
        row = credential_models.ApiKey(
            id=identifier(entity.api_key_id),
            tenant_id=identifier(entity.tenant_id),
            user_id=optional_identifier(entity.user_id),
            name=entity.name,
            key_prefix=entity.key_prefix,
            key_hash=entity.key_hash,
            scopes=from_tuple(entity.scopes),
            status=credential_models.ApiKeyStatus(entity.status.value),
            expires_at=from_timestamp(entity.expires_at),
            last_used_at=from_timestamp(entity.last_used_at),
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
        return row

    def apply(self, entity: ApiKey, row: credential_models.ApiKey) -> None:
        row.name = entity.name
        row.scopes = from_tuple(entity.scopes)
        row.status = credential_models.ApiKeyStatus(entity.status.value)
        row.expires_at = from_timestamp(entity.expires_at)
        row.last_used_at = from_timestamp(entity.last_used_at)
        if entity.status is ApiKeyStatus.REVOKED and row.revoked_at is None:
            row.revoked_at = utc_now()


class OAuthClientMapper(
    EntityMapper[OAuthClient, credential_models.OAuthClient]
):
    """Maps OAuth client rows to and from the OAuth client entity."""

    entity_name = "OAuth client"

    def to_entity(self, row: credential_models.OAuthClient) -> OAuthClient:
        return OAuthClient(
            client_id=OAuthClientId(row.id),
            tenant_id=TenantId(row.tenant_id),
            name=row.name,
            description=row.description,
            client_type=OAuthClientType(row.client_type.value),
            client_secret_hash=row.client_secret_hash,
            redirect_uris=to_tuple(row.redirect_uris),
            scopes=to_tuple(row.allowed_scopes),
            is_active=row.is_active,
            created_at=require_timestamp(row.created_at),
            updated_at=require_timestamp(row.updated_at),
        )

    def to_model(self, entity: OAuthClient) -> credential_models.OAuthClient:
        row = credential_models.OAuthClient(
            id=identifier(entity.client_id),
            tenant_id=identifier(entity.tenant_id),
            name=entity.name,
            description=entity.description,
            client_type=credential_models.OAuthClientType(
                entity.client_type.value
            ),
            client_secret_hash=entity.client_secret_hash,
            redirect_uris=from_tuple(entity.redirect_uris),
            allowed_scopes=from_tuple(entity.scopes),
            is_active=entity.is_active,
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
            row.updated_at = from_timestamp(entity.updated_at or entity.created_at)
        return row

    def apply(
        self, entity: OAuthClient, row: credential_models.OAuthClient
    ) -> None:
        row.name = entity.name
        row.description = entity.description
        row.redirect_uris = from_tuple(entity.redirect_uris)
        row.allowed_scopes = from_tuple(entity.scopes)
        row.is_active = entity.is_active
        if entity.client_secret_hash != row.client_secret_hash:
            row.client_secret_hash = entity.client_secret_hash
            row.secret_version = row.secret_version + 1
            row.secret_rotated_at = utc_now()
