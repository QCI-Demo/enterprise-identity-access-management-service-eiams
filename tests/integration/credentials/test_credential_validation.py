"""Integration tests for credential validation service.

Verifies:
1. Valid credentials are accepted
2. Expired credentials are rejected
3. Revoked credentials are rejected
4. Inactive credentials are rejected
5. Invalid credentials are rejected
6. Scope validation works correctly
"""

import pytest
from datetime import datetime, timedelta, timezone

from eiams.shared.context import RequestContextFactory
from eiams.shared.kernel import TenantId, Timestamp
from eiams.application.credentials import (
    OAuthClientService,
    ApiKeyService,
    CredentialValidationService,
)
from eiams.application.credentials.credential_validation_service import (
    ValidationOutcome,
)
from eiams.application.dto import (
    CreateOAuthClientCommand,
    CreateApiKeyCommand,
    CredentialStatusDTO,
)
from eiams.infrastructure.repositories import (
    InMemoryOAuthClientRepository,
    InMemoryApiKeyRepository,
)


class TestApiKeyValidation:
    """Tests for API key validation."""
    
    def test_valid_api_key_accepted(self) -> None:
        """Verify valid API key is accepted."""
        api_key_repo = InMemoryApiKeyRepository()
        api_key_service = ApiKeyService(repository=api_key_repo)
        validation_service = CredentialValidationService(
            api_key_repository=api_key_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create API key
        command = CreateApiKeyCommand(
            name="Test Key",
            scopes=["read", "write"],
        )
        created = api_key_service.create(context, command)
        
        # Validate
        result = validation_service.validate_api_key(context, created.api_key)
        
        assert result.is_valid
        assert result.outcome == ValidationOutcome.VALID
        assert result.tenant_id == str(tenant_id)
        assert "read" in result.scopes
        assert "write" in result.scopes
    
    def test_expired_api_key_rejected(self) -> None:
        """Verify expired API key is rejected."""
        api_key_repo = InMemoryApiKeyRepository()
        api_key_service = ApiKeyService(repository=api_key_repo)
        validation_service = CredentialValidationService(
            api_key_repository=api_key_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create key with past expiry
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        command = CreateApiKeyCommand(
            name="Expired Key",
            scopes=[],
            expires_at=past.isoformat(),
        )
        created = api_key_service.create(context, command)
        
        # Validate
        result = validation_service.validate_api_key(context, created.api_key)
        
        assert not result.is_valid
        assert result.outcome == ValidationOutcome.EXPIRED
    
    def test_revoked_api_key_rejected(self) -> None:
        """Verify revoked API key is rejected."""
        api_key_repo = InMemoryApiKeyRepository()
        api_key_service = ApiKeyService(repository=api_key_repo)
        validation_service = CredentialValidationService(
            api_key_repository=api_key_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create and revoke
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = api_key_service.create(context, command)
        api_key_service.revoke(context, created.api_key_id)
        
        # Validate
        result = validation_service.validate_api_key(context, created.api_key)
        
        assert not result.is_valid
        assert result.outcome == ValidationOutcome.REVOKED
    
    def test_inactive_api_key_rejected(self) -> None:
        """Verify inactive API key is rejected."""
        api_key_repo = InMemoryApiKeyRepository()
        api_key_service = ApiKeyService(repository=api_key_repo)
        validation_service = CredentialValidationService(
            api_key_repository=api_key_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create and deactivate
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = api_key_service.create(context, command)
        api_key_service.change_status(
            context, created.api_key_id, CredentialStatusDTO.INACTIVE
        )
        
        # Validate
        result = validation_service.validate_api_key(context, created.api_key)
        
        assert not result.is_valid
        assert result.outcome in (ValidationOutcome.INACTIVE, ValidationOutcome.REVOKED)
    
    def test_invalid_api_key_rejected(self) -> None:
        """Verify invalid API key is rejected."""
        api_key_repo = InMemoryApiKeyRepository()
        validation_service = CredentialValidationService(
            api_key_repository=api_key_repo,
        )
        
        context = RequestContextFactory.create_system()
        
        # Validate non-existent key
        result = validation_service.validate_api_key(context, "invalid_key")
        
        assert not result.is_valid
        assert result.outcome in (ValidationOutcome.NOT_FOUND, ValidationOutcome.INVALID_CREDENTIAL)
    
    def test_wrong_api_key_rejected(self) -> None:
        """Verify wrong API key (correct prefix, wrong value) is rejected."""
        api_key_repo = InMemoryApiKeyRepository()
        api_key_service = ApiKeyService(repository=api_key_repo)
        validation_service = CredentialValidationService(
            api_key_repository=api_key_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create API key
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = api_key_service.create(context, command)
        
        # Try to validate with modified key (same prefix)
        wrong_key = created.api_key[:-1] + "X"
        result = validation_service.validate_api_key(context, wrong_key)
        
        assert not result.is_valid
        assert result.outcome == ValidationOutcome.INVALID_CREDENTIAL
    
    def test_insufficient_scope_rejected(self) -> None:
        """Verify API key without required scopes is rejected."""
        api_key_repo = InMemoryApiKeyRepository()
        api_key_service = ApiKeyService(repository=api_key_repo)
        validation_service = CredentialValidationService(
            api_key_repository=api_key_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create key with limited scopes
        command = CreateApiKeyCommand(
            name="Limited",
            scopes=["read"],
        )
        created = api_key_service.create(context, command)
        
        # Validate with required scope key doesn't have
        result = validation_service.validate_api_key(
            context,
            created.api_key,
            required_scopes=["write"],
        )
        
        assert not result.is_valid
        assert result.outcome == ValidationOutcome.INSUFFICIENT_SCOPE
    
    def test_empty_api_key_rejected(self) -> None:
        """Verify empty API key is rejected."""
        api_key_repo = InMemoryApiKeyRepository()
        validation_service = CredentialValidationService(
            api_key_repository=api_key_repo,
        )
        
        context = RequestContextFactory.create_system()
        
        result = validation_service.validate_api_key(context, "")
        
        assert not result.is_valid
        assert result.outcome == ValidationOutcome.INVALID_CREDENTIAL


class TestOAuthClientValidation:
    """Tests for OAuth client validation."""
    
    def test_valid_client_accepted(self) -> None:
        """Verify valid OAuth client credentials are accepted."""
        oauth_repo = InMemoryOAuthClientRepository()
        oauth_service = OAuthClientService(repository=oauth_repo)
        validation_service = CredentialValidationService(
            oauth_client_repository=oauth_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create client
        command = CreateOAuthClientCommand(
            name="Test Client",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=["read", "write"],
        )
        created = oauth_service.create(context, command)
        
        # Validate
        result = validation_service.validate_oauth_client(
            context,
            created.client_id,
            created.client_secret,
        )
        
        assert result.is_valid
        assert result.outcome == ValidationOutcome.VALID
        assert result.tenant_id == str(tenant_id)
    
    def test_revoked_client_rejected(self) -> None:
        """Verify revoked OAuth client is rejected."""
        oauth_repo = InMemoryOAuthClientRepository()
        oauth_service = OAuthClientService(repository=oauth_repo)
        validation_service = CredentialValidationService(
            oauth_client_repository=oauth_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create and revoke
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = oauth_service.create(context, command)
        oauth_service.revoke(context, created.client_id)
        
        # Validate
        result = validation_service.validate_oauth_client(
            context,
            created.client_id,
            created.client_secret,
        )
        
        assert not result.is_valid
        assert result.outcome == ValidationOutcome.REVOKED
    
    def test_wrong_secret_rejected(self) -> None:
        """Verify wrong client secret is rejected."""
        oauth_repo = InMemoryOAuthClientRepository()
        oauth_service = OAuthClientService(repository=oauth_repo)
        validation_service = CredentialValidationService(
            oauth_client_repository=oauth_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create client
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = oauth_service.create(context, command)
        
        # Validate with wrong secret
        result = validation_service.validate_oauth_client(
            context,
            created.client_id,
            "wrong_secret",
        )
        
        assert not result.is_valid
        assert result.outcome == ValidationOutcome.INVALID_CREDENTIAL
    
    def test_nonexistent_client_rejected(self) -> None:
        """Verify non-existent client is rejected."""
        oauth_repo = InMemoryOAuthClientRepository()
        validation_service = CredentialValidationService(
            oauth_client_repository=oauth_repo,
        )
        
        context = RequestContextFactory.create_system()
        
        result = validation_service.validate_oauth_client(
            context,
            "00000000-0000-0000-0000-000000000001",
            "secret",
        )
        
        assert not result.is_valid
        assert result.outcome == ValidationOutcome.NOT_FOUND
    
    def test_insufficient_scope_rejected(self) -> None:
        """Verify client without required scopes is rejected."""
        oauth_repo = InMemoryOAuthClientRepository()
        oauth_service = OAuthClientService(repository=oauth_repo)
        validation_service = CredentialValidationService(
            oauth_client_repository=oauth_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create client with limited scopes
        command = CreateOAuthClientCommand(
            name="Limited",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=["read"],
        )
        created = oauth_service.create(context, command)
        
        # Validate with required scope client doesn't have
        result = validation_service.validate_oauth_client(
            context,
            created.client_id,
            created.client_secret,
            required_scopes=["admin"],
        )
        
        assert not result.is_valid
        assert result.outcome == ValidationOutcome.INSUFFICIENT_SCOPE


class TestValidationResultSafety:
    """Tests for validation result safety properties."""
    
    def test_validation_result_does_not_contain_secret(self) -> None:
        """Verify validation result doesn't contain the secret."""
        api_key_repo = InMemoryApiKeyRepository()
        api_key_service = ApiKeyService(repository=api_key_repo)
        validation_service = CredentialValidationService(
            api_key_repository=api_key_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = api_key_service.create(context, command)
        
        result = validation_service.validate_api_key(context, created.api_key)
        
        # Check result serialization
        result_dict = result.to_dict()
        result_str = str(result_dict)
        
        assert created.api_key not in result_str
    
    def test_validation_result_serializable(self) -> None:
        """Verify validation result can be safely serialized."""
        api_key_repo = InMemoryApiKeyRepository()
        api_key_service = ApiKeyService(repository=api_key_repo)
        validation_service = CredentialValidationService(
            api_key_repository=api_key_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=["read"])
        created = api_key_service.create(context, command)
        
        result = validation_service.validate_api_key(context, created.api_key)
        result_dict = result.to_dict()
        
        # Verify structure
        assert "outcome" in result_dict
        assert "credential_id" in result_dict
        assert "is_valid" in result_dict
        assert result_dict["is_valid"] is True


class TestRotatedCredentialValidation:
    """Tests for validation of rotated credentials."""
    
    def test_old_api_key_invalid_after_rotation(self) -> None:
        """Verify old API key is invalid after rotation."""
        api_key_repo = InMemoryApiKeyRepository()
        api_key_service = ApiKeyService(repository=api_key_repo)
        validation_service = CredentialValidationService(
            api_key_repository=api_key_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create and rotate
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = api_key_service.create(context, command)
        old_key = created.api_key
        
        rotated = api_key_service.rotate(context, created.api_key_id)
        new_key = rotated.new_api_key
        
        # Old key should be invalid (prefix changed)
        old_result = validation_service.validate_api_key(context, old_key)
        assert not old_result.is_valid
        
        # New key should be valid
        new_result = validation_service.validate_api_key(context, new_key)
        assert new_result.is_valid
    
    def test_old_client_secret_invalid_after_rotation(self) -> None:
        """Verify old client secret is invalid after rotation."""
        oauth_repo = InMemoryOAuthClientRepository()
        oauth_service = OAuthClientService(repository=oauth_repo)
        validation_service = CredentialValidationService(
            oauth_client_repository=oauth_repo,
        )
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create and rotate
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = oauth_service.create(context, command)
        old_secret = created.client_secret
        
        rotated = oauth_service.rotate_secret(context, created.client_id)
        new_secret = rotated.new_client_secret
        
        # Old secret should be invalid
        old_result = validation_service.validate_oauth_client(
            context, created.client_id, old_secret
        )
        assert not old_result.is_valid
        
        # New secret should be valid
        new_result = validation_service.validate_oauth_client(
            context, created.client_id, new_secret
        )
        assert new_result.is_valid
