"""Tests for OAuth client lifecycle service.

Verifies:
1. CRUD operations work correctly
2. Tenant isolation is enforced
3. Secrets are only available in create/rotate responses
4. State transitions are validated
"""

import pytest

from eiams.shared.context import RequestContextFactory
from eiams.shared.kernel import TenantId
from eiams.shared.errors import TenantRequiredError, ValidationError, PermissionDeniedError
from eiams.application.credentials import OAuthClientService
from eiams.application.dto import (
    CreateOAuthClientCommand,
    UpdateOAuthClientCommand,
    OAuthClientCreateResponseDTO,
    OAuthClientMetadataDTO,
    CredentialStatusDTO,
)
from eiams.infrastructure.repositories import InMemoryOAuthClientRepository


class TestOAuthClientServiceCreate:
    """Tests for OAuth client creation."""
    
    def test_create_confidential_client_returns_secret(self) -> None:
        """Verify creating confidential client returns the secret."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test Client",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=["read", "write"],
        )
        
        result = service.create(context, command)
        
        assert isinstance(result, OAuthClientCreateResponseDTO)
        assert result.client_secret is not None
        assert len(result.client_secret) > 0
        assert result.name == "Test Client"
        assert result.client_type == "confidential"
    
    def test_create_public_client_has_empty_secret(self) -> None:
        """Verify creating public client has no secret."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Public Client",
            client_type="public",
            redirect_uris=["https://example.com/callback"],
            scopes=["read"],
        )
        
        result = service.create(context, command)
        
        assert result.client_secret == ""
    
    def test_create_requires_tenant_context(self) -> None:
        """Verify create fails without tenant context."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        context = RequestContextFactory.create_system()  # No tenant
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        
        with pytest.raises(TenantRequiredError):
            service.create(context, command)
    
    def test_create_validates_command(self) -> None:
        """Verify create validates command fields."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Missing name
        command = CreateOAuthClientCommand(
            name="",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        
        with pytest.raises(ValidationError, match="name"):
            service.create(context, command)
    
    def test_create_rejects_duplicate_name(self) -> None:
        """Verify create rejects duplicate client names."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Duplicate",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        
        service.create(context, command)
        
        with pytest.raises(ValidationError, match="already exists"):
            service.create(context, command)
    
    def test_create_response_repr_hides_secret(self) -> None:
        """Verify create response repr doesn't expose secret."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        
        result = service.create(context, command)
        repr_str = repr(result)
        
        assert result.client_secret not in repr_str
        assert "[REDACTED]" in repr_str


class TestOAuthClientServiceGet:
    """Tests for OAuth client retrieval."""
    
    def test_get_returns_metadata_only(self) -> None:
        """Verify get returns metadata without secret."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=["read"],
        )
        
        created = service.create(context, command)
        retrieved = service.get(context, created.client_id)
        
        assert isinstance(retrieved, OAuthClientMetadataDTO)
        # Metadata DTO has no secret attribute
        assert not hasattr(retrieved, 'client_secret')
    
    def test_get_returns_none_for_nonexistent(self) -> None:
        """Verify get returns None for non-existent client."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        result = service.get(context, "00000000-0000-0000-0000-000000000001")
        assert result is None
    
    def test_get_denies_cross_tenant_access(self) -> None:
        """Verify get denies access to other tenant's clients."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        # Create in tenant 1
        tenant1 = TenantId.generate()
        context1 = RequestContextFactory.create_system(tenant_id=str(tenant1))
        
        command = CreateOAuthClientCommand(
            name="Tenant1 Client",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = service.create(context1, command)
        
        # Try to access from tenant 2
        tenant2 = TenantId.generate()
        context2 = RequestContextFactory.create_system(tenant_id=str(tenant2))
        
        # Should return None (not found) to avoid info disclosure
        result = service.get(context2, created.client_id)
        assert result is None


class TestOAuthClientServiceList:
    """Tests for OAuth client listing."""
    
    def test_list_returns_metadata_dtos(self) -> None:
        """Verify list returns metadata DTOs without secrets."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create some clients
        for i in range(3):
            command = CreateOAuthClientCommand(
                name=f"Client {i}",
                client_type="confidential",
                redirect_uris=["https://example.com/callback"],
                scopes=[],
            )
            service.create(context, command)
        
        result = service.list(context)
        
        assert result.total == 3
        assert len(result.clients) == 3
        for client in result.clients:
            assert isinstance(client, OAuthClientMetadataDTO)
    
    def test_list_respects_tenant_isolation(self) -> None:
        """Verify list only returns tenant's clients."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        # Create in tenant 1
        tenant1 = TenantId.generate()
        context1 = RequestContextFactory.create_system(tenant_id=str(tenant1))
        
        command1 = CreateOAuthClientCommand(
            name="Tenant1 Client",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        service.create(context1, command1)
        
        # Create in tenant 2
        tenant2 = TenantId.generate()
        context2 = RequestContextFactory.create_system(tenant_id=str(tenant2))
        
        command2 = CreateOAuthClientCommand(
            name="Tenant2 Client",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        service.create(context2, command2)
        
        # List from tenant 1
        result1 = service.list(context1)
        assert result1.total == 1
        assert result1.clients[0].name == "Tenant1 Client"
        
        # List from tenant 2
        result2 = service.list(context2)
        assert result2.total == 1
        assert result2.clients[0].name == "Tenant2 Client"


class TestOAuthClientServiceRotate:
    """Tests for OAuth client secret rotation."""
    
    def test_rotate_returns_new_secret(self) -> None:
        """Verify rotate returns the new secret."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = service.create(context, command)
        
        rotated = service.rotate_secret(context, created.client_id)
        
        assert rotated.new_client_secret is not None
        assert len(rotated.new_client_secret) > 0
        # New secret should be different from original
        assert rotated.new_client_secret != created.client_secret
    
    def test_rotate_rejects_public_client(self) -> None:
        """Verify cannot rotate secret for public clients."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Public",
            client_type="public",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = service.create(context, command)
        
        with pytest.raises(ValidationError, match="public"):
            service.rotate_secret(context, created.client_id)
    
    def test_rotate_rejects_inactive_client(self) -> None:
        """Verify cannot rotate secret for inactive clients."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = service.create(context, command)
        
        # Deactivate
        service.change_status(context, created.client_id, CredentialStatusDTO.INACTIVE)
        
        with pytest.raises(ValidationError, match="inactive"):
            service.rotate_secret(context, created.client_id)
    
    def test_rotate_response_repr_hides_secret(self) -> None:
        """Verify rotate response repr doesn't expose secret."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = service.create(context, command)
        rotated = service.rotate_secret(context, created.client_id)
        
        repr_str = repr(rotated)
        assert rotated.new_client_secret not in repr_str
        assert "[REDACTED]" in repr_str


class TestOAuthClientServiceStatusChange:
    """Tests for OAuth client status changes."""
    
    def test_revoke_client(self) -> None:
        """Verify client can be revoked."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = service.create(context, command)
        
        result = service.revoke(context, created.client_id)
        assert result is True
        
        # Verify status changed
        retrieved = service.get(context, created.client_id)
        assert retrieved.status == CredentialStatusDTO.REVOKED
    
    def test_cannot_reactivate_revoked_client(self) -> None:
        """Verify revoked clients cannot be reactivated."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = service.create(context, command)
        service.revoke(context, created.client_id)
        
        with pytest.raises(ValidationError, match="reactivate"):
            service.change_status(context, created.client_id, CredentialStatusDTO.ACTIVE)


class TestOAuthClientServicePersistence:
    """Tests for persistence behavior regarding secrets."""
    
    def test_secret_not_stored_in_repository(self) -> None:
        """Verify raw secret is not stored in repository."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = service.create(context, command)
        raw_secret = created.client_secret
        
        # Inspect stored data
        stored_data = repo.get_all_stored_data()
        
        # Convert to string to search
        stored_str = str(stored_data)
        
        assert raw_secret not in stored_str
        # Verify hash is present
        tenant_data = stored_data[str(tenant_id)]
        client_data = list(tenant_data.values())[0]
        assert client_data["has_secret_hash"] is True
        assert client_data["secret_hash_format"] == "sha256"
