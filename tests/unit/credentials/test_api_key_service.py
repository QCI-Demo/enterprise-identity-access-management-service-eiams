"""Tests for API key lifecycle service.

Verifies:
1. CRUD operations work correctly
2. Tenant isolation is enforced
3. Keys are only available in create/rotate responses
4. Expiry and status enforcement
"""

import pytest
from datetime import datetime, timedelta, timezone

from eiams.shared.context import RequestContextFactory
from eiams.shared.kernel import TenantId, Timestamp
from eiams.shared.errors import TenantRequiredError, ValidationError
from eiams.application.credentials import ApiKeyService
from eiams.application.dto import (
    CreateApiKeyCommand,
    UpdateApiKeyCommand,
    ApiKeyCreateResponseDTO,
    ApiKeyMetadataDTO,
    CredentialStatusDTO,
)
from eiams.infrastructure.repositories import InMemoryApiKeyRepository


class TestApiKeyServiceCreate:
    """Tests for API key creation."""
    
    def test_create_returns_api_key(self) -> None:
        """Verify creating API key returns the raw key."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(
            name="Test Key",
            scopes=["read", "write"],
        )
        
        result = service.create(context, command)
        
        assert isinstance(result, ApiKeyCreateResponseDTO)
        assert result.api_key is not None
        assert len(result.api_key) > 0
        assert result.name == "Test Key"
    
    def test_create_key_has_prefix(self) -> None:
        """Verify created key has identifiable prefix."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(
            name="Test",
            scopes=[],
        )
        
        result = service.create(context, command)
        
        assert result.api_key.startswith("eiams_")
        assert result.key_prefix is not None
        assert result.api_key.startswith(result.key_prefix)
    
    def test_create_requires_tenant_context(self) -> None:
        """Verify create fails without tenant context."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        context = RequestContextFactory.create_system()  # No tenant
        
        command = CreateApiKeyCommand(
            name="Test",
            scopes=[],
        )
        
        with pytest.raises(TenantRequiredError):
            service.create(context, command)
    
    def test_create_validates_command(self) -> None:
        """Verify create validates command fields."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(
            name="",  # Empty name
            scopes=[],
        )
        
        with pytest.raises(ValidationError, match="name"):
            service.create(context, command)
    
    def test_create_with_expiry(self) -> None:
        """Verify API key can be created with expiry."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        future = datetime.now(timezone.utc) + timedelta(days=30)
        
        command = CreateApiKeyCommand(
            name="Expiring Key",
            scopes=["read"],
            expires_at=future.isoformat(),
        )
        
        result = service.create(context, command)
        
        assert result.expires_at is not None
    
    def test_create_response_repr_hides_key(self) -> None:
        """Verify create response repr doesn't expose key."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(
            name="Test",
            scopes=[],
        )
        
        result = service.create(context, command)
        repr_str = repr(result)
        
        assert result.api_key not in repr_str
        assert "[REDACTED]" in repr_str


class TestApiKeyServiceGet:
    """Tests for API key retrieval."""
    
    def test_get_returns_metadata_only(self) -> None:
        """Verify get returns metadata without raw key."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(
            name="Test",
            scopes=["read"],
        )
        
        created = service.create(context, command)
        retrieved = service.get(context, created.api_key_id)
        
        assert isinstance(retrieved, ApiKeyMetadataDTO)
        # Metadata has prefix but not the full key
        assert retrieved.key_prefix is not None
        assert not hasattr(retrieved, 'api_key')
    
    def test_get_returns_none_for_nonexistent(self) -> None:
        """Verify get returns None for non-existent key."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        result = service.get(context, "00000000-0000-0000-0000-000000000001")
        assert result is None
    
    def test_get_denies_cross_tenant_access(self) -> None:
        """Verify get denies access to other tenant's keys."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        # Create in tenant 1
        tenant1 = TenantId.generate()
        context1 = RequestContextFactory.create_system(tenant_id=str(tenant1))
        
        command = CreateApiKeyCommand(
            name="Tenant1 Key",
            scopes=[],
        )
        created = service.create(context1, command)
        
        # Try to access from tenant 2
        tenant2 = TenantId.generate()
        context2 = RequestContextFactory.create_system(tenant_id=str(tenant2))
        
        result = service.get(context2, created.api_key_id)
        assert result is None


class TestApiKeyServiceList:
    """Tests for API key listing."""
    
    def test_list_returns_metadata_dtos(self) -> None:
        """Verify list returns metadata DTOs without raw keys."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        for i in range(3):
            command = CreateApiKeyCommand(
                name=f"Key {i}",
                scopes=[],
            )
            service.create(context, command)
        
        result = service.list(context)
        
        assert result.total == 3
        assert len(result.api_keys) == 3
        for key in result.api_keys:
            assert isinstance(key, ApiKeyMetadataDTO)
            assert key.key_prefix is not None
    
    def test_list_respects_tenant_isolation(self) -> None:
        """Verify list only returns tenant's keys."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        # Create in tenant 1
        tenant1 = TenantId.generate()
        context1 = RequestContextFactory.create_system(tenant_id=str(tenant1))
        
        command1 = CreateApiKeyCommand(name="Tenant1 Key", scopes=[])
        service.create(context1, command1)
        
        # Create in tenant 2
        tenant2 = TenantId.generate()
        context2 = RequestContextFactory.create_system(tenant_id=str(tenant2))
        
        command2 = CreateApiKeyCommand(name="Tenant2 Key", scopes=[])
        service.create(context2, command2)
        
        # List from tenant 1
        result1 = service.list(context1)
        assert result1.total == 1
        assert result1.api_keys[0].name == "Tenant1 Key"
        
        # List from tenant 2
        result2 = service.list(context2)
        assert result2.total == 1
        assert result2.api_keys[0].name == "Tenant2 Key"


class TestApiKeyServiceRotate:
    """Tests for API key rotation."""
    
    def test_rotate_returns_new_key(self) -> None:
        """Verify rotate returns the new key."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(
            name="Test",
            scopes=[],
        )
        created = service.create(context, command)
        
        rotated = service.rotate(context, created.api_key_id)
        
        assert rotated.new_api_key is not None
        assert len(rotated.new_api_key) > 0
        # New key should be different
        assert rotated.new_api_key != created.api_key
    
    def test_rotate_updates_prefix(self) -> None:
        """Verify rotation updates the key prefix."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = service.create(context, command)
        
        rotated = service.rotate(context, created.api_key_id)
        
        # New prefix should match new key
        assert rotated.new_api_key.startswith(rotated.new_key_prefix)
    
    def test_rotate_rejects_revoked_key(self) -> None:
        """Verify cannot rotate revoked keys."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = service.create(context, command)
        
        service.revoke(context, created.api_key_id)
        
        with pytest.raises(ValidationError, match="inactive"):
            service.rotate(context, created.api_key_id)
    
    def test_rotate_response_repr_hides_key(self) -> None:
        """Verify rotate response repr doesn't expose key."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = service.create(context, command)
        rotated = service.rotate(context, created.api_key_id)
        
        repr_str = repr(rotated)
        assert rotated.new_api_key not in repr_str
        assert "[REDACTED]" in repr_str


class TestApiKeyServiceStatusChange:
    """Tests for API key status changes."""
    
    def test_revoke_key(self) -> None:
        """Verify key can be revoked."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = service.create(context, command)
        
        result = service.revoke(context, created.api_key_id)
        assert result is True
        
        retrieved = service.get(context, created.api_key_id)
        assert retrieved.status == CredentialStatusDTO.REVOKED
    
    def test_cannot_reactivate_revoked_key(self) -> None:
        """Verify revoked keys cannot be reactivated."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = service.create(context, command)
        service.revoke(context, created.api_key_id)
        
        with pytest.raises(ValidationError, match="reactivate"):
            service.change_status(context, created.api_key_id, CredentialStatusDTO.ACTIVE)


class TestApiKeyServiceUpdate:
    """Tests for API key updates."""
    
    def test_update_name(self) -> None:
        """Verify key name can be updated."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Original", scopes=[])
        created = service.create(context, command)
        
        update_cmd = UpdateApiKeyCommand(name="Updated")
        updated = service.update(context, created.api_key_id, update_cmd)
        
        assert updated.name == "Updated"
    
    def test_update_scopes(self) -> None:
        """Verify key scopes can be updated."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=["read"])
        created = service.create(context, command)
        
        update_cmd = UpdateApiKeyCommand(scopes=["read", "write"])
        updated = service.update(context, created.api_key_id, update_cmd)
        
        assert "write" in updated.scopes


class TestApiKeyServicePersistence:
    """Tests for persistence behavior regarding secrets."""
    
    def test_raw_key_not_stored_in_repository(self) -> None:
        """Verify raw API key is not stored in repository."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = service.create(context, command)
        raw_key = created.api_key
        
        # Inspect stored data
        stored_data = repo.get_all_stored_data()
        stored_str = str(stored_data)
        
        # Raw key should not appear anywhere
        assert raw_key not in stored_str
        
        # But hash metadata should be present
        tenant_data = stored_data[str(tenant_id)]
        key_data = list(tenant_data.values())[0]
        assert key_data["has_key_hash"] is True
        assert key_data["key_hash_format"] == "sha256"
    
    def test_prefix_is_stored(self) -> None:
        """Verify key prefix is stored for identification."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = service.create(context, command)
        
        stored_data = repo.get_all_stored_data()
        tenant_data = stored_data[str(tenant_id)]
        key_data = list(tenant_data.values())[0]
        
        assert key_data["key_prefix"] == created.key_prefix
