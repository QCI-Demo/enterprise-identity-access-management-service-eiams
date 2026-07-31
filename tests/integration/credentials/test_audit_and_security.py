"""Integration tests for audit and security properties.

Verifies:
1. Audit events contain only safe metadata
2. Secrets never appear in audit events
3. Secrets never appear in logs
4. Secrets never appear in error messages
5. One-time presentation behavior
"""

import pytest
from typing import Any

from eiams.shared.context import RequestContextFactory
from eiams.shared.kernel import TenantId
from eiams.domain.audit.contracts import AuditEventType, AuditSeverity
from eiams.application.credentials import (
    OAuthClientService,
    ApiKeyService,
)
from eiams.application.dto import (
    CreateOAuthClientCommand,
    CreateApiKeyCommand,
)
from eiams.infrastructure.repositories import (
    InMemoryOAuthClientRepository,
    InMemoryApiKeyRepository,
)
from eiams.shared.logging.redaction import SecretRedactor


class MockAuditService:
    """Mock audit service that captures events for verification."""
    
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
    
    def record_event(
        self,
        context: Any,
        event_type: AuditEventType,
        action: str,
        outcome: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        resource_type: str | None = None,
        resource_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Record an audit event."""
        self.events.append({
            "event_type": event_type.value,
            "action": action,
            "outcome": outcome,
            "severity": severity.value,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details or {},
        })
    
    def clear(self) -> None:
        """Clear recorded events."""
        self.events.clear()
    
    def get_events_as_string(self) -> str:
        """Get all events as a string for scanning."""
        return str(self.events)


class TestAuditSecretNonDisclosure:
    """Tests verifying secrets never appear in audit events."""
    
    def test_oauth_client_create_audit_has_no_secret(self) -> None:
        """Verify OAuth client creation audit doesn't contain secret."""
        repo = InMemoryOAuthClientRepository()
        audit = MockAuditService()
        service = OAuthClientService(repository=repo, audit_service=audit)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=["read"],
        )
        
        result = service.create(context, command)
        
        # Verify secret not in audit events
        audit_str = audit.get_events_as_string()
        assert result.client_secret not in audit_str
        
        # Verify event was recorded
        assert len(audit.events) == 1
        assert audit.events[0]["action"] == "create"
    
    def test_oauth_client_rotate_audit_has_no_secret(self) -> None:
        """Verify OAuth client rotation audit doesn't contain secret."""
        repo = InMemoryOAuthClientRepository()
        audit = MockAuditService()
        service = OAuthClientService(repository=repo, audit_service=audit)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        
        created = service.create(context, command)
        audit.clear()
        
        rotated = service.rotate_secret(context, created.client_id)
        
        # Verify neither old nor new secret in audit
        audit_str = audit.get_events_as_string()
        assert created.client_secret not in audit_str
        assert rotated.new_client_secret not in audit_str
        
        # Verify rotation event recorded
        assert len(audit.events) == 1
        assert audit.events[0]["action"] == "rotate_secret"
    
    def test_api_key_create_audit_has_no_key(self) -> None:
        """Verify API key creation audit doesn't contain raw key."""
        repo = InMemoryApiKeyRepository()
        audit = MockAuditService()
        service = ApiKeyService(repository=repo, audit_service=audit)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(
            name="Test",
            scopes=["read"],
        )
        
        result = service.create(context, command)
        
        # Verify raw key not in audit events
        audit_str = audit.get_events_as_string()
        assert result.api_key not in audit_str
        
        # Verify event was recorded with safe metadata
        assert len(audit.events) == 1
        assert audit.events[0]["action"] == "create"
        assert "key_prefix" in audit.events[0]["details"]
    
    def test_api_key_rotate_audit_has_no_key(self) -> None:
        """Verify API key rotation audit doesn't contain raw key."""
        repo = InMemoryApiKeyRepository()
        audit = MockAuditService()
        service = ApiKeyService(repository=repo, audit_service=audit)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = service.create(context, command)
        audit.clear()
        
        rotated = service.rotate(context, created.api_key_id)
        
        # Verify neither old nor new key in audit
        audit_str = audit.get_events_as_string()
        assert created.api_key not in audit_str
        assert rotated.new_api_key not in audit_str
        
        # Prefix is OK to include
        assert "new_key_prefix" in str(audit.events[0]["details"])
    
    def test_audit_details_sanitized(self) -> None:
        """Verify audit details don't contain any secret-related fields."""
        repo = InMemoryOAuthClientRepository()
        audit = MockAuditService()
        service = OAuthClientService(repository=repo, audit_service=audit)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        
        service.create(context, command)
        
        # Check that no secret-related keys are in details
        details = audit.events[0]["details"]
        forbidden_keys = {"secret", "client_secret", "raw_secret", "hash", "api_key", "key"}
        
        for key in details.keys():
            assert key.lower() not in forbidden_keys


class TestResponseSecretPresentation:
    """Tests verifying one-time secret presentation behavior."""
    
    def test_oauth_client_secret_only_in_create_response(self) -> None:
        """Verify client secret only available in create response."""
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
        
        # Create returns secret
        created = service.create(context, command)
        assert created.client_secret is not None
        assert len(created.client_secret) > 0
        
        # Get returns metadata only (no secret attribute)
        retrieved = service.get(context, created.client_id)
        assert not hasattr(retrieved, 'client_secret')
        
        # List returns metadata only
        listed = service.list(context)
        for client in listed.clients:
            assert not hasattr(client, 'client_secret')
    
    def test_oauth_client_secret_only_in_rotate_response(self) -> None:
        """Verify new client secret only available in rotate response."""
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
        
        # Rotate returns new secret
        assert rotated.new_client_secret is not None
        assert len(rotated.new_client_secret) > 0
        
        # But get still returns metadata only
        retrieved = service.get(context, created.client_id)
        assert not hasattr(retrieved, 'client_secret')
        assert not hasattr(retrieved, 'new_client_secret')
    
    def test_api_key_only_in_create_response(self) -> None:
        """Verify raw API key only available in create response."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        
        # Create returns raw key
        created = service.create(context, command)
        assert created.api_key is not None
        assert len(created.api_key) > 0
        
        # Get returns metadata only
        retrieved = service.get(context, created.api_key_id)
        assert not hasattr(retrieved, 'api_key')
        assert retrieved.key_prefix is not None  # Only prefix
        
        # List returns metadata only
        listed = service.list(context)
        for key in listed.api_keys:
            assert not hasattr(key, 'api_key')
    
    def test_api_key_only_in_rotate_response(self) -> None:
        """Verify new API key only available in rotate response."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = service.create(context, command)
        rotated = service.rotate(context, created.api_key_id)
        
        # Rotate returns new key
        assert rotated.new_api_key is not None
        assert len(rotated.new_api_key) > 0
        
        # Get still returns metadata only
        retrieved = service.get(context, created.api_key_id)
        assert not hasattr(retrieved, 'api_key')
        assert not hasattr(retrieved, 'new_api_key')


class TestSecretRedactionIntegration:
    """Tests verifying secret redaction works correctly."""
    
    def test_redactor_catches_api_key(self) -> None:
        """Verify redactor catches API key patterns."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = service.create(context, command)
        
        # Simulate logging the response (bad practice, but testing redaction)
        redactor = SecretRedactor()
        response_dict = created.to_response_dict()
        
        redacted = redactor.redact(response_dict)
        
        # Verify key is redacted if it matches patterns
        # Note: The actual key format might not match generic patterns,
        # but the api_key field name should trigger redaction
        assert created.api_key not in str(redacted)
    
    def test_redactor_catches_client_secret(self) -> None:
        """Verify redactor catches client_secret field."""
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
        
        redactor = SecretRedactor()
        response_dict = created.to_response_dict()
        
        redacted = redactor.redact(response_dict)
        
        # The client_secret field should be redacted
        assert redacted.get("client_secret") == "[REDACTED]"


class TestErrorSecretNonDisclosure:
    """Tests verifying secrets don't appear in errors."""
    
    def test_validation_error_has_no_secret(self) -> None:
        """Verify validation errors don't expose secrets."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        # Create a client first
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = service.create(context, command)
        
        # Try to create duplicate (will fail)
        try:
            service.create(context, command)
        except Exception as e:
            error_str = str(e)
            # The secret should never appear in error messages
            assert created.client_secret not in error_str
    
    def test_cross_tenant_error_generic(self) -> None:
        """Verify cross-tenant errors don't disclose information."""
        repo = InMemoryOAuthClientRepository()
        service = OAuthClientService(repository=repo)
        
        # Create in tenant 1
        tenant1 = TenantId.generate()
        context1 = RequestContextFactory.create_system(tenant_id=str(tenant1))
        
        command = CreateOAuthClientCommand(
            name="Test",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            scopes=[],
        )
        created = service.create(context1, command)
        
        # Try to access from tenant 2
        tenant2 = TenantId.generate()
        context2 = RequestContextFactory.create_system(tenant_id=str(tenant2))
        
        # Should return None, not an error with details
        result = service.get(context2, created.client_id)
        assert result is None  # No information disclosure


class TestPersistenceSecretNonDisclosure:
    """Tests verifying secrets aren't stored in persistence."""
    
    def test_oauth_repository_stores_only_hash(self) -> None:
        """Verify OAuth repository stores hash, not secret."""
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
        
        # Inspect all stored data
        stored = repo.get_all_stored_data()
        stored_str = str(stored)
        
        # Raw secret should never appear
        assert created.client_secret not in stored_str
        
        # Verify hash format is stored
        tenant_data = stored[str(tenant_id)]
        client_data = list(tenant_data.values())[0]
        assert client_data["has_secret_hash"] is True
    
    def test_api_key_repository_stores_only_hash(self) -> None:
        """Verify API key repository stores hash, not raw key."""
        repo = InMemoryApiKeyRepository()
        service = ApiKeyService(repository=repo)
        
        tenant_id = TenantId.generate()
        context = RequestContextFactory.create_system(tenant_id=str(tenant_id))
        
        command = CreateApiKeyCommand(name="Test", scopes=[])
        created = service.create(context, command)
        
        # Inspect all stored data
        stored = repo.get_all_stored_data()
        stored_str = str(stored)
        
        # Raw key should never appear
        assert created.api_key not in stored_str
        
        # Verify hash format is stored
        tenant_data = stored[str(tenant_id)]
        key_data = list(tenant_data.values())[0]
        assert key_data["has_key_hash"] is True
        
        # Prefix is OK to store
        assert key_data["key_prefix"] == created.key_prefix
