"""In-memory OAuth client repository for testing.

This repository stores only safe metadata and hashes.
Raw secrets are never persisted.
"""

from typing import Any

from eiams.shared.context import RequestContext
from eiams.domain.credentials.contracts import (
    OAuthClient,
    OAuthClientId,
    OAuthClientRepository,
)


class InMemoryOAuthClientRepository(OAuthClientRepository):
    """In-memory implementation of OAuth client repository.
    
    Stores OAuth clients in memory, keyed by client_id and tenant_id.
    Enforces tenant isolation - clients are only visible within their tenant.
    
    IMPORTANT: This repository stores client_secret_hash, NOT the raw secret.
    The raw secret is only available during create/rotate operations and
    is not persisted anywhere.
    """
    
    def __init__(self) -> None:
        """Initialize the repository."""
        # Storage: {tenant_id: {client_id: OAuthClient}}
        self._clients: dict[str, dict[str, OAuthClient]] = {}
        # Name index: {tenant_id: {name: client_id}}
        self._name_index: dict[str, dict[str, str]] = {}
    
    def find_by_id(
        self, context: RequestContext, client_id: OAuthClientId
    ) -> OAuthClient | None:
        """Find client by ID within tenant context."""
        if not context.has_tenant:
            return None
        
        tenant_key = str(context.tenant_id)
        client_key = str(client_id)
        
        tenant_clients = self._clients.get(tenant_key, {})
        return tenant_clients.get(client_key)
    
    def find_by_name(
        self, context: RequestContext, name: str
    ) -> OAuthClient | None:
        """Find client by name within tenant context."""
        if not context.has_tenant:
            return None
        
        tenant_key = str(context.tenant_id)
        tenant_index = self._name_index.get(tenant_key, {})
        client_id = tenant_index.get(name)
        
        if client_id is None:
            return None
        
        return self._clients.get(tenant_key, {}).get(client_id)
    
    def find_active(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[OAuthClient]:
        """Find all active clients within tenant with pagination."""
        clients, _ = self.find_all(context, offset, limit)
        return [c for c in clients if c.is_active]
    
    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> tuple[list[OAuthClient], int]:
        """Find all clients within tenant with total count."""
        if not context.has_tenant:
            return [], 0
        
        tenant_key = str(context.tenant_id)
        tenant_clients = self._clients.get(tenant_key, {})
        
        all_clients = list(tenant_clients.values())
        total = len(all_clients)
        
        # Sort by created_at for consistent ordering
        all_clients.sort(key=lambda c: c.created_at.to_iso())
        
        # Apply pagination
        paginated = all_clients[offset:offset + limit]
        
        return paginated, total
    
    def save(self, context: RequestContext, client: OAuthClient) -> OAuthClient:
        """Persist client.
        
        Stores the client with its hashed secret. The raw secret
        is never passed to or stored by this method.
        """
        tenant_key = str(client.tenant_id)
        client_key = str(client.client_id)
        
        # Initialize tenant storage if needed
        if tenant_key not in self._clients:
            self._clients[tenant_key] = {}
            self._name_index[tenant_key] = {}
        
        # Remove old name from index if exists
        old_client = self._clients[tenant_key].get(client_key)
        if old_client and old_client.name != client.name:
            if old_client.name in self._name_index[tenant_key]:
                del self._name_index[tenant_key][old_client.name]
        
        # Store client
        self._clients[tenant_key][client_key] = client
        
        # Update name index
        self._name_index[tenant_key][client.name] = client_key
        
        return client
    
    def delete(self, context: RequestContext, client_id: OAuthClientId) -> bool:
        """Delete client."""
        if not context.has_tenant:
            return False
        
        tenant_key = str(context.tenant_id)
        client_key = str(client_id)
        
        tenant_clients = self._clients.get(tenant_key, {})
        client = tenant_clients.get(client_key)
        
        if client is None:
            return False
        
        # Remove from name index
        tenant_index = self._name_index.get(tenant_key, {})
        if client.name in tenant_index:
            del tenant_index[client.name]
        
        # Remove client
        del tenant_clients[client_key]
        
        return True
    
    def clear(self) -> None:
        """Clear all data (for testing)."""
        self._clients.clear()
        self._name_index.clear()
    
    def get_all_stored_data(self) -> dict[str, Any]:
        """Get all stored data for inspection (testing only).
        
        This method is for test verification only.
        Returns client data including hashes but NOT raw secrets.
        """
        result = {}
        for tenant_id, clients in self._clients.items():
            result[tenant_id] = {}
            for client_id, client in clients.items():
                result[tenant_id][client_id] = {
                    "client_id": str(client.client_id),
                    "tenant_id": str(client.tenant_id),
                    "name": client.name,
                    "client_type": client.client_type.value,
                    "has_secret_hash": client.client_secret_hash is not None,
                    # Note: We store the hash format, not the hash itself
                    "secret_hash_format": (
                        client.client_secret_hash.split("$")[1]
                        if client.client_secret_hash else None
                    ),
                    "redirect_uris": list(client.redirect_uris),
                    "scopes": list(client.scopes),
                    "is_active": client.is_active,
                }
        return result
