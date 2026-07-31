"""In-memory API key repository for testing.

This repository stores only safe metadata and key hashes.
Raw API keys are never persisted.
"""

from typing import Any

from eiams.shared.context import RequestContext
from eiams.domain.credentials.contracts import (
    ApiKey,
    ApiKeyId,
    ApiKeyRepository,
)
from eiams.domain.identity.contracts import UserId


class InMemoryApiKeyRepository(ApiKeyRepository):
    """In-memory implementation of API key repository.
    
    Stores API keys in memory, keyed by api_key_id and tenant_id.
    Enforces tenant isolation - keys are only visible within their tenant.
    
    IMPORTANT: This repository stores key_hash, NOT the raw API key.
    The raw key is only available during create/rotate operations and
    is not persisted anywhere.
    """
    
    def __init__(self) -> None:
        """Initialize the repository."""
        # Storage: {tenant_id: {api_key_id: ApiKey}}
        self._keys: dict[str, dict[str, ApiKey]] = {}
        # Prefix index: {tenant_id: {prefix: api_key_id}}
        self._prefix_index: dict[str, dict[str, str]] = {}
        # User index: {tenant_id: {user_id: [api_key_id]}}
        self._user_index: dict[str, dict[str, list[str]]] = {}
    
    def find_by_id(
        self, context: RequestContext, api_key_id: ApiKeyId
    ) -> ApiKey | None:
        """Find API key by ID within tenant context."""
        if not context.has_tenant:
            return None
        
        tenant_key = str(context.tenant_id)
        key_id = str(api_key_id)
        
        tenant_keys = self._keys.get(tenant_key, {})
        return tenant_keys.get(key_id)
    
    def find_by_prefix(
        self, context: RequestContext, prefix: str
    ) -> ApiKey | None:
        """Find API key by prefix.
        
        Note: In a real implementation, this would search across
        all tenants since the key is provided by an external client.
        For this in-memory implementation, we search all tenants.
        """
        # Search all tenants since API key validation doesn't require tenant context
        for tenant_key, prefix_index in self._prefix_index.items():
            api_key_id = prefix_index.get(prefix)
            if api_key_id:
                return self._keys.get(tenant_key, {}).get(api_key_id)
        return None
    
    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[ApiKey]:
        """Find all API keys for a user within tenant."""
        if not context.has_tenant:
            return []
        
        tenant_key = str(context.tenant_id)
        user_key = str(user_id)
        
        user_index = self._user_index.get(tenant_key, {})
        key_ids = user_index.get(user_key, [])
        
        tenant_keys = self._keys.get(tenant_key, {})
        return [tenant_keys[k] for k in key_ids if k in tenant_keys]
    
    def find_active(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[ApiKey]:
        """Find all active API keys within tenant with pagination."""
        keys, _ = self.find_all(context, offset, limit)
        return [k for k in keys if k.is_active]
    
    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> tuple[list[ApiKey], int]:
        """Find all API keys within tenant with total count."""
        if not context.has_tenant:
            return [], 0
        
        tenant_key = str(context.tenant_id)
        tenant_keys = self._keys.get(tenant_key, {})
        
        all_keys = list(tenant_keys.values())
        total = len(all_keys)
        
        # Sort by created_at for consistent ordering
        all_keys.sort(key=lambda k: k.created_at.to_iso())
        
        # Apply pagination
        paginated = all_keys[offset:offset + limit]
        
        return paginated, total
    
    def save(self, context: RequestContext, api_key: ApiKey) -> ApiKey:
        """Persist API key.
        
        Stores the key with its hash. The raw API key
        is never passed to or stored by this method.
        """
        tenant_key = str(api_key.tenant_id)
        key_id = str(api_key.api_key_id)
        
        # Initialize tenant storage if needed
        if tenant_key not in self._keys:
            self._keys[tenant_key] = {}
            self._prefix_index[tenant_key] = {}
            self._user_index[tenant_key] = {}
        
        # Remove old prefix from index if exists and changed
        old_key = self._keys[tenant_key].get(key_id)
        if old_key and old_key.key_prefix != api_key.key_prefix:
            if old_key.key_prefix in self._prefix_index[tenant_key]:
                del self._prefix_index[tenant_key][old_key.key_prefix]
        
        # Update user index if needed
        if old_key and old_key.user_id != api_key.user_id:
            if old_key.user_id:
                old_user_key = str(old_key.user_id)
                if old_user_key in self._user_index[tenant_key]:
                    self._user_index[tenant_key][old_user_key] = [
                        k for k in self._user_index[tenant_key][old_user_key]
                        if k != key_id
                    ]
        
        # Store key
        self._keys[tenant_key][key_id] = api_key
        
        # Update prefix index
        self._prefix_index[tenant_key][api_key.key_prefix] = key_id
        
        # Update user index
        if api_key.user_id:
            user_key = str(api_key.user_id)
            if user_key not in self._user_index[tenant_key]:
                self._user_index[tenant_key][user_key] = []
            if key_id not in self._user_index[tenant_key][user_key]:
                self._user_index[tenant_key][user_key].append(key_id)
        
        return api_key
    
    def delete(self, context: RequestContext, api_key_id: ApiKeyId) -> bool:
        """Delete API key."""
        if not context.has_tenant:
            return False
        
        tenant_key = str(context.tenant_id)
        key_id = str(api_key_id)
        
        tenant_keys = self._keys.get(tenant_key, {})
        api_key = tenant_keys.get(key_id)
        
        if api_key is None:
            return False
        
        # Remove from prefix index
        prefix_index = self._prefix_index.get(tenant_key, {})
        if api_key.key_prefix in prefix_index:
            del prefix_index[api_key.key_prefix]
        
        # Remove from user index
        if api_key.user_id:
            user_key = str(api_key.user_id)
            user_index = self._user_index.get(tenant_key, {})
            if user_key in user_index:
                user_index[user_key] = [k for k in user_index[user_key] if k != key_id]
        
        # Remove key
        del tenant_keys[key_id]
        
        return True
    
    def clear(self) -> None:
        """Clear all data (for testing)."""
        self._keys.clear()
        self._prefix_index.clear()
        self._user_index.clear()
    
    def get_all_stored_data(self) -> dict[str, Any]:
        """Get all stored data for inspection (testing only).
        
        This method is for test verification only.
        Returns key data including hashes but NOT raw keys.
        """
        result = {}
        for tenant_id, keys in self._keys.items():
            result[tenant_id] = {}
            for key_id, api_key in keys.items():
                result[tenant_id][key_id] = {
                    "api_key_id": str(api_key.api_key_id),
                    "tenant_id": str(api_key.tenant_id),
                    "user_id": str(api_key.user_id) if api_key.user_id else None,
                    "name": api_key.name,
                    "key_prefix": api_key.key_prefix,
                    "has_key_hash": api_key.key_hash is not None,
                    # Note: We store the hash format, not the hash itself
                    "key_hash_format": (
                        api_key.key_hash.split("$")[1]
                        if api_key.key_hash else None
                    ),
                    "scopes": list(api_key.scopes),
                    "status": api_key.status.value,
                }
        return result
