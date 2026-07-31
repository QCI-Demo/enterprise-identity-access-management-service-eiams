"""Credential DTOs with strict separation of secret and metadata responses.

This module enforces that:
1. Raw secrets are ONLY present in create/rotate response DTOs
2. Metadata DTOs never contain secret material
3. All DTOs are serialization-safe and audit-friendly

WARNING: OAuthClientCreateResponseDTO and ApiKeyCreateResponseDTO contain
one-time secrets that must never be logged, stored, or sent in error responses.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class CredentialStatusDTO(str, Enum):
    """Status of a credential for API responses."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    REVOKED = "revoked"
    EXPIRED = "expired"


# =============================================================================
# OAuth Client DTOs
# =============================================================================


@dataclass(frozen=True)
class OAuthClientMetadataDTO:
    """OAuth client metadata - safe for storage, logging, and API responses.
    
    This DTO explicitly EXCLUDES the client secret and secret hash.
    Use this for list, retrieve, and update response operations.
    """
    client_id: str
    tenant_id: str
    name: str
    description: str | None
    client_type: str  # "confidential" or "public"
    redirect_uris: tuple[str, ...]
    scopes: tuple[str, ...]
    status: CredentialStatusDTO
    created_at: str  # ISO 8601
    updated_at: str  # ISO 8601
    secret_last_rotated_at: str | None = None
    version: int = 1
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for API response."""
        return {
            "client_id": self.client_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "description": self.description,
            "client_type": self.client_type,
            "redirect_uris": list(self.redirect_uris),
            "scopes": list(self.scopes),
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "secret_last_rotated_at": self.secret_last_rotated_at,
            "version": self.version,
        }


@dataclass(frozen=True)
class OAuthClientCreateResponseDTO:
    """OAuth client creation response with ONE-TIME SECRET.
    
    WARNING: The client_secret field contains sensitive material that:
    - Must be returned to the caller exactly once
    - Must NEVER be logged, stored in persistence, or included in error responses
    - Must NEVER appear in audit events
    
    After the client receives this response, the secret cannot be recovered.
    """
    client_id: str
    tenant_id: str
    name: str
    client_secret: str  # ONE-TIME SECRET - DO NOT LOG/STORE
    client_type: str
    redirect_uris: tuple[str, ...]
    scopes: tuple[str, ...]
    status: CredentialStatusDTO
    created_at: str
    
    def to_response_dict(self) -> dict[str, Any]:
        """Serialize for one-time API response ONLY.
        
        This method should only be called when returning the creation
        response to the client. Never use for logging or persistence.
        """
        return {
            "client_id": self.client_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "client_secret": self.client_secret,  # One-time only
            "client_type": self.client_type,
            "redirect_uris": list(self.redirect_uris),
            "scopes": list(self.scopes),
            "status": self.status.value,
            "created_at": self.created_at,
            "message": "Store the client_secret securely. It cannot be retrieved again.",
        }
    
    def to_metadata(self) -> OAuthClientMetadataDTO:
        """Convert to metadata-only DTO (strips secret)."""
        return OAuthClientMetadataDTO(
            client_id=self.client_id,
            tenant_id=self.tenant_id,
            name=self.name,
            description=None,
            client_type=self.client_type,
            redirect_uris=self.redirect_uris,
            scopes=self.scopes,
            status=self.status,
            created_at=self.created_at,
            updated_at=self.created_at,
        )
    
    def __repr__(self) -> str:
        """Safe repr that hides the secret."""
        return (
            f"OAuthClientCreateResponseDTO(client_id='{self.client_id}', "
            f"name='{self.name}', client_secret='[REDACTED]')"
        )


@dataclass(frozen=True)
class OAuthClientRotateResponseDTO:
    """OAuth client secret rotation response with ONE-TIME SECRET.
    
    WARNING: The new_client_secret field contains sensitive material.
    Same security constraints as OAuthClientCreateResponseDTO apply.
    """
    client_id: str
    new_client_secret: str  # ONE-TIME SECRET - DO NOT LOG/STORE
    rotated_at: str
    version: int
    
    def to_response_dict(self) -> dict[str, Any]:
        """Serialize for one-time API response ONLY."""
        return {
            "client_id": self.client_id,
            "new_client_secret": self.new_client_secret,  # One-time only
            "rotated_at": self.rotated_at,
            "version": self.version,
            "message": "Store the new_client_secret securely. It cannot be retrieved again.",
        }
    
    def __repr__(self) -> str:
        """Safe repr that hides the secret."""
        return (
            f"OAuthClientRotateResponseDTO(client_id='{self.client_id}', "
            f"new_client_secret='[REDACTED]', version={self.version})"
        )


@dataclass(frozen=True)
class OAuthClientListDTO:
    """Paginated list of OAuth client metadata."""
    clients: tuple[OAuthClientMetadataDTO, ...]
    total: int
    offset: int
    limit: int
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize for API response."""
        return {
            "clients": [c.to_dict() for c in self.clients],
            "total": self.total,
            "offset": self.offset,
            "limit": self.limit,
        }


@dataclass
class CreateOAuthClientCommand:
    """Command to create a new OAuth client."""
    name: str
    client_type: str  # "confidential" or "public"
    redirect_uris: list[str]
    scopes: list[str]
    description: str | None = None
    
    # Validation constraints
    NAME_MIN_LENGTH: int = 1
    NAME_MAX_LENGTH: int = 255
    MAX_REDIRECT_URIS: int = 10
    MAX_SCOPES: int = 50
    SCOPE_MAX_LENGTH: int = 100
    
    def validate(self) -> list[str]:
        """Validate command and return list of errors."""
        errors = []
        
        if not self.name or len(self.name) < self.NAME_MIN_LENGTH:
            errors.append("name is required")
        elif len(self.name) > self.NAME_MAX_LENGTH:
            errors.append(f"name must not exceed {self.NAME_MAX_LENGTH} characters")
        
        if self.client_type not in ("confidential", "public"):
            errors.append("client_type must be 'confidential' or 'public'")
        
        if not self.redirect_uris:
            errors.append("at least one redirect_uri is required")
        elif len(self.redirect_uris) > self.MAX_REDIRECT_URIS:
            errors.append(f"maximum {self.MAX_REDIRECT_URIS} redirect_uris allowed")
        
        for uri in self.redirect_uris:
            if not uri.startswith(("http://", "https://")):
                errors.append(f"invalid redirect_uri: {uri}")
        
        if len(self.scopes) > self.MAX_SCOPES:
            errors.append(f"maximum {self.MAX_SCOPES} scopes allowed")
        
        for scope in self.scopes:
            if len(scope) > self.SCOPE_MAX_LENGTH:
                errors.append(f"scope '{scope[:20]}...' exceeds maximum length")
        
        return errors


@dataclass
class UpdateOAuthClientCommand:
    """Command to update OAuth client metadata."""
    name: str | None = None
    description: str | None = None
    redirect_uris: list[str] | None = None
    scopes: list[str] | None = None
    status: CredentialStatusDTO | None = None
    
    def validate(self) -> list[str]:
        """Validate command and return list of errors."""
        errors = []
        
        if self.name is not None and len(self.name) > 255:
            errors.append("name must not exceed 255 characters")
        
        if self.redirect_uris is not None:
            if len(self.redirect_uris) > 10:
                errors.append("maximum 10 redirect_uris allowed")
            for uri in self.redirect_uris:
                if not uri.startswith(("http://", "https://")):
                    errors.append(f"invalid redirect_uri: {uri}")
        
        if self.scopes is not None and len(self.scopes) > 50:
            errors.append("maximum 50 scopes allowed")
        
        # Validate state transitions
        if self.status == CredentialStatusDTO.REVOKED:
            # Once revoked, cannot be reactivated through update
            pass  # Allowed transition
        
        return errors


# =============================================================================
# API Key DTOs
# =============================================================================


@dataclass(frozen=True)
class ApiKeyMetadataDTO:
    """API key metadata - safe for storage, logging, and API responses.
    
    This DTO explicitly EXCLUDES the raw API key and key hash.
    Contains only the key prefix for identification.
    """
    api_key_id: str
    tenant_id: str
    user_id: str | None
    name: str
    key_prefix: str  # Safe display prefix (e.g., "eiams_abc")
    scopes: tuple[str, ...]
    status: CredentialStatusDTO
    created_at: str  # ISO 8601
    expires_at: str | None  # ISO 8601 or None
    last_used_at: str | None  # ISO 8601 or None
    version: int = 1
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for API response."""
        return {
            "api_key_id": self.api_key_id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "scopes": list(self.scopes),
            "status": self.status.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_used_at": self.last_used_at,
            "version": self.version,
        }


@dataclass(frozen=True)
class ApiKeyCreateResponseDTO:
    """API key creation response with ONE-TIME SECRET.
    
    WARNING: The api_key field contains sensitive material that:
    - Must be returned to the caller exactly once
    - Must NEVER be logged, stored in persistence, or included in error responses
    - Must NEVER appear in audit events
    
    After the client receives this response, the key cannot be recovered.
    """
    api_key_id: str
    tenant_id: str
    name: str
    api_key: str  # ONE-TIME SECRET - DO NOT LOG/STORE
    key_prefix: str
    scopes: tuple[str, ...]
    status: CredentialStatusDTO
    created_at: str
    expires_at: str | None
    
    def to_response_dict(self) -> dict[str, Any]:
        """Serialize for one-time API response ONLY."""
        return {
            "api_key_id": self.api_key_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "api_key": self.api_key,  # One-time only
            "key_prefix": self.key_prefix,
            "scopes": list(self.scopes),
            "status": self.status.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "message": "Store the api_key securely. It cannot be retrieved again.",
        }
    
    def to_metadata(self) -> ApiKeyMetadataDTO:
        """Convert to metadata-only DTO (strips secret)."""
        return ApiKeyMetadataDTO(
            api_key_id=self.api_key_id,
            tenant_id=self.tenant_id,
            user_id=None,
            name=self.name,
            key_prefix=self.key_prefix,
            scopes=self.scopes,
            status=self.status,
            created_at=self.created_at,
            expires_at=self.expires_at,
            last_used_at=None,
        )
    
    def __repr__(self) -> str:
        """Safe repr that hides the secret."""
        return (
            f"ApiKeyCreateResponseDTO(api_key_id='{self.api_key_id}', "
            f"name='{self.name}', api_key='[REDACTED]')"
        )


@dataclass(frozen=True)
class ApiKeyRotateResponseDTO:
    """API key rotation response with ONE-TIME SECRET.
    
    WARNING: The new_api_key field contains sensitive material.
    Same security constraints as ApiKeyCreateResponseDTO apply.
    """
    api_key_id: str
    new_api_key: str  # ONE-TIME SECRET - DO NOT LOG/STORE
    new_key_prefix: str
    rotated_at: str
    version: int
    expires_at: str | None
    
    def to_response_dict(self) -> dict[str, Any]:
        """Serialize for one-time API response ONLY."""
        return {
            "api_key_id": self.api_key_id,
            "new_api_key": self.new_api_key,  # One-time only
            "new_key_prefix": self.new_key_prefix,
            "rotated_at": self.rotated_at,
            "version": self.version,
            "expires_at": self.expires_at,
            "message": "Store the new_api_key securely. It cannot be retrieved again.",
        }
    
    def __repr__(self) -> str:
        """Safe repr that hides the secret."""
        return (
            f"ApiKeyRotateResponseDTO(api_key_id='{self.api_key_id}', "
            f"new_api_key='[REDACTED]', version={self.version})"
        )


@dataclass(frozen=True)
class ApiKeyListDTO:
    """Paginated list of API key metadata."""
    api_keys: tuple[ApiKeyMetadataDTO, ...]
    total: int
    offset: int
    limit: int
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize for API response."""
        return {
            "api_keys": [k.to_dict() for k in self.api_keys],
            "total": self.total,
            "offset": self.offset,
            "limit": self.limit,
        }


@dataclass
class CreateApiKeyCommand:
    """Command to create a new API key."""
    name: str
    scopes: list[str]
    user_id: str | None = None  # None for service-level keys
    expires_at: str | None = None  # ISO 8601
    
    # Validation constraints
    NAME_MIN_LENGTH: int = 1
    NAME_MAX_LENGTH: int = 255
    MAX_SCOPES: int = 50
    SCOPE_MAX_LENGTH: int = 100
    
    def validate(self) -> list[str]:
        """Validate command and return list of errors."""
        errors = []
        
        if not self.name or len(self.name) < self.NAME_MIN_LENGTH:
            errors.append("name is required")
        elif len(self.name) > self.NAME_MAX_LENGTH:
            errors.append(f"name must not exceed {self.NAME_MAX_LENGTH} characters")
        
        if len(self.scopes) > self.MAX_SCOPES:
            errors.append(f"maximum {self.MAX_SCOPES} scopes allowed")
        
        for scope in self.scopes:
            if len(scope) > self.SCOPE_MAX_LENGTH:
                errors.append(f"scope '{scope[:20]}...' exceeds maximum length")
        
        if self.expires_at:
            try:
                from datetime import datetime
                datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
            except ValueError:
                errors.append("expires_at must be a valid ISO 8601 datetime")
        
        return errors


@dataclass
class UpdateApiKeyCommand:
    """Command to update API key metadata."""
    name: str | None = None
    scopes: list[str] | None = None
    status: CredentialStatusDTO | None = None
    expires_at: str | None = None
    
    def validate(self) -> list[str]:
        """Validate command and return list of errors."""
        errors = []
        
        if self.name is not None and len(self.name) > 255:
            errors.append("name must not exceed 255 characters")
        
        if self.scopes is not None and len(self.scopes) > 50:
            errors.append("maximum 50 scopes allowed")
        
        if self.expires_at:
            try:
                from datetime import datetime
                datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
            except ValueError:
                errors.append("expires_at must be a valid ISO 8601 datetime")
        
        return errors
