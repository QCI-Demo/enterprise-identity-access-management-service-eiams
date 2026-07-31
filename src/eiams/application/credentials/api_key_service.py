"""API key lifecycle service with tenant-aware operations.

Implements create, retrieve, update, rotate, status change, and revoke
operations for API keys. Secret material is only available in
create and rotate response paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, Any

from eiams.shared.context import RequestContext
from eiams.shared.kernel import TenantId, Timestamp
from eiams.shared.errors import (
    ValidationError,
    TenantRequiredError,
    PermissionDeniedError,
)
from eiams.domain.credentials.contracts import (
    ApiKey,
    ApiKeyId,
    ApiKeyStatus,
)
from eiams.domain.identity.contracts import UserId
from eiams.domain.audit.contracts import AuditEventType, AuditSeverity
from eiams.application.dto import (
    ApiKeyMetadataDTO,
    ApiKeyCreateResponseDTO,
    ApiKeyRotateResponseDTO,
    ApiKeyListDTO,
    CreateApiKeyCommand,
    UpdateApiKeyCommand,
    CredentialStatusDTO,
)
from eiams.infrastructure.crypto import (
    CredentialGenerator,
    SecretHasher,
)


class ApiKeyRepositoryPort(Protocol):
    """Port for API key persistence operations."""
    
    def find_by_id(
        self, context: RequestContext, api_key_id: ApiKeyId
    ) -> ApiKey | None:
        """Find API key by ID within tenant context."""
        ...
    
    def find_by_prefix(
        self, context: RequestContext, prefix: str
    ) -> ApiKey | None:
        """Find API key by prefix for validation."""
        ...
    
    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[ApiKey]:
        """Find all API keys for a user."""
        ...
    
    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> tuple[list[ApiKey], int]:
        """Find all API keys within tenant with total count."""
        ...
    
    def save(self, context: RequestContext, api_key: ApiKey) -> ApiKey:
        """Persist API key."""
        ...
    
    def delete(self, context: RequestContext, api_key_id: ApiKeyId) -> bool:
        """Delete API key."""
        ...


class AuditServicePort(Protocol):
    """Port for audit event recording."""
    
    def record_event(
        self,
        context: RequestContext,
        event_type: AuditEventType,
        action: str,
        outcome: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        resource_type: str | None = None,
        resource_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Record an audit event with safe metadata only."""
        ...


@dataclass(frozen=True)
class ApiKeyServiceConfig:
    """Configuration for API key service."""
    max_keys_per_tenant: int = 500
    max_keys_per_user: int = 10
    default_expiry_days: int | None = 365  # None for no default expiry
    allow_service_keys: bool = True  # Keys without user_id


class ApiKeyService:
    """Application service for API key lifecycle management.
    
    All operations require validated tenant context. Secret material
    is only available in create() and rotate() responses.
    """
    
    def __init__(
        self,
        repository: ApiKeyRepositoryPort,
        audit_service: AuditServicePort | None = None,
        credential_generator: CredentialGenerator | None = None,
        secret_hasher: SecretHasher | None = None,
        config: ApiKeyServiceConfig | None = None,
    ) -> None:
        """Initialize the API key service.
        
        Args:
            repository: Port for API key persistence.
            audit_service: Optional port for audit event recording.
            credential_generator: Credential generator (uses default if None).
            secret_hasher: Secret hasher (uses default if None).
            config: Service configuration.
        """
        self._repository = repository
        self._audit = audit_service
        self._generator = credential_generator or CredentialGenerator()
        self._hasher = secret_hasher or SecretHasher()
        self._config = config or ApiKeyServiceConfig()
    
    def _require_tenant(self, context: RequestContext) -> TenantId:
        """Validate tenant context is present."""
        if not context.has_tenant:
            raise TenantRequiredError("Tenant context is required for API key operations")
        return context.tenant_id
    
    def _verify_ownership(
        self, context: RequestContext, api_key: ApiKey
    ) -> None:
        """Verify the API key belongs to the request tenant.
        
        Raises generic error to prevent tenant enumeration.
        """
        tenant_id = self._require_tenant(context)
        if str(api_key.tenant_id) != str(tenant_id):
            # Generic error to prevent information disclosure
            raise PermissionDeniedError(
                "Access denied",
                resource="api_key",
            )
    
    def _emit_audit(
        self,
        context: RequestContext,
        event_type: AuditEventType,
        action: str,
        outcome: str,
        api_key_id: str | None = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Emit audit event with safe metadata only."""
        if self._audit is None:
            return
        
        # Ensure no secrets in details
        safe_details = details or {}
        # Remove any potential secret fields
        safe_details = {
            k: v for k, v in safe_details.items()
            if k not in ("key", "api_key", "raw_key", "secret", "hash")
        }
        
        self._audit.record_event(
            context=context,
            event_type=event_type,
            action=action,
            outcome=outcome,
            severity=severity,
            resource_type="api_key",
            resource_id=api_key_id,
            details=safe_details,
        )
    
    def create(
        self,
        context: RequestContext,
        command: CreateApiKeyCommand,
    ) -> ApiKeyCreateResponseDTO:
        """Create a new API key.
        
        The returned DTO contains the api_key which must be
        presented to the caller exactly once. After this, the key
        cannot be recovered.
        
        Args:
            context: Request context with tenant scope.
            command: API key creation command.
            
        Returns:
            Creation response with one-time API key.
            
        Raises:
            TenantRequiredError: If tenant context is missing.
            ValidationError: If command validation fails.
        """
        tenant_id = self._require_tenant(context)
        
        # Validate command
        errors = command.validate()
        if errors:
            raise ValidationError(
                f"Invalid API key command: {'; '.join(errors)}",
                field="command",
                details={"errors": errors},
            )
        
        # Check if service keys are allowed
        if command.user_id is None and not self._config.allow_service_keys:
            raise ValidationError(
                "Service-level API keys are not allowed",
                field="user_id",
            )
        
        # Check tenant quota
        _, total = self._repository.find_all(context, limit=1)
        if total >= self._config.max_keys_per_tenant:
            raise ValidationError(
                f"Maximum number of API keys ({self._config.max_keys_per_tenant}) reached",
                field="tenant",
            )
        
        # Check user quota if user_id provided
        if command.user_id:
            user_id = UserId(command.user_id)
            user_keys = self._repository.find_by_user(context, user_id)
            if len(user_keys) >= self._config.max_keys_per_user:
                raise ValidationError(
                    f"Maximum API keys per user ({self._config.max_keys_per_user}) reached",
                    field="user_id",
                )
        
        # Generate API key
        api_key_id = ApiKeyId.generate()
        generated = self._generator.generate_api_key()
        raw_key = generated.raw_secret
        key_prefix = generated.display_prefix
        
        # Hash the key for storage
        hashed = self._hasher.hash_secret(raw_key)
        
        now = Timestamp.now()
        
        # Parse expiry
        expires_at: Timestamp | None = None
        if command.expires_at:
            expires_at = Timestamp.from_iso(command.expires_at)
        elif self._config.default_expiry_days:
            from datetime import timedelta
            expiry_dt = now.value + timedelta(days=self._config.default_expiry_days)
            expires_at = Timestamp(expiry_dt)
        
        # Create domain entity
        api_key = ApiKey(
            api_key_id=api_key_id,
            tenant_id=tenant_id,
            user_id=UserId(command.user_id) if command.user_id else None,
            name=command.name,
            key_prefix=key_prefix,
            key_hash=hashed.to_storage_string(),
            scopes=tuple(command.scopes),
            status=ApiKeyStatus.ACTIVE,
            created_at=now,
            expires_at=expires_at,
            last_used_at=None,
        )
        
        # Persist
        saved = self._repository.save(context, api_key)
        
        # Audit - NO SECRET IN DETAILS
        self._emit_audit(
            context=context,
            event_type=AuditEventType.API_KEY_CREATED,
            action="create",
            outcome="success",
            api_key_id=str(api_key_id),
            details={
                "name": command.name,
                "key_prefix": key_prefix,
                "scopes": command.scopes,
                "has_expiry": expires_at is not None,
            },
        )
        
        # Return response with one-time secret
        return ApiKeyCreateResponseDTO(
            api_key_id=str(saved.api_key_id),
            tenant_id=str(saved.tenant_id),
            name=saved.name,
            api_key=raw_key,  # ONE-TIME ONLY
            key_prefix=saved.key_prefix,
            scopes=saved.scopes,
            status=CredentialStatusDTO.ACTIVE,
            created_at=saved.created_at.to_iso(),
            expires_at=saved.expires_at.to_iso() if saved.expires_at else None,
        )
    
    def get(
        self,
        context: RequestContext,
        api_key_id: str,
    ) -> ApiKeyMetadataDTO | None:
        """Retrieve API key metadata.
        
        Returns metadata only - never the raw key.
        
        Args:
            context: Request context with tenant scope.
            api_key_id: The API key ID to retrieve.
            
        Returns:
            API key metadata or None if not found.
        """
        self._require_tenant(context)
        
        parsed_id = ApiKeyId(api_key_id)
        api_key = self._repository.find_by_id(context, parsed_id)
        
        if api_key is None:
            return None
        
        self._verify_ownership(context, api_key)
        
        return self._to_metadata_dto(api_key)
    
    def list(
        self,
        context: RequestContext,
        offset: int = 0,
        limit: int = 100,
    ) -> ApiKeyListDTO:
        """List API keys for the tenant.
        
        Returns metadata only - never raw keys.
        
        Args:
            context: Request context with tenant scope.
            offset: Pagination offset.
            limit: Maximum results to return.
            
        Returns:
            Paginated list of API key metadata.
        """
        self._require_tenant(context)
        
        # Enforce pagination limits
        limit = min(limit, 100)
        offset = max(offset, 0)
        
        api_keys, total = self._repository.find_all(context, offset, limit)
        
        return ApiKeyListDTO(
            api_keys=tuple(self._to_metadata_dto(k) for k in api_keys),
            total=total,
            offset=offset,
            limit=limit,
        )
    
    def update(
        self,
        context: RequestContext,
        api_key_id: str,
        command: UpdateApiKeyCommand,
    ) -> ApiKeyMetadataDTO:
        """Update API key metadata.
        
        Cannot update the key itself - use rotate for that.
        
        Args:
            context: Request context with tenant scope.
            api_key_id: The API key ID to update.
            command: Update command.
            
        Returns:
            Updated API key metadata.
        """
        self._require_tenant(context)
        
        errors = command.validate()
        if errors:
            raise ValidationError(
                f"Invalid update command: {'; '.join(errors)}",
                field="command",
                details={"errors": errors},
            )
        
        parsed_id = ApiKeyId(api_key_id)
        api_key = self._repository.find_by_id(context, parsed_id)
        
        if api_key is None:
            raise ValidationError(
                "API key not found",
                field="api_key_id",
            )
        
        self._verify_ownership(context, api_key)
        
        # Build updated API key
        now = Timestamp.now()
        
        # Parse new expiry if provided
        new_expires_at = api_key.expires_at
        if command.expires_at is not None:
            new_expires_at = Timestamp.from_iso(command.expires_at)
        
        # Resolve new status
        new_status = api_key.status
        if command.status is not None:
            new_status = self._map_dto_status_to_domain(command.status)
        
        updated = ApiKey(
            api_key_id=api_key.api_key_id,
            tenant_id=api_key.tenant_id,
            user_id=api_key.user_id,
            name=command.name if command.name is not None else api_key.name,
            key_prefix=api_key.key_prefix,
            key_hash=api_key.key_hash,
            scopes=tuple(command.scopes) if command.scopes is not None else api_key.scopes,
            status=new_status,
            created_at=api_key.created_at,
            expires_at=new_expires_at,
            last_used_at=api_key.last_used_at,
        )
        
        saved = self._repository.save(context, updated)
        
        self._emit_audit(
            context=context,
            event_type=AuditEventType.API_KEY_CREATED,  # Using available type
            action="update",
            outcome="success",
            api_key_id=str(api_key_id),
            details={"updated_fields": self._get_updated_fields(command)},
        )
        
        return self._to_metadata_dto(saved)
    
    def rotate(
        self,
        context: RequestContext,
        api_key_id: str,
    ) -> ApiKeyRotateResponseDTO:
        """Rotate an API key.
        
        The returned DTO contains the new_api_key which must be
        presented to the caller exactly once.
        
        Args:
            context: Request context with tenant scope.
            api_key_id: The API key ID to rotate.
            
        Returns:
            Rotation response with one-time API key.
        """
        self._require_tenant(context)
        
        parsed_id = ApiKeyId(api_key_id)
        api_key = self._repository.find_by_id(context, parsed_id)
        
        if api_key is None:
            raise ValidationError(
                "API key not found",
                field="api_key_id",
            )
        
        self._verify_ownership(context, api_key)
        
        if api_key.status != ApiKeyStatus.ACTIVE:
            raise ValidationError(
                "Cannot rotate inactive or revoked API key",
                field="status",
            )
        
        # Generate new key
        generated = self._generator.generate_api_key()
        raw_key = generated.raw_secret
        new_prefix = generated.display_prefix
        
        # Hash the new key
        hashed = self._hasher.hash_secret(raw_key)
        
        now = Timestamp.now()
        
        # Update API key with new hash
        updated = ApiKey(
            api_key_id=api_key.api_key_id,
            tenant_id=api_key.tenant_id,
            user_id=api_key.user_id,
            name=api_key.name,
            key_prefix=new_prefix,
            key_hash=hashed.to_storage_string(),
            scopes=api_key.scopes,
            status=api_key.status,
            created_at=api_key.created_at,
            expires_at=api_key.expires_at,
            last_used_at=api_key.last_used_at,
        )
        
        self._repository.save(context, updated)
        
        # Audit - NO SECRET
        self._emit_audit(
            context=context,
            event_type=AuditEventType.API_KEY_CREATED,  # Using available type
            action="rotate",
            outcome="success",
            api_key_id=str(api_key_id),
            details={"new_key_prefix": new_prefix},
        )
        
        return ApiKeyRotateResponseDTO(
            api_key_id=str(api_key_id),
            new_api_key=raw_key,  # ONE-TIME ONLY
            new_key_prefix=new_prefix,
            rotated_at=now.to_iso(),
            version=1,  # Would increment in real implementation
            expires_at=api_key.expires_at.to_iso() if api_key.expires_at else None,
        )
    
    def change_status(
        self,
        context: RequestContext,
        api_key_id: str,
        new_status: CredentialStatusDTO,
    ) -> ApiKeyMetadataDTO:
        """Change the API key status (activate, deactivate, revoke).
        
        Args:
            context: Request context with tenant scope.
            api_key_id: The API key ID to update.
            new_status: The new status.
            
        Returns:
            Updated API key metadata.
        """
        self._require_tenant(context)
        
        parsed_id = ApiKeyId(api_key_id)
        api_key = self._repository.find_by_id(context, parsed_id)
        
        if api_key is None:
            raise ValidationError(
                "API key not found",
                field="api_key_id",
            )
        
        self._verify_ownership(context, api_key)
        
        # Validate state transition
        current_status = self._map_domain_status_to_dto(api_key.status)
        
        if new_status == CredentialStatusDTO.ACTIVE:
            if current_status == CredentialStatusDTO.REVOKED:
                raise ValidationError(
                    "Cannot reactivate revoked API key",
                    field="status",
                )
        
        now = Timestamp.now()
        domain_status = self._map_dto_status_to_domain(new_status)
        
        updated = ApiKey(
            api_key_id=api_key.api_key_id,
            tenant_id=api_key.tenant_id,
            user_id=api_key.user_id,
            name=api_key.name,
            key_prefix=api_key.key_prefix,
            key_hash=api_key.key_hash,
            scopes=api_key.scopes,
            status=domain_status,
            created_at=api_key.created_at,
            expires_at=api_key.expires_at,
            last_used_at=api_key.last_used_at,
        )
        
        saved = self._repository.save(context, updated)
        
        self._emit_audit(
            context=context,
            event_type=AuditEventType.API_KEY_CREATED,  # Using available type
            action="change_status",
            outcome="success",
            api_key_id=str(api_key_id),
            details={"new_status": new_status.value},
        )
        
        return self._to_metadata_dto(saved)
    
    def revoke(
        self,
        context: RequestContext,
        api_key_id: str,
    ) -> bool:
        """Revoke an API key.
        
        Args:
            context: Request context with tenant scope.
            api_key_id: The API key ID to revoke.
            
        Returns:
            True if revoked successfully.
        """
        self._require_tenant(context)
        
        parsed_id = ApiKeyId(api_key_id)
        api_key = self._repository.find_by_id(context, parsed_id)
        
        if api_key is None:
            return False
        
        self._verify_ownership(context, api_key)
        
        now = Timestamp.now()
        
        revoked = ApiKey(
            api_key_id=api_key.api_key_id,
            tenant_id=api_key.tenant_id,
            user_id=api_key.user_id,
            name=api_key.name,
            key_prefix=api_key.key_prefix,
            key_hash=api_key.key_hash,
            scopes=api_key.scopes,
            status=ApiKeyStatus.REVOKED,
            created_at=api_key.created_at,
            expires_at=api_key.expires_at,
            last_used_at=api_key.last_used_at,
        )
        
        self._repository.save(context, revoked)
        
        self._emit_audit(
            context=context,
            event_type=AuditEventType.API_KEY_REVOKED,
            action="revoke",
            outcome="success",
            api_key_id=str(api_key_id),
            severity=AuditSeverity.WARNING,
            details={},
        )
        
        return True
    
    def _to_metadata_dto(self, api_key: ApiKey) -> ApiKeyMetadataDTO:
        """Convert domain entity to metadata DTO (no secret)."""
        return ApiKeyMetadataDTO(
            api_key_id=str(api_key.api_key_id),
            tenant_id=str(api_key.tenant_id),
            user_id=str(api_key.user_id) if api_key.user_id else None,
            name=api_key.name,
            key_prefix=api_key.key_prefix,
            scopes=api_key.scopes,
            status=self._map_domain_status_to_dto(api_key.status),
            created_at=api_key.created_at.to_iso(),
            expires_at=api_key.expires_at.to_iso() if api_key.expires_at else None,
            last_used_at=api_key.last_used_at.to_iso() if api_key.last_used_at else None,
        )
    
    def _map_domain_status_to_dto(self, status: ApiKeyStatus) -> CredentialStatusDTO:
        """Map domain status to DTO status."""
        mapping = {
            ApiKeyStatus.ACTIVE: CredentialStatusDTO.ACTIVE,
            ApiKeyStatus.REVOKED: CredentialStatusDTO.REVOKED,
            ApiKeyStatus.EXPIRED: CredentialStatusDTO.EXPIRED,
        }
        return mapping.get(status, CredentialStatusDTO.INACTIVE)
    
    def _map_dto_status_to_domain(self, status: CredentialStatusDTO) -> ApiKeyStatus:
        """Map DTO status to domain status."""
        mapping = {
            CredentialStatusDTO.ACTIVE: ApiKeyStatus.ACTIVE,
            CredentialStatusDTO.INACTIVE: ApiKeyStatus.REVOKED,
            CredentialStatusDTO.REVOKED: ApiKeyStatus.REVOKED,
            CredentialStatusDTO.EXPIRED: ApiKeyStatus.EXPIRED,
        }
        return mapping.get(status, ApiKeyStatus.REVOKED)
    
    def _get_updated_fields(self, command: UpdateApiKeyCommand) -> list[str]:
        """Get list of fields being updated."""
        fields = []
        if command.name is not None:
            fields.append("name")
        if command.scopes is not None:
            fields.append("scopes")
        if command.status is not None:
            fields.append("status")
        if command.expires_at is not None:
            fields.append("expires_at")
        return fields
