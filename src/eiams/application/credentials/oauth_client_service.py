"""OAuth client lifecycle service with tenant-aware operations.

Implements create, retrieve, update, rotate, status change, and revoke
operations for OAuth clients. Secret material is only available in
create and rotate response paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Any

from eiams.shared.context import RequestContext
from eiams.shared.kernel import TenantId, Timestamp
from eiams.shared.errors import (
    ValidationError,
    TenantRequiredError,
    PermissionDeniedError,
)
from eiams.domain.credentials.contracts import (
    OAuthClient,
    OAuthClientId,
    OAuthClientType,
)
from eiams.domain.audit.contracts import AuditEventType, AuditSeverity
from eiams.application.dto import (
    OAuthClientMetadataDTO,
    OAuthClientCreateResponseDTO,
    OAuthClientRotateResponseDTO,
    OAuthClientListDTO,
    CreateOAuthClientCommand,
    UpdateOAuthClientCommand,
    CredentialStatusDTO,
)
from eiams.infrastructure.crypto import (
    CredentialGenerator,
    SecretHasher,
)


class OAuthClientRepositoryPort(Protocol):
    """Port for OAuth client persistence operations."""
    
    def find_by_id(
        self, context: RequestContext, client_id: OAuthClientId
    ) -> OAuthClient | None:
        """Find client by ID within tenant context."""
        ...
    
    def find_by_name(
        self, context: RequestContext, name: str
    ) -> OAuthClient | None:
        """Find client by name within tenant context."""
        ...
    
    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> tuple[list[OAuthClient], int]:
        """Find all clients within tenant with total count."""
        ...
    
    def save(self, context: RequestContext, client: OAuthClient) -> OAuthClient:
        """Persist client."""
        ...
    
    def delete(self, context: RequestContext, client_id: OAuthClientId) -> bool:
        """Delete client."""
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
class OAuthClientServiceConfig:
    """Configuration for OAuth client service."""
    max_clients_per_tenant: int = 100
    allow_public_clients: bool = True
    default_scopes: tuple[str, ...] = ()


class OAuthClientService:
    """Application service for OAuth client lifecycle management.
    
    All operations require validated tenant context. Secret material
    is only available in create() and rotate_secret() responses.
    """
    
    def __init__(
        self,
        repository: OAuthClientRepositoryPort,
        audit_service: AuditServicePort | None = None,
        credential_generator: CredentialGenerator | None = None,
        secret_hasher: SecretHasher | None = None,
        config: OAuthClientServiceConfig | None = None,
    ) -> None:
        """Initialize the OAuth client service.
        
        Args:
            repository: Port for OAuth client persistence.
            audit_service: Optional port for audit event recording.
            credential_generator: Credential generator (uses default if None).
            secret_hasher: Secret hasher (uses default if None).
            config: Service configuration.
        """
        self._repository = repository
        self._audit = audit_service
        self._generator = credential_generator or CredentialGenerator()
        self._hasher = secret_hasher or SecretHasher()
        self._config = config or OAuthClientServiceConfig()
    
    def _require_tenant(self, context: RequestContext) -> TenantId:
        """Validate tenant context is present."""
        if not context.has_tenant:
            raise TenantRequiredError("Tenant context is required for OAuth client operations")
        return context.tenant_id
    
    def _verify_ownership(
        self, context: RequestContext, client: OAuthClient
    ) -> None:
        """Verify the client belongs to the request tenant.
        
        Raises generic error to prevent tenant enumeration.
        """
        tenant_id = self._require_tenant(context)
        if str(client.tenant_id) != str(tenant_id):
            # Generic error to prevent information disclosure
            raise PermissionDeniedError(
                "Access denied",
                resource="oauth_client",
            )
    
    def _emit_audit(
        self,
        context: RequestContext,
        event_type: AuditEventType,
        action: str,
        outcome: str,
        client_id: str | None = None,
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
            if k not in ("secret", "client_secret", "raw_secret", "hash")
        }
        
        self._audit.record_event(
            context=context,
            event_type=event_type,
            action=action,
            outcome=outcome,
            severity=severity,
            resource_type="oauth_client",
            resource_id=client_id,
            details=safe_details,
        )
    
    def create(
        self,
        context: RequestContext,
        command: CreateOAuthClientCommand,
    ) -> OAuthClientCreateResponseDTO:
        """Create a new OAuth client.
        
        The returned DTO contains the client_secret which must be
        presented to the caller exactly once. After this, the secret
        cannot be recovered.
        
        Args:
            context: Request context with tenant scope.
            command: Client creation command.
            
        Returns:
            Creation response with one-time secret.
            
        Raises:
            TenantRequiredError: If tenant context is missing.
            ValidationError: If command validation fails.
        """
        tenant_id = self._require_tenant(context)
        
        # Validate command
        errors = command.validate()
        if errors:
            raise ValidationError(
                f"Invalid OAuth client command: {'; '.join(errors)}",
                field="command",
                details={"errors": errors},
            )
        
        # Check for name conflict
        existing = self._repository.find_by_name(context, command.name)
        if existing is not None:
            raise ValidationError(
                f"OAuth client with name '{command.name}' already exists",
                field="name",
            )
        
        # Check tenant quota
        _, total = self._repository.find_all(context, limit=1)
        if total >= self._config.max_clients_per_tenant:
            raise ValidationError(
                f"Maximum number of OAuth clients ({self._config.max_clients_per_tenant}) reached",
                field="tenant",
            )
        
        # Generate client ID and secret for confidential clients
        client_id = OAuthClientId.generate()
        client_type = OAuthClientType(command.client_type)
        
        raw_secret: str | None = None
        secret_hash: str | None = None
        
        if client_type == OAuthClientType.CONFIDENTIAL:
            generated = self._generator.generate_client_secret()
            raw_secret = generated.raw_secret
            hashed = self._hasher.hash_secret(raw_secret)
            secret_hash = hashed.to_storage_string()
        elif not self._config.allow_public_clients:
            raise ValidationError(
                "Public clients are not allowed",
                field="client_type",
            )
        
        now = Timestamp.now()
        
        # Create domain entity
        client = OAuthClient(
            client_id=client_id,
            tenant_id=tenant_id,
            name=command.name,
            description=command.description,
            client_type=client_type,
            client_secret_hash=secret_hash,
            redirect_uris=tuple(command.redirect_uris),
            scopes=tuple(command.scopes),
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        
        # Persist
        saved = self._repository.save(context, client)
        
        # Audit - NO SECRET IN DETAILS
        self._emit_audit(
            context=context,
            event_type=AuditEventType.CLIENT_CREATED,
            action="create",
            outcome="success",
            client_id=str(client_id),
            details={
                "name": command.name,
                "client_type": command.client_type,
                "scopes": command.scopes,
            },
        )
        
        # Return response with one-time secret
        return OAuthClientCreateResponseDTO(
            client_id=str(saved.client_id),
            tenant_id=str(saved.tenant_id),
            name=saved.name,
            client_secret=raw_secret or "",  # Empty for public clients
            client_type=saved.client_type.value,
            redirect_uris=saved.redirect_uris,
            scopes=saved.scopes,
            status=CredentialStatusDTO.ACTIVE,
            created_at=saved.created_at.to_iso(),
        )
    
    def get(
        self,
        context: RequestContext,
        client_id: str,
    ) -> OAuthClientMetadataDTO | None:
        """Retrieve OAuth client metadata.
        
        Returns metadata only - never the secret.
        
        Args:
            context: Request context with tenant scope.
            client_id: The client ID to retrieve.
            
        Returns:
            Client metadata or None if not found.
        """
        self._require_tenant(context)
        
        parsed_id = OAuthClientId(client_id)
        client = self._repository.find_by_id(context, parsed_id)
        
        if client is None:
            return None
        
        self._verify_ownership(context, client)
        
        return self._to_metadata_dto(client)
    
    def list(
        self,
        context: RequestContext,
        offset: int = 0,
        limit: int = 100,
    ) -> OAuthClientListDTO:
        """List OAuth clients for the tenant.
        
        Returns metadata only - never secrets.
        
        Args:
            context: Request context with tenant scope.
            offset: Pagination offset.
            limit: Maximum results to return.
            
        Returns:
            Paginated list of client metadata.
        """
        self._require_tenant(context)
        
        # Enforce pagination limits
        limit = min(limit, 100)
        offset = max(offset, 0)
        
        clients, total = self._repository.find_all(context, offset, limit)
        
        return OAuthClientListDTO(
            clients=tuple(self._to_metadata_dto(c) for c in clients),
            total=total,
            offset=offset,
            limit=limit,
        )
    
    def update(
        self,
        context: RequestContext,
        client_id: str,
        command: UpdateOAuthClientCommand,
    ) -> OAuthClientMetadataDTO:
        """Update OAuth client metadata.
        
        Cannot update secret - use rotate_secret for that.
        
        Args:
            context: Request context with tenant scope.
            client_id: The client ID to update.
            command: Update command.
            
        Returns:
            Updated client metadata.
        """
        self._require_tenant(context)
        
        errors = command.validate()
        if errors:
            raise ValidationError(
                f"Invalid update command: {'; '.join(errors)}",
                field="command",
                details={"errors": errors},
            )
        
        parsed_id = OAuthClientId(client_id)
        client = self._repository.find_by_id(context, parsed_id)
        
        if client is None:
            raise ValidationError(
                "OAuth client not found",
                field="client_id",
            )
        
        self._verify_ownership(context, client)
        
        # Check if client is revoked
        if not client.is_active and command.status != CredentialStatusDTO.ACTIVE:
            # Allow other updates even if inactive
            pass
        
        # Build updated client
        now = Timestamp.now()
        updated = OAuthClient(
            client_id=client.client_id,
            tenant_id=client.tenant_id,
            name=command.name if command.name is not None else client.name,
            description=command.description if command.description is not None else client.description,
            client_type=client.client_type,
            client_secret_hash=client.client_secret_hash,
            redirect_uris=tuple(command.redirect_uris) if command.redirect_uris is not None else client.redirect_uris,
            scopes=tuple(command.scopes) if command.scopes is not None else client.scopes,
            is_active=self._resolve_status(client.is_active, command.status),
            created_at=client.created_at,
            updated_at=now,
        )
        
        saved = self._repository.save(context, updated)
        
        self._emit_audit(
            context=context,
            event_type=AuditEventType.CLIENT_CREATED,  # Using available event type
            action="update",
            outcome="success",
            client_id=str(client_id),
            details={"updated_fields": self._get_updated_fields(command)},
        )
        
        return self._to_metadata_dto(saved)
    
    def rotate_secret(
        self,
        context: RequestContext,
        client_id: str,
    ) -> OAuthClientRotateResponseDTO:
        """Rotate the client secret.
        
        The returned DTO contains the new_client_secret which must be
        presented to the caller exactly once.
        
        Args:
            context: Request context with tenant scope.
            client_id: The client ID to rotate.
            
        Returns:
            Rotation response with one-time secret.
        """
        self._require_tenant(context)
        
        parsed_id = OAuthClientId(client_id)
        client = self._repository.find_by_id(context, parsed_id)
        
        if client is None:
            raise ValidationError(
                "OAuth client not found",
                field="client_id",
            )
        
        self._verify_ownership(context, client)
        
        # Cannot rotate secret for public clients
        if client.client_type == OAuthClientType.PUBLIC:
            raise ValidationError(
                "Cannot rotate secret for public clients",
                field="client_type",
            )
        
        if not client.is_active:
            raise ValidationError(
                "Cannot rotate secret for inactive client",
                field="status",
            )
        
        # Generate new secret
        generated = self._generator.generate_client_secret()
        raw_secret = generated.raw_secret
        hashed = self._hasher.hash_secret(raw_secret)
        
        now = Timestamp.now()
        
        # Update client with new hash
        updated = OAuthClient(
            client_id=client.client_id,
            tenant_id=client.tenant_id,
            name=client.name,
            description=client.description,
            client_type=client.client_type,
            client_secret_hash=hashed.to_storage_string(),
            redirect_uris=client.redirect_uris,
            scopes=client.scopes,
            is_active=client.is_active,
            created_at=client.created_at,
            updated_at=now,
        )
        
        self._repository.save(context, updated)
        
        # Audit - NO SECRET
        self._emit_audit(
            context=context,
            event_type=AuditEventType.CLIENT_SECRET_ROTATED,
            action="rotate_secret",
            outcome="success",
            client_id=str(client_id),
            details={},
        )
        
        return OAuthClientRotateResponseDTO(
            client_id=str(client_id),
            new_client_secret=raw_secret,
            rotated_at=now.to_iso(),
            version=1,  # Would increment in real implementation
        )
    
    def change_status(
        self,
        context: RequestContext,
        client_id: str,
        new_status: CredentialStatusDTO,
    ) -> OAuthClientMetadataDTO:
        """Change the client status (activate, deactivate, revoke).
        
        Args:
            context: Request context with tenant scope.
            client_id: The client ID to update.
            new_status: The new status.
            
        Returns:
            Updated client metadata.
        """
        self._require_tenant(context)
        
        parsed_id = OAuthClientId(client_id)
        client = self._repository.find_by_id(context, parsed_id)
        
        if client is None:
            raise ValidationError(
                "OAuth client not found",
                field="client_id",
            )
        
        self._verify_ownership(context, client)
        
        # Validate state transition
        if new_status == CredentialStatusDTO.REVOKED:
            pass  # Always allowed
        elif new_status == CredentialStatusDTO.ACTIVE:
            # Cannot reactivate revoked clients
            current_status = self._get_status(client)
            if current_status == CredentialStatusDTO.REVOKED:
                raise ValidationError(
                    "Cannot reactivate revoked client",
                    field="status",
                )
        
        now = Timestamp.now()
        is_active = new_status == CredentialStatusDTO.ACTIVE
        
        updated = OAuthClient(
            client_id=client.client_id,
            tenant_id=client.tenant_id,
            name=client.name,
            description=client.description,
            client_type=client.client_type,
            client_secret_hash=client.client_secret_hash,
            redirect_uris=client.redirect_uris,
            scopes=client.scopes,
            is_active=is_active,
            created_at=client.created_at,
            updated_at=now,
        )
        
        saved = self._repository.save(context, updated)
        
        self._emit_audit(
            context=context,
            event_type=AuditEventType.CLIENT_CREATED,  # Using available type
            action="change_status",
            outcome="success",
            client_id=str(client_id),
            details={"new_status": new_status.value},
        )
        
        return self._to_metadata_dto(saved)
    
    def revoke(
        self,
        context: RequestContext,
        client_id: str,
    ) -> bool:
        """Revoke an OAuth client.
        
        Args:
            context: Request context with tenant scope.
            client_id: The client ID to revoke.
            
        Returns:
            True if revoked successfully.
        """
        self._require_tenant(context)
        
        parsed_id = OAuthClientId(client_id)
        client = self._repository.find_by_id(context, parsed_id)
        
        if client is None:
            return False
        
        self._verify_ownership(context, client)
        
        now = Timestamp.now()
        
        revoked = OAuthClient(
            client_id=client.client_id,
            tenant_id=client.tenant_id,
            name=client.name,
            description=client.description,
            client_type=client.client_type,
            client_secret_hash=client.client_secret_hash,
            redirect_uris=client.redirect_uris,
            scopes=client.scopes,
            is_active=False,
            created_at=client.created_at,
            updated_at=now,
        )
        
        self._repository.save(context, revoked)
        
        self._emit_audit(
            context=context,
            event_type=AuditEventType.CLIENT_CREATED,  # Using available type
            action="revoke",
            outcome="success",
            client_id=str(client_id),
            severity=AuditSeverity.WARNING,
            details={},
        )
        
        return True
    
    def _to_metadata_dto(self, client: OAuthClient) -> OAuthClientMetadataDTO:
        """Convert domain entity to metadata DTO (no secret)."""
        return OAuthClientMetadataDTO(
            client_id=str(client.client_id),
            tenant_id=str(client.tenant_id),
            name=client.name,
            description=client.description,
            client_type=client.client_type.value,
            redirect_uris=client.redirect_uris,
            scopes=client.scopes,
            status=self._get_status(client),
            created_at=client.created_at.to_iso(),
            updated_at=client.updated_at.to_iso(),
        )
    
    def _get_status(self, client: OAuthClient) -> CredentialStatusDTO:
        """Determine the status of a client."""
        if not client.is_active:
            return CredentialStatusDTO.REVOKED
        return CredentialStatusDTO.ACTIVE
    
    def _resolve_status(
        self, current_active: bool, new_status: CredentialStatusDTO | None
    ) -> bool:
        """Resolve new is_active value from status command."""
        if new_status is None:
            return current_active
        return new_status == CredentialStatusDTO.ACTIVE
    
    def _get_updated_fields(self, command: UpdateOAuthClientCommand) -> list[str]:
        """Get list of fields being updated."""
        fields = []
        if command.name is not None:
            fields.append("name")
        if command.description is not None:
            fields.append("description")
        if command.redirect_uris is not None:
            fields.append("redirect_uris")
        if command.scopes is not None:
            fields.append("scopes")
        if command.status is not None:
            fields.append("status")
        return fields
