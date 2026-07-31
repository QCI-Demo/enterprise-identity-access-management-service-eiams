"""Credential validation service for API keys and OAuth clients.

Validates credentials against stored hashes and enforces status,
expiry, and scope constraints. Expired, inactive, and revoked
credentials are rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, Any
from enum import Enum

from eiams.shared.context import RequestContext
from eiams.shared.kernel import TenantId, Timestamp
from eiams.domain.credentials.contracts import (
    ApiKey,
    ApiKeyId,
    ApiKeyStatus,
    OAuthClient,
    OAuthClientId,
    OAuthClientType,
)
from eiams.domain.audit.contracts import AuditEventType, AuditSeverity
from eiams.infrastructure.crypto import SecretHasher, HashedSecret


class ValidationOutcome(str, Enum):
    """Outcome of credential validation."""
    VALID = "valid"
    INVALID_CREDENTIAL = "invalid_credential"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INACTIVE = "inactive"
    NOT_FOUND = "not_found"
    INSUFFICIENT_SCOPE = "insufficient_scope"


@dataclass(frozen=True)
class CredentialValidationResult:
    """Result of credential validation.
    
    Contains only safe metadata - never the validated secret.
    """
    outcome: ValidationOutcome
    credential_id: str | None = None
    credential_type: str | None = None  # "api_key" or "oauth_client"
    tenant_id: str | None = None
    user_id: str | None = None
    scopes: tuple[str, ...] = ()
    
    @property
    def is_valid(self) -> bool:
        """Check if validation succeeded."""
        return self.outcome == ValidationOutcome.VALID
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize for audit/logging (safe - no secrets)."""
        return {
            "outcome": self.outcome.value,
            "credential_id": self.credential_id,
            "credential_type": self.credential_type,
            "tenant_id": self.tenant_id,
            "is_valid": self.is_valid,
        }


class ApiKeyRepositoryPort(Protocol):
    """Port for API key lookup during validation."""
    
    def find_by_prefix(
        self, context: RequestContext, prefix: str
    ) -> ApiKey | None:
        """Find API key by prefix."""
        ...
    
    def save(self, context: RequestContext, api_key: ApiKey) -> ApiKey:
        """Update API key (for last_used_at tracking)."""
        ...


class OAuthClientRepositoryPort(Protocol):
    """Port for OAuth client lookup during validation."""
    
    def find_by_id(
        self, context: RequestContext, client_id: OAuthClientId
    ) -> OAuthClient | None:
        """Find OAuth client by ID."""
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
        """Record an audit event."""
        ...


@dataclass(frozen=True)
class ValidationConfig:
    """Configuration for credential validation."""
    update_last_used: bool = True
    audit_successes: bool = True
    audit_failures: bool = True
    api_key_prefix_length: int = 8


class CredentialValidationService:
    """Service for validating API keys and OAuth client credentials.
    
    Enforces:
    - Credential hash verification
    - Status checks (active/inactive/revoked)
    - Expiry enforcement
    - Scope validation
    
    Never logs or returns the plaintext credential.
    """
    
    def __init__(
        self,
        api_key_repository: ApiKeyRepositoryPort | None = None,
        oauth_client_repository: OAuthClientRepositoryPort | None = None,
        audit_service: AuditServicePort | None = None,
        secret_hasher: SecretHasher | None = None,
        config: ValidationConfig | None = None,
    ) -> None:
        """Initialize the validation service.
        
        Args:
            api_key_repository: Repository for API key lookups.
            oauth_client_repository: Repository for OAuth client lookups.
            audit_service: Optional audit service for event recording.
            secret_hasher: Secret hasher for verification.
            config: Service configuration.
        """
        self._api_key_repo = api_key_repository
        self._oauth_client_repo = oauth_client_repository
        self._audit = audit_service
        self._hasher = secret_hasher or SecretHasher()
        self._config = config or ValidationConfig()
    
    def _emit_audit(
        self,
        context: RequestContext,
        event_type: AuditEventType,
        action: str,
        outcome: str,
        credential_type: str,
        credential_id: str | None = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Emit audit event with safe metadata only."""
        if self._audit is None:
            return
        
        should_audit = (
            (outcome == "success" and self._config.audit_successes) or
            (outcome != "success" and self._config.audit_failures)
        )
        
        if not should_audit:
            return
        
        # Ensure no secrets in details
        safe_details = details or {}
        safe_details = {
            k: v for k, v in safe_details.items()
            if k not in ("key", "api_key", "secret", "client_secret", "credential", "hash")
        }
        safe_details["credential_type"] = credential_type
        
        self._audit.record_event(
            context=context,
            event_type=event_type,
            action=action,
            outcome=outcome,
            severity=severity,
            resource_type=credential_type,
            resource_id=credential_id,
            details=safe_details,
        )
    
    def validate_api_key(
        self,
        context: RequestContext,
        raw_api_key: str,
        required_scopes: list[str] | None = None,
    ) -> CredentialValidationResult:
        """Validate an API key.
        
        Args:
            context: Request context.
            raw_api_key: The raw API key to validate.
            required_scopes: Optional scopes that must be present.
            
        Returns:
            Validation result with safe metadata.
        """
        if self._api_key_repo is None:
            return CredentialValidationResult(
                outcome=ValidationOutcome.INVALID_CREDENTIAL,
            )
        
        if not raw_api_key:
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_api_key",
                outcome="failure",
                credential_type="api_key",
                severity=AuditSeverity.WARNING,
                details={"reason": "empty_key"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.INVALID_CREDENTIAL,
            )
        
        # Extract prefix for lookup
        prefix = raw_api_key[:self._config.api_key_prefix_length]
        
        # Find API key by prefix
        api_key = self._api_key_repo.find_by_prefix(context, prefix)
        
        if api_key is None:
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_api_key",
                outcome="failure",
                credential_type="api_key",
                severity=AuditSeverity.WARNING,
                details={"reason": "not_found"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.NOT_FOUND,
            )
        
        # Check status
        if api_key.status == ApiKeyStatus.REVOKED:
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_api_key",
                outcome="failure",
                credential_type="api_key",
                credential_id=str(api_key.api_key_id),
                severity=AuditSeverity.WARNING,
                details={"reason": "revoked"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.REVOKED,
                credential_id=str(api_key.api_key_id),
                credential_type="api_key",
                tenant_id=str(api_key.tenant_id),
            )
        
        if api_key.status != ApiKeyStatus.ACTIVE:
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_api_key",
                outcome="failure",
                credential_type="api_key",
                credential_id=str(api_key.api_key_id),
                severity=AuditSeverity.WARNING,
                details={"reason": "inactive"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.INACTIVE,
                credential_id=str(api_key.api_key_id),
                credential_type="api_key",
                tenant_id=str(api_key.tenant_id),
            )
        
        # Check expiry
        if api_key.expires_at and Timestamp.now() > api_key.expires_at:
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_api_key",
                outcome="failure",
                credential_type="api_key",
                credential_id=str(api_key.api_key_id),
                severity=AuditSeverity.WARNING,
                details={"reason": "expired"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.EXPIRED,
                credential_id=str(api_key.api_key_id),
                credential_type="api_key",
                tenant_id=str(api_key.tenant_id),
            )
        
        # Verify hash
        if not self._hasher.verify_from_storage(raw_api_key, api_key.key_hash):
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_api_key",
                outcome="failure",
                credential_type="api_key",
                credential_id=str(api_key.api_key_id),
                severity=AuditSeverity.WARNING,
                details={"reason": "invalid_credential"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.INVALID_CREDENTIAL,
                credential_id=str(api_key.api_key_id),
                credential_type="api_key",
                tenant_id=str(api_key.tenant_id),
            )
        
        # Check required scopes
        if required_scopes:
            key_scopes = set(api_key.scopes)
            missing = [s for s in required_scopes if s not in key_scopes]
            if missing:
                self._emit_audit(
                    context=context,
                    event_type=AuditEventType.PERMISSION_DENIED,
                    action="validate_api_key",
                    outcome="failure",
                    credential_type="api_key",
                    credential_id=str(api_key.api_key_id),
                    severity=AuditSeverity.WARNING,
                    details={"reason": "insufficient_scope", "missing_scopes": missing},
                )
                return CredentialValidationResult(
                    outcome=ValidationOutcome.INSUFFICIENT_SCOPE,
                    credential_id=str(api_key.api_key_id),
                    credential_type="api_key",
                    tenant_id=str(api_key.tenant_id),
                    scopes=api_key.scopes,
                )
        
        # Update last_used_at if configured
        if self._config.update_last_used:
            updated = ApiKey(
                api_key_id=api_key.api_key_id,
                tenant_id=api_key.tenant_id,
                user_id=api_key.user_id,
                name=api_key.name,
                key_prefix=api_key.key_prefix,
                key_hash=api_key.key_hash,
                scopes=api_key.scopes,
                status=api_key.status,
                created_at=api_key.created_at,
                expires_at=api_key.expires_at,
                last_used_at=Timestamp.now(),
            )
            self._api_key_repo.save(context, updated)
        
        # Success
        self._emit_audit(
            context=context,
            event_type=AuditEventType.TOKEN_ISSUED,  # Using available type
            action="validate_api_key",
            outcome="success",
            credential_type="api_key",
            credential_id=str(api_key.api_key_id),
            details={},
        )
        
        return CredentialValidationResult(
            outcome=ValidationOutcome.VALID,
            credential_id=str(api_key.api_key_id),
            credential_type="api_key",
            tenant_id=str(api_key.tenant_id),
            user_id=str(api_key.user_id) if api_key.user_id else None,
            scopes=api_key.scopes,
        )
    
    def validate_oauth_client(
        self,
        context: RequestContext,
        client_id: str,
        client_secret: str,
        required_scopes: list[str] | None = None,
    ) -> CredentialValidationResult:
        """Validate OAuth client credentials.
        
        Args:
            context: Request context.
            client_id: The client ID.
            client_secret: The client secret.
            required_scopes: Optional scopes that must be present.
            
        Returns:
            Validation result with safe metadata.
        """
        if self._oauth_client_repo is None:
            return CredentialValidationResult(
                outcome=ValidationOutcome.INVALID_CREDENTIAL,
            )
        
        if not client_id or not client_secret:
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_oauth_client",
                outcome="failure",
                credential_type="oauth_client",
                severity=AuditSeverity.WARNING,
                details={"reason": "missing_credentials"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.INVALID_CREDENTIAL,
            )
        
        # Parse client ID
        try:
            parsed_id = OAuthClientId(client_id)
        except Exception:
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_oauth_client",
                outcome="failure",
                credential_type="oauth_client",
                severity=AuditSeverity.WARNING,
                details={"reason": "invalid_client_id"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.INVALID_CREDENTIAL,
            )
        
        # Find client
        client = self._oauth_client_repo.find_by_id(context, parsed_id)
        
        if client is None:
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_oauth_client",
                outcome="failure",
                credential_type="oauth_client",
                credential_id=client_id,
                severity=AuditSeverity.WARNING,
                details={"reason": "not_found"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.NOT_FOUND,
            )
        
        # Check status
        if not client.is_active:
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_oauth_client",
                outcome="failure",
                credential_type="oauth_client",
                credential_id=client_id,
                severity=AuditSeverity.WARNING,
                details={"reason": "inactive"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.REVOKED,
                credential_id=str(client.client_id),
                credential_type="oauth_client",
                tenant_id=str(client.tenant_id),
            )
        
        # Public clients don't have secrets
        if client.client_type == OAuthClientType.PUBLIC:
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_oauth_client",
                outcome="failure",
                credential_type="oauth_client",
                credential_id=client_id,
                severity=AuditSeverity.WARNING,
                details={"reason": "public_client_secret_provided"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.INVALID_CREDENTIAL,
                credential_id=str(client.client_id),
                credential_type="oauth_client",
                tenant_id=str(client.tenant_id),
            )
        
        # Verify secret hash
        if client.client_secret_hash is None:
            return CredentialValidationResult(
                outcome=ValidationOutcome.INVALID_CREDENTIAL,
                credential_id=str(client.client_id),
                credential_type="oauth_client",
                tenant_id=str(client.tenant_id),
            )
        
        if not self._hasher.verify_from_storage(client_secret, client.client_secret_hash):
            self._emit_audit(
                context=context,
                event_type=AuditEventType.PERMISSION_DENIED,
                action="validate_oauth_client",
                outcome="failure",
                credential_type="oauth_client",
                credential_id=client_id,
                severity=AuditSeverity.WARNING,
                details={"reason": "invalid_secret"},
            )
            return CredentialValidationResult(
                outcome=ValidationOutcome.INVALID_CREDENTIAL,
                credential_id=str(client.client_id),
                credential_type="oauth_client",
                tenant_id=str(client.tenant_id),
            )
        
        # Check required scopes
        if required_scopes:
            client_scopes = set(client.scopes)
            missing = [s for s in required_scopes if s not in client_scopes]
            if missing:
                self._emit_audit(
                    context=context,
                    event_type=AuditEventType.PERMISSION_DENIED,
                    action="validate_oauth_client",
                    outcome="failure",
                    credential_type="oauth_client",
                    credential_id=client_id,
                    severity=AuditSeverity.WARNING,
                    details={"reason": "insufficient_scope", "missing_scopes": missing},
                )
                return CredentialValidationResult(
                    outcome=ValidationOutcome.INSUFFICIENT_SCOPE,
                    credential_id=str(client.client_id),
                    credential_type="oauth_client",
                    tenant_id=str(client.tenant_id),
                    scopes=client.scopes,
                )
        
        # Success
        self._emit_audit(
            context=context,
            event_type=AuditEventType.TOKEN_ISSUED,  # Using available type
            action="validate_oauth_client",
            outcome="success",
            credential_type="oauth_client",
            credential_id=client_id,
            details={},
        )
        
        return CredentialValidationResult(
            outcome=ValidationOutcome.VALID,
            credential_id=str(client.client_id),
            credential_type="oauth_client",
            tenant_id=str(client.tenant_id),
            scopes=client.scopes,
        )
