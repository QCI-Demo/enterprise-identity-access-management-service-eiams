"""Credentials domain module.

Manages credential lifecycle and security, including:
- Password storage and validation
- API key generation and management
- OAuth client credentials
- Credential rotation policies
"""

from .contracts import (
    ApiKey,
    ApiKeyId,
    ApiKeyStatus,
    OAuthClient,
    OAuthClientId,
    OAuthClientType,
    PasswordCredentialId,
    PasswordHashAlgorithm,
    PasswordVerificationOutcome,
    PasswordVerificationResult,
    StoredPasswordCredential,
    ApiKeyRepository,
    OAuthClientRepository,
    PasswordCredentialRepository,
    CredentialService,
)

__all__ = [
    "ApiKey",
    "ApiKeyId",
    "ApiKeyStatus",
    "OAuthClient",
    "OAuthClientId",
    "OAuthClientType",
    "PasswordCredentialId",
    "PasswordHashAlgorithm",
    "PasswordVerificationOutcome",
    "PasswordVerificationResult",
    "StoredPasswordCredential",
    "ApiKeyRepository",
    "OAuthClientRepository",
    "PasswordCredentialRepository",
    "CredentialService",
]
