"""Authentication domain module.

Manages authentication flows and session lifecycle, including:
- Login and logout operations
- Session management and validation
- Token issuance and validation
- Refresh token rotation
"""

from .contracts import (
    AuthenticationFailureCategory,
    AuthenticationMethod,
    AuthenticationOutcome,
    Session,
    SessionId,
    SessionStatus,
    TokenClaims,
    SessionRepository,
    AuthenticationService,
)

__all__ = [
    "AuthenticationFailureCategory",
    "AuthenticationMethod",
    "AuthenticationOutcome",
    "Session",
    "SessionId",
    "SessionStatus",
    "TokenClaims",
    "SessionRepository",
    "AuthenticationService",
]
