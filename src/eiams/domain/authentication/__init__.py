"""Authentication domain module.

Manages authentication flows and session lifecycle, including:
- Login and logout operations
- Session management and validation
- Token issuance and validation
- Refresh token rotation
"""

from .contracts import (
    Session,
    SessionId,
    SessionStatus,
    TokenClaims,
    SessionRepository,
    AuthenticationService,
)

__all__ = [
    "Session",
    "SessionId",
    "SessionStatus",
    "TokenClaims",
    "SessionRepository",
    "AuthenticationService",
]
