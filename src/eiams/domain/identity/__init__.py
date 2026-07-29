"""Identity domain module.

Manages user and organization identity lifecycle, including:
- User identity creation and management
- Organization structure and hierarchy
- Membership relationships
- Identity attributes and profiles
"""

from .contracts import (
    User,
    UserId,
    UserStatus,
    Organization,
    OrganizationId,
    Membership,
    MembershipId,
    MembershipStatus,
    UserRepository,
    OrganizationRepository,
    MembershipRepository,
    IdentityService,
)

__all__ = [
    "User",
    "UserId",
    "UserStatus",
    "Organization",
    "OrganizationId",
    "Membership",
    "MembershipId",
    "MembershipStatus",
    "UserRepository",
    "OrganizationRepository",
    "MembershipRepository",
    "IdentityService",
]
