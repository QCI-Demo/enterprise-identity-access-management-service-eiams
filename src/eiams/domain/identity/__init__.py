"""Identity domain module.

Manages user and organization identity lifecycle, including:
- User identity creation and management
- Organization structure and hierarchy
- Membership relationships
- Identity attributes and profiles
"""

from .contracts import (
    User,
    Organization,
    Membership,
    UserRepository,
    OrganizationRepository,
    MembershipRepository,
    IdentityService,
)

__all__ = [
    "User",
    "Organization",
    "Membership",
    "UserRepository",
    "OrganizationRepository",
    "MembershipRepository",
    "IdentityService",
]
