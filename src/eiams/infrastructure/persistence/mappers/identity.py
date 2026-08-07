"""Mapping for the identity entity group."""

from eiams.domain.identity.contracts import (
    Membership,
    MembershipId,
    MembershipStatus,
    Organization,
    OrganizationId,
    User,
    UserId,
    UserStatus,
)
from eiams.infrastructure.persistence.models import identity as identity_models
from eiams.shared.kernel import TenantId

from .base import (
    EntityMapper,
    from_timestamp,
    identifier,
    optional_identifier,
    require_timestamp,
    slugify,
    to_timestamp,
)


class UserMapper(EntityMapper[User, identity_models.User]):
    """Maps user rows to and from the user entity."""

    entity_name = "user"

    def to_entity(self, row: identity_models.User) -> User:
        return User(
            user_id=UserId(row.id),
            tenant_id=TenantId(row.tenant_id),
            email=row.email,
            display_name=row.display_name,
            status=UserStatus(row.status.value),
            created_at=require_timestamp(row.created_at),
            updated_at=require_timestamp(row.updated_at),
            username=row.username,
            email_verified_at=to_timestamp(row.email_verified_at),
            last_login_at=to_timestamp(row.last_login_at),
        )

    def to_model(self, entity: User) -> identity_models.User:
        row = identity_models.User(
            id=identifier(entity.user_id),
            tenant_id=identifier(entity.tenant_id),
            email=entity.email,
            username=entity.username,
            display_name=entity.display_name,
            status=identity_models.UserStatus(entity.status.value),
            email_verified_at=from_timestamp(entity.email_verified_at),
            last_login_at=from_timestamp(entity.last_login_at),
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
            row.updated_at = from_timestamp(entity.updated_at or entity.created_at)
        return row

    def apply(self, entity: User, row: identity_models.User) -> None:
        row.email = entity.email
        row.username = entity.username
        row.display_name = entity.display_name
        row.status = identity_models.UserStatus(entity.status.value)
        row.email_verified_at = from_timestamp(entity.email_verified_at)
        row.last_login_at = from_timestamp(entity.last_login_at)


class OrganizationMapper(
    EntityMapper[Organization, identity_models.Organization]
):
    """Maps organization rows to and from the organization entity."""

    entity_name = "organization"

    def to_entity(self, row: identity_models.Organization) -> Organization:
        return Organization(
            organization_id=OrganizationId(row.id),
            tenant_id=TenantId(row.tenant_id),
            name=row.name,
            description=row.description,
            parent_id=(
                OrganizationId(row.parent_id) if row.parent_id else None
            ),
            created_at=require_timestamp(row.created_at),
            updated_at=require_timestamp(row.updated_at),
            slug=row.slug,
        )

    def to_model(self, entity: Organization) -> identity_models.Organization:
        row = identity_models.Organization(
            id=identifier(entity.organization_id),
            tenant_id=identifier(entity.tenant_id),
            name=entity.name,
            slug=entity.slug
            or slugify(entity.name, fallback=str(entity.organization_id)),
            description=entity.description,
            parent_id=optional_identifier(entity.parent_id),
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
            row.updated_at = from_timestamp(entity.updated_at or entity.created_at)
        return row

    def apply(
        self, entity: Organization, row: identity_models.Organization
    ) -> None:
        row.name = entity.name
        row.description = entity.description
        row.parent_id = optional_identifier(entity.parent_id)
        if entity.slug:
            row.slug = entity.slug


class MembershipMapper(EntityMapper[Membership, identity_models.Membership]):
    """Maps membership rows to and from the membership entity."""

    entity_name = "membership"

    def to_entity(self, row: identity_models.Membership) -> Membership:
        return Membership(
            membership_id=MembershipId(row.id),
            tenant_id=TenantId(row.tenant_id),
            user_id=UserId(row.user_id),
            organization_id=OrganizationId(row.organization_id),
            role=row.role,
            status=MembershipStatus(row.status.value),
            created_at=require_timestamp(row.created_at),
            updated_at=require_timestamp(row.updated_at),
        )

    def to_model(self, entity: Membership) -> identity_models.Membership:
        row = identity_models.Membership(
            id=identifier(entity.membership_id),
            tenant_id=identifier(entity.tenant_id),
            user_id=identifier(entity.user_id),
            organization_id=identifier(entity.organization_id),
            role=entity.role,
            status=identity_models.MembershipStatus(entity.status.value),
        )
        if entity.created_at is not None:
            row.created_at = from_timestamp(entity.created_at)
            row.updated_at = from_timestamp(entity.updated_at or entity.created_at)
        return row

    def apply(self, entity: Membership, row: identity_models.Membership) -> None:
        row.role = entity.role
        row.status = identity_models.MembershipStatus(entity.status.value)
