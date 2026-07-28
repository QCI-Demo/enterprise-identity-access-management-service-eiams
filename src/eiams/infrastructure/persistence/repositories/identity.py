"""Tenant-scoped repositories for the identity entity group."""

from eiams.domain.identity.contracts import (
    Membership,
    MembershipId,
    MembershipRepository,
    Organization,
    OrganizationId,
    OrganizationRepository,
    User,
    UserId,
    UserRepository,
    UserStatus,
)
from eiams.infrastructure.persistence.models import identity as identity_models
from eiams.shared.context import RequestContext

from ..mappers import MembershipMapper, OrganizationMapper, UserMapper
from ..mappers.base import identifier
from .base import TenantScopedSqlRepository


class SqlAlchemyUserRepository(
    TenantScopedSqlRepository[User, UserId, identity_models.User],
    UserRepository,
):
    """User identities within one tenant."""

    __model__ = identity_models.User
    __mapper__ = UserMapper()
    __entity_name__ = "user"

    def find_by_email(
        self, context: RequestContext, email: str
    ) -> User | None:
        statement = self._scoped_select(context).where(
            identity_models.User.email == email
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)

    def find_by_status(
        self,
        context: RequestContext,
        status: UserStatus,
        offset: int = 0,
        limit: int = 100,
    ) -> list[User]:
        statement = self._scoped_select(context).where(
            identity_models.User.status
            == identity_models.UserStatus(status.value)
        )
        return self._entities(
            self._rows(self._paginated(self._ordered(statement), offset, limit))
        )


class SqlAlchemyOrganizationRepository(
    TenantScopedSqlRepository[
        Organization, OrganizationId, identity_models.Organization
    ],
    OrganizationRepository,
):
    """Organizations within one tenant."""

    __model__ = identity_models.Organization
    __mapper__ = OrganizationMapper()
    __entity_name__ = "organization"

    def find_by_name(
        self, context: RequestContext, name: str
    ) -> Organization | None:
        statement = self._scoped_select(context).where(
            identity_models.Organization.name == name
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)

    def find_children(
        self, context: RequestContext, parent_id: OrganizationId
    ) -> list[Organization]:
        statement = self._scoped_select(context).where(
            identity_models.Organization.parent_id == identifier(parent_id)
        )
        return self._entities(self._rows(self._ordered(statement)))


class SqlAlchemyMembershipRepository(
    TenantScopedSqlRepository[
        Membership, MembershipId, identity_models.Membership
    ],
    MembershipRepository,
):
    """Memberships linking users to organizations within one tenant."""

    __model__ = identity_models.Membership
    __mapper__ = MembershipMapper()
    __entity_name__ = "membership"

    def find_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> list[Membership]:
        statement = self._scoped_select(context).where(
            identity_models.Membership.user_id == identifier(user_id)
        )
        return self._entities(self._rows(self._ordered(statement)))

    def find_by_organization(
        self, context: RequestContext, organization_id: OrganizationId
    ) -> list[Membership]:
        statement = self._scoped_select(context).where(
            identity_models.Membership.organization_id
            == identifier(organization_id)
        )
        return self._entities(self._rows(self._ordered(statement)))

    def find_by_user_and_organization(
        self,
        context: RequestContext,
        user_id: UserId,
        organization_id: OrganizationId,
    ) -> Membership | None:
        statement = (
            self._scoped_select(context)
            .where(identity_models.Membership.user_id == identifier(user_id))
            .where(
                identity_models.Membership.organization_id
                == identifier(organization_id)
            )
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)
