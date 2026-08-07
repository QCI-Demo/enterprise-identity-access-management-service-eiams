"""Tenant isolation tests across every IAM entity group.

Two tenants are seeded with an equivalent set of entities. Each test then
tries to reach one tenant's data from the other's context, directly by
identifier as well as through filtered reads and writes, and asserts the
attempt neither succeeds nor discloses that the data exists.
"""

import dataclasses

import pytest

from eiams.domain.authentication.contracts import SessionStatus
from eiams.domain.credentials.contracts import CredentialType
from eiams.domain.identity.contracts import UserStatus
from eiams.shared.errors import (
    EntityNotFoundError,
    TenantMismatchError,
    TenantRequiredError,
)

from .factories import (
    build_api_key,
    build_audit_event,
    build_credential,
    build_membership,
    build_oauth_client,
    build_organization,
    build_permission,
    build_refresh_token,
    build_role,
    build_role_assignment,
    build_session,
    build_user,
    new_id,
)


#: Accessor on the unit of work paired with the identifier attribute of the
#: entity it stores, covering every tenant-scoped entity group.
ENTITY_GROUPS = [
    ("users", "user_id"),
    ("organizations", "organization_id"),
    ("memberships", "membership_id"),
    ("permissions", "permission_id"),
    ("roles", "role_id"),
    ("role_assignments", "assignment_id"),
    ("credentials", "credential_id"),
    ("sessions", "session_id"),
    ("refresh_tokens", "refresh_token_id"),
    ("api_keys", "api_key_id"),
    ("oauth_clients", "client_id"),
    ("audit_events", "audit_event_id"),
]

#: Entity groups that expose a delete primitive; the audit store does not.
DELETABLE_ENTITY_GROUPS = [
    group for group in ENTITY_GROUPS if group[0] != "audit_events"
]


@dataclasses.dataclass(frozen=True)
class SeededTenant:
    """One entity of each group, all owned by a single tenant."""

    tenant_id: str
    user: object
    organization: object
    membership: object
    permission: object
    role: object
    assignment: object
    credential: object
    session: object
    refresh_token: object
    api_key: object
    oauth_client: object
    audit_event: object

    def entity(self, accessor: str):
        """Return the entity stored by the named unit-of-work accessor."""
        return {
            "users": self.user,
            "organizations": self.organization,
            "memberships": self.membership,
            "permissions": self.permission,
            "roles": self.role,
            "role_assignments": self.assignment,
            "credentials": self.credential,
            "sessions": self.session,
            "refresh_tokens": self.refresh_token,
            "api_keys": self.api_key,
            "oauth_clients": self.oauth_client,
            "audit_events": self.audit_event,
        }[accessor]


def seed_tenant(runner, context, tenant_id: str, label: str) -> SeededTenant:
    """Create one entity of every group inside a single tenant."""
    user = build_user(
        tenant_id, email="shared@example.com", display_name=f"{label} User"
    )
    organization = build_organization(tenant_id, name=f"{label} Org")
    membership = build_membership(
        tenant_id, str(user.user_id), str(organization.organization_id)
    )
    permission = build_permission(tenant_id, name=f"{label} permission")
    role = build_role(tenant_id, name=f"{label} role")
    assignment = build_role_assignment(
        tenant_id, str(user.user_id), str(role.role_id)
    )
    credential = build_credential(tenant_id, str(user.user_id))
    session = build_session(tenant_id, str(user.user_id))
    refresh_token = build_refresh_token(
        tenant_id, str(session.session_id), str(user.user_id)
    )
    api_key = build_api_key(tenant_id, name=f"{label} key")
    oauth_client = build_oauth_client(tenant_id, name=f"{label} client")
    audit_event = build_audit_event(
        tenant_id,
        actor_id=str(context.actor_id),
        correlation_id=f"{label}-trace",
        resource_type="user",
        resource_id=str(user.user_id),
    )

    with runner.unit_of_work(context) as uow:
        uow.users.add(context, user)
        uow.organizations.add(context, organization)
        uow.memberships.add(context, membership)
        uow.permissions.add(context, permission)
        uow.roles.add(context, role)
        uow.role_assignments.add(context, assignment)
        uow.credentials.add(context, credential)
        uow.sessions.add(context, session)
        uow.refresh_tokens.add(context, refresh_token)
        uow.api_keys.add(context, api_key)
        uow.oauth_clients.add(context, oauth_client)
        uow.audit_events.append(context, audit_event)

    return SeededTenant(
        tenant_id=tenant_id,
        user=user,
        organization=organization,
        membership=membership,
        permission=permission,
        role=role,
        assignment=assignment,
        credential=credential,
        session=session,
        refresh_token=refresh_token,
        api_key=api_key,
        oauth_client=oauth_client,
        audit_event=audit_event,
    )


@pytest.fixture
def alpha(runner, alpha_context, tenants) -> SeededTenant:
    return seed_tenant(runner, alpha_context, tenants.alpha, "Alpha")


@pytest.fixture
def beta(runner, beta_context, tenants) -> SeededTenant:
    return seed_tenant(runner, beta_context, tenants.beta, "Beta")


class TestDirectIdentifierAccess:
    """Knowing an identifier is not enough to read another tenant's data."""

    @pytest.mark.parametrize("accessor,id_attribute", ENTITY_GROUPS)
    def test_foreign_entity_reads_as_absent(
        self, runner, beta_context, alpha, beta, accessor, id_attribute
    ):
        foreign_id = getattr(alpha.entity(accessor), id_attribute)

        with runner.unit_of_work(beta_context) as uow:
            found = getattr(uow, accessor).find_by_id(beta_context, foreign_id)

        assert found is None

    @pytest.mark.parametrize("accessor,id_attribute", ENTITY_GROUPS)
    def test_foreign_entity_does_not_exist_for_the_caller(
        self, runner, beta_context, alpha, beta, accessor, id_attribute
    ):
        foreign_id = getattr(alpha.entity(accessor), id_attribute)

        with runner.unit_of_work(beta_context) as uow:
            assert getattr(uow, accessor).exists(beta_context, foreign_id) is False

    @pytest.mark.parametrize("accessor,id_attribute", ENTITY_GROUPS)
    def test_own_entity_is_reachable(
        self, runner, beta_context, alpha, beta, accessor, id_attribute
    ):
        own_id = getattr(beta.entity(accessor), id_attribute)

        with runner.unit_of_work(beta_context) as uow:
            found = getattr(uow, accessor).find_by_id(beta_context, own_id)

        assert found is not None


class TestScopedReads:
    """Listing and counting never reach beyond the caller's tenant."""

    @pytest.mark.parametrize("accessor,_", ENTITY_GROUPS)
    def test_listing_returns_only_the_callers_rows(
        self, runner, alpha_context, beta_context, alpha, beta, accessor, _
    ):
        with runner.unit_of_work(alpha_context) as uow:
            alpha_rows = getattr(uow, accessor).find_all(alpha_context)
        with runner.unit_of_work(beta_context) as uow:
            beta_rows = getattr(uow, accessor).find_all(beta_context)

        assert len(alpha_rows) == 1
        assert len(beta_rows) == 1
        assert {row.tenant_id.value for row in alpha_rows} == {alpha.tenant_id}
        assert {row.tenant_id.value for row in beta_rows} == {beta.tenant_id}

    @pytest.mark.parametrize("accessor,_", ENTITY_GROUPS)
    def test_counting_covers_only_the_callers_rows(
        self, runner, alpha_context, alpha, beta, accessor, _
    ):
        with runner.unit_of_work(alpha_context) as uow:
            assert getattr(uow, accessor).count(alpha_context) == 1

    def test_lookup_by_email_stays_inside_the_tenant(
        self, runner, alpha_context, beta_context, alpha, beta
    ):
        with runner.unit_of_work(alpha_context) as uow:
            from_alpha = uow.users.find_by_email(alpha_context, "shared@example.com")
        with runner.unit_of_work(beta_context) as uow:
            from_beta = uow.users.find_by_email(beta_context, "shared@example.com")

        assert from_alpha.user_id == alpha.user.user_id
        assert from_beta.user_id == beta.user.user_id

    def test_lookup_by_api_key_prefix_stays_inside_the_tenant(
        self, runner, beta_context, alpha, beta
    ):
        with runner.unit_of_work(beta_context) as uow:
            found = uow.api_keys.find_by_prefix(
                beta_context, alpha.api_key.key_prefix
            )

        assert found is None

    def test_lookup_by_refresh_token_hash_stays_inside_the_tenant(
        self, runner, beta_context, alpha, beta
    ):
        with runner.unit_of_work(beta_context) as uow:
            found = uow.refresh_tokens.find_by_token_hash(
                beta_context, alpha.refresh_token.token_hash
            )

        assert found is None

    def test_lookup_by_organization_name_stays_inside_the_tenant(
        self, runner, beta_context, alpha, beta
    ):
        with runner.unit_of_work(beta_context) as uow:
            found = uow.organizations.find_by_name(beta_context, "Alpha Org")

        assert found is None

    def test_lookup_by_oauth_client_name_stays_inside_the_tenant(
        self, runner, beta_context, alpha, beta
    ):
        with runner.unit_of_work(beta_context) as uow:
            found = uow.oauth_clients.find_by_name(beta_context, "Alpha client")

        assert found is None

    def test_permission_key_lookup_stays_inside_the_tenant(
        self, runner, beta_context, alpha, beta
    ):
        with runner.unit_of_work(beta_context) as uow:
            found = uow.permissions.find_by_key(beta_context, "user", "read")

        assert found.permission_id == beta.permission.permission_id

    def test_related_reads_do_not_follow_foreign_identifiers(
        self, runner, beta_context, alpha, beta
    ):
        with runner.unit_of_work(beta_context) as uow:
            memberships = uow.memberships.find_by_user(
                beta_context, alpha.user.user_id
            )
            sessions = uow.sessions.find_by_user(beta_context, alpha.user.user_id)
            assignments = uow.role_assignments.find_by_user(
                beta_context, alpha.user.user_id
            )
            credentials = uow.credentials.find_by_user(
                beta_context, alpha.user.user_id
            )
            tokens = uow.refresh_tokens.find_by_session(
                beta_context, alpha.session.session_id
            )

        assert memberships == []
        assert sessions == []
        assert assignments == []
        assert credentials == []
        assert tokens == []

    def test_audit_trail_is_not_readable_across_tenants(
        self, runner, alpha_context, beta_context, alpha, beta
    ):
        with runner.unit_of_work(beta_context) as uow:
            by_correlation = uow.audit_events.find_by_correlation_id(
                beta_context, "Alpha-trace"
            )
            by_actor = uow.audit_events.find_by_actor(
                beta_context, str(alpha_context.actor_id)
            )
            by_resource = uow.audit_events.find_by_resource(
                beta_context, "user", str(alpha.user.user_id)
            )

        assert by_correlation == []
        assert by_actor == []
        assert by_resource == []


class TestScopedWrites:
    """A write can neither reach nor create data in another tenant."""

    def test_updating_a_foreign_entity_is_refused(
        self, runner, beta_context, alpha, beta
    ):
        with pytest.raises(EntityNotFoundError):
            with runner.unit_of_work(beta_context) as uow:
                uow.users.update(
                    beta_context,
                    dataclasses.replace(
                        alpha.user,
                        tenant_id=beta.user.tenant_id,
                        display_name="Hijacked",
                    ),
                )

    def test_a_refused_update_leaves_the_foreign_entity_untouched(
        self, runner, alpha_context, beta_context, alpha, beta
    ):
        with pytest.raises(EntityNotFoundError):
            with runner.unit_of_work(beta_context) as uow:
                uow.users.update(
                    beta_context,
                    dataclasses.replace(
                        alpha.user,
                        tenant_id=beta.user.tenant_id,
                        display_name="Hijacked",
                    ),
                )

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.users.find_by_id(alpha_context, alpha.user.user_id)

        assert stored.display_name == "Alpha User"

    def test_saving_an_entity_that_claims_another_tenant_is_refused(
        self, runner, beta_context, alpha, beta
    ):
        with pytest.raises(TenantMismatchError):
            with runner.unit_of_work(beta_context) as uow:
                uow.users.save(beta_context, alpha.user)

    def test_creating_an_entity_for_another_tenant_is_refused(
        self, runner, beta_context, alpha, tenants, row_counts
    ):
        intruder = build_user(tenants.alpha, email="intruder@example.com")

        with pytest.raises(TenantMismatchError):
            with runner.unit_of_work(beta_context) as uow:
                uow.users.add(beta_context, intruder)

        assert row_counts("users", tenant_id=tenants.alpha) == 1

    def test_deleting_a_foreign_entity_reports_nothing_deleted(
        self, runner, beta_context, alpha, beta, tenants, row_counts
    ):
        with runner.unit_of_work(beta_context) as uow:
            deleted = uow.users.delete(beta_context, alpha.user.user_id)

        assert deleted is False
        assert row_counts("users", tenant_id=tenants.alpha) == 1

    @pytest.mark.parametrize("accessor,id_attribute", DELETABLE_ENTITY_GROUPS)
    def test_no_entity_group_can_be_deleted_across_tenants(
        self, runner, beta_context, alpha, beta, accessor, id_attribute
    ):
        foreign_id = getattr(alpha.entity(accessor), id_attribute)

        with runner.unit_of_work(beta_context) as uow:
            assert getattr(uow, accessor).delete(beta_context, foreign_id) is False

    def test_bulk_session_revocation_does_not_reach_another_tenant(
        self, runner, alpha_context, beta_context, alpha, beta
    ):
        with runner.unit_of_work(beta_context) as uow:
            revoked = uow.sessions.revoke_all_for_user(
                beta_context, alpha.user.user_id
            )

        with runner.unit_of_work(alpha_context) as uow:
            sessions = uow.sessions.find_by_user(alpha_context, alpha.user.user_id)

        assert revoked == 0
        assert [session.status for session in sessions] == [SessionStatus.ACTIVE]

    def test_expiry_sweep_does_not_reach_another_tenant(
        self, runner, alpha_context, beta_context, tenants, alpha, beta
    ):
        with runner.unit_of_work(alpha_context) as uow:
            uow.sessions.add(
                alpha_context,
                build_session(
                    tenants.alpha,
                    str(alpha.user.user_id),
                    expires_in_hours=-1,
                ),
            )

        with runner.unit_of_work(beta_context) as uow:
            cleaned = uow.sessions.cleanup_expired(beta_context)

        assert cleaned == 0

    def test_token_family_revocation_does_not_reach_another_tenant(
        self, runner, alpha_context, beta_context, alpha, beta
    ):
        family = alpha.refresh_token.token_family

        with runner.unit_of_work(beta_context) as uow:
            revoked = uow.refresh_tokens.revoke_family(beta_context, family)

        with runner.unit_of_work(alpha_context) as uow:
            tokens = uow.refresh_tokens.find_by_family(alpha_context, family)

        assert revoked == 0
        assert [token.is_revoked for token in tokens] == [False]

    def test_a_role_cannot_link_a_permission_of_another_tenant(
        self, runner, beta_context, alpha, beta, tenants
    ):
        role = build_role(
            tenants.beta,
            name="Borrowing role",
            permissions=(alpha.permission.permission_id,),
        )

        with pytest.raises(EntityNotFoundError):
            with runner.unit_of_work(beta_context) as uow:
                uow.roles.add(beta_context, role)

    def test_credential_lookup_by_type_stays_inside_the_tenant(
        self, runner, beta_context, alpha, beta
    ):
        with runner.unit_of_work(beta_context) as uow:
            found = uow.credentials.find_by_user_and_type(
                beta_context, alpha.user.user_id, CredentialType.PASSWORD
            )

        assert found is None


class TestPlatformSharedCatalogue:
    """System roles and permissions are readable by all, writable by none."""

    @pytest.fixture
    def system_records(self, runner, platform_context, session_factory, tenants):
        """Insert a system role and permission that belong to no tenant."""
        from eiams.infrastructure.persistence.models import (
            authorization as authorization_models,
        )

        role_id, permission_id = new_id(), new_id()
        session = session_factory()
        session.add(
            authorization_models.Permission(
                id=permission_id,
                tenant_id=None,
                name="Platform administration",
                resource_type="platform",
                action="administer",
                is_system=True,
            )
        )
        session.add(
            authorization_models.Role(
                id=role_id,
                tenant_id=None,
                name="Platform administrator",
                is_system=True,
            )
        )
        session.commit()
        session.close()
        return role_id, permission_id

    def test_both_tenants_can_read_system_roles(
        self, runner, alpha_context, beta_context, system_records
    ):
        role_id, _ = system_records

        with runner.unit_of_work(alpha_context) as uow:
            from_alpha = uow.roles.find_by_id(alpha_context, role_id)
        with runner.unit_of_work(beta_context) as uow:
            from_beta = uow.roles.find_by_id(beta_context, role_id)

        assert from_alpha is not None
        assert from_beta is not None
        assert from_alpha.tenant_id is None

    def test_system_roles_are_listed_separately(
        self, runner, alpha_context, alpha, system_records
    ):
        with runner.unit_of_work(alpha_context) as uow:
            system_roles = uow.roles.find_system_roles(alpha_context)

        assert [role.name for role in system_roles] == ["Platform administrator"]

    def test_a_tenant_cannot_modify_a_system_role(
        self, runner, alpha_context, system_records
    ):
        role_id, _ = system_records

        with runner.unit_of_work(alpha_context) as uow:
            existing = uow.roles.find_by_id(alpha_context, role_id)

        with pytest.raises(TenantMismatchError):
            with runner.unit_of_work(alpha_context) as uow:
                uow.roles.update(
                    alpha_context, dataclasses.replace(existing, name="Hijacked")
                )

    def test_a_tenant_cannot_delete_a_system_role(
        self, runner, alpha_context, system_records, row_counts
    ):
        role_id, _ = system_records

        with runner.unit_of_work(alpha_context) as uow:
            deleted = uow.roles.delete(alpha_context, role_id)

        assert deleted is False
        assert row_counts("roles") == 1

    def test_a_tenant_role_may_use_a_system_permission(
        self, runner, alpha_context, tenants, system_records
    ):
        _, permission_id = system_records
        from eiams.domain.authorization.contracts import PermissionId

        role = build_role(
            tenants.alpha,
            name="Uses system permission",
            permissions=(PermissionId(permission_id),),
        )

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.roles.add(alpha_context, role)

        assert stored.permissions == (PermissionId(permission_id),)


class TestMissingTenantContext:
    """Without tenant context there is no scope, so there is no access."""

    @pytest.mark.parametrize("accessor,id_attribute", ENTITY_GROUPS)
    def test_reads_are_refused(
        self, runner, untenanted_context, alpha, accessor, id_attribute
    ):
        entity_id = getattr(alpha.entity(accessor), id_attribute)

        with pytest.raises(TenantRequiredError):
            with runner.unit_of_work(untenanted_context) as uow:
                getattr(uow, accessor).find_by_id(untenanted_context, entity_id)

    @pytest.mark.parametrize("accessor,_", ENTITY_GROUPS)
    def test_listing_is_refused(
        self, runner, untenanted_context, alpha, accessor, _
    ):
        with pytest.raises(TenantRequiredError):
            with runner.unit_of_work(untenanted_context) as uow:
                getattr(uow, accessor).find_all(untenanted_context)

    def test_writes_are_refused_and_change_nothing(
        self, runner, untenanted_context, tenants, row_counts
    ):
        before = row_counts("users")

        with pytest.raises(TenantRequiredError):
            with runner.unit_of_work(untenanted_context) as uow:
                uow.users.add(untenanted_context, build_user(tenants.alpha))

        assert row_counts("users") == before

    def test_audit_append_is_refused(
        self, runner, untenanted_context, tenants, row_counts
    ):
        with pytest.raises(TenantRequiredError):
            with runner.unit_of_work(untenanted_context) as uow:
                uow.audit_events.append(
                    untenanted_context, build_audit_event(tenants.alpha)
                )

        assert row_counts("audit_events") == 0

    def test_anonymous_callers_cannot_reach_the_tenant_registry(
        self, runner, tenants
    ):
        from eiams.shared.context import RequestContextFactory
        from eiams.shared.errors import ActorRequiredError

        anonymous = RequestContextFactory.create_anonymous()

        with pytest.raises(ActorRequiredError):
            with runner.unit_of_work(anonymous) as uow:
                uow.tenants.find_all(anonymous)

    def test_status_filters_do_not_bypass_the_tenant_guard(
        self, runner, untenanted_context, alpha
    ):
        with pytest.raises(TenantRequiredError):
            with runner.unit_of_work(untenanted_context) as uow:
                uow.users.find_by_status(untenanted_context, UserStatus.ACTIVE)
