"""Update tests for every entity group.

Updating goes through a different mapping path than creating: only the
attributes the domain contract owns are copied onto the stored row, so
columns the contract does not model keep whatever the schema set on them.
These tests check both halves of that behaviour.
"""

import dataclasses

import pytest

from eiams.domain.administration.contracts import TenantStatus
from eiams.domain.authentication.contracts import SessionStatus
from eiams.domain.credentials.contracts import ApiKeyStatus
from eiams.domain.identity.contracts import MembershipStatus, UserStatus
from eiams.shared.errors import EntityNotFoundError
from eiams.shared.kernel import Timestamp

from .factories import (
    build_api_key,
    build_audit_event,
    build_credential,
    build_membership,
    build_oauth_client,
    build_organization,
    build_permission,
    build_refresh_token,
    build_role_assignment,
    build_role,
    build_session,
    build_tenant,
    build_user,
    new_id,
)


@pytest.fixture
def user(runner, alpha_context, tenants):
    """A committed user the other fixtures can hang off."""
    entity = build_user(tenants.alpha, email="subject@alpha.example")
    with runner.unit_of_work(alpha_context) as uow:
        uow.users.add(alpha_context, entity)
    return entity


class TestTenantRegistryLifecycle:
    """Platform-scoped reads and writes over the tenant registry."""

    def test_updates_a_tenant(self, runner, platform_context, tenants):
        with runner.unit_of_work(platform_context) as uow:
            existing = uow.tenants.find_by_id(platform_context, tenants.alpha)

        with runner.unit_of_work(platform_context) as uow:
            uow.tenants.update(
                platform_context,
                dataclasses.replace(
                    existing,
                    display_name="Alpha Corporation",
                    status=TenantStatus.SUSPENDED,
                ),
            )

        with runner.unit_of_work(platform_context) as uow:
            stored = uow.tenants.find_by_id(platform_context, tenants.alpha)

        assert stored.display_name == "Alpha Corporation"
        assert stored.status is TenantStatus.SUSPENDED

    def test_updating_an_absent_tenant_is_refused(self, runner, platform_context):
        with pytest.raises(EntityNotFoundError):
            with runner.unit_of_work(platform_context) as uow:
                uow.tenants.update(
                    platform_context, build_tenant(new_id(), "Nowhere")
                )

    def test_save_creates_then_updates(self, runner, platform_context, tenants):
        tenant = build_tenant(new_id(), "Theta")

        with runner.unit_of_work(platform_context) as uow:
            uow.tenants.save(platform_context, tenant)
        with runner.unit_of_work(platform_context) as uow:
            uow.tenants.save(
                platform_context,
                dataclasses.replace(tenant, display_name="Theta Holdings"),
            )

        with runner.unit_of_work(platform_context) as uow:
            stored = uow.tenants.find_by_id(platform_context, tenant.tenant_id)
            assert uow.tenants.count(platform_context) == 3

        assert stored.display_name == "Theta Holdings"

    def test_lists_and_counts_every_tenant(self, runner, platform_context, tenants):
        with runner.unit_of_work(platform_context) as uow:
            listed = uow.tenants.find_all(platform_context)
            counted = uow.tenants.count(platform_context)

        assert {tenant.name for tenant in listed} == {"Alpha Corp", "Beta Ltd"}
        assert counted == 2

    def test_reports_existence(self, runner, platform_context, tenants):
        with runner.unit_of_work(platform_context) as uow:
            assert uow.tenants.exists(platform_context, tenants.alpha) is True
            assert uow.tenants.exists(platform_context, new_id()) is False

    def test_deletes_a_tenant(self, runner, platform_context, row_counts):
        tenant = build_tenant(new_id(), "Temporary")
        with runner.unit_of_work(platform_context) as uow:
            uow.tenants.add(platform_context, tenant)

        with runner.unit_of_work(platform_context) as uow:
            deleted = uow.tenants.delete(platform_context, tenant.tenant_id)
            missing = uow.tenants.delete(platform_context, new_id())

        assert deleted is True
        assert missing is False
        assert row_counts("tenants") == 0


class TestIdentityUpdates:
    """Organizations and memberships."""

    def test_updates_an_organization(self, runner, alpha_context, tenants):
        organization = build_organization(tenants.alpha, name="Original")
        with runner.unit_of_work(alpha_context) as uow:
            uow.organizations.add(alpha_context, organization)

        with runner.unit_of_work(alpha_context) as uow:
            uow.organizations.update(
                alpha_context,
                dataclasses.replace(
                    organization, name="Renamed", description="Now described"
                ),
            )

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.organizations.find_by_id(
                alpha_context, organization.organization_id
            )

        assert stored.name == "Renamed"
        assert stored.description == "Now described"
        assert stored.slug == "original"

    def test_updates_a_membership(self, runner, alpha_context, tenants, user):
        organization = build_organization(tenants.alpha)
        membership = build_membership(
            tenants.alpha, str(user.user_id), str(organization.organization_id)
        )
        with runner.unit_of_work(alpha_context) as uow:
            uow.organizations.add(alpha_context, organization)
            uow.memberships.add(alpha_context, membership)

        with runner.unit_of_work(alpha_context) as uow:
            uow.memberships.update(
                alpha_context,
                dataclasses.replace(
                    membership, role="owner", status=MembershipStatus.INACTIVE
                ),
            )

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.memberships.find_by_id(
                alpha_context, membership.membership_id
            )

        assert stored.role == "owner"
        assert stored.status is MembershipStatus.INACTIVE

    def test_an_update_keeps_columns_the_contract_does_not_model(
        self, runner, alpha_context, tenants, engine
    ):
        from sqlalchemy import text

        entity = build_user(tenants.alpha, email="partial@alpha.example")
        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, entity)

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.update(
                alpha_context,
                dataclasses.replace(entity, status=UserStatus.SUSPENDED),
            )

        with engine.connect() as connection:
            created_at = connection.execute(
                text("SELECT created_at FROM users")
            ).scalar_one()

        assert created_at is not None


class TestAuthorizationUpdates:
    """Permissions and role assignments."""

    def test_updates_a_permission(self, runner, alpha_context, tenants):
        permission = build_permission(tenants.alpha, name="Original name")
        with runner.unit_of_work(alpha_context) as uow:
            uow.permissions.add(alpha_context, permission)

        with runner.unit_of_work(alpha_context) as uow:
            uow.permissions.update(
                alpha_context,
                dataclasses.replace(
                    permission, name="Revised name", description="Explained"
                ),
            )

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.permissions.find_by_id(
                alpha_context, permission.permission_id
            )

        assert stored.name == "Revised name"
        assert stored.description == "Explained"

    def test_revoking_a_role_assignment(
        self, runner, alpha_context, tenants, user
    ):
        role = build_role(tenants.alpha)
        assignment = build_role_assignment(
            tenants.alpha, str(user.user_id), str(role.role_id)
        )
        with runner.unit_of_work(alpha_context) as uow:
            uow.roles.add(alpha_context, role)
            uow.role_assignments.add(alpha_context, assignment)

        with runner.unit_of_work(alpha_context) as uow:
            uow.role_assignments.update(
                alpha_context,
                dataclasses.replace(assignment, revoked_at=Timestamp.now()),
            )

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.role_assignments.find_by_id(
                alpha_context, assignment.assignment_id
            )
            active = uow.role_assignments.find_active_by_user(
                alpha_context, user.user_id
            )
            by_role = uow.role_assignments.find_by_role(alpha_context, role.role_id)

        assert stored.is_revoked is True
        assert active == []
        assert len(by_role) == 1

    def test_saving_a_role_creates_then_replaces_its_permissions(
        self, runner, alpha_context, tenants
    ):
        permission = build_permission(tenants.alpha)
        role = build_role(tenants.alpha, name="Saved role")

        with runner.unit_of_work(alpha_context) as uow:
            uow.permissions.add(alpha_context, permission)
            uow.roles.save(alpha_context, role)
        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.roles.save(
                alpha_context,
                dataclasses.replace(role, permissions=(permission.permission_id,)),
            )

        assert stored.permissions == (permission.permission_id,)

        with runner.unit_of_work(alpha_context) as uow:
            assert uow.roles.count(alpha_context) == 1

    def test_listing_roles_covers_the_tenant(self, runner, alpha_context, tenants):
        with runner.unit_of_work(alpha_context) as uow:
            uow.roles.add(alpha_context, build_role(tenants.alpha, name="Reader"))
            uow.roles.add(alpha_context, build_role(tenants.alpha, name="Writer"))

        with runner.unit_of_work(alpha_context) as uow:
            named = uow.roles.find_by_name(alpha_context, "Reader")
            assert uow.roles.count(alpha_context) == 2

        assert named is not None


class TestCredentialUpdates:
    """Credentials, API keys, and OAuth clients."""

    def test_recording_a_failed_attempt(self, runner, alpha_context, tenants, user):
        credential = build_credential(tenants.alpha, str(user.user_id))
        with runner.unit_of_work(alpha_context) as uow:
            uow.credentials.add(alpha_context, credential)

        locked_until = Timestamp.now()
        with runner.unit_of_work(alpha_context) as uow:
            uow.credentials.update(
                alpha_context,
                dataclasses.replace(
                    credential,
                    failed_attempts=3,
                    locked_until=locked_until,
                    requires_reset=True,
                ),
            )

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.credentials.find_by_id(
                alpha_context, credential.credential_id
            )

        assert stored.failed_attempts == 3
        assert stored.requires_reset is True
        assert stored.locked_until is not None

    def test_revoking_an_api_key_stamps_the_revocation(
        self, runner, alpha_context, tenants, user
    ):
        api_key = build_api_key(tenants.alpha, user_id=str(user.user_id))
        with runner.unit_of_work(alpha_context) as uow:
            uow.api_keys.add(alpha_context, api_key)

        with runner.unit_of_work(alpha_context) as uow:
            uow.api_keys.update(
                alpha_context,
                dataclasses.replace(api_key, status=ApiKeyStatus.REVOKED),
            )

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.api_keys.find_by_id(alpha_context, api_key.api_key_id)
            for_user = uow.api_keys.find_by_user(alpha_context, user.user_id)
            active = uow.api_keys.find_active(alpha_context)

        assert stored.status is ApiKeyStatus.REVOKED
        assert stored.is_active is False
        assert len(for_user) == 1
        assert active == []

    def test_rotating_an_oauth_client_secret_bumps_the_version(
        self, runner, alpha_context, tenants, engine
    ):
        from sqlalchemy import text

        client = build_oauth_client(tenants.alpha)
        with runner.unit_of_work(alpha_context) as uow:
            uow.oauth_clients.add(alpha_context, client)

        with runner.unit_of_work(alpha_context) as uow:
            uow.oauth_clients.update(
                alpha_context,
                dataclasses.replace(
                    client, client_secret_hash="argon2id$rotated-verifier"
                ),
            )

        with engine.connect() as connection:
            version, rotated_at = connection.execute(
                text("SELECT secret_version, secret_rotated_at FROM oauth_clients")
            ).one()

        assert version == 2
        assert rotated_at is not None

    def test_deactivating_an_oauth_client(self, runner, alpha_context, tenants):
        client = build_oauth_client(tenants.alpha)
        with runner.unit_of_work(alpha_context) as uow:
            uow.oauth_clients.add(alpha_context, client)

        with runner.unit_of_work(alpha_context) as uow:
            uow.oauth_clients.update(
                alpha_context, dataclasses.replace(client, is_active=False)
            )

        with runner.unit_of_work(alpha_context) as uow:
            assert uow.oauth_clients.find_active(alpha_context) == []
            assert uow.oauth_clients.count(alpha_context) == 1


class TestAuthenticationUpdates:
    """Sessions and refresh tokens."""

    def test_logging_out_a_session_stamps_the_revocation(
        self, runner, alpha_context, tenants, user
    ):
        session = build_session(tenants.alpha, str(user.user_id))
        with runner.unit_of_work(alpha_context) as uow:
            uow.sessions.add(alpha_context, session)

        with runner.unit_of_work(alpha_context) as uow:
            uow.sessions.update(
                alpha_context,
                dataclasses.replace(session, status=SessionStatus.LOGGED_OUT),
            )

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.sessions.find_by_id(alpha_context, session.session_id)

        assert stored.status is SessionStatus.LOGGED_OUT
        assert stored.revoked_at is not None
        assert stored.is_active is False

    def test_marking_a_refresh_token_as_used(
        self, runner, alpha_context, tenants, user
    ):
        session = build_session(tenants.alpha, str(user.user_id))
        token = build_refresh_token(
            tenants.alpha, str(session.session_id), str(user.user_id)
        )
        with runner.unit_of_work(alpha_context) as uow:
            uow.sessions.add(alpha_context, session)
            uow.refresh_tokens.add(alpha_context, token)

        with runner.unit_of_work(alpha_context) as uow:
            uow.refresh_tokens.update(
                alpha_context, dataclasses.replace(token, used_at=Timestamp.now())
            )

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.refresh_tokens.find_by_id(
                alpha_context, token.refresh_token_id
            )
            for_session = uow.refresh_tokens.find_by_session(
                alpha_context, session.session_id
            )

        assert stored.used_at is not None
        assert stored.is_usable is False
        assert len(for_session) == 1

    def test_deleting_a_session_removes_it(
        self, runner, alpha_context, tenants, user, row_counts
    ):
        session = build_session(tenants.alpha, str(user.user_id))
        with runner.unit_of_work(alpha_context) as uow:
            uow.sessions.add(alpha_context, session)

        with runner.unit_of_work(alpha_context) as uow:
            assert uow.sessions.delete(alpha_context, session.session_id) is True

        assert row_counts("sessions") == 0


class TestAuditAppend:
    """The tenant an audit record lands in comes from the context."""

    def test_an_event_without_a_tenant_is_stamped_with_the_callers(
        self, runner, alpha_context, tenants
    ):
        event = build_audit_event(None, actor_id=str(alpha_context.actor_id))

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.audit_events.append(alpha_context, event)

        assert stored.tenant_id.value == tenants.alpha

    def test_appended_events_are_countable_and_listable(
        self, runner, alpha_context, tenants
    ):
        with runner.unit_of_work(alpha_context) as uow:
            for _ in range(3):
                uow.audit_events.append(
                    alpha_context,
                    build_audit_event(
                        tenants.alpha, actor_id=str(alpha_context.actor_id)
                    ),
                )

        with runner.unit_of_work(alpha_context) as uow:
            assert uow.audit_events.count(alpha_context) == 3
            assert len(uow.audit_events.find_all(alpha_context)) == 3
