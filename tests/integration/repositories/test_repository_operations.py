"""Round-trip tests for each IAM entity group against the migrated schema."""

import dataclasses

import pytest

from eiams.domain.administration.contracts import TenantStatus
from eiams.domain.audit.contracts import AuditEventType
from eiams.domain.authentication.contracts import SessionStatus
from eiams.domain.credentials.contracts import ApiKeyStatus, CredentialType
from eiams.domain.identity.contracts import UserStatus
from eiams.shared.errors import (
    EntityNotFoundError,
    RepositoryError,
    ValidationError,
)

from .conftest import HEAD_REVISION
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
    build_tenant,
    build_user,
    new_id,
)


class TestSchemaUnderTest:
    """The tests exercise the schema the migrations produce."""

    def test_database_is_migrated_to_head(self, schema_revision):
        assert schema_revision == HEAD_REVISION

    def test_tenant_fixtures_are_committed(self, tenants, row_counts):
        assert row_counts("tenants") == 2


class TestTenantRegistry:
    """Platform-scoped access to the tenant registry."""

    def test_creates_and_reads_back_a_tenant(self, runner, platform_context):
        tenant_id = new_id()

        with runner.unit_of_work(platform_context) as uow:
            uow.tenants.add(
                platform_context, build_tenant(tenant_id, "Gamma Group")
            )

        with runner.unit_of_work(platform_context) as uow:
            stored = uow.tenants.find_by_id(platform_context, tenant_id)

        assert stored is not None
        assert stored.name == "Gamma Group"
        assert stored.status is TenantStatus.ACTIVE

    def test_derives_a_slug_when_none_is_supplied(
        self, runner, platform_context
    ):
        tenant_id = new_id()

        with runner.unit_of_work(platform_context) as uow:
            stored = uow.tenants.add(
                platform_context, build_tenant(tenant_id, "Delta Industries")
            )

        assert stored.slug == "delta-industries"

    def test_finds_a_tenant_by_name_and_slug(self, runner, platform_context):
        tenant_id = new_id()
        with runner.unit_of_work(platform_context) as uow:
            uow.tenants.add(
                platform_context,
                build_tenant(tenant_id, "Epsilon", slug="epsilon"),
            )

        with runner.unit_of_work(platform_context) as uow:
            by_name = uow.tenants.find_by_name(platform_context, "Epsilon")
            by_slug = uow.tenants.find_by_slug(platform_context, "epsilon")

        assert by_name is not None
        assert by_slug is not None
        assert by_name.tenant_id == by_slug.tenant_id

    def test_lists_only_active_tenants(self, runner, platform_context, tenants):
        with runner.unit_of_work(platform_context) as uow:
            uow.tenants.add(
                platform_context,
                build_tenant(
                    new_id(), "Suspended Co", status=TenantStatus.SUSPENDED
                ),
            )

        with runner.unit_of_work(platform_context) as uow:
            active = uow.tenants.find_active(platform_context)

        assert {tenant.name for tenant in active} == {"Alpha Corp", "Beta Ltd"}

    def test_rejects_settings_the_schema_cannot_store(
        self, runner, platform_context
    ):
        tenant = dataclasses.replace(
            build_tenant(new_id(), "Zeta"), settings={"mfa_required": True}
        )

        with pytest.raises(ValidationError) as caught:
            with runner.unit_of_work(platform_context) as uow:
                uow.tenants.add(platform_context, tenant)

        assert caught.value.field == "settings"


class TestIdentityRepositories:
    """Users, organizations, and memberships."""

    def test_user_round_trip_preserves_attributes(self, runner, alpha_context, tenants):
        user = build_user(
            tenants.alpha,
            email="ada@alpha.example",
            display_name="Ada Lovelace",
            username="ada",
        )

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.users.find_by_id(alpha_context, user.user_id)

        assert stored is not None
        assert stored.email == "ada@alpha.example"
        assert stored.display_name == "Ada Lovelace"
        assert stored.username == "ada"
        assert stored.status is UserStatus.ACTIVE
        assert stored.tenant_id.value == tenants.alpha

    def test_reads_return_immutable_entities_not_rows(
        self, runner, alpha_context, tenants
    ):
        user = build_user(tenants.alpha, email="frozen@alpha.example")
        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.users.find_by_id(alpha_context, user.user_id)

        assert dataclasses.is_dataclass(stored)
        assert not hasattr(stored, "_sa_instance_state")
        with pytest.raises(dataclasses.FrozenInstanceError):
            stored.email = "other@alpha.example"

    def test_entities_stay_usable_after_the_transaction_closes(
        self, runner, alpha_context, tenants
    ):
        user = build_user(tenants.alpha, email="detached@alpha.example")
        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.users.find_by_id(alpha_context, user.user_id)

        assert stored.email == "detached@alpha.example"

    def test_updates_apply_to_the_stored_user(
        self, runner, alpha_context, tenants
    ):
        user = build_user(tenants.alpha, email="update@alpha.example")
        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.update(
                alpha_context,
                dataclasses.replace(
                    user, display_name="Renamed", status=UserStatus.SUSPENDED
                ),
            )

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.users.find_by_id(alpha_context, user.user_id)

        assert stored.display_name == "Renamed"
        assert stored.status is UserStatus.SUSPENDED

    def test_updating_an_absent_user_is_refused(
        self, runner, alpha_context, tenants
    ):
        with pytest.raises(EntityNotFoundError):
            with runner.unit_of_work(alpha_context) as uow:
                uow.users.update(alpha_context, build_user(tenants.alpha))

    def test_save_creates_then_updates(self, runner, alpha_context, tenants):
        user = build_user(tenants.alpha, email="save@alpha.example")

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.save(alpha_context, user)
        with runner.unit_of_work(alpha_context) as uow:
            uow.users.save(alpha_context, dataclasses.replace(user, display_name="Saved"))

        with runner.unit_of_work(alpha_context) as uow:
            assert uow.users.count(alpha_context) == 1
            assert (
                uow.users.find_by_id(alpha_context, user.user_id).display_name
                == "Saved"
            )

    def test_deletes_a_user(self, runner, alpha_context, tenants, row_counts):
        user = build_user(tenants.alpha, email="delete@alpha.example")
        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)

        with runner.unit_of_work(alpha_context) as uow:
            deleted = uow.users.delete(alpha_context, user.user_id)

        assert deleted is True
        assert row_counts("users", tenant_id=tenants.alpha) == 0

    def test_finds_users_by_email_and_status(
        self, runner, alpha_context, tenants
    ):
        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(
                alpha_context,
                build_user(tenants.alpha, email="active@alpha.example"),
            )
            uow.users.add(
                alpha_context,
                build_user(
                    tenants.alpha,
                    email="pending@alpha.example",
                    status=UserStatus.PENDING_VERIFICATION,
                ),
            )

        with runner.unit_of_work(alpha_context) as uow:
            found = uow.users.find_by_email(alpha_context, "active@alpha.example")
            pending = uow.users.find_by_status(
                alpha_context, UserStatus.PENDING_VERIFICATION
            )

        assert found is not None
        assert [user.email for user in pending] == ["pending@alpha.example"]

    def test_organization_slug_is_derived_from_the_name(
        self, runner, alpha_context, tenants
    ):
        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.organizations.add(
                alpha_context,
                build_organization(tenants.alpha, name="Platform Engineering"),
            )

        assert stored.slug == "platform-engineering"

    def test_finds_child_organizations(self, runner, alpha_context, tenants):
        parent = build_organization(tenants.alpha, name="Parent")
        child = build_organization(
            tenants.alpha, name="Child", parent_id=str(parent.organization_id)
        )

        with runner.unit_of_work(alpha_context) as uow:
            uow.organizations.add(alpha_context, parent)
            uow.organizations.add(alpha_context, child)

        with runner.unit_of_work(alpha_context) as uow:
            children = uow.organizations.find_children(
                alpha_context, parent.organization_id
            )

        assert [org.name for org in children] == ["Child"]

    def test_membership_links_a_user_to_an_organization(
        self, runner, alpha_context, tenants
    ):
        user = build_user(tenants.alpha, email="member@alpha.example")
        organization = build_organization(tenants.alpha)
        membership = build_membership(
            tenants.alpha,
            str(user.user_id),
            str(organization.organization_id),
            role="owner",
        )

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)
            uow.organizations.add(alpha_context, organization)
            uow.memberships.add(alpha_context, membership)

        with runner.unit_of_work(alpha_context) as uow:
            found = uow.memberships.find_by_user_and_organization(
                alpha_context, user.user_id, organization.organization_id
            )
            by_user = uow.memberships.find_by_user(alpha_context, user.user_id)
            by_org = uow.memberships.find_by_organization(
                alpha_context, organization.organization_id
            )

        assert found is not None
        assert found.role == "owner"
        assert len(by_user) == 1
        assert len(by_org) == 1

    def test_membership_referencing_an_absent_user_is_refused(
        self, runner, alpha_context, tenants
    ):
        organization = build_organization(tenants.alpha)

        with pytest.raises(RepositoryError):
            with runner.unit_of_work(alpha_context) as uow:
                uow.organizations.add(alpha_context, organization)
                uow.memberships.add(
                    alpha_context,
                    build_membership(
                        tenants.alpha,
                        new_id(),
                        str(organization.organization_id),
                    ),
                )


class TestAuthorizationRepositories:
    """Permissions, roles, and role assignments."""

    def test_permission_round_trip(self, runner, alpha_context, tenants):
        permission = build_permission(tenants.alpha, action="write")

        with runner.unit_of_work(alpha_context) as uow:
            uow.permissions.add(alpha_context, permission)

        with runner.unit_of_work(alpha_context) as uow:
            found = uow.permissions.find_by_key(alpha_context, "user", "write")
            by_type = uow.permissions.find_by_resource_type(alpha_context, "user")

        assert found is not None
        assert found.permission_id == permission.permission_id
        assert len(by_type) == 1

    def test_role_carries_its_permissions(self, runner, alpha_context, tenants):
        permission = build_permission(tenants.alpha)
        role = build_role(
            tenants.alpha, permissions=(permission.permission_id,)
        )

        with runner.unit_of_work(alpha_context) as uow:
            uow.permissions.add(alpha_context, permission)
            stored = uow.roles.add(alpha_context, role)

        assert stored.permissions == (permission.permission_id,)

        with runner.unit_of_work(alpha_context) as uow:
            reloaded = uow.roles.find_by_id(alpha_context, role.role_id)

        assert reloaded.permissions == (permission.permission_id,)

    def test_role_permissions_can_be_replaced(
        self, runner, alpha_context, tenants
    ):
        first = build_permission(tenants.alpha, action="read")
        second = build_permission(tenants.alpha, action="write")
        role = build_role(tenants.alpha, permissions=(first.permission_id,))

        with runner.unit_of_work(alpha_context) as uow:
            uow.permissions.add(alpha_context, first)
            uow.permissions.add(alpha_context, second)
            uow.roles.add(alpha_context, role)

        with runner.unit_of_work(alpha_context) as uow:
            uow.roles.update(
                alpha_context,
                dataclasses.replace(role, permissions=(second.permission_id,)),
            )

        with runner.unit_of_work(alpha_context) as uow:
            reloaded = uow.roles.find_by_id(alpha_context, role.role_id)

        assert reloaded.permissions == (second.permission_id,)

    def test_role_assignment_defaults_the_scope_kind(
        self, runner, alpha_context, tenants
    ):
        user = build_user(tenants.alpha, email="assignee@alpha.example")
        role = build_role(tenants.alpha)
        organization = build_organization(tenants.alpha)
        assignment = build_role_assignment(
            tenants.alpha,
            str(user.user_id),
            str(role.role_id),
            scope=str(organization.organization_id),
        )

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)
            uow.organizations.add(alpha_context, organization)
            uow.roles.add(alpha_context, role)
            stored = uow.role_assignments.add(alpha_context, assignment)

        assert stored.scope == str(organization.organization_id)
        assert stored.scope_type == "organization"

    def test_active_assignments_exclude_expired_ones(
        self, runner, alpha_context, tenants
    ):
        user = build_user(tenants.alpha, email="roles@alpha.example")
        role = build_role(tenants.alpha, name="Reader")
        expired_role = build_role(tenants.alpha, name="Legacy")

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)
            uow.roles.add(alpha_context, role)
            uow.roles.add(alpha_context, expired_role)
            uow.role_assignments.add(
                alpha_context,
                build_role_assignment(
                    tenants.alpha, str(user.user_id), str(role.role_id)
                ),
            )
            uow.role_assignments.add(
                alpha_context,
                build_role_assignment(
                    tenants.alpha,
                    str(user.user_id),
                    str(expired_role.role_id),
                    expires_in_hours=-1,
                ),
            )

        with runner.unit_of_work(alpha_context) as uow:
            active = uow.role_assignments.find_active_by_user(
                alpha_context, user.user_id
            )
            everything = uow.role_assignments.find_by_user(
                alpha_context, user.user_id
            )

        assert len(active) == 1
        assert len(everything) == 2


class TestCredentialRepositories:
    """Credentials, API keys, and OAuth clients."""

    def test_credential_round_trip(self, runner, alpha_context, tenants):
        user = build_user(tenants.alpha, email="creds@alpha.example")
        credential = build_credential(tenants.alpha, str(user.user_id))

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)
            uow.credentials.add(alpha_context, credential)

        with runner.unit_of_work(alpha_context) as uow:
            found = uow.credentials.find_by_user_and_type(
                alpha_context, user.user_id, CredentialType.PASSWORD
            )
            for_user = uow.credentials.find_by_user(alpha_context, user.user_id)

        assert found is not None
        assert found.hash_algorithm == "argon2id"
        assert len(for_user) == 1

    def test_api_key_scopes_survive_the_round_trip(
        self, runner, alpha_context, tenants
    ):
        api_key = build_api_key(tenants.alpha, scopes=("user:read", "role:list"))

        with runner.unit_of_work(alpha_context) as uow:
            uow.api_keys.add(alpha_context, api_key)

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.api_keys.find_by_prefix(alpha_context, api_key.key_prefix)

        assert stored.scopes == ("user:read", "role:list")

    def test_revoked_api_keys_are_excluded_from_active_reads(
        self, runner, alpha_context, tenants
    ):
        active = build_api_key(tenants.alpha, name="Active")
        revoked = build_api_key(
            tenants.alpha, name="Revoked", status=ApiKeyStatus.REVOKED
        )

        with runner.unit_of_work(alpha_context) as uow:
            uow.api_keys.add(alpha_context, active)
            uow.api_keys.add(alpha_context, revoked)

        with runner.unit_of_work(alpha_context) as uow:
            listed = uow.api_keys.find_active(alpha_context)

        assert [key.name for key in listed] == ["Active"]

    def test_oauth_client_round_trip(self, runner, alpha_context, tenants):
        client = build_oauth_client(tenants.alpha)

        with runner.unit_of_work(alpha_context) as uow:
            uow.oauth_clients.add(alpha_context, client)

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.oauth_clients.find_by_name(alpha_context, "Portal")
            active = uow.oauth_clients.find_active(alpha_context)

        assert stored.redirect_uris == ("https://portal.example.com/callback",)
        assert stored.scopes == ("openid", "profile")
        assert len(active) == 1


class TestAuthenticationRepositories:
    """Sessions and refresh tokens."""

    def test_session_and_token_round_trip(self, runner, alpha_context, tenants):
        user = build_user(tenants.alpha, email="session@alpha.example")
        session = build_session(tenants.alpha, str(user.user_id))
        token = build_refresh_token(
            tenants.alpha, str(session.session_id), str(user.user_id)
        )

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)
            uow.sessions.add(alpha_context, session)
            uow.refresh_tokens.add(alpha_context, token)

        with runner.unit_of_work(alpha_context) as uow:
            active = uow.sessions.find_active_by_user(alpha_context, user.user_id)
            stored_token = uow.refresh_tokens.find_by_token_hash(
                alpha_context, token.token_hash
            )

        assert len(active) == 1
        assert stored_token is not None
        assert stored_token.is_usable is True

    def test_revoking_all_sessions_of_a_user(
        self, runner, alpha_context, tenants
    ):
        user = build_user(tenants.alpha, email="revoke@alpha.example")

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)
            uow.sessions.add(
                alpha_context, build_session(tenants.alpha, str(user.user_id))
            )
            uow.sessions.add(
                alpha_context, build_session(tenants.alpha, str(user.user_id))
            )

        with runner.unit_of_work(alpha_context) as uow:
            revoked = uow.sessions.revoke_all_for_user(alpha_context, user.user_id)

        with runner.unit_of_work(alpha_context) as uow:
            remaining = uow.sessions.find_active_by_user(
                alpha_context, user.user_id
            )
            all_sessions = uow.sessions.find_by_user(alpha_context, user.user_id)

        assert revoked == 2
        assert remaining == []
        assert all(
            session.status is SessionStatus.REVOKED for session in all_sessions
        )

    def test_expired_sessions_are_marked(self, runner, alpha_context, tenants):
        user = build_user(tenants.alpha, email="expire@alpha.example")

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)
            uow.sessions.add(
                alpha_context,
                build_session(
                    tenants.alpha, str(user.user_id), expires_in_hours=-1
                ),
            )

        with runner.unit_of_work(alpha_context) as uow:
            cleaned = uow.sessions.cleanup_expired(alpha_context)

        assert cleaned == 1

    def test_revoking_a_token_family(self, runner, alpha_context, tenants):
        user = build_user(tenants.alpha, email="family@alpha.example")
        session = build_session(tenants.alpha, str(user.user_id))
        family = new_id()

        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(alpha_context, user)
            uow.sessions.add(alpha_context, session)
            for _ in range(3):
                uow.refresh_tokens.add(
                    alpha_context,
                    build_refresh_token(
                        tenants.alpha,
                        str(session.session_id),
                        str(user.user_id),
                        token_family=family,
                    ),
                )

        with runner.unit_of_work(alpha_context) as uow:
            revoked = uow.refresh_tokens.revoke_family(alpha_context, family)

        with runner.unit_of_work(alpha_context) as uow:
            tokens = uow.refresh_tokens.find_by_family(alpha_context, family)

        assert revoked == 3
        assert all(token.is_revoked for token in tokens)


class TestAuditRepository:
    """Append-only audit access."""

    def test_appends_and_reads_back_an_event(
        self, runner, alpha_context, tenants
    ):
        event = build_audit_event(
            tenants.alpha,
            actor_id=str(alpha_context.actor_id),
            details={"source": "test"},
        )

        with runner.unit_of_work(alpha_context) as uow:
            uow.audit_events.append(alpha_context, event)

        with runner.unit_of_work(alpha_context) as uow:
            stored = uow.audit_events.find_by_id(
                alpha_context, event.audit_event_id
            )

        assert stored is not None
        assert stored.event_type is AuditEventType.USER_CREATED
        assert stored.details == {"source": "test"}
        assert stored.correlation_id == "correlation-1"

    def test_reads_by_actor_correlation_and_resource(
        self, runner, alpha_context, tenants
    ):
        actor_id = str(alpha_context.actor_id)
        target_id = new_id()

        with runner.unit_of_work(alpha_context) as uow:
            uow.audit_events.append(
                alpha_context,
                build_audit_event(
                    tenants.alpha,
                    actor_id=actor_id,
                    correlation_id="trace-1",
                    resource_type="user",
                    resource_id=target_id,
                ),
            )
            uow.audit_events.append(
                alpha_context,
                build_audit_event(
                    tenants.alpha,
                    actor_id=actor_id,
                    event_type=AuditEventType.LOGIN_SUCCESS,
                    correlation_id="trace-2",
                ),
            )

        with runner.unit_of_work(alpha_context) as uow:
            by_actor = uow.audit_events.find_by_actor(alpha_context, actor_id)
            by_correlation = uow.audit_events.find_by_correlation_id(
                alpha_context, "trace-1"
            )
            by_type = uow.audit_events.find_by_event_type(
                alpha_context, AuditEventType.LOGIN_SUCCESS
            )
            by_resource = uow.audit_events.find_by_resource(
                alpha_context, "user", target_id
            )

        assert len(by_actor) == 2
        assert len(by_correlation) == 1
        assert len(by_type) == 1
        assert len(by_resource) == 1

    def test_reads_within_a_time_range(self, runner, alpha_context, tenants):
        event = build_audit_event(tenants.alpha, actor_id=str(alpha_context.actor_id))

        with runner.unit_of_work(alpha_context) as uow:
            uow.audit_events.append(alpha_context, event)

        with runner.unit_of_work(alpha_context) as uow:
            found = uow.audit_events.find_by_time_range(
                alpha_context, event.timestamp, event.timestamp
            )

        assert len(found) == 1

    def test_recording_the_same_event_twice_is_refused(
        self, runner, alpha_context, tenants, row_counts
    ):
        event = build_audit_event(tenants.alpha, actor_id=str(alpha_context.actor_id))

        with runner.unit_of_work(alpha_context) as uow:
            uow.audit_events.append(alpha_context, event)

        with pytest.raises(RepositoryError):
            with runner.unit_of_work(alpha_context) as uow:
                uow.audit_events.append(alpha_context, event)

        assert row_counts("audit_events") == 1
