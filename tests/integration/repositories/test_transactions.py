"""Transaction boundary tests for multi-repository writes.

Each test drives a change that spans several entity groups and then checks
the committed database directly, so a partially applied change would be
visible rather than hidden behind the same repositories that wrote it.
"""

import pytest

from eiams.shared.errors import (
    ContextError,
    DuplicateEntityError,
    IntegrityViolationError,
    RepositoryError,
    TenantMismatchError,
)

from .factories import (
    build_audit_event,
    build_credential,
    build_membership,
    build_organization,
    build_session,
    build_user,
    new_id,
)


class InjectedFailure(RuntimeError):
    """Raised by a test to abort a transaction part-way through."""


def provision_team(uow, context, tenant_id: str, email: str):
    """Create a user, an organization, a membership, and an audit record.

    This is the shape of change the story is about: several entity groups
    written together, which must either all land or none.
    """
    user = build_user(tenant_id, email=email)
    organization = build_organization(tenant_id, name=f"Org for {email}")
    membership = build_membership(
        tenant_id, str(user.user_id), str(organization.organization_id)
    )
    credential = build_credential(tenant_id, str(user.user_id))
    audit_event = build_audit_event(
        tenant_id,
        actor_id=str(context.actor_id),
        resource_type="user",
        resource_id=str(user.user_id),
    )

    uow.users.add(context, user)
    uow.organizations.add(context, organization)
    uow.memberships.add(context, membership)
    uow.credentials.add(context, credential)
    uow.audit_events.append(context, audit_event)
    return user, organization


class TestCommitBoundary:
    """A transaction that finishes normally commits every change it made."""

    def test_multi_entity_change_lands_as_a_whole(
        self, runner, alpha_context, tenants, row_counts
    ):
        with runner.unit_of_work(alpha_context) as uow:
            provision_team(uow, alpha_context, tenants.alpha, "team@alpha.example")

        assert row_counts("users", tenant_id=tenants.alpha) == 1
        assert row_counts("organizations", tenant_id=tenants.alpha) == 1
        assert row_counts("memberships", tenant_id=tenants.alpha) == 1
        assert row_counts("user_credentials", tenant_id=tenants.alpha) == 1
        assert row_counts("audit_events", tenant_id=tenants.alpha) == 1

    def test_changes_are_not_visible_before_the_commit(
        self, runner, alpha_context, tenants, row_counts
    ):
        with runner.unit_of_work(alpha_context) as uow:
            provision_team(uow, alpha_context, tenants.alpha, "pending@alpha.example")
            uow.flush()
            assert row_counts("users", tenant_id=tenants.alpha) == 0

        assert row_counts("users", tenant_id=tenants.alpha) == 1

    def test_repositories_share_one_transaction(
        self, runner, alpha_context, tenants
    ):
        with runner.unit_of_work(alpha_context) as uow:
            user, organization = provision_team(
                uow, alpha_context, tenants.alpha, "shared@alpha.example"
            )

            # A read through a different repository sees the uncommitted
            # write, which is only possible on a shared session.
            membership = uow.memberships.find_by_user_and_organization(
                alpha_context, user.user_id, organization.organization_id
            )

        assert membership is not None

    def test_run_returns_the_result_of_the_work(
        self, runner, alpha_context, tenants
    ):
        def work(uow):
            user, _ = provision_team(
                uow, alpha_context, tenants.alpha, "result@alpha.example"
            )
            return user.user_id

        created_id = runner.run(alpha_context, work)

        with runner.unit_of_work(alpha_context) as uow:
            assert uow.users.find_by_id(alpha_context, created_id) is not None

    def test_a_later_transaction_sees_committed_data(
        self, runner, alpha_context, tenants
    ):
        with runner.unit_of_work(alpha_context) as uow:
            user, _ = provision_team(
                uow, alpha_context, tenants.alpha, "first@alpha.example"
            )

        with runner.unit_of_work(alpha_context) as uow:
            assert uow.users.find_by_id(alpha_context, user.user_id) is not None


class TestRollbackBoundary:
    """A transaction that raises leaves no trace of its writes."""

    def test_injected_failure_discards_every_write(
        self, runner, alpha_context, tenants, row_counts
    ):
        with pytest.raises(InjectedFailure):
            with runner.unit_of_work(alpha_context) as uow:
                provision_team(
                    uow, alpha_context, tenants.alpha, "aborted@alpha.example"
                )
                raise InjectedFailure("something went wrong downstream")

        assert row_counts("users") == 0
        assert row_counts("organizations") == 0
        assert row_counts("memberships") == 0
        assert row_counts("user_credentials") == 0
        assert row_counts("audit_events") == 0

    def test_failure_after_a_flush_still_discards_every_write(
        self, runner, alpha_context, tenants, row_counts
    ):
        with pytest.raises(InjectedFailure):
            with runner.unit_of_work(alpha_context) as uow:
                provision_team(
                    uow, alpha_context, tenants.alpha, "flushed@alpha.example"
                )
                uow.flush()
                raise InjectedFailure("failed after flushing")

        assert row_counts("users") == 0
        assert row_counts("audit_events") == 0

    def test_run_propagates_the_failure_and_rolls_back(
        self, runner, alpha_context, tenants, row_counts
    ):
        def work(uow):
            provision_team(uow, alpha_context, tenants.alpha, "run@alpha.example")
            raise InjectedFailure("aborted inside run")

        with pytest.raises(InjectedFailure):
            runner.run(alpha_context, work)

        assert row_counts("users") == 0

    def test_earlier_committed_state_survives_a_later_rollback(
        self, runner, alpha_context, tenants, row_counts
    ):
        with runner.unit_of_work(alpha_context) as uow:
            provision_team(uow, alpha_context, tenants.alpha, "kept@alpha.example")

        with pytest.raises(InjectedFailure):
            with runner.unit_of_work(alpha_context) as uow:
                provision_team(
                    uow, alpha_context, tenants.alpha, "discarded@alpha.example"
                )
                raise InjectedFailure("aborted")

        assert row_counts("users") == 1

    def test_the_session_is_usable_again_after_a_rollback(
        self, runner, alpha_context, tenants, row_counts
    ):
        with pytest.raises(InjectedFailure):
            with runner.unit_of_work(alpha_context) as uow:
                provision_team(uow, alpha_context, tenants.alpha, "retry@alpha.example")
                raise InjectedFailure("aborted")

        with runner.unit_of_work(alpha_context) as uow:
            provision_team(uow, alpha_context, tenants.alpha, "retry@alpha.example")

        assert row_counts("users") == 1


class TestDuplicateConflicts:
    """Uniqueness violations surface as domain errors and abort the change."""

    def test_duplicate_within_one_transaction_is_reported(
        self, runner, alpha_context, tenants
    ):
        with pytest.raises(DuplicateEntityError) as caught:
            with runner.unit_of_work(alpha_context) as uow:
                uow.users.add(
                    alpha_context,
                    build_user(tenants.alpha, email="clash@alpha.example"),
                )
                uow.users.add(
                    alpha_context,
                    build_user(tenants.alpha, email="clash@alpha.example"),
                )

        assert caught.value.details["entity"] == "user"

    def test_duplicate_within_one_transaction_leaves_no_partial_state(
        self, runner, alpha_context, tenants, row_counts
    ):
        with pytest.raises(DuplicateEntityError):
            with runner.unit_of_work(alpha_context) as uow:
                provision_team(
                    uow, alpha_context, tenants.alpha, "clash@alpha.example"
                )
                uow.users.add(
                    alpha_context,
                    build_user(tenants.alpha, email="clash@alpha.example"),
                )

        assert row_counts("users") == 0
        assert row_counts("organizations") == 0
        assert row_counts("audit_events") == 0

    def test_duplicate_of_a_committed_row_is_reported(
        self, runner, alpha_context, tenants, row_counts
    ):
        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(
                alpha_context,
                build_user(tenants.alpha, email="existing@alpha.example"),
            )

        with pytest.raises(DuplicateEntityError):
            with runner.unit_of_work(alpha_context) as uow:
                uow.organizations.add(
                    alpha_context, build_organization(tenants.alpha)
                )
                uow.users.add(
                    alpha_context,
                    build_user(tenants.alpha, email="existing@alpha.example"),
                )

        assert row_counts("users") == 1
        assert row_counts("organizations") == 0

    def test_conflict_report_names_the_conflicting_fields(
        self, runner, alpha_context, tenants
    ):
        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(
                alpha_context, build_user(tenants.alpha, email="fields@alpha.example")
            )

        with pytest.raises(DuplicateEntityError) as caught:
            with runner.unit_of_work(alpha_context) as uow:
                uow.users.add(
                    alpha_context,
                    build_user(tenants.alpha, email="fields@alpha.example"),
                )

        assert "email" in caught.value.details["conflicting_fields"]

    def test_conflict_report_does_not_leak_driver_detail(
        self, runner, alpha_context, tenants
    ):
        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(
                alpha_context, build_user(tenants.alpha, email="leak@alpha.example")
            )

        with pytest.raises(DuplicateEntityError) as caught:
            with runner.unit_of_work(alpha_context) as uow:
                uow.users.add(
                    alpha_context,
                    build_user(tenants.alpha, email="leak@alpha.example"),
                )

        assert "leak@alpha.example" not in caught.value.message
        assert "UNIQUE constraint" not in caught.value.message
        assert "INSERT" not in caught.value.message

    def test_the_same_value_is_free_in_another_tenant(
        self, runner, alpha_context, beta_context, tenants, row_counts
    ):
        with runner.unit_of_work(alpha_context) as uow:
            uow.users.add(
                alpha_context, build_user(tenants.alpha, email="same@example.com")
            )
        with runner.unit_of_work(beta_context) as uow:
            uow.users.add(
                beta_context, build_user(tenants.beta, email="same@example.com")
            )

        assert row_counts("users") == 2


class TestIntegrityFailures:
    """Other integrity violations abort the transaction the same way."""

    def test_referencing_an_absent_row_is_refused(
        self, runner, alpha_context, tenants, row_counts
    ):
        with pytest.raises(IntegrityViolationError):
            with runner.unit_of_work(alpha_context) as uow:
                uow.organizations.add(
                    alpha_context, build_organization(tenants.alpha)
                )
                uow.sessions.add(
                    alpha_context, build_session(tenants.alpha, new_id())
                )

        assert row_counts("organizations") == 0
        assert row_counts("sessions") == 0

    def test_integrity_failures_are_repository_errors(
        self, runner, alpha_context, tenants
    ):
        with pytest.raises(RepositoryError):
            with runner.unit_of_work(alpha_context) as uow:
                uow.sessions.add(
                    alpha_context, build_session(tenants.alpha, new_id())
                )


class TestScopeFailuresAbortTheTransaction:
    """A scope violation anywhere in a change discards the whole change."""

    def test_cross_tenant_write_discards_the_earlier_writes(
        self, runner, alpha_context, beta_context, tenants, row_counts
    ):
        with pytest.raises(TenantMismatchError):
            with runner.unit_of_work(beta_context) as uow:
                uow.organizations.add(
                    beta_context, build_organization(tenants.beta)
                )
                uow.users.add(beta_context, build_user(tenants.alpha))

        assert row_counts("organizations") == 0
        assert row_counts("users") == 0

    def test_a_transaction_needs_a_context(self, runner):
        with pytest.raises(ContextError):
            with runner.unit_of_work(None):
                pass
