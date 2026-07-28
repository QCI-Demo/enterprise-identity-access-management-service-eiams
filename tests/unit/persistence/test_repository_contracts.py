"""Tests for repository scope contracts and predicate binding.

These tests construct repositories with no session at all. Anything they
prove therefore happened before a statement could reach a database: if a
guard let a call through, the test would fail with an attribute error on
the missing session rather than the expected domain error.
"""

import inspect
from uuid import uuid4

import pytest

from eiams.application.ports import TransactionRunnerPort, UnitOfWorkPort
from eiams.domain.audit.contracts import AuditEventRepository
from eiams.domain.base import (
    AppendOnlyRepository,
    PlatformScopedRepository,
    Repository,
    TenantScopedRepository,
)
from eiams.infrastructure.persistence.mappers import AuditEventMapper
from eiams.infrastructure.persistence.repositories import (
    MAX_PAGE_SIZE,
    SqlAlchemyApiKeyRepository,
    SqlAlchemyAuditEventRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyOAuthClientRepository,
    SqlAlchemyOrganizationRepository,
    SqlAlchemyPermissionRepository,
    SqlAlchemyRefreshTokenRepository,
    SqlAlchemyRoleAssignmentRepository,
    SqlAlchemyRoleRepository,
    SqlAlchemySessionRepository,
    SqlAlchemyTenantRepository,
    SqlAlchemyUserCredentialRepository,
    SqlAlchemyUserRepository,
)
from eiams.infrastructure.persistence.transaction import (
    SqlAlchemyTransactionRunner,
    SqlAlchemyUnitOfWork,
)
from eiams.shared.context import (
    RepositoryScope,
    RequestContextFactory,
)
from eiams.shared.errors import (
    AppendOnlyViolationError,
    ContextError,
    RepositoryError,
    TenantMismatchError,
    TenantRequiredError,
    ValidationError,
)
from eiams.shared.kernel import TenantId, Timestamp

from eiams.domain.identity.contracts import User, UserId, UserStatus


TENANT_SCOPED_REPOSITORIES = [
    SqlAlchemyUserRepository,
    SqlAlchemyOrganizationRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyPermissionRepository,
    SqlAlchemyRoleRepository,
    SqlAlchemyRoleAssignmentRepository,
    SqlAlchemyUserCredentialRepository,
    SqlAlchemySessionRepository,
    SqlAlchemyRefreshTokenRepository,
    SqlAlchemyApiKeyRepository,
    SqlAlchemyOAuthClientRepository,
]


@pytest.fixture
def tenant_id() -> str:
    return str(uuid4())


@pytest.fixture
def tenant_context(tenant_id):
    return RequestContextFactory.create(actor_id=str(uuid4()), tenant_id=tenant_id)


@pytest.fixture
def untenanted_context():
    return RequestContextFactory.create(actor_id=str(uuid4()))


def build_user(tenant_id: str) -> User:
    """Build a user entity owned by the given tenant."""
    now = Timestamp.now()
    return User(
        user_id=UserId(str(uuid4())),
        tenant_id=TenantId(tenant_id),
        email="person@example.com",
        display_name="Person",
        status=UserStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )


class TestScopeDeclarations:
    """Every repository declares the scope its contract promises."""

    @pytest.mark.parametrize("repository_type", TENANT_SCOPED_REPOSITORIES)
    def test_tenant_scoped_repositories_declare_tenant_scope(
        self, repository_type
    ):
        assert issubclass(repository_type, TenantScopedRepository)
        assert repository_type.scope is RepositoryScope.TENANT

    def test_tenant_registry_is_platform_scoped(self):
        assert issubclass(SqlAlchemyTenantRepository, PlatformScopedRepository)
        assert SqlAlchemyTenantRepository.scope is RepositoryScope.PLATFORM

    def test_audit_repository_is_append_only(self):
        assert issubclass(SqlAlchemyAuditEventRepository, AppendOnlyRepository)
        assert SqlAlchemyAuditEventRepository.scope is RepositoryScope.TENANT

    @pytest.mark.parametrize("repository_type", TENANT_SCOPED_REPOSITORIES)
    def test_tenant_scoped_repositories_bind_a_tenant_column(
        self, repository_type
    ):
        assert repository_type.__tenant_column__ == "tenant_id"
        assert hasattr(repository_type.__model__, "tenant_id")


class TestAppendOnlyAuditInterface:
    """The audit interface offers no way to express a mutation."""

    @pytest.mark.parametrize("operation", ["save", "update", "delete"])
    def test_contract_excludes_mutating_operations(self, operation):
        assert not hasattr(AuditEventRepository, operation)

    @pytest.mark.parametrize("operation", ["save", "update", "delete"])
    def test_implementation_excludes_mutating_operations(self, operation):
        assert not hasattr(SqlAlchemyAuditEventRepository, operation)

    def test_contract_does_not_inherit_the_writable_repository(self):
        assert not issubclass(AuditEventRepository, Repository)

    def test_append_is_the_only_write_primitive(self):
        writers = {
            name
            for name, _ in inspect.getmembers(
                SqlAlchemyAuditEventRepository, inspect.isfunction
            )
            if name in {"append", "add", "save", "update", "delete"}
        }
        assert writers == {"append"}

    def test_mapping_an_update_onto_a_recorded_event_is_refused(self):
        with pytest.raises(AppendOnlyViolationError):
            AuditEventMapper().apply(object(), object())


class TestTenantPredicateBinding:
    """The tenant filter is part of every statement a repository builds."""

    def test_scoped_select_binds_the_predicate(self, tenant_context, tenant_id):
        repository = SqlAlchemyUserRepository(session=None)

        statement = repository._scoped_select(tenant_context)

        assert "users.tenant_id = :tenant_id_1" in _sql(statement)
        assert tenant_id in _params(statement).values()

    def test_caller_criteria_are_appended_after_the_predicate(
        self, tenant_context
    ):
        repository = SqlAlchemyUserRepository(session=None)

        statement = repository._scoped_select(tenant_context).where(
            repository.__model__.email == "person@example.com"
        )

        rendered = _sql(statement)
        assert rendered.index("users.tenant_id") < rendered.index("users.email")

    def test_shared_catalogue_reads_admit_unowned_rows(
        self, tenant_context, tenant_id
    ):
        repository = SqlAlchemyRoleRepository(session=None)
        statement = repository._scoped_select(tenant_context)

        rendered = _sql(statement)

        assert "roles.tenant_id = :tenant_id_1" in rendered
        assert "roles.tenant_id IS NULL" in rendered
        assert tenant_id in _params(statement).values()

    def test_shared_catalogue_writes_exclude_unowned_rows(
        self, tenant_context, tenant_id
    ):
        repository = SqlAlchemyRoleRepository(session=None)
        statement = repository._scoped_select(tenant_context, for_write=True)

        rendered = _sql(statement)

        assert "roles.tenant_id = :tenant_id_1" in rendered
        assert "IS NULL" not in rendered
        assert tenant_id in _params(statement).values()

    def test_audit_reads_exclude_events_written_outside_any_tenant(
        self, tenant_context, tenant_id
    ):
        repository = SqlAlchemyAuditEventRepository(session=None)
        statement = repository._scoped_select(tenant_context)

        rendered = _sql(statement)

        assert "audit_events.tenant_id = :tenant_id_1" in rendered
        assert "IS NULL" not in rendered
        assert tenant_id in _params(statement).values()


class TestFailClosedWithoutTenantContext:
    """No tenant context means no statement, never an unfiltered one."""

    @pytest.mark.parametrize("repository_type", TENANT_SCOPED_REPOSITORIES)
    def test_predicate_construction_is_refused(
        self, repository_type, untenanted_context
    ):
        repository = repository_type(session=None)

        with pytest.raises(TenantRequiredError):
            repository.tenant_predicate(untenanted_context)

    @pytest.mark.parametrize(
        "call",
        [
            lambda repo, ctx: repo.find_by_id(ctx, str(uuid4())),
            lambda repo, ctx: repo.exists(ctx, str(uuid4())),
            lambda repo, ctx: repo.find_all(ctx),
            lambda repo, ctx: repo.count(ctx),
            lambda repo, ctx: repo.delete(ctx, str(uuid4())),
            lambda repo, ctx: repo.find_by_email(ctx, "person@example.com"),
        ],
        ids=["find_by_id", "exists", "find_all", "count", "delete", "find_by_email"],
    )
    def test_read_and_delete_operations_are_refused(
        self, call, untenanted_context
    ):
        repository = SqlAlchemyUserRepository(session=None)

        with pytest.raises(TenantRequiredError):
            call(repository, untenanted_context)

    @pytest.mark.parametrize("operation", ["add", "update", "save"])
    def test_write_operations_are_refused(
        self, operation, untenanted_context, tenant_id
    ):
        repository = SqlAlchemyUserRepository(session=None)

        with pytest.raises(TenantRequiredError):
            getattr(repository, operation)(
                untenanted_context, build_user(tenant_id)
            )

    def test_audit_append_is_refused(self, untenanted_context):
        repository = SqlAlchemyAuditEventRepository(session=None)

        with pytest.raises(TenantRequiredError):
            repository.append(untenanted_context, object())

    def test_platform_scope_still_refuses_anonymous_callers(self):
        repository = SqlAlchemyTenantRepository(session=None)
        anonymous = RequestContextFactory.create_anonymous()

        with pytest.raises(ContextError):
            repository.find_all(anonymous)


class TestTenantMismatchOnWrite:
    """A write is rejected before it can place a row in another tenant."""

    @pytest.mark.parametrize("operation", ["add", "update", "save"])
    def test_entity_of_another_tenant_is_refused(
        self, operation, tenant_context
    ):
        repository = SqlAlchemyUserRepository(session=None)
        foreign_user = build_user(str(uuid4()))

        with pytest.raises(TenantMismatchError):
            getattr(repository, operation)(tenant_context, foreign_user)

    def test_platform_shared_records_cannot_be_written_by_a_tenant(
        self, tenant_context
    ):
        from eiams.domain.authorization.contracts import Role, RoleId

        repository = SqlAlchemyRoleRepository(session=None)
        system_role = Role(
            role_id=RoleId(str(uuid4())),
            tenant_id=None,
            name="platform-admin",
            description=None,
            permissions=(),
            is_system_role=True,
            created_at=Timestamp.now(),
            updated_at=Timestamp.now(),
        )

        with pytest.raises(TenantMismatchError):
            repository.add(tenant_context, system_role)


class TestPageValidation:
    """Page arguments cannot be used to widen a read."""

    def test_negative_offset_is_refused(self, tenant_context):
        repository = SqlAlchemyUserRepository(session=None)

        with pytest.raises(ValidationError):
            repository.find_all(tenant_context, offset=-1)

    def test_zero_limit_is_refused(self, tenant_context):
        repository = SqlAlchemyUserRepository(session=None)

        with pytest.raises(ValidationError):
            repository.find_all(tenant_context, limit=0)

    def test_oversized_limit_is_refused(self, tenant_context):
        repository = SqlAlchemyUserRepository(session=None)

        with pytest.raises(ValidationError):
            repository.find_all(tenant_context, limit=MAX_PAGE_SIZE + 1)


class TestReadFailures:
    """A failing read reports a repository error, not a driver exception."""

    class ExplodingSession:
        """Session whose every statement fails at the driver."""

        def execute(self, statement):
            from sqlalchemy.exc import OperationalError

            raise OperationalError(
                "SELECT users.secret FROM users", {}, Exception("no such column")
            )

    def test_driver_failures_are_translated(self, tenant_context):
        repository = SqlAlchemyUserRepository(session=self.ExplodingSession())

        with pytest.raises(RepositoryError) as caught:
            repository.find_all(tenant_context)

        assert "no such column" not in str(caught.value.to_dict())
        assert caught.value.details["entity"] == "user"

    def test_counting_failures_are_translated(self, tenant_context):
        repository = SqlAlchemyUserRepository(session=self.ExplodingSession())

        with pytest.raises(RepositoryError):
            repository.count(tenant_context)


class TestUnitOfWorkPorts:
    """The unit of work exposes each entity group through one session."""

    def test_runner_implements_the_port(self):
        assert issubclass(SqlAlchemyTransactionRunner, TransactionRunnerPort)

    def test_unit_of_work_implements_the_port(self):
        assert issubclass(SqlAlchemyUnitOfWork, UnitOfWorkPort)

    @pytest.mark.parametrize(
        "accessor",
        [
            "tenants",
            "users",
            "organizations",
            "memberships",
            "roles",
            "permissions",
            "role_assignments",
            "credentials",
            "sessions",
            "refresh_tokens",
            "api_keys",
            "oauth_clients",
            "audit_events",
        ],
    )
    def test_every_entity_group_is_reachable(self, accessor, tenant_context):
        uow = SqlAlchemyUnitOfWork(session=None, context=tenant_context)

        assert getattr(uow, accessor) is not None

    def test_repositories_are_reused_within_one_unit_of_work(
        self, tenant_context
    ):
        uow = SqlAlchemyUnitOfWork(session=None, context=tenant_context)

        assert uow.users is uow.users

    def test_tenant_registry_is_the_only_platform_scoped_accessor(
        self, tenant_context
    ):
        uow = SqlAlchemyUnitOfWork(session=None, context=tenant_context)

        assert uow.tenants.scope is RepositoryScope.PLATFORM
        assert uow.users.scope is RepositoryScope.TENANT


def _sql(statement) -> str:
    """Render a statement as SQL text with named bind parameters."""
    return str(statement.compile())


def _params(statement) -> dict:
    """Return the values bound to a statement's parameters."""
    return statement.compile().params
