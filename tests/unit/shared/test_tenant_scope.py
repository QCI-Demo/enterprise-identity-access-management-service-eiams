"""Tests for tenant scope value objects and the guards that build them."""

from uuid import uuid4

import pytest

from eiams.shared.context import (
    ActorType,
    RepositoryScope,
    RequestContextFactory,
    TenantPredicate,
    assert_tenant_match,
    build_tenant_predicate,
    require_platform_scope,
    require_tenant_scope,
)
from eiams.shared.errors import (
    ActorRequiredError,
    ContextError,
    ErrorCode,
    InvalidTenantError,
    TenantMismatchError,
    TenantRequiredError,
    ValidationError,
)
from eiams.shared.kernel import TenantId


@pytest.fixture
def tenant_id() -> str:
    return str(uuid4())


@pytest.fixture
def other_tenant_id() -> str:
    return str(uuid4())


@pytest.fixture
def tenant_context(tenant_id):
    """Authenticated context carrying tenant scope."""
    return RequestContextFactory.create(
        actor_id=str(uuid4()),
        tenant_id=tenant_id,
    )


@pytest.fixture
def untenanted_context():
    """Authenticated context with no tenant scope."""
    return RequestContextFactory.create(actor_id=str(uuid4()))


class TestTenantPredicate:
    """Tests for the predicate value object itself."""

    def test_binds_column_and_tenant(self, tenant_id):
        predicate = TenantPredicate(
            column="tenant_id", tenant_id=TenantId(tenant_id)
        )

        assert predicate.column == "tenant_id"
        assert predicate.value == tenant_id
        assert predicate.include_shared is False

    def test_is_immutable(self, tenant_id):
        predicate = TenantPredicate(
            column="tenant_id", tenant_id=TenantId(tenant_id)
        )

        with pytest.raises(Exception):
            predicate.column = "other_column"

    def test_requires_a_column_name(self, tenant_id):
        with pytest.raises(ValidationError):
            TenantPredicate(column="", tenant_id=TenantId(tenant_id))

    def test_requires_a_validated_tenant_id(self, tenant_id):
        with pytest.raises(InvalidTenantError):
            TenantPredicate(column="tenant_id", tenant_id=tenant_id)

    def test_matches_only_the_bound_tenant(self, tenant_id, other_tenant_id):
        predicate = TenantPredicate(
            column="tenant_id", tenant_id=TenantId(tenant_id)
        )

        assert predicate.matches(tenant_id) is True
        assert predicate.matches(tenant_id.upper()) is True
        assert predicate.matches(other_tenant_id) is False

    def test_rejects_unowned_rows_by_default(self, tenant_id):
        predicate = TenantPredicate(
            column="tenant_id", tenant_id=TenantId(tenant_id)
        )

        assert predicate.matches(None) is False

    def test_shared_variant_matches_unowned_rows(self, tenant_id):
        predicate = TenantPredicate(
            column="tenant_id",
            tenant_id=TenantId(tenant_id),
            include_shared=True,
        )

        assert predicate.matches(None) is True

    def test_write_variant_drops_shared_rows(self, tenant_id):
        predicate = TenantPredicate(
            column="tenant_id",
            tenant_id=TenantId(tenant_id),
            include_shared=True,
        )

        write_predicate = predicate.for_write()

        assert write_predicate.include_shared is False
        assert write_predicate.matches(None) is False
        assert write_predicate.value == tenant_id

    def test_write_variant_of_strict_predicate_is_itself(self, tenant_id):
        predicate = TenantPredicate(
            column="tenant_id", tenant_id=TenantId(tenant_id)
        )

        assert predicate.for_write() == predicate

    def test_serializes_for_logging(self, tenant_id):
        predicate = TenantPredicate(
            column="owner_tenant", tenant_id=TenantId(tenant_id)
        )

        assert predicate.to_dict() == {
            "column": "owner_tenant",
            "tenant_id": tenant_id,
            "include_shared": False,
        }

    def test_renders_the_filter_it_describes(self, tenant_id):
        strict = TenantPredicate(
            column="tenant_id", tenant_id=TenantId(tenant_id)
        )
        shared = TenantPredicate(
            column="tenant_id",
            tenant_id=TenantId(tenant_id),
            include_shared=True,
        )

        assert str(strict) == f"tenant_id = {tenant_id}"
        assert "IS NULL" in str(shared)


class TestRequireTenantScope:
    """Tests for resolving tenant scope from request context."""

    def test_returns_the_validated_tenant(self, tenant_context, tenant_id):
        resolved = require_tenant_scope(tenant_context)

        assert isinstance(resolved, TenantId)
        assert resolved.value == tenant_id

    def test_rejects_missing_context(self):
        with pytest.raises(ContextError):
            require_tenant_scope(None)

    def test_rejects_context_without_tenant(self, untenanted_context):
        with pytest.raises(TenantRequiredError) as caught:
            require_tenant_scope(untenanted_context)

        assert caught.value.code is ErrorCode.TENANT_REQUIRED

    def test_records_the_operation_in_error_details(self, untenanted_context):
        with pytest.raises(TenantRequiredError) as caught:
            require_tenant_scope(untenanted_context, operation="user")

        assert caught.value.details["operation"] == "user"

    def test_anonymous_context_has_no_tenant(self):
        anonymous = RequestContextFactory.create_anonymous()

        with pytest.raises(TenantRequiredError):
            require_tenant_scope(anonymous)


class TestRequirePlatformScope:
    """Tests for guarding operations that intentionally span tenants."""

    def test_allows_authenticated_caller_without_tenant(
        self, untenanted_context
    ):
        require_platform_scope(untenanted_context)

    def test_allows_system_actor(self):
        require_platform_scope(RequestContextFactory.create_system())

    def test_rejects_missing_context(self):
        with pytest.raises(ContextError):
            require_platform_scope(None)

    def test_rejects_anonymous_caller(self):
        anonymous = RequestContextFactory.create_anonymous()
        assert anonymous.actor.actor_type is ActorType.ANONYMOUS

        with pytest.raises(ActorRequiredError):
            require_platform_scope(anonymous)


class TestBuildTenantPredicate:
    """Tests for predicate construction from request context."""

    def test_binds_the_context_tenant(self, tenant_context, tenant_id):
        predicate = build_tenant_predicate(tenant_context)

        assert predicate.column == "tenant_id"
        assert predicate.value == tenant_id

    def test_accepts_a_custom_column(self, tenant_context):
        predicate = build_tenant_predicate(tenant_context, "owner_tenant_id")

        assert predicate.column == "owner_tenant_id"

    def test_can_admit_shared_rows(self, tenant_context):
        predicate = build_tenant_predicate(tenant_context, include_shared=True)

        assert predicate.include_shared is True

    def test_fails_closed_without_tenant_context(self, untenanted_context):
        with pytest.raises(TenantRequiredError):
            build_tenant_predicate(untenanted_context)

    def test_fails_closed_without_any_context(self):
        with pytest.raises(ContextError):
            build_tenant_predicate(None)


class TestAssertTenantMatch:
    """Tests for the tenant-mismatch failure path."""

    def test_accepts_a_resource_of_the_same_tenant(
        self, tenant_context, tenant_id
    ):
        assert_tenant_match(tenant_context, tenant_id)
        assert_tenant_match(tenant_context, TenantId(tenant_id))

    def test_rejects_a_resource_of_another_tenant(
        self, tenant_context, other_tenant_id
    ):
        with pytest.raises(TenantMismatchError) as caught:
            assert_tenant_match(tenant_context, other_tenant_id)

        assert caught.value.code is ErrorCode.TENANT_MISMATCH

    def test_does_not_disclose_the_owning_tenant(
        self, tenant_context, other_tenant_id
    ):
        with pytest.raises(TenantMismatchError) as caught:
            assert_tenant_match(
                tenant_context, other_tenant_id, resource_type="user"
            )

        serialized = str(caught.value.to_dict())
        assert other_tenant_id not in serialized

    def test_reports_the_expected_tenant_and_resource(
        self, tenant_context, tenant_id, other_tenant_id
    ):
        with pytest.raises(TenantMismatchError) as caught:
            assert_tenant_match(
                tenant_context,
                other_tenant_id,
                resource_type="user",
                resource_id="abc",
            )

        details = caught.value.details
        assert details["expected_tenant_id"] == tenant_id
        assert details["resource_type"] == "user"
        assert details["resource_id"] == "abc"

    def test_rejects_an_unowned_resource_by_default(self, tenant_context):
        with pytest.raises(TenantMismatchError):
            assert_tenant_match(tenant_context, None)

    def test_accepts_an_unowned_resource_when_shared(self, tenant_context):
        assert_tenant_match(tenant_context, None, allow_shared=True)

    def test_fails_closed_without_tenant_context(
        self, untenanted_context, tenant_id
    ):
        with pytest.raises(TenantRequiredError):
            assert_tenant_match(untenanted_context, tenant_id)


class TestRepositoryScope:
    """Tests for the scope enumeration."""

    def test_has_platform_and_tenant_scopes(self):
        assert RepositoryScope.PLATFORM.value == "platform"
        assert RepositoryScope.TENANT.value == "tenant"
