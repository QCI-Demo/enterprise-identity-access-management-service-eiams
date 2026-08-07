"""Tests for turning driver exceptions into caller-safe errors.

A driver message can carry SQL text and row values, so these tests check
both that the failure is classified correctly and that nothing from the
original message survives into the error a caller sees.
"""

import pytest
from sqlalchemy.exc import IntegrityError, OperationalError

from eiams.infrastructure.persistence.errors import (
    translate_database_error,
    translate_integrity_error,
    translate_transaction_error,
)
from eiams.shared.errors import (
    DuplicateEntityError,
    ErrorCode,
    IntegrityViolationError,
    RepositoryError,
    TransactionError,
)


SENSITIVE_STATEMENT = (
    "INSERT INTO users (tenant_id, email) VALUES (?, 'ada@example.com')"
)


class DriverError(Exception):
    """Stand-in for a DBAPI exception, optionally carrying a SQLSTATE."""

    def __init__(self, message: str, sqlstate: str | None = None) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


def integrity_error(message: str, sqlstate: str | None = None) -> IntegrityError:
    return IntegrityError(
        SENSITIVE_STATEMENT,
        {"email": "ada@example.com"},
        DriverError(message, sqlstate),
    )


class TestUniquenessViolations:
    """Uniqueness violations become duplicate errors."""

    def test_sqlite_message_is_recognised(self):
        error = translate_integrity_error(
            integrity_error("UNIQUE constraint failed: users.tenant_id, users.email"),
            entity="user",
        )

        assert isinstance(error, DuplicateEntityError)
        assert error.code is ErrorCode.RESOURCE_ALREADY_EXISTS

    def test_conflicting_columns_are_reported(self):
        error = translate_integrity_error(
            integrity_error("UNIQUE constraint failed: users.tenant_id, users.email"),
            entity="user",
        )

        assert error.details["conflicting_fields"] == ["tenant_id", "email"]

    def test_sqlstate_is_recognised_without_a_recognisable_message(self):
        error = translate_integrity_error(
            integrity_error("duplicate key value violates constraint", "23505"),
            entity="user",
        )

        assert isinstance(error, DuplicateEntityError)

    def test_the_entity_group_is_reported(self):
        error = translate_integrity_error(
            integrity_error("UNIQUE constraint failed: api_keys.key_prefix"),
            entity="API key",
        )

        assert error.details["entity"] == "API key"


class TestOtherIntegrityViolations:
    """Every other integrity failure becomes an integrity violation."""

    @pytest.mark.parametrize(
        "message",
        [
            "FOREIGN KEY constraint failed",
            "NOT NULL constraint failed: users.email",
            "CHECK constraint failed: valid_user_status",
            "something the driver did not explain",
        ],
    )
    def test_failures_are_classified_as_integrity_violations(self, message):
        error = translate_integrity_error(integrity_error(message), entity="user")

        assert isinstance(error, IntegrityViolationError)
        assert error.code is ErrorCode.RESOURCE_CONFLICT

    def test_integrity_sqlstate_class_is_recognised(self):
        error = translate_integrity_error(
            integrity_error("violates foreign key constraint", "23503"),
            entity="membership",
        )

        assert isinstance(error, IntegrityViolationError)


class TestCallerSafety:
    """No driver detail reaches the caller."""

    @pytest.mark.parametrize(
        "message",
        [
            "UNIQUE constraint failed: users.tenant_id, users.email",
            "FOREIGN KEY constraint failed",
        ],
    )
    def test_the_driver_message_is_not_repeated(self, message):
        error = translate_integrity_error(integrity_error(message), entity="user")

        serialized = str(error.to_dict())
        assert message not in serialized
        assert "ada@example.com" not in serialized
        assert "INSERT INTO" not in serialized


class TestOtherDatabaseFailures:
    """Failures that are not integrity violations stay generic."""

    def test_operational_failures_become_repository_errors(self):
        error = translate_database_error(
            OperationalError(SENSITIVE_STATEMENT, {}, DriverError("disk I/O error")),
            entity="user",
        )

        assert isinstance(error, RepositoryError)
        assert error.code is ErrorCode.PERSISTENCE_ERROR
        assert "disk I/O error" not in str(error.to_dict())

    def test_integrity_failures_are_still_classified(self):
        error = translate_database_error(
            integrity_error("UNIQUE constraint failed: users.email"), entity="user"
        )

        assert isinstance(error, DuplicateEntityError)

    def test_commit_failures_become_transaction_errors(self):
        error = translate_transaction_error(
            OperationalError(SENSITIVE_STATEMENT, {}, DriverError("database is locked"))
        )

        assert isinstance(error, TransactionError)
        assert error.code is ErrorCode.TRANSACTION_FAILED

    def test_a_commit_time_conflict_is_reported_as_a_duplicate(self):
        error = translate_transaction_error(
            integrity_error("UNIQUE constraint failed: users.email")
        )

        assert isinstance(error, DuplicateEntityError)
