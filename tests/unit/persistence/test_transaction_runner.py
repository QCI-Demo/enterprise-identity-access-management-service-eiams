"""Tests for transaction boundary handling around failing sessions.

Commit and flush failures are hard to provoke against a real database
because the repositories flush eagerly, so these tests drive the runner
with a session that fails on demand and check what it does with the
transaction afterwards.
"""

from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError, OperationalError

from eiams.infrastructure.persistence.transaction import (
    SqlAlchemyTransactionRunner,
    SqlAlchemyUnitOfWork,
)
from eiams.shared.context import RequestContextFactory
from eiams.shared.errors import DuplicateEntityError, TransactionError


class FailingSession:
    """Minimal stand-in for a session that fails where a test asks it to."""

    def __init__(
        self,
        *,
        commit_error: Exception | None = None,
        flush_error: Exception | None = None,
    ) -> None:
        self._commit_error = commit_error
        self._flush_error = flush_error
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def commit(self) -> None:
        if self._commit_error is not None:
            raise self._commit_error
        self.committed = True

    def flush(self) -> None:
        if self._flush_error is not None:
            raise self._flush_error

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def context():
    return RequestContextFactory.create(
        actor_id=str(uuid4()), tenant_id=str(uuid4())
    )


def operational_error(message: str) -> OperationalError:
    return OperationalError("SELECT 1", {}, Exception(message))


def integrity_error(message: str) -> IntegrityError:
    return IntegrityError("INSERT INTO users", {}, Exception(message))


class TestCommitFailures:
    """A commit that fails rolls back and reports a transaction error."""

    def test_failure_is_reported_as_a_transaction_error(self, context):
        session = FailingSession(
            commit_error=operational_error("database is locked")
        )
        runner = SqlAlchemyTransactionRunner(lambda: session)

        with pytest.raises(TransactionError):
            with runner.unit_of_work(context):
                pass

    def test_failure_rolls_back_and_closes_the_session(self, context):
        session = FailingSession(
            commit_error=operational_error("database is locked")
        )
        runner = SqlAlchemyTransactionRunner(lambda: session)

        with pytest.raises(TransactionError):
            with runner.unit_of_work(context):
                pass

        assert session.rolled_back is True
        assert session.closed is True

    def test_a_conflict_detected_at_commit_is_reported_as_a_duplicate(
        self, context
    ):
        session = FailingSession(
            commit_error=integrity_error("UNIQUE constraint failed: users.email")
        )
        runner = SqlAlchemyTransactionRunner(lambda: session)

        with pytest.raises(DuplicateEntityError):
            with runner.unit_of_work(context):
                pass

    def test_the_driver_message_does_not_reach_the_caller(self, context):
        session = FailingSession(
            commit_error=operational_error("no such column: users.secret")
        )
        runner = SqlAlchemyTransactionRunner(lambda: session)

        with pytest.raises(TransactionError) as caught:
            with runner.unit_of_work(context):
                pass

        assert "no such column" not in str(caught.value.to_dict())


class TestBodyFailures:
    """A body that raises rolls back and lets the original error through."""

    def test_the_original_error_propagates(self, context):
        session = FailingSession()
        runner = SqlAlchemyTransactionRunner(lambda: session)

        with pytest.raises(ZeroDivisionError):
            with runner.unit_of_work(context):
                raise ZeroDivisionError("business rule failed")

        assert session.rolled_back is True
        assert session.committed is False
        assert session.closed is True

    def test_a_successful_body_commits_and_closes(self, context):
        session = FailingSession()
        runner = SqlAlchemyTransactionRunner(lambda: session)

        with runner.unit_of_work(context):
            pass

        assert session.committed is True
        assert session.rolled_back is False
        assert session.closed is True


class TestFlushFailures:
    """An explicit flush classifies failures the same way a write does."""

    def test_a_conflict_is_reported_as_a_duplicate(self, context):
        session = FailingSession(
            flush_error=integrity_error("UNIQUE constraint failed: users.email")
        )

        with pytest.raises(DuplicateEntityError):
            SqlAlchemyUnitOfWork(session, context).flush()

    def test_other_failures_are_reported_as_transaction_errors(self, context):
        session = FailingSession(flush_error=operational_error("disk I/O error"))

        with pytest.raises(TransactionError):
            SqlAlchemyUnitOfWork(session, context).flush()


class TestUnitOfWorkContext:
    """The unit of work carries the context it was opened for."""

    def test_context_is_exposed(self, context):
        session = FailingSession()
        runner = SqlAlchemyTransactionRunner(lambda: session)

        with runner.unit_of_work(context) as uow:
            assert uow.context is context
            assert uow.session is session
