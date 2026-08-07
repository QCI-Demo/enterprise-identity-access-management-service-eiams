"""Explicit transaction boundaries for multi-repository writes.

A unit of work hands out repositories that all read and write through one
session. The runner opens that session, commits it when the block finishes,
and rolls it back if anything raises, so a change spanning several entity
groups either lands completely or leaves no trace.
"""

from contextlib import contextmanager
from typing import Callable, Iterator, TypeVar

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from eiams.application.ports.repository import TransactionRunnerPort, UnitOfWorkPort
from eiams.shared.context import RequestContext, require_context

from .database import DatabaseManager
from .errors import translate_integrity_error, translate_transaction_error
from .repositories import (
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


Result = TypeVar("Result")

#: Repository classes reachable from a unit of work, keyed by accessor name.
_REPOSITORY_TYPES = {
    "tenants": SqlAlchemyTenantRepository,
    "users": SqlAlchemyUserRepository,
    "organizations": SqlAlchemyOrganizationRepository,
    "memberships": SqlAlchemyMembershipRepository,
    "roles": SqlAlchemyRoleRepository,
    "permissions": SqlAlchemyPermissionRepository,
    "role_assignments": SqlAlchemyRoleAssignmentRepository,
    "credentials": SqlAlchemyUserCredentialRepository,
    "sessions": SqlAlchemySessionRepository,
    "refresh_tokens": SqlAlchemyRefreshTokenRepository,
    "api_keys": SqlAlchemyApiKeyRepository,
    "oauth_clients": SqlAlchemyOAuthClientRepository,
    "audit_events": SqlAlchemyAuditEventRepository,
}


class SqlAlchemyUnitOfWork(UnitOfWorkPort):
    """Repositories sharing one session, and therefore one transaction."""

    def __init__(self, session: Session, context: RequestContext) -> None:
        """Bind a unit of work to a session and the context it serves."""
        self._session = session
        self._context = context
        self._repositories: dict[str, object] = {}

    @property
    def context(self) -> RequestContext:
        return self._context

    @property
    def session(self) -> Session:
        """The session every repository of this unit of work writes through."""
        return self._session

    @property
    def tenants(self) -> SqlAlchemyTenantRepository:
        return self._repository("tenants")

    @property
    def users(self) -> SqlAlchemyUserRepository:
        return self._repository("users")

    @property
    def organizations(self) -> SqlAlchemyOrganizationRepository:
        return self._repository("organizations")

    @property
    def memberships(self) -> SqlAlchemyMembershipRepository:
        return self._repository("memberships")

    @property
    def roles(self) -> SqlAlchemyRoleRepository:
        return self._repository("roles")

    @property
    def permissions(self) -> SqlAlchemyPermissionRepository:
        return self._repository("permissions")

    @property
    def role_assignments(self) -> SqlAlchemyRoleAssignmentRepository:
        return self._repository("role_assignments")

    @property
    def credentials(self) -> SqlAlchemyUserCredentialRepository:
        return self._repository("credentials")

    @property
    def sessions(self) -> SqlAlchemySessionRepository:
        return self._repository("sessions")

    @property
    def refresh_tokens(self) -> SqlAlchemyRefreshTokenRepository:
        return self._repository("refresh_tokens")

    @property
    def api_keys(self) -> SqlAlchemyApiKeyRepository:
        return self._repository("api_keys")

    @property
    def oauth_clients(self) -> SqlAlchemyOAuthClientRepository:
        return self._repository("oauth_clients")

    @property
    def audit_events(self) -> SqlAlchemyAuditEventRepository:
        return self._repository("audit_events")

    def flush(self) -> None:
        try:
            self._session.flush()
        except IntegrityError as error:
            raise translate_integrity_error(error, entity="record") from error
        except SQLAlchemyError as error:
            raise translate_transaction_error(error) from error

    def _repository(self, name: str):
        repository = self._repositories.get(name)
        if repository is None:
            repository = _REPOSITORY_TYPES[name](self._session)
            self._repositories[name] = repository
        return repository


class SqlAlchemyTransactionRunner(TransactionRunnerPort):
    """Runs units of work inside explicit transaction boundaries."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        """Create a runner that opens one session per transaction."""
        self._session_factory = session_factory

    @classmethod
    def from_manager(
        cls, manager: DatabaseManager
    ) -> "SqlAlchemyTransactionRunner":
        """Build a runner from a configured database manager."""
        return cls(manager.session_factory)

    @contextmanager
    def unit_of_work(
        self, context: RequestContext
    ) -> Iterator[SqlAlchemyUnitOfWork]:
        """Open a transaction, yield its unit of work, then commit or roll back.

        Args:
            context: Request context propagated to every repository.

        Yields:
            The unit of work bound to the open transaction.

        Raises:
            ContextError: If the context is missing or structurally invalid.
            TransactionError: If the commit itself fails.
            Exception: Anything the body raised, after the rollback.
        """
        require_context(context)
        session = self._session_factory()
        try:
            try:
                yield SqlAlchemyUnitOfWork(session, context)
            except BaseException:
                session.rollback()
                raise
            try:
                session.commit()
            except SQLAlchemyError as error:
                session.rollback()
                raise translate_transaction_error(error) from error
        finally:
            session.close()

    def run(
        self,
        context: RequestContext,
        work: Callable[[SqlAlchemyUnitOfWork], Result],
    ) -> Result:
        """Run a callable inside one transaction and return its result."""
        with self.unit_of_work(context) as uow:
            return work(uow)
