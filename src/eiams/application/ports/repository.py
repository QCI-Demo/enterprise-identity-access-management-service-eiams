"""Persistence ports for repositories and transactional work.

The scope-aware repository contracts themselves live in the domain layer so
that domain services can depend on them directly. This module re-exports
them as ports and adds the boundaries that only the application layer needs:
a scoped unit of work grouping repositories that share one transaction, and
the runner that executes work inside explicit transaction boundaries.
"""

from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from typing import Callable, TypeVar

from eiams.domain.administration.contracts import TenantRepository
from eiams.domain.audit.contracts import AuditEventRepository
from eiams.domain.authentication.contracts import (
    RefreshTokenRepository,
    SessionRepository,
)
from eiams.domain.authorization.contracts import (
    PermissionRepository,
    RoleAssignmentRepository,
    RoleRepository,
)
from eiams.domain.base import (
    AppendOnlyRepository,
    PlatformScopedRepository,
    ReadableRepository,
    Repository,
    TenantScopedRepository,
)
from eiams.domain.credentials.contracts import (
    ApiKeyRepository,
    OAuthClientRepository,
    UserCredentialRepository,
)
from eiams.domain.identity.contracts import (
    MembershipRepository,
    OrganizationRepository,
    UserRepository,
)
from eiams.shared.context import RequestContext

from .base import OutputPort


Result = TypeVar("Result")


class UnitOfWorkPort(OutputPort, ABC):
    """A set of repositories sharing a single transaction boundary.

    Repositories reached through one unit of work read and write through the
    same session, so a multi-entity change either commits as a whole or
    leaves no trace.
    """

    @property
    @abstractmethod
    def context(self) -> RequestContext:
        """The request context this unit of work was opened for."""
        ...

    @property
    @abstractmethod
    def tenants(self) -> TenantRepository:
        """Platform-scoped tenant registry."""
        ...

    @property
    @abstractmethod
    def users(self) -> UserRepository:
        """Tenant-scoped user identities."""
        ...

    @property
    @abstractmethod
    def organizations(self) -> OrganizationRepository:
        """Tenant-scoped organizations."""
        ...

    @property
    @abstractmethod
    def memberships(self) -> MembershipRepository:
        """Tenant-scoped organization memberships."""
        ...

    @property
    @abstractmethod
    def roles(self) -> RoleRepository:
        """Tenant-scoped roles, including platform-shared system roles."""
        ...

    @property
    @abstractmethod
    def permissions(self) -> PermissionRepository:
        """Tenant-scoped permissions, including platform-shared permissions."""
        ...

    @property
    @abstractmethod
    def role_assignments(self) -> RoleAssignmentRepository:
        """Tenant-scoped role assignments."""
        ...

    @property
    @abstractmethod
    def credentials(self) -> UserCredentialRepository:
        """Tenant-scoped user credentials."""
        ...

    @property
    @abstractmethod
    def sessions(self) -> SessionRepository:
        """Tenant-scoped authentication sessions."""
        ...

    @property
    @abstractmethod
    def refresh_tokens(self) -> RefreshTokenRepository:
        """Tenant-scoped refresh tokens."""
        ...

    @property
    @abstractmethod
    def api_keys(self) -> ApiKeyRepository:
        """Tenant-scoped API keys."""
        ...

    @property
    @abstractmethod
    def oauth_clients(self) -> OAuthClientRepository:
        """Tenant-scoped OAuth clients."""
        ...

    @property
    @abstractmethod
    def audit_events(self) -> AuditEventRepository:
        """Append-only audit event store."""
        ...

    @abstractmethod
    def flush(self) -> None:
        """Send pending changes to the store without ending the transaction.

        Raises:
            RepositoryError: If the pending changes violate an integrity rule.
        """
        ...


class TransactionRunnerPort(OutputPort, ABC):
    """Executes units of work inside explicit transaction boundaries."""

    @abstractmethod
    def unit_of_work(
        self, context: RequestContext
    ) -> AbstractContextManager[UnitOfWorkPort]:
        """Open a transaction and yield the unit of work bound to it.

        The transaction commits when the block exits normally and rolls back
        if it raises, so a failure part-way through a multi-entity change
        leaves no partial state behind.

        Args:
            context: Request context propagated to every repository.

        Returns:
            A context manager yielding the scoped unit of work.
        """
        ...

    @abstractmethod
    def run(
        self,
        context: RequestContext,
        work: Callable[[UnitOfWorkPort], Result],
    ) -> Result:
        """Run a callable inside one transaction and return its result.

        Args:
            context: Request context propagated to every repository.
            work: Callable receiving the scoped unit of work.

        Returns:
            Whatever the callable returned, after the commit succeeded.

        Raises:
            Exception: Whatever the callable raised, after the rollback.
        """
        ...


__all__ = [
    "Repository",
    "ReadableRepository",
    "PlatformScopedRepository",
    "TenantScopedRepository",
    "AppendOnlyRepository",
    "UnitOfWorkPort",
    "TransactionRunnerPort",
]
