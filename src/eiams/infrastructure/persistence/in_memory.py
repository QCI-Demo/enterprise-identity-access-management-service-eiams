"""In-memory persistence adapters.

Tenant-scoped, process-local implementations of the repository and unit of
work contracts. They back local development and tests until the database
adapters land, and they enforce the same tenant isolation rules as any
other adapter: every read and write requires tenant context.
"""

from __future__ import annotations

from typing import Iterable

from eiams.shared.context import RequestContext, require_tenant
from eiams.shared.kernel import TenantId, Timestamp
from eiams.application.ports.transaction import UnitOfWork
from eiams.domain.audit.contracts import (
    AuditEvent,
    AuditEventId,
    AuditEventRepository,
    AuditEventType,
)
from eiams.domain.credentials.contracts import (
    PasswordCredentialId,
    PasswordCredentialRepository,
    StoredPasswordCredential,
)
from eiams.domain.identity.contracts import User, UserId, UserRepository


class InMemoryUnitOfWork(UnitOfWork):
    """Unit of work that records transaction outcomes.

    The in-memory stores apply writes immediately, so this scope tracks
    commit and rollback signals rather than buffering state. It still
    enforces the contract that a scope is used exactly once.
    """

    def __init__(self) -> None:
        self._active = True
        self._committed = False
        self._rolled_back = False

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def committed(self) -> bool:
        """Whether the scope was committed."""
        return self._committed

    @property
    def rolled_back(self) -> bool:
        """Whether the scope was rolled back."""
        return self._rolled_back

    def commit(self) -> None:
        if not self._active:
            raise RuntimeError("Unit of work is no longer active")
        self._committed = True
        self._active = False

    def rollback(self) -> None:
        if not self._active:
            return
        self._rolled_back = True
        self._active = False


class InMemoryUnitOfWorkFactory:
    """Factory that opens in-memory units of work and retains them."""

    def __init__(self) -> None:
        self._scopes: list[InMemoryUnitOfWork] = []

    def __call__(self) -> InMemoryUnitOfWork:
        scope = InMemoryUnitOfWork()
        self._scopes.append(scope)
        return scope

    @property
    def scopes(self) -> tuple[InMemoryUnitOfWork, ...]:
        """All scopes opened by this factory, in order."""
        return tuple(self._scopes)


class InMemoryUserRepository(UserRepository):
    """Tenant-scoped in-memory user repository."""

    def __init__(self, users: Iterable[User] | None = None) -> None:
        self._users: dict[str, User] = {}
        for user in users or ():
            self._users[str(user.user_id)] = user

    def find_by_id(self, context: RequestContext, entity_id: UserId) -> User | None:
        require_tenant(context)
        user = self._users.get(str(entity_id))
        return user if self._in_scope(context, user) else None

    def find_by_email(self, context: RequestContext, email: str) -> User | None:
        require_tenant(context)
        normalized = (email or "").strip().lower()
        if not normalized:
            return None
        for user in self._users.values():
            if user.email.strip().lower() == normalized and self._in_scope(
                context, user
            ):
                return user
        return None

    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[User]:
        require_tenant(context)
        scoped = [u for u in self._users.values() if self._in_scope(context, u)]
        return scoped[offset : offset + limit]

    def count(self, context: RequestContext) -> int:
        require_tenant(context)
        return len([u for u in self._users.values() if self._in_scope(context, u)])

    def save(self, context: RequestContext, entity: User) -> User:
        require_tenant(context)
        self._users[str(entity.user_id)] = entity
        return entity

    def delete(self, context: RequestContext, entity_id: UserId) -> bool:
        require_tenant(context)
        user = self._users.get(str(entity_id))
        if not self._in_scope(context, user):
            return False
        del self._users[str(entity_id)]
        return True

    @staticmethod
    def _in_scope(context: RequestContext, user: User | None) -> bool:
        """Whether the entity belongs to the context's tenant."""
        return user is not None and user.tenant_id == context.tenant_id


class InMemoryPasswordCredentialRepository(PasswordCredentialRepository):
    """Tenant-scoped in-memory password credential repository."""

    def __init__(
        self, credentials: Iterable[StoredPasswordCredential] | None = None
    ) -> None:
        self._credentials: dict[str, StoredPasswordCredential] = {}
        for credential in credentials or ():
            self._credentials[str(credential.credential_id)] = credential

    def find_by_id(
        self, context: RequestContext, entity_id: PasswordCredentialId
    ) -> StoredPasswordCredential | None:
        require_tenant(context)
        credential = self._credentials.get(str(entity_id))
        return credential if self._in_scope(context, credential) else None

    def find_active_by_user(
        self, context: RequestContext, user_id: UserId
    ) -> StoredPasswordCredential | None:
        require_tenant(context)
        for credential in self._credentials.values():
            if (
                credential.user_id == user_id
                and credential.is_active
                and self._in_scope(context, credential)
            ):
                return credential
        return None

    def save(
        self, context: RequestContext, entity: StoredPasswordCredential
    ) -> StoredPasswordCredential:
        require_tenant(context)
        self._credentials[str(entity.credential_id)] = entity
        return entity

    def delete(
        self, context: RequestContext, entity_id: PasswordCredentialId
    ) -> bool:
        require_tenant(context)
        credential = self._credentials.get(str(entity_id))
        if not self._in_scope(context, credential):
            return False
        del self._credentials[str(entity_id)]
        return True

    @staticmethod
    def _in_scope(
        context: RequestContext, credential: StoredPasswordCredential | None
    ) -> bool:
        """Whether the credential belongs to the context's tenant."""
        return credential is not None and credential.tenant_id == context.tenant_id


class InMemoryAuditEventRepository(AuditEventRepository):
    """Append-only in-memory audit event repository."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        """All recorded events in insertion order."""
        return tuple(self._events)

    def clear(self) -> None:
        """Remove all recorded events. Intended for test setup."""
        self._events.clear()

    def save(self, context: RequestContext, entity: AuditEvent) -> AuditEvent:
        self._events.append(entity)
        return entity

    def find_by_id(
        self, context: RequestContext, entity_id: AuditEventId
    ) -> AuditEvent | None:
        for event in self._events:
            if event.audit_event_id == entity_id:
                return event
        return None

    def delete(self, context: RequestContext, entity_id: AuditEventId) -> bool:
        raise NotImplementedError("Audit events are append-only")

    def find_by_actor(
        self,
        context: RequestContext,
        actor_id: str,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        matches = [e for e in self._events if e.actor_id == actor_id]
        return matches[offset : offset + limit]

    def find_by_event_type(
        self,
        context: RequestContext,
        event_type: AuditEventType,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        matches = [e for e in self._events if e.event_type == event_type]
        return matches[offset : offset + limit]

    def find_by_correlation_id(
        self,
        context: RequestContext,
        correlation_id: str,
    ) -> list[AuditEvent]:
        return [e for e in self._events if e.correlation_id_value == correlation_id]

    def find_by_time_range(
        self,
        context: RequestContext,
        start: Timestamp,
        end: Timestamp,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        matches = [e for e in self._events if start <= e.timestamp <= end]
        return matches[offset : offset + limit]

    def find_by_resource(
        self,
        context: RequestContext,
        resource_type: str,
        resource_id: str,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        matches = [
            e
            for e in self._events
            if e.resource_type == resource_type and e.resource_id == resource_id
        ]
        return matches[offset : offset + limit]

    def find_by_tenant(self, tenant_id: TenantId) -> list[AuditEvent]:
        """Find events recorded for a tenant."""
        return [e for e in self._events if e.tenant_id == tenant_id]
