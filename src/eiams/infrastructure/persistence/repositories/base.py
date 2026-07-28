"""SQLAlchemy repository bases enforcing scope before any data access.

Three bases cover the scopes the contracts define:

``PlatformScopedSqlRepository``
    For entity groups the schema places outside any tenant. It still
    requires an authenticated caller.

``TenantScopedSqlRepository``
    Resolves tenant scope from the request context and binds the resulting
    predicate to the statement before any caller-supplied criterion is
    appended. Writes additionally verify that the entity being written is
    owned by the tenant in context, and stamp the tenant column from the
    context rather than from the incoming entity, so a forged tenant value
    cannot place a row in another tenant.

``AppendOnlySqlRepository``
    Tenant scoped reads plus a single append primitive. There is no update
    or delete path to reach.

Absent tenant context is never treated as "no filter": every tenant-scoped
operation fails closed before a statement is built.
"""

from typing import Any, ClassVar, Generic, Sequence, TypeVar

from sqlalchemy import Select, func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from eiams.domain.base import (
    AppendOnlyRepository,
    PlatformScopedRepository,
    TenantScopedRepository,
)
from eiams.shared.context import (
    RequestContext,
    TenantPredicate,
    assert_tenant_match,
    build_tenant_predicate,
    require_platform_scope,
)
from eiams.shared.errors import (
    EntityNotFoundError,
    TenantMismatchError,
    ValidationError,
)

from ..errors import translate_database_error, translate_integrity_error
from ..mappers.base import EntityMapper, identifier


Entity = TypeVar("Entity")
Identifier = TypeVar("Identifier")
Model = TypeVar("Model")

#: Upper bound on a single page, so a caller cannot request an unbounded read.
MAX_PAGE_SIZE = 500


class SqlAlchemyRepository(Generic[Entity, Identifier, Model]):
    """Shared statement building and error handling for all repositories."""

    #: ORM model backing this repository.
    __model__: ClassVar[Any]
    #: Mapper converting between rows and domain entities.
    __mapper__: ClassVar[EntityMapper]
    #: Caller-facing name of the entity group, used in error messages.
    __entity_name__: ClassVar[str]
    #: Column rows are ordered by, newest first.
    __order_column__: ClassVar[str] = "created_at"
    #: Loader options applied to every read, keeping mapping session free.
    __load_options__: ClassVar[tuple] = ()

    def __init__(self, session: Session) -> None:
        """Bind the repository to the session of the current unit of work."""
        self._session = session

    @property
    def session(self) -> Session:
        """The session this repository reads and writes through."""
        return self._session

    @property
    def entity_name(self) -> str:
        """Caller-facing name of the entity group."""
        return self.__entity_name__

    def _select(self) -> Select:
        """Start a statement with the repository's standard loader options."""
        statement = select(self.__model__)
        if self.__load_options__:
            statement = statement.options(*self.__load_options__)
        return statement

    def _ordered(self, statement: Select) -> Select:
        order_column = getattr(self.__model__, self.__order_column__)
        return statement.order_by(order_column.desc(), self.__model__.id)

    def _paginated(self, statement: Select, offset: int, limit: int) -> Select:
        offset, limit = self._validate_page(offset, limit)
        return statement.offset(offset).limit(limit)

    @staticmethod
    def _validate_page(offset: int, limit: int) -> tuple[int, int]:
        """Reject page arguments that would widen a read beyond its bounds."""
        if offset < 0:
            raise ValidationError("Offset must not be negative", field="offset")
        if limit < 1:
            raise ValidationError("Limit must be at least 1", field="limit")
        if limit > MAX_PAGE_SIZE:
            raise ValidationError(
                f"Limit must not exceed {MAX_PAGE_SIZE}",
                field="limit",
                details={"max_limit": MAX_PAGE_SIZE},
            )
        return offset, limit

    def _execute(self, statement: Select):
        """Run a statement, keeping driver failures out of the caller's lap."""
        try:
            return self._session.execute(statement)
        except SQLAlchemyError as error:
            raise translate_database_error(
                error, entity=self.__entity_name__
            ) from error

    def _rows(self, statement: Select) -> Sequence[Model]:
        return self._execute(statement).scalars().all()

    def _first_row(self, statement: Select) -> Model | None:
        return self._execute(statement).scalars().first()

    def _entities(self, rows: Sequence[Model]) -> list[Entity]:
        return [self.__mapper__.to_entity(row) for row in rows]

    def _count(self, clause: ColumnElement | None = None) -> int:
        statement = select(func.count()).select_from(self.__model__)
        if clause is not None:
            statement = statement.where(clause)
        return int(self._execute(statement).scalar_one())

    def _flush(self) -> None:
        """Push pending changes so violations surface as domain errors."""
        try:
            self._session.flush()
        except IntegrityError as error:
            raise translate_integrity_error(
                error, entity=self.__entity_name__
            ) from error
        except SQLAlchemyError as error:
            raise translate_database_error(
                error, entity=self.__entity_name__
            ) from error

    def _not_found(self, entity_id: Identifier) -> EntityNotFoundError:
        return EntityNotFoundError(
            f"No {self.__entity_name__} found in the caller's scope",
            entity=self.__entity_name__,
            entity_id=identifier(entity_id),
        )


class PlatformScopedSqlRepository(
    PlatformScopedRepository[Entity, Identifier],
    SqlAlchemyRepository[Entity, Identifier, Model],
):
    """Base for repositories over entity groups that have no tenant owner."""

    def find_by_id(
        self, context: RequestContext, entity_id: Identifier
    ) -> Entity | None:
        row = self._find_row(context, entity_id)
        return None if row is None else self.__mapper__.to_entity(row)

    def exists(self, context: RequestContext, entity_id: Identifier) -> bool:
        return self._find_row(context, entity_id) is not None

    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[Entity]:
        statement = self._paginated(
            self._ordered(self._platform_select(context)), offset, limit
        )
        return self._entities(self._rows(statement))

    def count(self, context: RequestContext) -> int:
        require_platform_scope(context, operation=self.__entity_name__)
        return self._count()

    def add(self, context: RequestContext, entity: Entity) -> Entity:
        require_platform_scope(context, operation=self.__entity_name__)
        row = self.__mapper__.to_model(entity)
        self._session.add(row)
        self._flush()
        return self.__mapper__.to_entity(row)

    def update(self, context: RequestContext, entity: Entity) -> Entity:
        row = self._find_row(context, entity.id)
        if row is None:
            raise self._not_found(entity.id)
        self.__mapper__.apply(entity, row)
        self._flush()
        return self.__mapper__.to_entity(row)

    def save(self, context: RequestContext, entity: Entity) -> Entity:
        row = self._find_row(context, entity.id)
        if row is None:
            return self.add(context, entity)
        self.__mapper__.apply(entity, row)
        self._flush()
        return self.__mapper__.to_entity(row)

    def delete(self, context: RequestContext, entity_id: Identifier) -> bool:
        row = self._find_row(context, entity_id)
        if row is None:
            return False
        self._session.delete(row)
        self._flush()
        return True

    def _platform_select(self, context: RequestContext) -> Select:
        """Start a statement for a caller allowed to cross tenant boundaries."""
        require_platform_scope(context, operation=self.__entity_name__)
        return self._select()

    def _find_row(
        self, context: RequestContext, entity_id: Identifier
    ) -> Model | None:
        statement = self._platform_select(context).where(
            self.__model__.id == identifier(entity_id)
        )
        return self._first_row(statement)


class TenantScopedSqlRepository(
    TenantScopedRepository[Entity, Identifier],
    SqlAlchemyRepository[Entity, Identifier, Model],
):
    """Base for repositories confined to the tenant in the request context."""

    #: Column carrying tenant ownership on the backing table.
    __tenant_column__: ClassVar[str] = "tenant_id"
    #: Whether rows with no tenant owner form a platform-shared catalogue
    #: that every tenant may read. Writes never include them.
    __shared_rows__: ClassVar[bool] = False

    def tenant_predicate(self, context: RequestContext) -> TenantPredicate:
        return build_tenant_predicate(
            context,
            self.__tenant_column__,
            include_shared=self.__shared_rows__,
            operation=self.__entity_name__,
        )

    def find_by_id(
        self, context: RequestContext, entity_id: Identifier
    ) -> Entity | None:
        row = self._find_row(context, entity_id)
        return None if row is None else self.__mapper__.to_entity(row)

    def exists(self, context: RequestContext, entity_id: Identifier) -> bool:
        return self._find_row(context, entity_id) is not None

    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[Entity]:
        statement = self._paginated(
            self._ordered(self._scoped_select(context)), offset, limit
        )
        return self._entities(self._rows(statement))

    def count(self, context: RequestContext) -> int:
        return self._count(self._tenant_clause(self.tenant_predicate(context)))

    def add(self, context: RequestContext, entity: Entity) -> Entity:
        predicate = self._write_predicate(context)
        self._assert_writable(context, entity)
        row = self.__mapper__.to_model(entity)
        # The owning tenant comes from the validated context, never from the
        # incoming entity, so a forged value cannot land in another tenant.
        setattr(row, predicate.column, predicate.value)
        self._session.add(row)
        self._flush()
        return self.__mapper__.to_entity(row)

    def update(self, context: RequestContext, entity: Entity) -> Entity:
        self._assert_writable(context, entity)
        row = self._find_row(context, entity.id, for_write=True)
        if row is None:
            raise self._not_found(entity.id)
        self.__mapper__.apply(entity, row)
        self._flush()
        return self.__mapper__.to_entity(row)

    def save(self, context: RequestContext, entity: Entity) -> Entity:
        self._assert_writable(context, entity)
        row = self._find_row(context, entity.id, for_write=True)
        if row is None:
            return self.add(context, entity)
        self.__mapper__.apply(entity, row)
        self._flush()
        return self.__mapper__.to_entity(row)

    def delete(self, context: RequestContext, entity_id: Identifier) -> bool:
        row = self._find_row(context, entity_id, for_write=True)
        if row is None:
            return False
        self._session.delete(row)
        self._flush()
        return True

    def _tenant_clause(self, predicate: TenantPredicate) -> ColumnElement:
        """Translate a tenant predicate into a filter on the backing table."""
        column = getattr(self.__model__, predicate.column)
        clause = column == predicate.value
        if predicate.include_shared:
            return or_(clause, column.is_(None))
        return clause

    def _write_predicate(self, context: RequestContext) -> TenantPredicate:
        return self.tenant_predicate(context).for_write()

    def _scoped_select(
        self, context: RequestContext, *, for_write: bool = False
    ) -> Select:
        """Start a statement with the tenant predicate already bound.

        Subclasses append their own criteria to the result, which means the
        tenant filter is part of every statement they can build.
        """
        predicate = self.tenant_predicate(context)
        if for_write:
            predicate = predicate.for_write()
        return self._select().where(self._tenant_clause(predicate))

    def _find_row(
        self,
        context: RequestContext,
        entity_id: Identifier,
        *,
        for_write: bool = False,
    ) -> Model | None:
        statement = self._scoped_select(context, for_write=for_write).where(
            self.__model__.id == identifier(entity_id)
        )
        return self._first_row(statement)

    def _require_row(
        self,
        context: RequestContext,
        entity_id: Identifier,
        *,
        for_write: bool = False,
    ) -> Model:
        row = self._find_row(context, entity_id, for_write=for_write)
        if row is None:
            raise self._not_found(entity_id)
        return row

    def _assert_writable(self, context: RequestContext, entity: Entity) -> None:
        """Reject a write whose entity is not owned by the context tenant."""
        owner = getattr(entity, "tenant_id", None)
        entity_id = getattr(entity, "id", None)
        if owner is None and self.__shared_rows__:
            raise TenantMismatchError(
                f"Platform-shared {self.__entity_name__} records cannot be "
                "written through a tenant-scoped repository",
                expected_tenant_id=self.tenant_predicate(context).value,
                resource_type=self.__entity_name__,
                resource_id=None if entity_id is None else identifier(entity_id),
            )
        assert_tenant_match(
            context,
            owner,
            resource_type=self.__entity_name__,
            resource_id=None if entity_id is None else identifier(entity_id),
        )


class AppendOnlySqlRepository(
    AppendOnlyRepository[Entity, Identifier],
    SqlAlchemyRepository[Entity, Identifier, Model],
):
    """Base for tenant-scoped stores whose rows are immutable once written."""

    __tenant_column__: ClassVar[str] = "tenant_id"

    def tenant_predicate(self, context: RequestContext) -> TenantPredicate:
        return build_tenant_predicate(
            context,
            self.__tenant_column__,
            operation=self.__entity_name__,
        )

    def append(self, context: RequestContext, entity: Entity) -> Entity:
        predicate = self.tenant_predicate(context)
        self._assert_writable(context, entity)
        row = self.__mapper__.to_model(entity)
        setattr(row, predicate.column, predicate.value)
        self._session.add(row)
        self._flush()
        return self.__mapper__.to_entity(row)

    def find_by_id(
        self, context: RequestContext, entity_id: Identifier
    ) -> Entity | None:
        statement = self._scoped_select(context).where(
            self.__model__.id == identifier(entity_id)
        )
        row = self._first_row(statement)
        return None if row is None else self.__mapper__.to_entity(row)

    def exists(self, context: RequestContext, entity_id: Identifier) -> bool:
        return self.find_by_id(context, entity_id) is not None

    def find_all(
        self, context: RequestContext, offset: int = 0, limit: int = 100
    ) -> list[Entity]:
        statement = self._paginated(
            self._ordered(self._scoped_select(context)), offset, limit
        )
        return self._entities(self._rows(statement))

    def count(self, context: RequestContext) -> int:
        return self._count(self._tenant_clause(self.tenant_predicate(context)))

    def _tenant_clause(self, predicate: TenantPredicate) -> ColumnElement:
        return getattr(self.__model__, predicate.column) == predicate.value

    def _scoped_select(self, context: RequestContext) -> Select:
        predicate = self.tenant_predicate(context)
        return self._select().where(self._tenant_clause(predicate))

    def _assert_writable(self, context: RequestContext, entity: Entity) -> None:
        owner = getattr(entity, "tenant_id", None)
        if owner is None:
            # An entity with no tenant is stamped with the context tenant on
            # append; there is nothing to mismatch.
            return
        entity_id = getattr(entity, "id", None)
        assert_tenant_match(
            context,
            owner,
            resource_type=self.__entity_name__,
            resource_id=None if entity_id is None else identifier(entity_id),
        )
