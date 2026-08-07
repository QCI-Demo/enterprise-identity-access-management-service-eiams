"""Translation of driver exceptions into framework-isolated errors.

Callers of a repository must never receive a SQLAlchemy exception: driver
messages carry SQL text, table names, and sometimes row values, none of
which belong in an error that may be logged or serialized towards a client.
Everything raised out of the persistence adapters therefore passes through
this module first.
"""

import re

from sqlalchemy.exc import DBAPIError, IntegrityError, SQLAlchemyError

from eiams.shared.errors import (
    DuplicateEntityError,
    IntegrityViolationError,
    RepositoryError,
    TransactionError,
)


# SQLite reports the offending columns inline; other drivers use SQLSTATE.
_SQLITE_UNIQUE = re.compile(r"UNIQUE constraint failed:\s*(?P<columns>[^\n]+)")
_SQLITE_FOREIGN_KEY = "FOREIGN KEY constraint failed"
_SQLITE_NOT_NULL = "NOT NULL constraint failed"
_SQLITE_CHECK = "CHECK constraint failed"

_SQLSTATE_UNIQUE_VIOLATION = "23505"
_SQLSTATE_INTEGRITY_CLASS = "23"


def _sqlstate(error: DBAPIError) -> str | None:
    """Read the SQLSTATE code from a driver exception, if it exposes one."""
    orig = getattr(error, "orig", None)
    code = getattr(orig, "pgcode", None) or getattr(orig, "sqlstate", None)
    return str(code) if code else None


def _conflicting_fields(message: str) -> tuple[str, ...]:
    """Extract the column names a uniqueness violation names, if any."""
    match = _SQLITE_UNIQUE.search(message)
    if not match:
        return ()
    columns = []
    for raw in match.group("columns").split(","):
        column = raw.strip().split(".")[-1]
        if column:
            columns.append(column)
    return tuple(columns)


def _is_unique_violation(error: IntegrityError, message: str) -> bool:
    if _SQLITE_UNIQUE.search(message):
        return True
    return _sqlstate(error) == _SQLSTATE_UNIQUE_VIOLATION


def translate_integrity_error(
    error: IntegrityError, *, entity: str
) -> RepositoryError:
    """Map an integrity violation onto a caller-safe repository error.

    Args:
        error: The driver exception raised during flush or commit.
        entity: Name of the entity group the write targeted.

    Returns:
        A DuplicateEntityError for uniqueness violations, otherwise an
        IntegrityViolationError. Neither carries the driver message.
    """
    message = str(getattr(error, "orig", error))

    if _is_unique_violation(error, message):
        return DuplicateEntityError(
            f"A {entity} with the same unique attributes already exists",
            entity=entity,
            conflicting_fields=_conflicting_fields(message) or None,
        )

    sqlstate = _sqlstate(error) or ""
    if _SQLITE_FOREIGN_KEY in message or sqlstate.startswith(
        _SQLSTATE_INTEGRITY_CLASS
    ):
        return IntegrityViolationError(
            f"Operation on {entity} violates a referential integrity rule",
            entity=entity,
        )
    if _SQLITE_NOT_NULL in message:
        return IntegrityViolationError(
            f"Operation on {entity} is missing a required attribute",
            entity=entity,
        )
    if _SQLITE_CHECK in message:
        return IntegrityViolationError(
            f"Operation on {entity} violates a value constraint",
            entity=entity,
        )
    return IntegrityViolationError(
        f"Operation on {entity} violates a data integrity rule",
        entity=entity,
    )


def translate_database_error(
    error: SQLAlchemyError, *, entity: str | None = None
) -> RepositoryError:
    """Map any other database failure onto a caller-safe repository error."""
    if isinstance(error, IntegrityError):
        return translate_integrity_error(error, entity=entity or "record")
    return RepositoryError("The data store rejected the operation", entity=entity)


def translate_transaction_error(error: SQLAlchemyError) -> RepositoryError:
    """Map a commit or rollback failure onto a caller-safe error."""
    if isinstance(error, IntegrityError):
        return translate_integrity_error(error, entity="record")
    return TransactionError("The transaction could not be completed")
