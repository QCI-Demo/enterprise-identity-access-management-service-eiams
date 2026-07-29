"""Transaction boundary ports.

Application services declare their transactional intent through these
ports. Infrastructure supplies the concrete unit of work bound to the
underlying store.
"""

from abc import ABC, abstractmethod
from types import TracebackType
from typing import Protocol


class UnitOfWork(ABC):
    """A single transactional scope.

    Used as a context manager: leaving the block without an explicit
    commit rolls back, so a failed or abandoned operation never leaves
    partial state behind.
    """

    @abstractmethod
    def commit(self) -> None:
        """Commit the work performed in this scope."""
        ...

    @abstractmethod
    def rollback(self) -> None:
        """Discard the work performed in this scope."""
        ...

    @property
    @abstractmethod
    def is_active(self) -> bool:
        """Whether the scope is still open."""
        ...

    def __enter__(self) -> "UnitOfWork":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.is_active:
            self.rollback()


class UnitOfWorkFactory(Protocol):
    """Factory that opens a new transactional scope."""

    def __call__(self) -> UnitOfWork:
        """Open a new unit of work."""
        ...
