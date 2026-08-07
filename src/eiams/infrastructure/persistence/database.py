"""Database configuration and connection management.

Provides SQLAlchemy engine, session factory, and base model definitions
for the EIAMS persistence layer.
"""

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, MetaData
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


# Naming conventions for consistent constraint naming across databases
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models.
    
    Uses consistent naming conventions for all database constraints.
    """
    
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class DatabaseConfig:
    """Database configuration container."""
    
    def __init__(
        self,
        url: str = "sqlite:///:memory:",
        echo: bool = False,
        pool_pre_ping: bool = True,
    ) -> None:
        """Initialize database configuration.
        
        Args:
            url: Database connection URL.
            echo: If True, log all SQL statements.
            pool_pre_ping: If True, check connections before use.
        """
        self.url = url
        self.echo = echo
        self.pool_pre_ping = pool_pre_ping


class DatabaseManager:
    """Manages database engine and session lifecycle."""
    
    def __init__(self, config: DatabaseConfig) -> None:
        """Initialize database manager with configuration.
        
        Args:
            config: Database configuration settings.
        """
        self._config = config
        self._engine: Engine | None = None
        self._session_factory: sessionmaker[Session] | None = None
    
    @property
    def engine(self) -> Engine:
        """Get or create the database engine."""
        if self._engine is None:
            self._engine = create_engine(
                self._config.url,
                echo=self._config.echo,
                pool_pre_ping=self._config.pool_pre_ping,
            )
        return self._engine
    
    @property
    def session_factory(self) -> sessionmaker[Session]:
        """Get or create the session factory."""
        if self._session_factory is None:
            self._session_factory = sessionmaker(
                bind=self.engine,
                autocommit=False,
                autoflush=False,
            )
        return self._session_factory
    
    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """Create a context-managed database session.
        
        Yields:
            A SQLAlchemy Session that auto-commits on success
            and auto-rolls-back on exception.
        """
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def create_all_tables(self) -> None:
        """Create all tables defined in the Base metadata."""
        Base.metadata.create_all(self.engine)
    
    def drop_all_tables(self) -> None:
        """Drop all tables defined in the Base metadata."""
        Base.metadata.drop_all(self.engine)
    
    def dispose(self) -> None:
        """Dispose of the engine and all connections."""
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None
