"""Test fixtures for persistence integration tests.

Provides isolated database fixtures for migration testing.
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import Session, sessionmaker

from eiams.infrastructure.persistence.database import Base, DatabaseConfig, DatabaseManager

# Import all models to register them with Base.metadata
from eiams.infrastructure.persistence.models import (  # noqa: F401
    Tenant,
    Organization,
    User,
    Membership,
    Permission,
    Role,
    RolePermission,
    RoleAssignment,
    UserCredential,
    OAuthClient,
    ApiKey,
    Session as SessionModel,
    RefreshToken,
    AuditEvent,
)


from sqlalchemy import event

def _set_sqlite_pragma(dbapi_conn, connection_record):
    """Enable foreign key enforcement in SQLite."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@pytest.fixture
def in_memory_db():
    """Create an isolated in-memory SQLite database with FK enforcement."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    event.listen(engine, "connect", _set_sqlite_pragma)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(in_memory_db):
    """Create a database session for testing."""
    SessionLocal = sessionmaker(bind=in_memory_db, autocommit=False, autoflush=False)
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def db_manager():
    """Create a DatabaseManager with in-memory SQLite and FK enforcement."""
    config = DatabaseConfig(url="sqlite:///:memory:")
    manager = DatabaseManager(config)
    
    # Enable foreign key enforcement
    event.listen(manager.engine, "connect", _set_sqlite_pragma)
    
    manager.create_all_tables()
    yield manager
    manager.dispose()


@pytest.fixture
def sample_tenant_id():
    """Generate a sample tenant ID."""
    return str(uuid4())


@pytest.fixture
def sample_user_id():
    """Generate a sample user ID."""
    return str(uuid4())


@pytest.fixture
def sample_org_id():
    """Generate a sample organization ID."""
    return str(uuid4())


@pytest.fixture
def now():
    """Current UTC timestamp."""
    return datetime.now(timezone.utc)


@pytest.fixture
def future_time(now):
    """Future timestamp (1 hour from now)."""
    return now + timedelta(hours=1)


def get_table_names(engine) -> set:
    """Get all table names from the database."""
    inspector = inspect(engine)
    return set(inspector.get_table_names())


def get_index_names(engine, table_name: str) -> set:
    """Get all index names for a table."""
    inspector = inspect(engine)
    return {idx["name"] for idx in inspector.get_indexes(table_name)}


def get_foreign_keys(engine, table_name: str) -> list:
    """Get all foreign keys for a table."""
    inspector = inspect(engine)
    return inspector.get_foreign_keys(table_name)


def get_unique_constraints(engine, table_name: str) -> list:
    """Get all unique constraints for a table."""
    inspector = inspect(engine)
    return inspector.get_unique_constraints(table_name)


def get_columns(engine, table_name: str) -> dict:
    """Get all columns for a table."""
    inspector = inspect(engine)
    return {col["name"]: col for col in inspector.get_columns(table_name)}
