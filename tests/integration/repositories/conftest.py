"""Fixtures for repository integration tests.

The schema under test is the one the executable migrations produce: the
migrations are run once into a template database, and each test works on a
private copy of that file. Nothing here creates tables from ORM metadata, so
a repository that relies on a column the migrations do not create will fail.
"""

import shutil
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from eiams.infrastructure.persistence.transaction import (
    SqlAlchemyTransactionRunner,
)
from eiams.shared.context import RequestContext, RequestContextFactory

from .factories import build_tenant, new_id


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS_PATH = (
    REPOSITORY_ROOT / "src" / "eiams" / "infrastructure" / "persistence" / "migrations"
)
#: Revision the migrations are expected to end at.
HEAD_REVISION = "014_audit_events"


def _alembic_config(database_url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_PATH))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _enable_foreign_keys(dbapi_connection, connection_record) -> None:
    """SQLite only enforces foreign keys when asked to, per connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@pytest.fixture(scope="session")
def migrated_template(tmp_path_factory) -> Path:
    """Run the migrations once and keep the result as a template database."""
    template = tmp_path_factory.mktemp("eiams-schema") / "template.db"
    command.upgrade(_alembic_config(f"sqlite:///{template}"), "head")
    return template


@pytest.fixture
def engine(migrated_template, tmp_path):
    """An isolated database carrying the migrated schema."""
    database = tmp_path / "eiams.db"
    shutil.copyfile(migrated_template, database)

    engine = create_engine(f"sqlite:///{database}")
    event.listen(engine, "connect", _enable_foreign_keys)
    yield engine
    engine.dispose()


@pytest.fixture
def session_factory(engine):
    """Session factory the transaction runner opens transactions from."""
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)

@pytest.fixture
def runner(session_factory) -> SqlAlchemyTransactionRunner:
    """Transaction runner under test."""
    return SqlAlchemyTransactionRunner(session_factory)


@pytest.fixture
def schema_revision(engine) -> str:
    """Revision the test database was migrated to."""
    with engine.connect() as connection:
        return connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()


@dataclass(frozen=True)
class TenantPair:
    """Two tenants that must never see each other's data."""

    alpha: str
    beta: str


@pytest.fixture
def platform_context() -> RequestContext:
    """Authenticated context with no tenant scope, for the tenant registry."""
    return RequestContextFactory.create_system()


@pytest.fixture
def tenants(runner, platform_context) -> TenantPair:
    """Two committed tenants."""
    pair = TenantPair(alpha=new_id(), beta=new_id())
    with runner.unit_of_work(platform_context) as uow:
        uow.tenants.add(platform_context, build_tenant(pair.alpha, "Alpha Corp"))
        uow.tenants.add(platform_context, build_tenant(pair.beta, "Beta Ltd"))
    return pair


@pytest.fixture
def alpha_context(tenants) -> RequestContext:
    """Request context scoped to the first tenant."""
    return RequestContextFactory.create(
        actor_id=str(uuid4()),
        tenant_id=tenants.alpha,
        correlation_id="alpha-correlation",
    )


@pytest.fixture
def beta_context(tenants) -> RequestContext:
    """Request context scoped to the second tenant."""
    return RequestContextFactory.create(
        actor_id=str(uuid4()),
        tenant_id=tenants.beta,
        correlation_id="beta-correlation",
    )


@pytest.fixture
def untenanted_context() -> RequestContext:
    """Authenticated context that carries no tenant scope."""
    return RequestContextFactory.create(actor_id=str(uuid4()))


@pytest.fixture
def row_counts(engine):
    """Read committed row counts straight from the database.

    Assertions about partial state use this rather than a repository, so a
    scoping bug in the repository cannot hide leftover rows.
    """

    def _count(table: str, **filters) -> int:
        # SQLite keeps UUID columns as unhyphenated hex, so raw comparisons
        # need the stored form rather than the canonical one.
        values = {column: _stored(value) for column, value in filters.items()}
        clause = ""
        if values:
            conditions = " AND ".join(f"{column} = :{column}" for column in values)
            clause = f" WHERE {conditions}"
        statement = text(f"SELECT COUNT(*) FROM {table}{clause}")
        with engine.connect() as connection:
            return connection.execute(statement, values).scalar_one()

    return _count


def _stored(value):
    """Render a value the way SQLite holds it for a UUID column."""
    if isinstance(value, str) and len(value) == 36 and value.count("-") == 4:
        return value.replace("-", "")
    return value
