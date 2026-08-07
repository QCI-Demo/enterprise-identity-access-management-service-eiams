"""Alembic migration environment configuration.

This module configures how Alembic runs migrations,
including database connection and metadata handling.
"""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from eiams.infrastructure.persistence.database import Base

# Import all models to ensure metadata is populated
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
    Session,
    RefreshToken,
    AuditEvent,
)

# Alembic Config object
config = context.config

# Configure logging from alembic.ini if present
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate
target_metadata = Base.metadata


def get_url() -> str:
    """Get database URL from environment or config."""
    return os.environ.get(
        "DATABASE_URL",
        config.get_main_option("sqlalchemy.url", "sqlite:///./eiams.db"),
    )


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.
    
    Generates SQL scripts without connecting to a database.
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # Enable batch mode for SQLite ALTER TABLE support
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.
    
    Creates an engine and connects to the database.
    """
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()
    
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # Enable batch mode for SQLite ALTER TABLE support
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
