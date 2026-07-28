"""Tests for migration forward and rollback operations.

Validates that migrations can be applied and rolled back correctly.
"""

import pytest
from sqlalchemy import create_engine, inspect, text
from alembic import command
from alembic.config import Config

from eiams.infrastructure.persistence.database import Base


class TestMigrationIntegrity:
    """Test suite for migration integrity validation."""

    @pytest.fixture
    def alembic_config(self, tmp_path):
        """Create Alembic config for testing."""
        # Create temporary database
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"
        
        config = Config()
        config.set_main_option("script_location", "src/eiams/infrastructure/persistence/migrations")
        config.set_main_option("sqlalchemy.url", db_url)
        
        return config, db_url

    def test_forward_migration_creates_all_tables(self, alembic_config):
        """Test that forward migrations create all required tables."""
        config, db_url = alembic_config
        
        # Run all migrations
        command.upgrade(config, "head")
        
        # Verify tables exist
        engine = create_engine(db_url)
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        
        expected_tables = {
            "alembic_version",
            "tenants",
            "organizations",
            "users",
            "memberships",
            "permissions",
            "roles",
            "role_permissions",
            "role_assignments",
            "user_credentials",
            "oauth_clients",
            "api_keys",
            "sessions",
            "refresh_tokens",
            "audit_events",
        }
        
        assert expected_tables.issubset(tables), f"Missing tables: {expected_tables - tables}"
        engine.dispose()

    def test_rollback_to_base_drops_all_tables(self, alembic_config):
        """Test that rolling back all migrations drops tables."""
        config, db_url = alembic_config
        
        # Run all migrations
        command.upgrade(config, "head")
        
        # Rollback to base
        command.downgrade(config, "base")
        
        # Verify only alembic_version remains
        engine = create_engine(db_url)
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        
        # All tables except alembic_version should be dropped
        assert tables == {"alembic_version"} or tables == set()
        engine.dispose()

    def test_incremental_migration(self, alembic_config):
        """Test that migrations can be applied incrementally."""
        config, db_url = alembic_config
        
        # Run first migration (tenants)
        command.upgrade(config, "001_tenants")
        
        engine = create_engine(db_url)
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        
        assert "tenants" in tables
        assert "users" not in tables  # Not yet created
        
        # Run up to users
        command.upgrade(config, "003_users")
        
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        
        assert "tenants" in tables
        assert "organizations" in tables
        assert "users" in tables
        assert "memberships" not in tables  # Not yet created
        
        engine.dispose()

    def test_partial_rollback(self, alembic_config):
        """Test that partial rollback works correctly."""
        config, db_url = alembic_config
        
        # Run all migrations
        command.upgrade(config, "head")
        
        # Rollback to before audit_events
        command.downgrade(config, "013_refresh_tokens")
        
        engine = create_engine(db_url)
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        
        # audit_events should be dropped
        assert "audit_events" not in tables
        # But other tables should exist
        assert "tenants" in tables
        assert "users" in tables
        assert "refresh_tokens" in tables
        
        engine.dispose()

    def test_migration_idempotency(self, alembic_config):
        """Test that running upgrade twice is safe."""
        config, db_url = alembic_config
        
        # Run all migrations twice
        command.upgrade(config, "head")
        command.upgrade(config, "head")  # Should be no-op
        
        # Verify tables still exist
        engine = create_engine(db_url)
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        
        assert "tenants" in tables
        assert "users" in tables
        engine.dispose()


class TestMigrationDataPreservation:
    """Test that migrations preserve existing data."""

    @pytest.fixture
    def alembic_config_with_data(self, tmp_path):
        """Create Alembic config with pre-populated data."""
        db_path = tmp_path / "test_data.db"
        db_url = f"sqlite:///{db_path}"
        
        config = Config()
        config.set_main_option("script_location", "src/eiams/infrastructure/persistence/migrations")
        config.set_main_option("sqlalchemy.url", db_url)
        
        # Run initial migrations and add test data
        command.upgrade(config, "head")
        
        engine = create_engine(db_url)
        with engine.connect() as conn:
            # Insert test tenant
            conn.execute(text("""
                INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
                VALUES ('test-tenant-id', 'Test Tenant', 'test', 'active', datetime('now'), datetime('now'))
            """))
            conn.commit()
        
        return config, db_url, engine

    def test_data_survives_no_op_migration(self, alembic_config_with_data):
        """Test that data survives a no-op migration cycle."""
        config, db_url, engine = alembic_config_with_data
        
        # Run upgrade again (no-op)
        command.upgrade(config, "head")
        
        # Verify data still exists
        with engine.connect() as conn:
            result = conn.execute(text("SELECT name FROM tenants WHERE id = 'test-tenant-id'"))
            row = result.fetchone()
            assert row is not None
            assert row[0] == "Test Tenant"
        
        engine.dispose()


class TestMigrationCurrentState:
    """Test migration current state operations."""

    def test_current_revision_shows_head(self, tmp_path):
        """Test that current revision is correct after migrations."""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"
        
        config = Config()
        config.set_main_option("script_location", "src/eiams/infrastructure/persistence/migrations")
        config.set_main_option("sqlalchemy.url", db_url)
        
        # Run all migrations
        command.upgrade(config, "head")
        
        # Check current revision
        engine = create_engine(db_url)
        with engine.connect() as conn:
            result = conn.execute(text("SELECT version_num FROM alembic_version"))
            row = result.fetchone()
            assert row is not None
            # Should be the last migration
            assert row[0] == "014_audit_events"
        
        engine.dispose()
