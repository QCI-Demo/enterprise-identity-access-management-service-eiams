"""Tests verifying schema metadata, constraints, and indexes.

Validates that all required tables, columns, constraints, indexes,
and foreign keys exist after migrations are applied.
"""

import pytest
from sqlalchemy import inspect

from eiams.infrastructure.persistence.database import Base
from tests.integration.persistence.conftest import (
    get_table_names,
    get_index_names,
    get_foreign_keys,
    get_unique_constraints,
    get_columns,
)


class TestSchemaMetadata:
    """Test suite for schema metadata validation."""

    def test_all_required_tables_exist(self, in_memory_db):
        """Verify all required tables are created."""
        tables = get_table_names(in_memory_db)
        
        required_tables = {
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
        
        assert required_tables.issubset(tables), f"Missing tables: {required_tables - tables}"

    def test_tenants_table_columns(self, in_memory_db):
        """Verify tenants table has all required columns."""
        columns = get_columns(in_memory_db, "tenants")
        
        required_columns = {
            "id", "name", "slug", "display_name", "description",
            "status", "created_at", "updated_at"
        }
        
        assert required_columns.issubset(columns.keys())
        assert columns["id"]["nullable"] is False
        assert columns["name"]["nullable"] is False
        assert columns["slug"]["nullable"] is False
        assert columns["status"]["nullable"] is False

    def test_users_table_columns(self, in_memory_db):
        """Verify users table has all required columns."""
        columns = get_columns(in_memory_db, "users")
        
        required_columns = {
            "id", "tenant_id", "email", "username", "display_name",
            "status", "email_verified_at", "created_at", "updated_at", "last_login_at"
        }
        
        assert required_columns.issubset(columns.keys())
        assert columns["id"]["nullable"] is False
        assert columns["tenant_id"]["nullable"] is False
        assert columns["email"]["nullable"] is False
        assert columns["status"]["nullable"] is False

    def test_organizations_table_columns(self, in_memory_db):
        """Verify organizations table has all required columns."""
        columns = get_columns(in_memory_db, "organizations")
        
        required_columns = {
            "id", "tenant_id", "name", "slug", "description",
            "parent_id", "created_at", "updated_at"
        }
        
        assert required_columns.issubset(columns.keys())
        assert columns["parent_id"]["nullable"] is True  # Self-referential, nullable

    def test_memberships_table_columns(self, in_memory_db):
        """Verify memberships table has all required columns."""
        columns = get_columns(in_memory_db, "memberships")
        
        required_columns = {
            "id", "tenant_id", "user_id", "organization_id",
            "role", "status", "created_at", "updated_at"
        }
        
        assert required_columns.issubset(columns.keys())

    def test_audit_events_table_columns(self, in_memory_db):
        """Verify audit_events table has all required columns."""
        columns = get_columns(in_memory_db, "audit_events")
        
        required_columns = {
            "id", "event_type", "severity", "actor_id", "actor_type",
            "tenant_id", "target_type", "target_id", "action", "outcome",
            "correlation_id", "ip_address", "user_agent", "event_metadata",
            "error_code", "error_message", "event_time"
        }
        
        assert required_columns.issubset(columns.keys())
        assert columns["correlation_id"]["nullable"] is False
        assert columns["action"]["nullable"] is False
        assert columns["outcome"]["nullable"] is False

    def test_sessions_table_columns(self, in_memory_db):
        """Verify sessions table has all required columns."""
        columns = get_columns(in_memory_db, "sessions")
        
        required_columns = {
            "id", "tenant_id", "user_id", "status",
            "ip_address", "user_agent", "device_fingerprint",
            "created_at", "expires_at", "last_activity_at", "revoked_at"
        }
        
        assert required_columns.issubset(columns.keys())

    def test_refresh_tokens_table_columns(self, in_memory_db):
        """Verify refresh_tokens table has all required columns."""
        columns = get_columns(in_memory_db, "refresh_tokens")
        
        required_columns = {
            "id", "tenant_id", "session_id", "user_id",
            "token_hash", "token_family", "previous_token_id",
            "is_revoked", "created_at", "expires_at", "used_at", "revoked_at"
        }
        
        assert required_columns.issubset(columns.keys())

    def test_oauth_clients_table_columns(self, in_memory_db):
        """Verify oauth_clients table has all required columns."""
        columns = get_columns(in_memory_db, "oauth_clients")
        
        required_columns = {
            "id", "tenant_id", "name", "description", "client_type",
            "client_secret_hash", "secret_version", "secret_rotated_at",
            "redirect_uris", "allowed_scopes", "allowed_grant_types",
            "access_token_lifetime_seconds", "refresh_token_lifetime_seconds",
            "is_active", "created_at", "updated_at"
        }
        
        assert required_columns.issubset(columns.keys())

    def test_api_keys_table_columns(self, in_memory_db):
        """Verify api_keys table has all required columns."""
        columns = get_columns(in_memory_db, "api_keys")
        
        required_columns = {
            "id", "tenant_id", "user_id", "name", "description",
            "key_prefix", "key_hash", "scopes", "status",
            "created_at", "expires_at", "last_used_at", "revoked_at"
        }
        
        assert required_columns.issubset(columns.keys())

    def test_user_credentials_table_columns(self, in_memory_db):
        """Verify user_credentials table has all required columns."""
        columns = get_columns(in_memory_db, "user_credentials")
        
        required_columns = {
            "id", "tenant_id", "user_id", "credential_type",
            "credential_hash", "hash_algorithm", "is_active",
            "requires_reset", "failed_attempts", "locked_until",
            "created_at", "updated_at", "last_used_at"
        }
        
        assert required_columns.issubset(columns.keys())

    def test_roles_table_columns(self, in_memory_db):
        """Verify roles table has all required columns."""
        columns = get_columns(in_memory_db, "roles")
        
        required_columns = {
            "id", "tenant_id", "name", "description",
            "is_system", "created_at", "updated_at"
        }
        
        assert required_columns.issubset(columns.keys())

    def test_permissions_table_columns(self, in_memory_db):
        """Verify permissions table has all required columns."""
        columns = get_columns(in_memory_db, "permissions")
        
        required_columns = {
            "id", "tenant_id", "name", "description",
            "resource_type", "action", "is_system", "created_at"
        }
        
        assert required_columns.issubset(columns.keys())

    def test_role_assignments_table_columns(self, in_memory_db):
        """Verify role_assignments table has all required columns."""
        columns = get_columns(in_memory_db, "role_assignments")
        
        required_columns = {
            "id", "tenant_id", "user_id", "role_id",
            "scope_type", "scope_id", "created_at", "expires_at", "revoked_at"
        }
        
        assert required_columns.issubset(columns.keys())


class TestForeignKeyConstraints:
    """Test suite for foreign key constraint validation."""

    def test_users_foreign_key_to_tenants(self, in_memory_db):
        """Verify users table has foreign key to tenants."""
        fks = get_foreign_keys(in_memory_db, "users")
        tenant_fk = next((fk for fk in fks if "tenants" in fk["referred_table"]), None)
        
        assert tenant_fk is not None
        assert "tenant_id" in tenant_fk["constrained_columns"]

    def test_organizations_foreign_key_to_tenants(self, in_memory_db):
        """Verify organizations table has foreign key to tenants."""
        fks = get_foreign_keys(in_memory_db, "organizations")
        tenant_fk = next((fk for fk in fks if fk["referred_table"] == "tenants"), None)
        
        assert tenant_fk is not None
        assert "tenant_id" in tenant_fk["constrained_columns"]

    def test_organizations_self_referential_foreign_key(self, in_memory_db):
        """Verify organizations table has self-referential foreign key for hierarchy."""
        fks = get_foreign_keys(in_memory_db, "organizations")
        parent_fk = next((fk for fk in fks if fk["referred_table"] == "organizations"), None)
        
        assert parent_fk is not None
        assert "parent_id" in parent_fk["constrained_columns"]

    def test_memberships_foreign_keys(self, in_memory_db):
        """Verify memberships table has all required foreign keys."""
        fks = get_foreign_keys(in_memory_db, "memberships")
        
        referred_tables = {fk["referred_table"] for fk in fks}
        assert "tenants" in referred_tables
        assert "users" in referred_tables
        assert "organizations" in referred_tables

    def test_sessions_foreign_keys(self, in_memory_db):
        """Verify sessions table has all required foreign keys."""
        fks = get_foreign_keys(in_memory_db, "sessions")
        
        referred_tables = {fk["referred_table"] for fk in fks}
        assert "tenants" in referred_tables
        assert "users" in referred_tables

    def test_refresh_tokens_foreign_keys(self, in_memory_db):
        """Verify refresh_tokens table has all required foreign keys."""
        fks = get_foreign_keys(in_memory_db, "refresh_tokens")
        
        referred_tables = {fk["referred_table"] for fk in fks}
        assert "tenants" in referred_tables
        assert "sessions" in referred_tables
        assert "users" in referred_tables
        assert "refresh_tokens" in referred_tables  # Self-referential for token chain

    def test_role_assignments_foreign_keys(self, in_memory_db):
        """Verify role_assignments table has all required foreign keys."""
        fks = get_foreign_keys(in_memory_db, "role_assignments")
        
        referred_tables = {fk["referred_table"] for fk in fks}
        assert "tenants" in referred_tables
        assert "users" in referred_tables
        assert "roles" in referred_tables


class TestUniqueConstraints:
    """Test suite for unique constraint validation."""

    def test_tenants_unique_name(self, in_memory_db):
        """Verify tenants have unique name constraint."""
        ucs = get_unique_constraints(in_memory_db, "tenants")
        name_uc = next((uc for uc in ucs if "name" in uc.get("column_names", [])), None)
        
        assert name_uc is not None

    def test_tenants_unique_slug(self, in_memory_db):
        """Verify tenants have unique slug constraint."""
        ucs = get_unique_constraints(in_memory_db, "tenants")
        slug_uc = next((uc for uc in ucs if "slug" in uc.get("column_names", [])), None)
        
        assert slug_uc is not None

    def test_users_unique_email_per_tenant(self, in_memory_db):
        """Verify users have unique email per tenant constraint."""
        ucs = get_unique_constraints(in_memory_db, "users")
        email_uc = next(
            (uc for uc in ucs if "email" in uc.get("column_names", []) and "tenant_id" in uc.get("column_names", [])),
            None
        )
        
        assert email_uc is not None

    def test_organizations_unique_name_per_tenant(self, in_memory_db):
        """Verify organizations have unique name per tenant constraint."""
        ucs = get_unique_constraints(in_memory_db, "organizations")
        name_uc = next(
            (uc for uc in ucs if "name" in uc.get("column_names", []) and "tenant_id" in uc.get("column_names", [])),
            None
        )
        
        assert name_uc is not None

    def test_memberships_unique_user_organization(self, in_memory_db):
        """Verify memberships have unique user-organization pair constraint."""
        ucs = get_unique_constraints(in_memory_db, "memberships")
        membership_uc = next(
            (uc for uc in ucs if "user_id" in uc.get("column_names", []) and "organization_id" in uc.get("column_names", [])),
            None
        )
        
        assert membership_uc is not None

    def test_api_keys_unique_prefix(self, in_memory_db):
        """Verify api_keys have unique prefix constraint."""
        ucs = get_unique_constraints(in_memory_db, "api_keys")
        prefix_uc = next((uc for uc in ucs if "key_prefix" in uc.get("column_names", [])), None)
        
        assert prefix_uc is not None

    def test_refresh_tokens_unique_hash(self, in_memory_db):
        """Verify refresh_tokens have unique token_hash constraint."""
        ucs = get_unique_constraints(in_memory_db, "refresh_tokens")
        hash_uc = next((uc for uc in ucs if "token_hash" in uc.get("column_names", [])), None)
        
        assert hash_uc is not None


class TestIndexes:
    """Test suite for index validation."""

    def test_tenants_indexes(self, in_memory_db):
        """Verify tenants table has required indexes."""
        indexes = get_index_names(in_memory_db, "tenants")
        
        # Core lookup indexes
        assert any("name" in idx for idx in indexes)
        assert any("slug" in idx for idx in indexes)
        assert any("status" in idx for idx in indexes)

    def test_users_indexes(self, in_memory_db):
        """Verify users table has required indexes."""
        indexes = get_index_names(in_memory_db, "users")
        
        # Core lookup indexes
        assert any("tenant_id" in idx for idx in indexes)
        assert any("status" in idx for idx in indexes)
        assert any("email" in idx for idx in indexes)

    def test_audit_events_indexes(self, in_memory_db):
        """Verify audit_events table has required indexes for query patterns."""
        indexes = get_index_names(in_memory_db, "audit_events")
        
        # Primary query indexes
        assert any("tenant_id" in idx for idx in indexes)
        assert any("event_time" in idx for idx in indexes)
        assert any("correlation_id" in idx for idx in indexes)
        assert any("actor_id" in idx for idx in indexes)
        assert any("event_type" in idx for idx in indexes)

    def test_sessions_indexes(self, in_memory_db):
        """Verify sessions table has required indexes."""
        indexes = get_index_names(in_memory_db, "sessions")
        
        assert any("tenant_id" in idx for idx in indexes)
        assert any("user_id" in idx for idx in indexes)
        assert any("status" in idx for idx in indexes)
        assert any("expires_at" in idx for idx in indexes)

    def test_memberships_indexes(self, in_memory_db):
        """Verify memberships table has required indexes."""
        indexes = get_index_names(in_memory_db, "memberships")
        
        assert any("tenant_id" in idx for idx in indexes)
        assert any("user_id" in idx for idx in indexes)
        assert any("organization_id" in idx for idx in indexes)

    def test_role_assignments_indexes(self, in_memory_db):
        """Verify role_assignments table has required indexes."""
        indexes = get_index_names(in_memory_db, "role_assignments")
        
        assert any("tenant_id" in idx for idx in indexes)
        assert any("user_id" in idx for idx in indexes)
        assert any("role_id" in idx for idx in indexes)
