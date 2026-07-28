"""Tests for constraint violation handling.

Validates that invalid data operations fail as expected:
- Duplicate key violations
- Foreign key violations
- Check constraint violations
- Cross-tenant isolation violations
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from eiams.infrastructure.persistence.models import (
    Tenant,
    Organization,
    User,
    Membership,
    Permission,
    Role,
    RoleAssignment,
    Session,
    RefreshToken,
    ApiKey,
    OAuthClient,
    UserCredential,
    AuditEvent,
)
from eiams.infrastructure.persistence.models.tenant import TenantStatus
from eiams.infrastructure.persistence.models.identity import UserStatus, MembershipStatus
from eiams.infrastructure.persistence.models.credentials import ApiKeyStatus, OAuthClientType, CredentialType
from eiams.infrastructure.persistence.models.authentication import SessionStatus


class TestDuplicateKeyViolations:
    """Tests for duplicate key constraint violations."""

    def test_duplicate_tenant_name_fails(self, db_manager):
        """Duplicate tenant names should be rejected."""
        with db_manager.session() as session:
            tenant1 = Tenant(
                id=str(uuid4()),
                name="Acme Corp",
                slug="acme",
            )
            session.add(tenant1)
            session.flush()
        
        with pytest.raises(IntegrityError):
            with db_manager.session() as session:
                tenant2 = Tenant(
                    id=str(uuid4()),
                    name="Acme Corp",  # Duplicate
                    slug="acme-2",
                )
                session.add(tenant2)
                session.flush()

    def test_duplicate_tenant_slug_fails(self, db_manager):
        """Duplicate tenant slugs should be rejected."""
        with db_manager.session() as session:
            tenant1 = Tenant(
                id=str(uuid4()),
                name="Acme Corp",
                slug="acme",
            )
            session.add(tenant1)
            session.flush()
        
        with pytest.raises(IntegrityError):
            with db_manager.session() as session:
                tenant2 = Tenant(
                    id=str(uuid4()),
                    name="Acme Corp 2",
                    slug="acme",  # Duplicate
                )
                session.add(tenant2)
                session.flush()

    def test_duplicate_user_email_same_tenant_fails(self, db_manager):
        """Duplicate user emails within same tenant should be rejected."""
        tenant_id = str(uuid4())
        
        with db_manager.session() as session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            session.add(tenant)
            user1 = User(
                id=str(uuid4()),
                tenant_id=tenant_id,
                email="user@example.com",
                display_name="User 1",
            )
            session.add(user1)
            session.flush()
        
        with pytest.raises(IntegrityError):
            with db_manager.session() as session:
                user2 = User(
                    id=str(uuid4()),
                    tenant_id=tenant_id,
                    email="user@example.com",  # Duplicate within tenant
                    display_name="User 2",
                )
                session.add(user2)
                session.flush()

    def test_same_user_email_different_tenants_succeeds(self, db_manager):
        """Same email in different tenants should succeed."""
        tenant1_id = str(uuid4())
        tenant2_id = str(uuid4())
        
        with db_manager.session() as session:
            tenant1 = Tenant(id=tenant1_id, name="Tenant 1", slug="tenant1")
            tenant2 = Tenant(id=tenant2_id, name="Tenant 2", slug="tenant2")
            session.add_all([tenant1, tenant2])
            
            user1 = User(
                id=str(uuid4()),
                tenant_id=tenant1_id,
                email="user@example.com",
                display_name="User 1",
            )
            user2 = User(
                id=str(uuid4()),
                tenant_id=tenant2_id,
                email="user@example.com",  # Same email, different tenant
                display_name="User 2",
            )
            session.add_all([user1, user2])
            session.flush()
            
            # Should succeed - no exception raised

    def test_duplicate_membership_fails(self, db_manager):
        """Duplicate user-organization membership should be rejected."""
        tenant_id = str(uuid4())
        user_id = str(uuid4())
        org_id = str(uuid4())
        
        with db_manager.session() as session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            user = User(id=user_id, tenant_id=tenant_id, email="u@t.com", display_name="U")
            org = Organization(id=org_id, tenant_id=tenant_id, name="Org", slug="org")
            session.add_all([tenant, user, org])
            
            membership1 = Membership(
                id=str(uuid4()),
                tenant_id=tenant_id,
                user_id=user_id,
                organization_id=org_id,
                role="member",
            )
            session.add(membership1)
            session.flush()
        
        with pytest.raises(IntegrityError):
            with db_manager.session() as session:
                membership2 = Membership(
                    id=str(uuid4()),
                    tenant_id=tenant_id,
                    user_id=user_id,
                    organization_id=org_id,  # Duplicate
                    role="admin",
                )
                session.add(membership2)
                session.flush()

    def test_duplicate_api_key_prefix_fails(self, db_manager):
        """Duplicate API key prefixes should be rejected."""
        tenant_id = str(uuid4())
        
        with db_manager.session() as session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            session.add(tenant)
            
            key1 = ApiKey(
                id=str(uuid4()),
                tenant_id=tenant_id,
                name="Key 1",
                key_prefix="eiams_abc123",
                key_hash="hash1",
            )
            session.add(key1)
            session.flush()
        
        with pytest.raises(IntegrityError):
            with db_manager.session() as session:
                key2 = ApiKey(
                    id=str(uuid4()),
                    tenant_id=tenant_id,
                    name="Key 2",
                    key_prefix="eiams_abc123",  # Duplicate
                    key_hash="hash2",
                )
                session.add(key2)
                session.flush()


class TestForeignKeyViolations:
    """Tests for foreign key constraint violations."""

    def test_user_invalid_tenant_fails(self, db_manager):
        """User with non-existent tenant should be rejected."""
        with pytest.raises(IntegrityError):
            with db_manager.session() as session:
                user = User(
                    id=str(uuid4()),
                    tenant_id=str(uuid4()),  # Non-existent tenant
                    email="user@example.com",
                    display_name="User",
                    status=UserStatus.ACTIVE,
                )
                session.add(user)
                session.flush()

    def test_organization_invalid_tenant_fails(self, db_manager):
        """Organization with non-existent tenant should be rejected."""
        with pytest.raises(IntegrityError):
            with db_manager.session() as session:
                org = Organization(
                    id=str(uuid4()),
                    tenant_id=str(uuid4()),  # Non-existent tenant
                    name="Org",
                    slug="org",
                )
                session.add(org)
                session.flush()

    def test_membership_invalid_user_fails(self, db_manager):
        """Membership with non-existent user should be rejected."""
        tenant_id = str(uuid4())
        org_id = str(uuid4())
        
        with db_manager.session() as session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            org = Organization(id=org_id, tenant_id=tenant_id, name="Org", slug="org")
            session.add_all([tenant, org])
            session.flush()
        
        with pytest.raises(IntegrityError):
            with db_manager.session() as session:
                membership = Membership(
                    id=str(uuid4()),
                    tenant_id=tenant_id,
                    user_id=str(uuid4()),  # Non-existent user
                    organization_id=org_id,
                    role="member",
                )
                session.add(membership)
                session.flush()

    def test_membership_invalid_organization_fails(self, db_manager):
        """Membership with non-existent organization should be rejected."""
        tenant_id = str(uuid4())
        user_id = str(uuid4())
        
        with db_manager.session() as session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            user = User(id=user_id, tenant_id=tenant_id, email="u@t.com", display_name="U")
            session.add_all([tenant, user])
            session.flush()
        
        with pytest.raises(IntegrityError):
            with db_manager.session() as session:
                membership = Membership(
                    id=str(uuid4()),
                    tenant_id=tenant_id,
                    user_id=user_id,
                    organization_id=str(uuid4()),  # Non-existent organization
                    role="member",
                )
                session.add(membership)
                session.flush()

    def test_session_invalid_user_fails(self, db_manager):
        """Session with non-existent user should be rejected."""
        tenant_id = str(uuid4())
        
        with db_manager.session() as session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            session.add(tenant)
            session.flush()
        
        with pytest.raises(IntegrityError):
            with db_manager.session() as session:
                sess = Session(
                    id=str(uuid4()),
                    tenant_id=tenant_id,
                    user_id=str(uuid4()),  # Non-existent user
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                )
                session.add(sess)
                session.flush()

    def test_role_assignment_invalid_role_fails(self, db_manager):
        """Role assignment with non-existent role should be rejected."""
        tenant_id = str(uuid4())
        user_id = str(uuid4())
        
        with db_manager.session() as session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            user = User(id=user_id, tenant_id=tenant_id, email="u@t.com", display_name="U")
            session.add_all([tenant, user])
            session.flush()
        
        with pytest.raises(IntegrityError):
            with db_manager.session() as session:
                assignment = RoleAssignment(
                    id=str(uuid4()),
                    tenant_id=tenant_id,
                    user_id=user_id,
                    role_id=str(uuid4()),  # Non-existent role
                )
                session.add(assignment)
                session.flush()


class TestCascadeDelete:
    """Tests for cascade delete behavior."""

    def test_tenant_delete_cascades_to_users(self, db_manager):
        """Deleting a tenant should cascade to users."""
        tenant_id = str(uuid4())
        user_id = str(uuid4())
        
        with db_manager.session() as session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            user = User(id=user_id, tenant_id=tenant_id, email="u@t.com", display_name="U")
            session.add_all([tenant, user])
            session.flush()
        
        with db_manager.session() as session:
            session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
            session.flush()
            
            # User should be deleted
            result = session.execute(text("SELECT COUNT(*) FROM users WHERE id = :id"), {"id": user_id})
            assert result.scalar() == 0

    def test_user_delete_cascades_to_memberships(self, db_manager):
        """Deleting a user should cascade to memberships."""
        tenant_id = str(uuid4())
        user_id = str(uuid4())
        org_id = str(uuid4())
        membership_id = str(uuid4())
        
        with db_manager.session() as session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            user = User(id=user_id, tenant_id=tenant_id, email="u@t.com", display_name="U")
            org = Organization(id=org_id, tenant_id=tenant_id, name="Org", slug="org")
            membership = Membership(
                id=membership_id,
                tenant_id=tenant_id,
                user_id=user_id,
                organization_id=org_id,
                role="member",
            )
            session.add_all([tenant, user, org, membership])
            session.flush()
        
        with db_manager.session() as session:
            session.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
            session.flush()
            
            # Membership should be deleted
            result = session.execute(text("SELECT COUNT(*) FROM memberships WHERE id = :id"), {"id": membership_id})
            assert result.scalar() == 0

    def test_session_delete_cascades_to_refresh_tokens(self, db_manager):
        """Deleting a session should cascade to refresh tokens."""
        tenant_id = str(uuid4())
        user_id = str(uuid4())
        session_id = str(uuid4())
        token_id = str(uuid4())
        
        with db_manager.session() as db_session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            user = User(id=user_id, tenant_id=tenant_id, email="u@t.com", display_name="U")
            sess = Session(
                id=session_id,
                tenant_id=tenant_id,
                user_id=user_id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
            token = RefreshToken(
                id=token_id,
                tenant_id=tenant_id,
                session_id=session_id,
                user_id=user_id,
                token_hash="hash123",
                token_family=str(uuid4()),
                expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            )
            db_session.add_all([tenant, user, sess, token])
            db_session.flush()
        
        with db_manager.session() as db_session:
            db_session.execute(text("DELETE FROM sessions WHERE id = :id"), {"id": session_id})
            db_session.flush()
            
            # Refresh token should be deleted
            result = db_session.execute(text("SELECT COUNT(*) FROM refresh_tokens WHERE id = :id"), {"id": token_id})
            assert result.scalar() == 0


class TestValidDataCreation:
    """Tests for valid data creation scenarios."""

    def test_create_complete_tenant_hierarchy(self, db_manager):
        """Test creating a complete tenant with organizations, users, and memberships."""
        tenant_id = str(uuid4())
        user_id = str(uuid4())
        org_id = str(uuid4())
        
        with db_manager.session() as session:
            # Create tenant
            tenant = Tenant(
                id=tenant_id,
                name="Complete Corp",
                slug="complete",
                display_name="Complete Corporation",
            )
            session.add(tenant)
            
            # Create organization
            org = Organization(
                id=org_id,
                tenant_id=tenant_id,
                name="Engineering",
                slug="engineering",
                description="Engineering department",
            )
            session.add(org)
            
            # Create user
            user = User(
                id=user_id,
                tenant_id=tenant_id,
                email="engineer@complete.com",
                display_name="Engineer",
            )
            session.add(user)
            
            # Create membership
            membership = Membership(
                id=str(uuid4()),
                tenant_id=tenant_id,
                user_id=user_id,
                organization_id=org_id,
                role="member",
            )
            session.add(membership)
            session.flush()
            
            # Verify all entities created
            assert session.query(Tenant).filter_by(id=tenant_id).count() == 1
            assert session.query(Organization).filter_by(id=org_id).count() == 1
            assert session.query(User).filter_by(id=user_id).count() == 1
            assert session.query(Membership).filter_by(user_id=user_id).count() == 1

    def test_create_audit_event(self, db_manager):
        """Test creating an audit event."""
        with db_manager.session() as session:
            event = AuditEvent(
                id=str(uuid4()),
                event_type="login_success",
                severity="info",
                actor_id=str(uuid4()),
                actor_type="user",
                tenant_id=str(uuid4()),
                action="user.login",
                outcome="success",
                correlation_id=str(uuid4()),
                ip_address="192.168.1.1",
                event_time=datetime.now(timezone.utc),
            )
            session.add(event)
            session.flush()
            
            # Verify event created
            assert session.query(AuditEvent).count() == 1

    def test_create_oauth_client_confidential(self, db_manager):
        """Test creating a confidential OAuth client."""
        tenant_id = str(uuid4())
        
        with db_manager.session() as session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            session.add(tenant)
            
            client = OAuthClient(
                id=str(uuid4()),
                tenant_id=tenant_id,
                name="Confidential App",
                client_type=OAuthClientType.CONFIDENTIAL,
                client_secret_hash="hashed_secret_123",
                redirect_uris="https://app.example.com/callback",
                allowed_scopes="read,write",
            )
            session.add(client)
            session.flush()
            
            assert session.query(OAuthClient).count() == 1

    def test_create_session_with_refresh_token(self, db_manager):
        """Test creating a session with a refresh token."""
        tenant_id = str(uuid4())
        user_id = str(uuid4())
        session_id = str(uuid4())
        
        with db_manager.session() as db_session:
            tenant = Tenant(id=tenant_id, name="Test", slug="test")
            user = User(id=user_id, tenant_id=tenant_id, email="u@t.com", display_name="U")
            db_session.add_all([tenant, user])
            
            sess = Session(
                id=session_id,
                tenant_id=tenant_id,
                user_id=user_id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
            db_session.add(sess)
            
            token = RefreshToken(
                id=str(uuid4()),
                tenant_id=tenant_id,
                session_id=session_id,
                user_id=user_id,
                token_hash="token_hash_abc",
                token_family=str(uuid4()),
                expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            )
            db_session.add(token)
            db_session.flush()
            
            assert db_session.query(Session).count() == 1
            assert db_session.query(RefreshToken).count() == 1
