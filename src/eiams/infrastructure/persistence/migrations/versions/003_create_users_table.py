"""Create users table.

Revision ID: 003_users
Revises: 002_organizations
Create Date: 2024-01-01 00:00:02.000000

Users represent authenticated identities within a tenant.
Each user belongs to exactly one tenant.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "003_users"
down_revision: Union[str, None] = "002_organizations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("username", sa.String(63), nullable=True),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(25), nullable=False, server_default="pending_verification"),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_users_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
        sa.UniqueConstraint("tenant_id", "username", name="uq_users_tenant_username"),
        sa.CheckConstraint(
            "status IN ('active', 'inactive', 'suspended', 'pending_verification')",
            name="ck_users_valid_user_status",
        ),
    )
    
    # Indexes
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])
    op.create_index("ix_users_status", "users", ["status"])
    op.create_index("ix_users_tenant_id_email", "users", ["tenant_id", "email"])
    op.create_index("ix_users_tenant_id_status", "users", ["tenant_id", "status"])
    op.create_index("ix_users_tenant_id_created_at", "users", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_users_tenant_id_created_at", table_name="users")
    op.drop_index("ix_users_tenant_id_status", table_name="users")
    op.drop_index("ix_users_tenant_id_email", table_name="users")
    op.drop_index("ix_users_status", table_name="users")
    op.drop_index("ix_users_tenant_id", table_name="users")
    op.drop_table("users")
