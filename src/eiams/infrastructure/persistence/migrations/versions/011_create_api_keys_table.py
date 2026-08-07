"""Create api_keys table.

Revision ID: 011_api_keys
Revises: 010_oauth_clients
Create Date: 2024-01-01 00:00:10.000000

API keys for programmatic access.
Stores key prefix for identification and hash for validation only.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "011_api_keys"
down_revision: Union[str, None] = "010_oauth_clients"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("key_prefix", sa.String(32), nullable=False),
        sa.Column("key_hash", sa.String(512), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(10), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_api_keys_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name="fk_api_keys_user_id_users",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("key_prefix", name="uq_api_keys_key_prefix"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_api_keys_tenant_name"),
        sa.CheckConstraint(
            "status IN ('active', 'revoked', 'expired')",
            name="ck_api_keys_valid_api_key_status",
        ),
    )
    
    # Indexes
    op.create_index("ix_api_keys_tenant_id", "api_keys", ["tenant_id"])
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"])
    op.create_index("ix_api_keys_status", "api_keys", ["status"])
    op.create_index("ix_api_keys_tenant_id_status", "api_keys", ["tenant_id", "status"])
    op.create_index("ix_api_keys_user_id_status", "api_keys", ["user_id", "status"])
    op.create_index("ix_api_keys_tenant_id_created_at", "api_keys", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_api_keys_tenant_id_created_at", table_name="api_keys")
    op.drop_index("ix_api_keys_user_id_status", table_name="api_keys")
    op.drop_index("ix_api_keys_tenant_id_status", table_name="api_keys")
    op.drop_index("ix_api_keys_status", table_name="api_keys")
    op.drop_index("ix_api_keys_key_prefix", table_name="api_keys")
    op.drop_index("ix_api_keys_user_id", table_name="api_keys")
    op.drop_index("ix_api_keys_tenant_id", table_name="api_keys")
    op.drop_table("api_keys")
