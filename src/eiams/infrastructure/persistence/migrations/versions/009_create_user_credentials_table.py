"""Create user_credentials table.

Revision ID: 009_user_credentials
Revises: 008_role_assignments
Create Date: 2024-01-01 00:00:08.000000

User credentials store hashed authentication data.
Raw secrets are NEVER stored - only secure hashes.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "009_user_credentials"
down_revision: Union[str, None] = "008_role_assignments"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_credentials",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("credential_type", sa.String(20), nullable=False),
        sa.Column("credential_hash", sa.String(512), nullable=False),
        sa.Column("hash_algorithm", sa.String(63), nullable=False, server_default="argon2id"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("requires_reset", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_user_credentials"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_user_credentials_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name="fk_user_credentials_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("user_id", "credential_type", name="uq_user_credentials_user_type"),
        sa.CheckConstraint(
            "credential_type IN ('password', 'totp', 'webauthn', 'recovery_code')",
            name="ck_user_credentials_valid_credential_type",
        ),
    )
    
    # Indexes
    op.create_index("ix_user_credentials_tenant_id", "user_credentials", ["tenant_id"])
    op.create_index("ix_user_credentials_user_id", "user_credentials", ["user_id"])
    op.create_index("ix_user_credentials_user_id_type", "user_credentials", ["user_id", "credential_type"])
    op.create_index("ix_user_credentials_tenant_id_created_at", "user_credentials", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_user_credentials_tenant_id_created_at", table_name="user_credentials")
    op.drop_index("ix_user_credentials_user_id_type", table_name="user_credentials")
    op.drop_index("ix_user_credentials_user_id", table_name="user_credentials")
    op.drop_index("ix_user_credentials_tenant_id", table_name="user_credentials")
    op.drop_table("user_credentials")
