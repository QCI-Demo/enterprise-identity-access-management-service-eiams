"""Create oauth_clients table.

Revision ID: 010_oauth_clients
Revises: 009_user_credentials
Create Date: 2024-01-01 00:00:09.000000

OAuth clients for application authentication.
Stores client metadata and hashed secrets only.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "010_oauth_clients"
down_revision: Union[str, None] = "009_user_credentials"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "oauth_clients",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("client_type", sa.String(15), nullable=False),
        sa.Column("client_secret_hash", sa.String(512), nullable=True),
        sa.Column("secret_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("secret_rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("redirect_uris", sa.Text(), nullable=False, server_default=""),
        sa.Column("allowed_scopes", sa.Text(), nullable=False, server_default=""),
        sa.Column("allowed_grant_types", sa.String(255), nullable=False, server_default="authorization_code,refresh_token"),
        sa.Column("access_token_lifetime_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("refresh_token_lifetime_seconds", sa.Integer(), nullable=False, server_default="2592000"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_oauth_clients"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_oauth_clients_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "name", name="uq_oauth_clients_tenant_name"),
        sa.CheckConstraint(
            "client_type IN ('confidential', 'public')",
            name="ck_oauth_clients_valid_oauth_client_type",
        ),
        sa.CheckConstraint(
            "(client_type = 'public') OR (client_secret_hash IS NOT NULL)",
            name="ck_oauth_clients_confidential_client_requires_secret",
        ),
    )
    
    # Indexes
    op.create_index("ix_oauth_clients_tenant_id", "oauth_clients", ["tenant_id"])
    op.create_index("ix_oauth_clients_is_active", "oauth_clients", ["is_active"])
    op.create_index("ix_oauth_clients_tenant_id_is_active", "oauth_clients", ["tenant_id", "is_active"])
    op.create_index("ix_oauth_clients_tenant_id_created_at", "oauth_clients", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_oauth_clients_tenant_id_created_at", table_name="oauth_clients")
    op.drop_index("ix_oauth_clients_tenant_id_is_active", table_name="oauth_clients")
    op.drop_index("ix_oauth_clients_is_active", table_name="oauth_clients")
    op.drop_index("ix_oauth_clients_tenant_id", table_name="oauth_clients")
    op.drop_table("oauth_clients")
