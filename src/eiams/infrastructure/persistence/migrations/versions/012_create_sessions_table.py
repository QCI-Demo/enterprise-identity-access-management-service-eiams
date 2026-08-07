"""Create sessions table.

Revision ID: 012_sessions
Revises: 011_api_keys
Create Date: 2024-01-01 00:00:11.000000

Authentication sessions for user login tracking.
Supports session management and security audit.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "012_sessions"
down_revision: Union[str, None] = "011_api_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("status", sa.String(15), nullable=False, server_default="active"),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("device_fingerprint", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_sessions"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_sessions_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name="fk_sessions_user_id_users",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'expired', 'revoked', 'logged_out')",
            name="ck_sessions_valid_session_status",
        ),
    )
    
    # Indexes
    op.create_index("ix_sessions_tenant_id", "sessions", ["tenant_id"])
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_status", "sessions", ["status"])
    op.create_index("ix_sessions_user_id_status", "sessions", ["user_id", "status"])
    op.create_index("ix_sessions_tenant_id_status_expires_at", "sessions", ["tenant_id", "status", "expires_at"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])
    op.create_index("ix_sessions_tenant_id_created_at", "sessions", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_sessions_tenant_id_created_at", table_name="sessions")
    op.drop_index("ix_sessions_expires_at", table_name="sessions")
    op.drop_index("ix_sessions_tenant_id_status_expires_at", table_name="sessions")
    op.drop_index("ix_sessions_user_id_status", table_name="sessions")
    op.drop_index("ix_sessions_status", table_name="sessions")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_index("ix_sessions_tenant_id", table_name="sessions")
    op.drop_table("sessions")
