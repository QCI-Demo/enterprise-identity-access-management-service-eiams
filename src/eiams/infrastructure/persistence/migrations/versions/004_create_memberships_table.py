"""Create memberships table.

Revision ID: 004_memberships
Revises: 003_users
Create Date: 2024-01-01 00:00:03.000000

Memberships link users to organizations with roles.
Enforces unique user-organization pairs within a tenant.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "004_memberships"
down_revision: Union[str, None] = "003_users"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "memberships",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("role", sa.String(63), nullable=False, server_default="member"),
        sa.Column("status", sa.String(15), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_memberships"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_memberships_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name="fk_memberships_user_id_users",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"],
            name="fk_memberships_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("user_id", "organization_id", name="uq_memberships_user_organization"),
        sa.CheckConstraint(
            "status IN ('active', 'inactive', 'pending')",
            name="ck_memberships_valid_membership_status",
        ),
    )
    
    # Indexes
    op.create_index("ix_memberships_tenant_id", "memberships", ["tenant_id"])
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_index("ix_memberships_organization_id", "memberships", ["organization_id"])
    op.create_index("ix_memberships_status", "memberships", ["status"])
    op.create_index("ix_memberships_user_id_status", "memberships", ["user_id", "status"])
    op.create_index("ix_memberships_organization_id_status", "memberships", ["organization_id", "status"])
    op.create_index("ix_memberships_tenant_id_created_at", "memberships", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_memberships_tenant_id_created_at", table_name="memberships")
    op.drop_index("ix_memberships_organization_id_status", table_name="memberships")
    op.drop_index("ix_memberships_user_id_status", table_name="memberships")
    op.drop_index("ix_memberships_status", table_name="memberships")
    op.drop_index("ix_memberships_organization_id", table_name="memberships")
    op.drop_index("ix_memberships_user_id", table_name="memberships")
    op.drop_index("ix_memberships_tenant_id", table_name="memberships")
    op.drop_table("memberships")
