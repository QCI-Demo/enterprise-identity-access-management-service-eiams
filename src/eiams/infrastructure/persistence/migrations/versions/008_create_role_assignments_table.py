"""Create role_assignments table.

Revision ID: 008_role_assignments
Revises: 007_role_permissions
Create Date: 2024-01-01 00:00:07.000000

Role assignments link users to roles with optional scope.
Supports scoped permissions (e.g., organization-level access).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "008_role_assignments"
down_revision: Union[str, None] = "007_role_permissions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "role_assignments",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("role_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("scope_type", sa.String(63), nullable=True),
        sa.Column("scope_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_role_assignments"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_role_assignments_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name="fk_role_assignments_user_id_users",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"], ["roles.id"],
            name="fk_role_assignments_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("user_id", "role_id", "scope_type", "scope_id", name="uq_role_assignments_user_role_scope"),
        sa.CheckConstraint(
            "(scope_type IS NULL AND scope_id IS NULL) OR (scope_type IS NOT NULL AND scope_id IS NOT NULL)",
            name="ck_role_assignments_valid_scope_combination",
        ),
    )
    
    # Indexes
    op.create_index("ix_role_assignments_tenant_id", "role_assignments", ["tenant_id"])
    op.create_index("ix_role_assignments_user_id", "role_assignments", ["user_id"])
    op.create_index("ix_role_assignments_role_id", "role_assignments", ["role_id"])
    op.create_index("ix_role_assignments_user_id_role_id", "role_assignments", ["user_id", "role_id"])
    op.create_index("ix_role_assignments_scope_type_scope_id", "role_assignments", ["scope_type", "scope_id"])
    op.create_index("ix_role_assignments_tenant_id_created_at", "role_assignments", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_role_assignments_tenant_id_created_at", table_name="role_assignments")
    op.drop_index("ix_role_assignments_scope_type_scope_id", table_name="role_assignments")
    op.drop_index("ix_role_assignments_user_id_role_id", table_name="role_assignments")
    op.drop_index("ix_role_assignments_role_id", table_name="role_assignments")
    op.drop_index("ix_role_assignments_user_id", table_name="role_assignments")
    op.drop_index("ix_role_assignments_tenant_id", table_name="role_assignments")
    op.drop_table("role_assignments")
