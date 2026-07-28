"""Create role_permissions junction table.

Revision ID: 007_role_permissions
Revises: 006_roles
Create Date: 2024-01-01 00:00:06.000000

Many-to-many relationship between roles and permissions.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "007_role_permissions"
down_revision: Union[str, None] = "006_roles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("permission_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("role_id", "permission_id", name="pk_role_permissions"),
        sa.ForeignKeyConstraint(
            ["role_id"], ["roles.id"],
            name="fk_role_permissions_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["permission_id"], ["permissions.id"],
            name="fk_role_permissions_permission_id_permissions",
            ondelete="CASCADE",
        ),
    )
    
    # Indexes
    op.create_index("ix_role_permissions_permission_id", "role_permissions", ["permission_id"])


def downgrade() -> None:
    op.drop_index("ix_role_permissions_permission_id", table_name="role_permissions")
    op.drop_table("role_permissions")
