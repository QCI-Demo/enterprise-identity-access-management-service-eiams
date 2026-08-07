"""Create permissions table.

Revision ID: 005_permissions
Revises: 004_memberships
Create Date: 2024-01-01 00:00:04.000000

Permissions define granular access rights for resources.
System permissions (tenant_id=NULL) are available across all tenants.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "005_permissions"
down_revision: Union[str, None] = "004_memberships"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "permissions",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("resource_type", sa.String(63), nullable=False),
        sa.Column("action", sa.String(63), nullable=False),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_permissions"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_permissions_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "resource_type", "action", name="uq_permissions_tenant_resource_action"),
    )
    
    # Indexes
    op.create_index("ix_permissions_tenant_id", "permissions", ["tenant_id"])
    op.create_index("ix_permissions_resource_type_action", "permissions", ["resource_type", "action"])
    op.create_index("ix_permissions_tenant_id_name", "permissions", ["tenant_id", "name"])


def downgrade() -> None:
    op.drop_index("ix_permissions_tenant_id_name", table_name="permissions")
    op.drop_index("ix_permissions_resource_type_action", table_name="permissions")
    op.drop_index("ix_permissions_tenant_id", table_name="permissions")
    op.drop_table("permissions")
