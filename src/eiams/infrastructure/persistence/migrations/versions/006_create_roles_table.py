"""Create roles table.

Revision ID: 006_roles
Revises: 005_permissions
Create Date: 2024-01-01 00:00:05.000000

Roles aggregate permissions for assignment to users.
System roles (tenant_id=NULL) are available across all tenants.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "006_roles"
down_revision: Union[str, None] = "005_permissions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_roles"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_roles_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_name"),
    )
    
    # Indexes
    op.create_index("ix_roles_tenant_id", "roles", ["tenant_id"])
    op.create_index("ix_roles_tenant_id_name", "roles", ["tenant_id", "name"])
    op.create_index("ix_roles_is_system", "roles", ["is_system"])


def downgrade() -> None:
    op.drop_index("ix_roles_is_system", table_name="roles")
    op.drop_index("ix_roles_tenant_id_name", table_name="roles")
    op.drop_index("ix_roles_tenant_id", table_name="roles")
    op.drop_table("roles")
