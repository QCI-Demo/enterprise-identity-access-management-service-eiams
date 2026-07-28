"""Create organizations table.

Revision ID: 002_organizations
Revises: 001_tenants
Create Date: 2024-01-01 00:00:01.000000

Organizations provide hierarchical grouping within tenants.
They support parent-child relationships for nested structures.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "002_organizations"
down_revision: Union[str, None] = "001_tenants"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(63), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("parent_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_organizations"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_organizations_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["parent_id"], ["organizations.id"],
            name="fk_organizations_parent_id_organizations",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("tenant_id", "name", name="uq_organizations_tenant_name"),
        sa.UniqueConstraint("tenant_id", "slug", name="uq_organizations_tenant_slug"),
    )
    
    # Indexes
    op.create_index("ix_organizations_tenant_id", "organizations", ["tenant_id"])
    op.create_index("ix_organizations_parent_id", "organizations", ["parent_id"])
    op.create_index("ix_organizations_tenant_id_name", "organizations", ["tenant_id", "name"])
    op.create_index("ix_organizations_tenant_id_created_at", "organizations", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_organizations_tenant_id_created_at", table_name="organizations")
    op.drop_index("ix_organizations_tenant_id_name", table_name="organizations")
    op.drop_index("ix_organizations_parent_id", table_name="organizations")
    op.drop_index("ix_organizations_tenant_id", table_name="organizations")
    op.drop_table("organizations")
