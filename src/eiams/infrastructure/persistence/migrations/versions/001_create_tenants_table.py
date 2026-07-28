"""Create tenants table.

Revision ID: 001_tenants
Revises: None
Create Date: 2024-01-01 00:00:00.000000

Tenants are the root of the multi-tenant hierarchy.
All tenant-scoped entities reference tenants through foreign keys.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "001_tenants"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(63), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending_setup"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_tenants"),
        sa.UniqueConstraint("name", name="uq_tenants_name"),
        sa.UniqueConstraint("slug", name="uq_tenants_slug"),
        sa.CheckConstraint(
            "status IN ('active', 'inactive', 'suspended', 'pending_setup')",
            name="ck_tenants_valid_tenant_status",
        ),
    )
    
    # Indexes
    op.create_index("ix_tenants_name", "tenants", ["name"])
    op.create_index("ix_tenants_slug", "tenants", ["slug"])
    op.create_index("ix_tenants_status", "tenants", ["status"])
    op.create_index("ix_tenants_status_created_at", "tenants", ["status", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_tenants_status_created_at", table_name="tenants")
    op.drop_index("ix_tenants_status", table_name="tenants")
    op.drop_index("ix_tenants_slug", table_name="tenants")
    op.drop_index("ix_tenants_name", table_name="tenants")
    op.drop_table("tenants")
