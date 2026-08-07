"""Create audit_events table.

Revision ID: 014_audit_events
Revises: 013_refresh_tokens
Create Date: 2024-01-01 00:00:13.000000

Append-only audit events for security compliance.
Optimized for high-volume inserts and time-based queries.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "014_audit_events"
down_revision: Union[str, None] = "013_refresh_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False, server_default="info"),
        sa.Column("actor_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("actor_type", sa.String(63), nullable=False, server_default="user"),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("target_type", sa.String(63), nullable=True),
        sa.Column("target_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("outcome", sa.String(63), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("event_metadata", sa.JSON(), nullable=True),
        sa.Column("error_code", sa.String(63), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
        sa.CheckConstraint(
            "outcome IN ('success', 'failure', 'error', 'denied', 'timeout')",
            name="ck_audit_events_valid_audit_outcome",
        ),
        sa.CheckConstraint(
            "actor_type IN ('user', 'service', 'system', 'anonymous')",
            name="ck_audit_events_valid_audit_actor_type",
        ),
    )
    
    # Primary query pattern: tenant + time range
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])
    op.create_index("ix_audit_events_severity", "audit_events", ["severity"])
    op.create_index("ix_audit_events_actor_id", "audit_events", ["actor_id"])
    op.create_index("ix_audit_events_event_time", "audit_events", ["event_time"])
    op.create_index("ix_audit_events_correlation_id", "audit_events", ["correlation_id"])
    
    # Composite indexes for common query patterns
    op.create_index("ix_audit_events_tenant_id_event_time", "audit_events", ["tenant_id", "event_time"])
    op.create_index("ix_audit_events_actor_id_event_time", "audit_events", ["actor_id", "event_time"])
    op.create_index("ix_audit_events_target_type_target_id_event_time", "audit_events", ["target_type", "target_id", "event_time"])
    op.create_index("ix_audit_events_tenant_id_event_type_event_time", "audit_events", ["tenant_id", "event_type", "event_time"])
    op.create_index("ix_audit_events_severity_event_time", "audit_events", ["severity", "event_time"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_severity_event_time", table_name="audit_events")
    op.drop_index("ix_audit_events_tenant_id_event_type_event_time", table_name="audit_events")
    op.drop_index("ix_audit_events_target_type_target_id_event_time", table_name="audit_events")
    op.drop_index("ix_audit_events_actor_id_event_time", table_name="audit_events")
    op.drop_index("ix_audit_events_tenant_id_event_time", table_name="audit_events")
    op.drop_index("ix_audit_events_correlation_id", table_name="audit_events")
    op.drop_index("ix_audit_events_event_time", table_name="audit_events")
    op.drop_index("ix_audit_events_actor_id", table_name="audit_events")
    op.drop_index("ix_audit_events_severity", table_name="audit_events")
    op.drop_index("ix_audit_events_event_type", table_name="audit_events")
    op.drop_index("ix_audit_events_tenant_id", table_name="audit_events")
    op.drop_table("audit_events")
