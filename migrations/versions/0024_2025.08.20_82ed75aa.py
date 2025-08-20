"""Add a table for storing GHA workflow SSH keys

Revision ID: 0024_2025.08.20_82ed75aa
Revises: 0023_2025.08.19_61207323
Create Date: 2025-08-20 19:32:02.342122+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0024_2025.08.20_82ed75aa"
down_revision: str | None = "0023_2025.08.19_61207323"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workflowsshkey",
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("project_name", sa.String(), nullable=False),
        sa.Column("expires", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("fingerprint", name=op.f("pk_workflowsshkey")),
    )
    with op.batch_alter_table("workflowsshkey", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_workflowsshkey_fingerprint"), ["fingerprint"], unique=False)
        batch_op.create_index(batch_op.f("ix_workflowsshkey_project_name"), ["project_name"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("workflowsshkey", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_workflowsshkey_project_name"))
        batch_op.drop_index(batch_op.f("ix_workflowsshkey_fingerprint"))

    op.drop_table("workflowsshkey")
