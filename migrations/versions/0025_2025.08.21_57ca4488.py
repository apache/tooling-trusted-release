"""Add more metadata to GHA workflow SSH keys

Revision ID: 0025_2025.08.21_57ca4488
Revises: 0024_2025.08.20_82ed75aa
Create Date: 2025-08-21 14:15:26.799244+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0025_2025.08.21_57ca4488"
down_revision: str | None = "0024_2025.08.20_82ed75aa"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("workflowsshkey", schema=None) as batch_op:
        batch_op.add_column(sa.Column("asf_uid", sa.String(), nullable=False))
        batch_op.add_column(sa.Column("github_uid", sa.String(), nullable=False))
        batch_op.add_column(sa.Column("github_nid", sa.Integer(), nullable=False))
        batch_op.create_index(batch_op.f("ix_workflowsshkey_asf_uid"), ["asf_uid"], unique=False)
        batch_op.create_index(batch_op.f("ix_workflowsshkey_github_nid"), ["github_nid"], unique=False)
        batch_op.create_index(batch_op.f("ix_workflowsshkey_github_uid"), ["github_uid"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("workflowsshkey", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_workflowsshkey_github_uid"))
        batch_op.drop_index(batch_op.f("ix_workflowsshkey_github_nid"))
        batch_op.drop_index(batch_op.f("ix_workflowsshkey_asf_uid"))
        batch_op.drop_column("github_nid")
        batch_op.drop_column("github_uid")
        batch_op.drop_column("asf_uid")
