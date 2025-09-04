"""Add workflow release policy fields

Revision ID: 0026_2025.09.04_eb02c4d9
Revises: 0025_2025.08.21_57ca4488
Create Date: 2025-09-04 18:23:41.821738+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0026_2025.09.04_eb02c4d9"
down_revision: str | None = "0025_2025.08.21_57ca4488"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("DROP TABLE IF EXISTS _alembic_tmp_releasepolicy")
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.add_column(sa.Column("github_compose_workflow_path", sa.String(), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("github_vote_workflow_path", sa.String(), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("github_finish_workflow_path", sa.String(), nullable=False, server_default=""))
        batch_op.drop_column("github_workflow_path")


def downgrade() -> None:
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("github_workflow_path", sa.VARCHAR(), server_default=sa.text("('')"), nullable=False)
        )
        batch_op.drop_column("github_finish_workflow_path")
        batch_op.drop_column("github_vote_workflow_path")
        batch_op.drop_column("github_compose_workflow_path")
