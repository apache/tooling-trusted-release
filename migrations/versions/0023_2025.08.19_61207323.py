"""Add release policy fields for Trusted Publishing via OIDC

Revision ID: 0023_2025.08.19_61207323
Revises: 0022_2025.08.08_d7b4edf0
Create Date: 2025-08-19 19:52:24.232121+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0023_2025.08.19_61207323"
down_revision: str | None = "0022_2025.08.08_d7b4edf0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.add_column(sa.Column("github_repository_name", sa.String(), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("github_workflow_path", sa.String(), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.drop_column("github_workflow_path")
        batch_op.drop_column("github_repository_name")
