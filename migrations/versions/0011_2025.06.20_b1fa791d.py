"""Add binary and source artifact paths

Revision ID: 0011_2025.06.20_b1fa791d
Revises: 0010_2025.06.12_3b27ab22
Create Date: 2025-06-20 19:50:07.447190+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0011_2025.06.20_b1fa791d"
down_revision: str | None = "0010_2025.06.12_3b27ab22"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.add_column(sa.Column("binary_artifact_paths", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("source_artifact_paths", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.drop_column("source_artifact_paths")
        batch_op.drop_column("binary_artifact_paths")
