"""Add a release policy field to preserve existing download files

Revision ID: 0028_2025.09.09_a0037268
Revises: 0027_2025.09.08_69e565eb
Create Date: 2025-09-09 15:45:39.857545+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0028_2025.09.09_a0037268"
down_revision: str | None = "0027_2025.09.08_69e565eb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("preserve_download_files", sa.Boolean(), nullable=False, server_default=sa.false())
        )


def downgrade() -> None:
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.drop_column("preserve_download_files")
