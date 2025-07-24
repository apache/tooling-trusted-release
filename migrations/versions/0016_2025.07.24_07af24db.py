"""Add ASF UID to Task

Revision ID: 0016_2025.07.24_07af24db
Revises: 0015_2025.07.03_cb10d8d3
Create Date: 2025-07-24 14:41:24.008407+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0016_2025.07.24_07af24db"
down_revision: str | None = "0015_2025.07.03_cb10d8d3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("task", schema=None) as batch_op:
        batch_op.add_column(sa.Column("asf_uid", sa.String(), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("task", schema=None) as batch_op:
        batch_op.drop_column("asf_uid")
