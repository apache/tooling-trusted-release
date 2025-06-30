"""Add podling thread ID to releases

Revision ID: 0012_2025.06.30_f3240855
Revises: 0011_2025.06.20_b1fa791d
Create Date: 2025-06-30 15:56:26.123627+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0012_2025.06.30_f3240855"
down_revision: str | None = "0011_2025.06.20_b1fa791d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("release", schema=None) as batch_op:
        batch_op.add_column(sa.Column("podling_thread_id", sa.String(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("release", schema=None) as batch_op:
        batch_op.drop_column("podling_thread_id")
