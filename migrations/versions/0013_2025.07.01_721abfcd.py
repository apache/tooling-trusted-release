"""Add a strict checking property to release policies

Revision ID: 0013_2025.07.01_721abfcd
Revises: 0012_2025.06.30_f3240855
Create Date: 2025-07-01 16:16:29.328759+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0013_2025.07.01_721abfcd"
down_revision: str | None = "0012_2025.06.30_f3240855"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.add_column(sa.Column("strict_checking", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.drop_column("strict_checking")
