"""Add a manual vote property to releases

Revision ID: 0014_2025.07.02_dd73e63e
Revises: 0013_2025.07.01_721abfcd
Create Date: 2025-07-02 13:48:32.003582+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0014_2025.07.02_dd73e63e"
down_revision: str | None = "0013_2025.07.01_721abfcd"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("release", schema=None) as batch_op:
        batch_op.add_column(sa.Column("vote_manual", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("release", schema=None) as batch_op:
        batch_op.drop_column("vote_manual")
