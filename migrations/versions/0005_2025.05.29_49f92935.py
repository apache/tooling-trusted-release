"""Make minimum vote duration nullable to signify default

Revision ID: 0005_2025.05.29_49f92935
Revises: 0004_2025.05.27_52cbd2b5
Create Date: 2025-05-29 16:07:40.588955+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0005_2025.05.29_49f92935"
down_revision: str | None = "0004_2025.05.27_52cbd2b5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.alter_column("min_hours", existing_type=sa.INTEGER(), nullable=True)


def downgrade() -> None:
    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.alter_column("min_hours", existing_type=sa.INTEGER(), nullable=False)
