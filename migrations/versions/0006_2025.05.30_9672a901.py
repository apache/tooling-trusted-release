"""Remove Project.is_podling

Revision ID: 0006_2025.05.30_9672a901
Revises: 0005_2025.05.29_49f92935
Create Date: 2025-05-30 15:22:08.113248+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0006_2025.05.30_9672a901"
down_revision: str | None = "0005_2025.05.29_49f92935"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("project", schema=None) as batch_op:
        batch_op.drop_column("is_podling")


def downgrade() -> None:
    with op.batch_alter_table("project", schema=None) as batch_op:
        batch_op.add_column(sa.Column("is_podling", sa.BOOLEAN(), nullable=False))
