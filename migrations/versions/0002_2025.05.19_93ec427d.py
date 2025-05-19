"""Remove stages

Revision ID: 0002_2025.05.19_93ec427d
Revises: 0001_2025.05.15_1d3ee5a0
Create Date: 2025-05-19 17:39:29.657125+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0002_2025.05.19_93ec427d"
down_revision: str | None = "0001_2025.05.15_1d3ee5a0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("release", "stage")


def downgrade() -> None:
    # Stage was unused, so it is not necessary to map phases to stages here
    op.add_column("release", sa.Column("stage", sa.VARCHAR(length=17), nullable=False))
