"""Add a web URL field to Distribution

Revision ID: 0021_2025.08.08_3e1625a6
Revises: 0020_2025.08.07_23999f25
Create Date: 2025-08-08 15:23:07.713491+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0021_2025.08.08_3e1625a6"
down_revision: str | None = "0020_2025.08.07_23999f25"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("distribution", schema=None) as batch_op:
        batch_op.add_column(sa.Column("web_url", sa.String(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("distribution", schema=None) as batch_op:
        batch_op.drop_column("web_url")
