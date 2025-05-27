"""Make ASF UID optional on public keys

Revision ID: 0004_2025.05.27_52cbd2b5
Revises: 0003_2025.05.21_ebed2397
Create Date: 2025-05-27 13:18:44.637580+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0004_2025.05.27_52cbd2b5"
down_revision: str | None = "0003_2025.05.21_ebed2397"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("publicsigningkey", schema=None) as batch_op:
        batch_op.alter_column("apache_uid", existing_type=sa.VARCHAR(), nullable=True)


def downgrade() -> None:
    with op.batch_alter_table("publicsigningkey", schema=None) as batch_op:
        batch_op.alter_column("apache_uid", existing_type=sa.VARCHAR(), nullable=False)
