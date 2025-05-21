"""Add secondary signing key UIDs

Revision ID: 0003_2025.05.21_ebed2397
Revises: 0002_2025.05.19_93ec427d
Create Date: 2025-05-21 15:56:45.161982+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0003_2025.05.21_ebed2397"
down_revision: str | None = "0002_2025.05.19_93ec427d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("publicsigningkey", sa.Column("primary_declared_uid", sa.String(), nullable=True))
    op.add_column("publicsigningkey", sa.Column("secondary_declared_uids", sa.JSON(), nullable=True))
    op.execute("UPDATE publicsigningkey SET primary_declared_uid = declared_uid")
    op.drop_column("publicsigningkey", "declared_uid")


def downgrade() -> None:
    op.add_column("publicsigningkey", sa.Column("declared_uid", sa.VARCHAR(), nullable=True))
    op.execute("UPDATE publicsigningkey SET declared_uid = primary_declared_uid")
    op.drop_column("publicsigningkey", "secondary_declared_uids")
    op.drop_column("publicsigningkey", "primary_declared_uid")
