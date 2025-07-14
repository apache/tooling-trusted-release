"""Add a column for the latest key self signature

Revision ID: 0009_2025.06.12_d6037201
Revises: 0008_2025.06.12_26c0022b
Create Date: 2025-06-12 16:09:32.605808+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import atr.models.sql as sql

# Revision identifiers, used by Alembic
revision: str = "0009_2025.06.12_d6037201"
down_revision: str | None = "0008_2025.06.12_26c0022b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("publicsigningkey", schema=None) as batch_op:
        batch_op.add_column(sa.Column("latest_self_signature", sql.UTCDateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("publicsigningkey", schema=None) as batch_op:
        batch_op.drop_column("latest_self_signature")
