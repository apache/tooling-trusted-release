"""Add PATs

Revision ID: 0015_2025.07.03_cb10d8d3
Revises: 0014_2025.07.02_dd73e63e
Create Date: 2025-07-03 14:36:50.267367+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import atr.models.sql as sql

# Revision identifiers, used by Alembic
revision: str = "0015_2025.07.03_cb10d8d3"
down_revision: str | None = "0014_2025.07.02_dd73e63e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "personalaccesstoken",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asfuid", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("created", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("expires", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("last_used", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("label", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_personalaccesstoken")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_personalaccesstoken_token_hash")),
    )
    with op.batch_alter_table("personalaccesstoken", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_personalaccesstoken_asfuid"), ["asfuid"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("personalaccesstoken", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_personalaccesstoken_asfuid"))

    op.drop_table("personalaccesstoken")
