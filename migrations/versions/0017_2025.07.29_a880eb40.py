"""Add CheckResultIgnore

Revision ID: 0017_2025.07.29_a880eb40
Revises: 0016_2025.07.24_07af24db
Create Date: 2025-07-29 18:10:30.462421+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import atr.models.sql

# Revision identifiers, used by Alembic
revision: str = "0017_2025.07.29_a880eb40"
down_revision: str | None = "0016_2025.07.24_07af24db"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "checkresultignore",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asf_uid", sa.String(), nullable=False),
        sa.Column("created", atr.models.sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("committee_name", sa.String(), nullable=False),
        sa.Column("release_glob", sa.String(), nullable=True),
        sa.Column("revision_number", sa.String(), nullable=True),
        sa.Column("checker_glob", sa.String(), nullable=True),
        sa.Column("primary_rel_path_glob", sa.String(), nullable=True),
        sa.Column("member_rel_path_glob", sa.String(), nullable=True),
        sa.Column("status", sa.Enum("EXCEPTION", "FAILURE", "WARNING", name="checkresultstatusignore"), nullable=True),
        sa.Column("message_glob", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_checkresultignore")),
    )


def downgrade() -> None:
    op.drop_table("checkresultignore")
