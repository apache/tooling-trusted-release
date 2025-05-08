"""Add CheckResult.member_rel_path

Revision ID: 0002_2025.05.08_32fdbfe0
Revises: 0001_2025.05.06_38b0d2de
Create Date: 2025-05-08 14:28:07.435446+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0002_2025.05.08_32fdbfe0"
down_revision: str | None = "0001_2025.05.06_38b0d2de"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("checkresult", sa.Column("member_rel_path", sa.String(), nullable=True))
    op.create_index(op.f("ix_checkresult_member_rel_path"), "checkresult", ["member_rel_path"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_checkresult_member_rel_path"), table_name="checkresult")
    op.drop_column("checkresult", "member_rel_path")
