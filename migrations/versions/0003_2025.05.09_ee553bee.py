"""Add revision to CheckResult and ensure consistent naming

Revision ID: 0003_2025.05.09_ee553bee
Revises: 0002_2025.05.08_32fdbfe0
Create Date: 2025-05-09 13:54:38.132731+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0003_2025.05.09_ee553bee"
down_revision: str | None = "0002_2025.05.08_32fdbfe0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("checkresult", sa.Column("revision", sa.String(), nullable=False, server_default=""))
    op.create_index(op.f("ix_checkresult_revision"), "checkresult", ["revision"], unique=False)

    with op.batch_alter_table("task", schema=None) as batch_op:
        batch_op.alter_column(
            "draft_revision",
            new_column_name="revision",
            type_=sa.String(),
            existing_type=sa.VARCHAR(),
            nullable=True,
            existing_nullable=True,
        )

    with op.batch_alter_table("task", schema=None) as batch_op:
        batch_op.drop_index("ix_task_draft_revision")
        batch_op.create_index(op.f("ix_task_revision"), ["revision"], unique=False)

    op.drop_index("ix_checkresulthistorylink_draft_revision", table_name="checkresulthistorylink")
    op.drop_table("checkresulthistorylink")


def downgrade() -> None:
    op.create_table(
        "checkresulthistorylink",
        sa.Column("check_result_id", sa.INTEGER(), nullable=False),
        sa.Column("draft_revision", sa.VARCHAR(), nullable=False),
        sa.ForeignKeyConstraint(
            ["check_result_id"],
            ["checkresult.id"],
        ),
        sa.PrimaryKeyConstraint("check_result_id", "draft_revision"),
    )
    op.create_index(
        "ix_checkresulthistorylink_draft_revision", "checkresulthistorylink", ["draft_revision"], unique=False
    )

    with op.batch_alter_table("task", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_task_revision"))
        batch_op.create_index("ix_task_draft_revision", ["revision"], unique=False)

    with op.batch_alter_table("task", schema=None) as batch_op:
        batch_op.alter_column(
            "revision",
            new_column_name="draft_revision",
            type_=sa.VARCHAR(),
            existing_type=sa.String(),
            nullable=True,
            existing_nullable=True,
        )

    op.drop_index(op.f("ix_checkresult_revision"), table_name="checkresult")
    op.drop_column("checkresult", "revision")
