"""Add cascade delete to CheckResult on release

Revision ID: 0008_2025.06.12_26c0022b
Revises: 0007_2025.06.11_4887c85c
Create Date: 2025-06-12 14:34:03.092016+00:00
"""

from collections.abc import Sequence

from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0008_2025.06.12_26c0022b"
down_revision: str | None = "0007_2025.06.11_4887c85c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("checkresult", schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f("fk_checkresult_release_name_release"), type_="foreignkey")
        batch_op.create_foreign_key(
            batch_op.f("fk_checkresult_release_name_release"), "release", ["release_name"], ["name"], ondelete="CASCADE"
        )


def downgrade() -> None:
    with op.batch_alter_table("checkresult", schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f("fk_checkresult_release_name_release"), type_="foreignkey")
        batch_op.create_foreign_key(
            batch_op.f("fk_checkresult_release_name_release"), "release", ["release_name"], ["name"]
        )
