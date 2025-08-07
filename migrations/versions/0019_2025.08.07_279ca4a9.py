"""Ensure that Distribution rows are deleted on cascade

Revision ID: 0019_2025.08.07_279ca4a9
Revises: 0018_2025.08.07_41ccdd9a
Create Date: 2025-08-07 15:23:18.069506+00:00
"""

from collections.abc import Sequence

from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0019_2025.08.07_279ca4a9"
down_revision: str | None = "0018_2025.08.07_41ccdd9a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("distribution", schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f("fk_distribution_release_name_release"), type_="foreignkey")
        batch_op.create_foreign_key(
            batch_op.f("fk_distribution_release_name_release"),
            "release",
            ["release_name"],
            ["name"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    with op.batch_alter_table("distribution", schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f("fk_distribution_release_name_release"), type_="foreignkey")
        batch_op.create_foreign_key(
            batch_op.f("fk_distribution_release_name_release"), "release", ["release_name"], ["name"]
        )
