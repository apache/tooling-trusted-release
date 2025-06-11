"""Use project and version in tasks

Revision ID: 0007_2025.06.11_4887c85c
Revises: 0006_2025.05.30_9672a901
Create Date: 2025-06-11 15:27:25.527805+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0007_2025.06.11_4887c85c"
down_revision: str | None = "0006_2025.05.30_9672a901"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("task", schema=None) as batch_op:
        batch_op.add_column(sa.Column("project_name", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("version_name", sa.String(), nullable=True))
        batch_op.create_index(batch_op.f("ix_task_version_name"), ["version_name"], unique=False)
        batch_op.drop_constraint(batch_op.f("fk_task_release_name_release"), type_="foreignkey")
        batch_op.create_foreign_key(batch_op.f("fk_task_project_name_project"), "project", ["project_name"], ["name"])
        batch_op.drop_column("release_name")


def downgrade() -> None:
    with op.batch_alter_table("task", schema=None) as batch_op:
        batch_op.add_column(sa.Column("release_name", sa.VARCHAR(), nullable=True))
        batch_op.drop_constraint(batch_op.f("fk_task_project_name_project"), type_="foreignkey")
        batch_op.create_foreign_key(batch_op.f("fk_task_release_name_release"), "release", ["release_name"], ["name"])
        batch_op.drop_index(batch_op.f("ix_task_version_name"))
        batch_op.drop_column("version_name")
        batch_op.drop_column("project_name")
