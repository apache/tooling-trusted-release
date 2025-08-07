"""Add a compound primary key to Distribution

Revision ID: 0020_2025.08.07_23999f25
Revises: 0019_2025.08.07_279ca4a9
Create Date: 2025-08-07 15:53:27.260830+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0020_2025.08.07_23999f25"
down_revision: str | None = "0019_2025.08.07_279ca4a9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("UPDATE distribution SET owner_namespace = '' WHERE owner_namespace IS NULL")
    with op.batch_alter_table("distribution", schema=None) as batch_op:
        batch_op.drop_column("id")
        batch_op.alter_column("owner_namespace", existing_type=sa.VARCHAR(), nullable=False)
        batch_op.create_primary_key(
            "pk_distribution", ["release_name", "platform", "owner_namespace", "package", "version"]
        )
        batch_op.create_index(batch_op.f("ix_distribution_owner_namespace"), ["owner_namespace"], unique=False)
        batch_op.create_index(batch_op.f("ix_distribution_package"), ["package"], unique=False)
        batch_op.create_index(batch_op.f("ix_distribution_platform"), ["platform"], unique=False)
        batch_op.create_index(batch_op.f("ix_distribution_release_name"), ["release_name"], unique=False)
        batch_op.create_index(batch_op.f("ix_distribution_version"), ["version"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("distribution", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_distribution_version"))
        batch_op.drop_index(batch_op.f("ix_distribution_release_name"))
        batch_op.drop_index(batch_op.f("ix_distribution_platform"))
        batch_op.drop_index(batch_op.f("ix_distribution_package"))
        batch_op.drop_index(batch_op.f("ix_distribution_owner_namespace"))
        batch_op.drop_constraint("pk_distribution", type_="primary")
        batch_op.alter_column("owner_namespace", existing_type=sa.VARCHAR(), nullable=True)
        batch_op.add_column(sa.Column("id", sa.INTEGER(), nullable=False))
        batch_op.create_primary_key("pk_distribution_id", ["id"])
