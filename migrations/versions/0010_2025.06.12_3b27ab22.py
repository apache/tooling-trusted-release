"""Add project statuses

Revision ID: 0010_2025.06.12_3b27ab22
Revises: 0009_2025.06.12_d6037201
Create Date: 2025-06-12 19:03:06.665183+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0010_2025.06.12_3b27ab22"
down_revision: str | None = "0009_2025.06.12_d6037201"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("project", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "status",
                sa.Enum("ACTIVE", "DORMANT", "RETIRED", "STANDING", name="projectstatus"),
                nullable=False,
                server_default="ACTIVE",
            )
        )
        batch_op.drop_column("is_retired")


def downgrade() -> None:
    with op.batch_alter_table("project", schema=None) as batch_op:
        batch_op.add_column(sa.Column("is_retired", sa.BOOLEAN(), nullable=False))
        batch_op.drop_column("status")
