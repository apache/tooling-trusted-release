"""Delete tasks with obsolete ZIPFORMAT types

Revision ID: 0005_2025.05.13_d94f16f6
Revises: 0004_2025.05.13_657bf05b
Create Date: 2025-05-13 15:42:21.333191+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0005_2025.05.13_d94f16f6"
down_revision: str | None = "0004_2025.05.13_657bf05b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Delete tasks with obsolete ZIPFORMAT_LICENSE_FILES and ZIPFORMAT_LICENSE_HEADERS types."""
    bind = op.get_bind()
    result = bind.execute(
        sa.text(
            "SELECT 1 FROM task WHERE task_type IN ('ZIPFORMAT_LICENSE_FILES', 'ZIPFORMAT_LICENSE_HEADERS') LIMIT 1"
        )
    ).scalar_one_or_none()

    if result is not None:
        op.execute("DELETE FROM task WHERE task_type IN ('ZIPFORMAT_LICENSE_FILES', 'ZIPFORMAT_LICENSE_HEADERS')")


def downgrade() -> None:
    """
    Downgrade for this migration.

    Since the upgrade deletes data that corresponds to obsolete enum types,
    a downgrade doesn't have a straightforward way to restore these tasks
    without knowing their original context or reintroducing obsolete types.
    Therefore, this downgrade is a noop.
    """
    pass
