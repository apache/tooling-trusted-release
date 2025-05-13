"""Remove some check functions from TaskType

Revision ID: 0004_2025.05.13_657bf05b
Revises: 0003_2025.05.09_ee553bee
Create Date: 2025-05-13 14:41:31.781711+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0004_2025.05.13_657bf05b"
down_revision: str | None = "0003_2025.05.09_ee553bee"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ENUM_MEMBERS_BEFORE_REMOVAL = (
    "HASHING_CHECK",
    "KEYS_IMPORT_FILE",
    "LICENSE_FILES",
    "LICENSE_HEADERS",
    "MESSAGE_SEND",
    "PATHS_CHECK",
    "RAT_CHECK",
    "SBOM_GENERATE_CYCLONEDX",
    "SIGNATURE_CHECK",
    "SVN_IMPORT_FILES",
    "TARGZ_INTEGRITY",
    "TARGZ_STRUCTURE",
    "VOTE_INITIATE",
    "ZIPFORMAT_INTEGRITY",
    "ZIPFORMAT_LICENSE_FILES",
    "ZIPFORMAT_LICENSE_HEADERS",
    "ZIPFORMAT_STRUCTURE",
)

_ENUM_MEMBERS_AFTER_REMOVAL = tuple(
    m for m in _ENUM_MEMBERS_BEFORE_REMOVAL if m not in {"ZIPFORMAT_LICENSE_FILES", "ZIPFORMAT_LICENSE_HEADERS"}
)


def upgrade() -> None:
    with op.batch_alter_table("task", schema=None) as batch_op:
        batch_op.alter_column(
            "task_type",
            existing_type=sa.Enum(*_ENUM_MEMBERS_BEFORE_REMOVAL, name="tasktype"),
            type_=sa.Enum(*_ENUM_MEMBERS_AFTER_REMOVAL, name="tasktype"),
            existing_nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("task", schema=None) as batch_op:
        batch_op.alter_column(
            "task_type",
            existing_type=sa.Enum(*_ENUM_MEMBERS_AFTER_REMOVAL, name="tasktype"),
            type_=sa.Enum(*_ENUM_MEMBERS_BEFORE_REMOVAL, name="tasktype"),
            existing_nullable=False,
        )
