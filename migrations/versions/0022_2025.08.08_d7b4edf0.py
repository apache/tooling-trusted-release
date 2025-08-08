"""Rename DistributionPlatform enum fields for precision

Revision ID: 0022_2025.08.08_d7b4edf0
Revises: 0021_2025.08.08_3e1625a6
Create Date: 2025-08-08 16:03:59.033106+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0022_2025.08.08_d7b4edf0"
down_revision: str | None = "0021_2025.08.08_3e1625a6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("UPDATE distribution SET platform='ARTIFACT_HUB' WHERE platform='ARTIFACTHUB'")
    op.execute("UPDATE distribution SET platform='DOCKER_HUB' WHERE platform='DOCKER'")

    with op.batch_alter_table("distribution", schema=None) as batch_op:
        batch_op.alter_column(
            "platform",
            existing_type=sa.VARCHAR(length=11),
            type_=sa.Enum(
                "ARTIFACT_HUB",
                "DOCKER_HUB",
                "GITHUB",
                "MAVEN",
                "NPM",
                "NPM_SCOPED",
                "PYPI",
                name="distributionplatform",
            ),
            existing_nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("distribution", schema=None) as batch_op:
        batch_op.alter_column(
            "platform",
            existing_type=sa.Enum(
                "ARTIFACT_HUB",
                "DOCKER_HUB",
                "GITHUB",
                "MAVEN",
                "NPM",
                "NPM_SCOPED",
                "PYPI",
                name="distributionplatform",
            ),
            type_=sa.VARCHAR(length=11),
            existing_nullable=False,
        )

    op.execute("UPDATE distribution SET platform='ARTIFACTHUB' WHERE platform='ARTIFACT_HUB'")
    op.execute("UPDATE distribution SET platform='DOCKER' WHERE platform='DOCKER_HUB'")
