"""Add Distribution, and remove DistributionChannel

Revision ID: 0018_2025.08.07_41ccdd9a
Revises: 0017_2025.07.29_a880eb40
Create Date: 2025-08-07 14:32:07.523311+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0018_2025.08.07_41ccdd9a"
down_revision: str | None = "0017_2025.07.29_a880eb40"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "distribution",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("release_name", sa.String(), nullable=False),
        sa.Column(
            "platform",
            sa.Enum(
                "ARTIFACTHUB", "DOCKER", "GITHUB", "MAVEN", "NPM", "NPM_SCOPED", "PYPI", name="distributionplatform"
            ),
            nullable=False,
        ),
        sa.Column("owner_namespace", sa.String(), nullable=True),
        sa.Column("package", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False),
        sa.Column("staging", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("upload_date", sa.DateTime(), nullable=True),
        sa.Column("api_url", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["release_name"], ["release.name"], name=op.f("fk_distribution_release_name_release")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_distribution")),
    )
    with op.batch_alter_table("distributionchannel", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_distributionchannel_name"))

    op.drop_table("distributionchannel")


def downgrade() -> None:
    op.create_table(
        "distributionchannel",
        sa.Column("id", sa.INTEGER(), nullable=False),
        sa.Column("name", sa.VARCHAR(), nullable=False),
        sa.Column("url", sa.VARCHAR(), nullable=False),
        sa.Column("credentials", sa.VARCHAR(), nullable=False),
        sa.Column("is_test", sa.BOOLEAN(), nullable=False),
        sa.Column("automation_endpoint", sa.VARCHAR(), nullable=False),
        sa.Column("project_name", sa.VARCHAR(), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_name"], ["project.name"], name=op.f("fk_distributionchannel_project_name_project")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_distributionchannel")),
    )
    with op.batch_alter_table("distributionchannel", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_distributionchannel_name"), ["name"], unique=1)

    op.drop_table("distribution")
