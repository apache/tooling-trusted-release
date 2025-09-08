"""Use a list of strings for release policy workflow URLs

Revision ID: 0027_2025.09.08_69e565eb
Revises: 0026_2025.09.04_eb02c4d9
Create Date: 2025-09-08 18:57:18.049164+00:00
"""

import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic
revision: str = "0027_2025.09.08_69e565eb"
down_revision: str | None = "0026_2025.09.04_eb02c4d9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    for col in [
        "github_compose_workflow_path",
        "github_vote_workflow_path",
        "github_finish_workflow_path",
    ]:
        rows = bind.execute(sa.text(f"SELECT id, {col} AS v FROM releasepolicy")).mappings().all()
        for row in rows:
            v = row["v"]
            if not v:
                new_v = json.dumps([])
            elif isinstance(v, str):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        new_v = v
                    else:
                        new_v = json.dumps([v])
                except Exception:
                    new_v = json.dumps([v])
            else:
                continue
            bind.execute(
                sa.text(f"UPDATE releasepolicy SET {col} = :v WHERE id = :id"),
                {"v": new_v, "id": row["id"]},
            )

    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.alter_column(
            "github_compose_workflow_path", existing_type=sa.VARCHAR(), type_=sa.JSON(), nullable=False
        )
        batch_op.alter_column("github_vote_workflow_path", existing_type=sa.VARCHAR(), type_=sa.JSON(), nullable=False)
        batch_op.alter_column(
            "github_finish_workflow_path", existing_type=sa.VARCHAR(), type_=sa.JSON(), nullable=False
        )


def downgrade() -> None:
    bind = op.get_bind()
    for col in [
        "github_finish_workflow_path",
        "github_vote_workflow_path",
        "github_compose_workflow_path",
    ]:
        rows = bind.execute(sa.text(f"SELECT id, {col} AS v FROM releasepolicy")).mappings().all()
        for row in rows:
            v = row["v"]
            new_v = ""
            if isinstance(v, str):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list) and parsed:
                        new_v = str(parsed[0])
                except Exception:
                    new_v = v
            bind.execute(
                sa.text(f"UPDATE releasepolicy SET {col} = :v WHERE id = :id"),
                {"v": new_v, "id": row["id"]},
            )

    with op.batch_alter_table("releasepolicy", schema=None) as batch_op:
        batch_op.alter_column(
            "github_finish_workflow_path", existing_type=sa.JSON(), type_=sa.VARCHAR(), nullable=False
        )
        batch_op.alter_column("github_vote_workflow_path", existing_type=sa.JSON(), type_=sa.VARCHAR(), nullable=False)
        batch_op.alter_column(
            "github_compose_workflow_path", existing_type=sa.JSON(), type_=sa.VARCHAR(), nullable=False
        )
