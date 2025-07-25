"""Use the existing ATR schema

Revision ID: 0001_2025.05.15_1d3ee5a0
Revises:
Create Date: 2025-05-15 19:39:20.865550+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import atr.models.sql as sql

# Revision identifiers, used by Alembic
revision: str = "0001_2025.05.15_1d3ee5a0"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "committee",
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("full_name", sa.String(), nullable=True),
        sa.Column("is_podling", sa.Boolean(), nullable=False),
        sa.Column("parent_committee_name", sa.String(), nullable=True),
        sa.Column("committee_members", sa.JSON(), nullable=True),
        sa.Column("committers", sa.JSON(), nullable=True),
        sa.Column("release_managers", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["parent_committee_name"], ["committee.name"], name=op.f("fk_committee_parent_committee_name_committee")
        ),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_committee")),
        sa.UniqueConstraint("name", name=op.f("uq_committee_name")),
    )
    op.create_table(
        "publicsigningkey",
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("algorithm", sa.Integer(), nullable=False),
        sa.Column("length", sa.Integer(), nullable=False),
        sa.Column("created", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("expires", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("declared_uid", sa.String(), nullable=True),
        sa.Column("apache_uid", sa.String(), nullable=False),
        sa.Column("ascii_armored_key", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("fingerprint", name=op.f("pk_publicsigningkey")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_publicsigningkey_fingerprint")),
    )
    op.create_table(
        "releasepolicy",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("mailto_addresses", sa.JSON(), nullable=True),
        sa.Column("manual_vote", sa.Boolean(), nullable=False),
        sa.Column("min_hours", sa.Integer(), nullable=False),
        sa.Column("release_checklist", sa.String(), nullable=False),
        sa.Column("pause_for_rm", sa.Boolean(), nullable=False),
        sa.Column("start_vote_template", sa.String(), nullable=False),
        sa.Column("announce_release_template", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_releasepolicy")),
    )
    op.create_table(
        "sshkey",
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("asf_uid", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("fingerprint", name=op.f("pk_sshkey")),
    )
    op.create_table(
        "textvalue",
        sa.Column("ns", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("ns", "key", name=op.f("pk_textvalue")),
    )
    op.create_index(op.f("ix_textvalue_key"), "textvalue", ["key"], unique=False)
    op.create_index(op.f("ix_textvalue_ns"), "textvalue", ["ns"], unique=False)
    op.create_table(
        "keylink",
        sa.Column("committee_name", sa.String(), nullable=False),
        sa.Column("key_fingerprint", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["committee_name"], ["committee.name"], name=op.f("fk_keylink_committee_name_committee")
        ),
        sa.ForeignKeyConstraint(
            ["key_fingerprint"],
            ["publicsigningkey.fingerprint"],
            name=op.f("fk_keylink_key_fingerprint_publicsigningkey"),
        ),
        sa.PrimaryKeyConstraint("committee_name", "key_fingerprint", name=op.f("pk_keylink")),
    )
    op.create_table(
        "project",
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("full_name", sa.String(), nullable=True),
        sa.Column("is_podling", sa.Boolean(), nullable=False),
        sa.Column("is_retired", sa.Boolean(), nullable=False),
        sa.Column("super_project_name", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("category", sa.String(), nullable=True),
        sa.Column("programming_languages", sa.String(), nullable=True),
        sa.Column("committee_name", sa.String(), nullable=True),
        sa.Column("release_policy_id", sa.Integer(), nullable=True),
        sa.Column("created", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(
            ["committee_name"], ["committee.name"], name=op.f("fk_project_committee_name_committee")
        ),
        sa.ForeignKeyConstraint(
            ["release_policy_id"],
            ["releasepolicy.id"],
            name=op.f("fk_project_release_policy_id_releasepolicy"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["super_project_name"], ["project.name"], name=op.f("fk_project_super_project_name_project")
        ),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_project")),
        sa.UniqueConstraint("name", name=op.f("uq_project_name")),
    )
    op.create_table(
        "distributionchannel",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("credentials", sa.String(), nullable=False),
        sa.Column("is_test", sa.Boolean(), nullable=False),
        sa.Column("automation_endpoint", sa.String(), nullable=False),
        sa.Column("project_name", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_name"], ["project.name"], name=op.f("fk_distributionchannel_project_name_project")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_distributionchannel")),
    )
    op.create_index(op.f("ix_distributionchannel_name"), "distributionchannel", ["name"], unique=True)
    op.create_table(
        "release",
        sa.Column("name", sa.String(), nullable=False),
        sa.Column(
            "stage", sa.Enum("RELEASE_CANDIDATE", "RELEASE", "MIGRATION", "FAILED", name="releasestage"), nullable=False
        ),
        sa.Column(
            "phase",
            sa.Enum("RELEASE_CANDIDATE_DRAFT", "RELEASE_CANDIDATE", "RELEASE_PREVIEW", "RELEASE", name="releasephase"),
            nullable=False,
        ),
        sa.Column("created", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("released", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("project_name", sa.String(), nullable=False),
        sa.Column("package_managers", sa.JSON(), nullable=True),
        sa.Column("version", sa.String(), nullable=False),
        sa.Column("sboms", sa.JSON(), nullable=True),
        sa.Column("release_policy_id", sa.Integer(), nullable=True),
        sa.Column("votes", sa.JSON(), nullable=True),
        sa.Column("vote_started", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("vote_resolved", sql.UTCDateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["project_name"], ["project.name"], name=op.f("fk_release_project_name_project")),
        sa.ForeignKeyConstraint(
            ["release_policy_id"], ["releasepolicy.id"], name=op.f("fk_release_release_policy_id_releasepolicy")
        ),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_release")),
        sa.UniqueConstraint("name", name=op.f("uq_release_name")),
        sa.UniqueConstraint("project_name", "version", name="unique_project_version"),
    )
    op.create_table(
        "checkresult",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("release_name", sa.String(), nullable=False),
        sa.Column("revision_number", sa.String(), nullable=True),
        sa.Column("checker", sa.String(), nullable=False),
        sa.Column("primary_rel_path", sa.String(), nullable=True),
        sa.Column("member_rel_path", sa.String(), nullable=True),
        sa.Column("created", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column(
            "status", sa.Enum("EXCEPTION", "FAILURE", "SUCCESS", "WARNING", name="checkresultstatus"), nullable=False
        ),
        sa.Column("message", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["release_name"], ["release.name"], name=op.f("fk_checkresult_release_name_release")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_checkresult")),
    )
    op.create_index(op.f("ix_checkresult_member_rel_path"), "checkresult", ["member_rel_path"], unique=False)
    op.create_index(op.f("ix_checkresult_primary_rel_path"), "checkresult", ["primary_rel_path"], unique=False)
    op.create_index(op.f("ix_checkresult_revision_number"), "checkresult", ["revision_number"], unique=False)
    op.create_table(
        "revision",
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("release_name", sa.String(), nullable=True),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("number", sa.String(), nullable=False),
        sa.Column("asfuid", sa.String(), nullable=False),
        sa.Column("created", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column(
            "phase",
            sa.Enum("RELEASE_CANDIDATE_DRAFT", "RELEASE_CANDIDATE", "RELEASE_PREVIEW", "RELEASE", name="releasephase"),
            nullable=False,
        ),
        sa.Column("parent_name", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["parent_name"], ["revision.name"], name=op.f("fk_revision_parent_name_revision")),
        sa.ForeignKeyConstraint(["release_name"], ["release.name"], name=op.f("fk_revision_release_name_release")),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_revision")),
        sa.UniqueConstraint("name", name=op.f("uq_revision_name")),
        sa.UniqueConstraint("release_name", "number", name="uq_revision_release_number"),
        sa.UniqueConstraint("release_name", "seq", name="uq_revision_release_seq"),
    )
    op.create_table(
        "task",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("status", sa.Enum("QUEUED", "ACTIVE", "COMPLETED", "FAILED", name="taskstatus"), nullable=False),
        sa.Column(
            "task_type",
            sa.Enum(
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
                "ZIPFORMAT_STRUCTURE",
                name="tasktype",
            ),
            nullable=False,
        ),
        sa.Column("task_args", sa.JSON(), nullable=True),
        sa.Column("added", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("started", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("completed", sql.UTCDateTime(timezone=True), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("release_name", sa.String(), nullable=True),
        sa.Column("revision_number", sa.String(), nullable=True),
        sa.Column("primary_rel_path", sa.String(), nullable=True),
        sa.CheckConstraint(
            """
            (
                -- Initial state is always valid
                status = 'QUEUED'
                -- QUEUED -> ACTIVE requires setting started time and pid
                OR (status = 'ACTIVE' AND started IS NOT NULL AND pid IS NOT NULL)
                -- ACTIVE -> COMPLETED requires setting completed time and result
                OR (status = 'COMPLETED' AND completed IS NOT NULL AND result IS NOT NULL)
                -- ACTIVE -> FAILED requires setting completed time and error (result optional)
                OR (status = 'FAILED' AND completed IS NOT NULL AND error IS NOT NULL)
            )
            """,
            name=op.f("ck_task_valid_task_status_transitions"),
        ),
        sa.ForeignKeyConstraint(["release_name"], ["release.name"], name=op.f("fk_task_release_name_release")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task")),
    )
    op.create_index(op.f("ix_task_added"), "task", ["added"], unique=False)
    op.create_index(op.f("ix_task_primary_rel_path"), "task", ["primary_rel_path"], unique=False)
    op.create_index(op.f("ix_task_revision_number"), "task", ["revision_number"], unique=False)
    op.create_index(op.f("ix_task_status"), "task", ["status"], unique=False)
    op.create_index("ix_task_status_added", "task", ["status", "added"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_task_status_added", table_name="task")
    op.drop_index(op.f("ix_task_status"), table_name="task")
    op.drop_index(op.f("ix_task_revision_number"), table_name="task")
    op.drop_index(op.f("ix_task_primary_rel_path"), table_name="task")
    op.drop_index(op.f("ix_task_added"), table_name="task")
    op.drop_table("task")
    op.drop_table("revision")
    op.drop_index(op.f("ix_checkresult_revision_number"), table_name="checkresult")
    op.drop_index(op.f("ix_checkresult_primary_rel_path"), table_name="checkresult")
    op.drop_index(op.f("ix_checkresult_member_rel_path"), table_name="checkresult")
    op.drop_table("checkresult")
    op.drop_table("release")
    op.drop_index(op.f("ix_distributionchannel_name"), table_name="distributionchannel")
    op.drop_table("distributionchannel")
    op.drop_table("project")
    op.drop_table("keylink")
    op.drop_index(op.f("ix_textvalue_ns"), table_name="textvalue")
    op.drop_index(op.f("ix_textvalue_key"), table_name="textvalue")
    op.drop_table("textvalue")
    op.drop_table("sshkey")
    op.drop_table("releasepolicy")
    op.drop_table("publicsigningkey")
    op.drop_table("committee")
