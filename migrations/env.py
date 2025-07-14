import datetime
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from typing import Literal

import alembic
import alembic.autogenerate.api as api
import alembic.operations.ops as ops
import alembic.runtime.migration as migration
import sqlalchemy
import sqlmodel
import sqlmodel.sql.sqltypes as sqltypes

# Add the project root to the Python path
# This script must be at migrations/env.py for this to work
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


# Use database metadata from ATR directly
import atr.config

# Populate SQLModel.metadata as a side effect of importing the models
import atr.models.sql

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
alembic_config = alembic.context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
# if alembic_config.config_file_name is not None:
#     logging.config.fileConfig(alembic_config.config_file_name)

# The SQLModel.metadata object as populated by the ATR models
target_metadata = sqlmodel.SQLModel.metadata

# Get the database path from application configuration
app_config = atr.config.get()
absolute_db_path = os.path.join(app_config.STATE_DIR, app_config.SQLITE_DB_PATH)

# Construct the synchronous SQLite URL using the absolute path
# Three slashes come before any absolute or relative path
sync_sqlalchemy_url = f"sqlite:///{absolute_db_path}"


def get_short_commit_hash(project_root_path: str) -> str:
    """Get an eight character git commit hash, or a fallback."""
    try:
        process = subprocess.run(
            ["git", "rev-parse", "--short=8", "HEAD"],
            capture_output=True,
            text=True,
            cwd=project_root_path,
            check=True,
        )
        return process.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Return a placeholder if the git command fails
        return "00000000"


def process_revision_directives_custom_naming(
    context: migration.MigrationContext,
    revision: str | Iterable[str | None] | Iterable[str],
    directives: list[ops.MigrationScript],
) -> None:
    """Generate revision IDs and filenames like NNNN_YYYY.MM.DD_COMMITSHORT.py."""
    global project_root

    if context.script is None:
        raise RuntimeError("MigrationContext.script is None, cannot determine script directory")

    versions_path = os.path.join(context.script.dir, "versions")
    if not os.path.exists(versions_path):
        os.makedirs(versions_path)

    highest_num = 0
    pattern = re.compile(r"^(\d{4})_.*\.py$")
    try:
        for fname in os.listdir(versions_path):
            match = pattern.match(fname)
            if match:
                highest_num = max(highest_num, int(match.group(1)))
    except Exception as e:
        print(f"Warning: Error scanning versions directory '{versions_path}': {e!r}")

    next_num_str = f"{highest_num + 1:04d}"
    date_str = datetime.date.today().strftime("%Y.%m.%d")
    commit_short = get_short_commit_hash(project_root)
    new_rev_id = f"{next_num_str}_{date_str}_{commit_short}"
    calculated_path = os.path.join(versions_path, f"{new_rev_id}.py")

    for directive in directives:
        setattr(directive, "rev_id", new_rev_id)
        setattr(directive, "path", calculated_path)


def render_item_override(type_: str, item: object, autogen_context: api.AutogenContext) -> str | Literal[False]:
    """Apply custom rendering for SQLModel AutoString.

    Prevents autogenerate from rendering <AutoString>.
    Returns False to indicate no handler for other types.
    """
    # Add import for sqlalchemy as sa if not present
    autogen_context.imports.add("import sqlalchemy as sa")

    if (type_ == "type") and isinstance(item, sqltypes.AutoString):
        # Render sqlmodel.sql.sqltypes.AutoString as sa.String()
        return "sa.String()"

    # Default rendering for other types
    return False


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    alembic.context.configure(
        url=sync_sqlalchemy_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_item=render_item_override,
        process_revision_directives=process_revision_directives_custom_naming,
        render_as_batch=True,
    )

    with alembic.context.begin_transaction():
        alembic.context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    configuration = alembic_config.get_section(alembic_config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = sync_sqlalchemy_url

    connectable = sqlalchemy.engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=sqlalchemy.pool.NullPool,
    )

    with connectable.connect() as connection:
        alembic.context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_item=render_item_override,
            process_revision_directives=process_revision_directives_custom_naming,
            render_as_batch=True,
        )

        with alembic.context.begin_transaction():
            alembic.context.run_migrations()


if alembic.context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
