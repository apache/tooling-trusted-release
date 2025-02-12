# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"server.py"

import os

import asfquart
from asfquart.auth import Requirements as R, require
from asfquart.base import QuartApp
from sqlmodel import Session, SQLModel, create_engine, select
from alembic import command
from alembic.config import Config

from .models import PMC, __file__ as data_models_file


def register_routes() -> str:
    from . import routes

    # Must do this otherwise ruff "fixes" this function by removing the import.
    return routes.__name__


def create_app() -> QuartApp:
    if asfquart.construct is ...:
        raise ValueError("asfquart.construct is not set")
    app = asfquart.construct(__name__)

    @app.before_serving
    async def create_database():
        # Get the project root directory (where alembic.ini is)
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # Change working directory to "./state"
        state_dir = os.path.join(project_root, "state")
        if not os.path.isdir(state_dir):
            raise RuntimeError(f"State directory not found: {state_dir}")
        os.chdir(state_dir)
        print(f"Working directory changed to: {os.getcwd()}")

        sqlite_url = "sqlite:///./atr.db"
        engine = create_engine(
            sqlite_url,
            connect_args={
                "check_same_thread": False,
                "timeout": 30,
            },
        )

        # Set SQLite pragmas for better performance
        # Use 64 MB for the cache_size, and 5000ms for busy_timeout
        with engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
            conn.exec_driver_sql("PRAGMA cache_size=-64000")
            conn.exec_driver_sql("PRAGMA foreign_keys=ON")
            conn.exec_driver_sql("PRAGMA busy_timeout=5000")

        # Run any pending migrations
        # In dev we'd do this first:
        # poetry run alembic revision --autogenerate -m "description"
        # Then review the generated migration in migrations/versions/ and commit it
        alembic_ini_path = os.path.join(project_root, "alembic.ini")
        alembic_cfg = Config(alembic_ini_path)
        # Override the migrations directory location to use project root
        # TODO: Is it possible to set this in alembic.ini?
        alembic_cfg.set_main_option("script_location", os.path.join(project_root, "migrations"))
        # Set the database URL in the config
        alembic_cfg.set_main_option("sqlalchemy.url", sqlite_url)
        command.upgrade(alembic_cfg, "head")

        # Create any tables that might be missing
        SQLModel.metadata.create_all(engine)
        app.config["engine"] = engine

    @app.route("/secret")
    @require(R.committer)
    async def secret() -> str:
        return "Secret stuff!"

    @app.get("/database/debug")
    async def database_debug() -> str:
        """Debug information about the database."""
        with Session(app.config["engine"]) as session:
            statement = select(PMC)
            pmcs = session.exec(statement).all()
            return f"Database using {data_models_file} has {len(pmcs)} PMCs"

    @app.after_serving
    async def shutdown():
        app.background_tasks.clear()

    register_routes()

    return app


def main() -> None:
    "Quart debug server"
    app = create_app()
    app.run(port=8080, ssl_keyfile="key.pem", ssl_certfile="cert.pem")


app = None
if __name__ == "__main__":
    main()
else:
    app = create_app()
