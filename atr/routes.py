"routes.py"

from typing import List

from asfquart.base import ASFQuartException
from quart import current_app, render_template
from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError

from asfquart import APP
from .models import PMC


@APP.route("/")
async def root() -> str:
    """Main PMC directory page."""
    with Session(current_app.config["engine"]) as session:
        # Get all PMCs and their latest releases
        statement = select(PMC)
        pmcs = session.exec(statement).all()
        return await render_template("root.html", pmcs=pmcs)


@APP.route("/pmc/create/<project_name>")
async def pmc_create_arg(project_name: str) -> dict:
    """Create a new PMC with some sample data."""
    pmc = PMC(
        project_name=project_name,
        pmc_members=["alice", "bob"],
        committers=["charlie", "dave"],
        release_managers=["alice"],
    )

    with Session(current_app.config["engine"]) as session:
        try:
            session.add(pmc)
            session.commit()
            session.refresh(pmc)
        except IntegrityError:
            raise ASFQuartException(
                f"PMC with name '{project_name}' already exists", errorcode=409  # HTTP 409 Conflict
            )

        # Convert to dict for response
        return {
            "id": pmc.id,
            "project_name": pmc.project_name,
            "pmc_members": pmc.pmc_members,
            "committers": pmc.committers,
            "release_managers": pmc.release_managers,
        }


@APP.route("/pmc/list")
async def pmc_list() -> List[dict]:
    """List all PMCs in the database."""
    with Session(current_app.config["engine"]) as session:
        statement = select(PMC)
        pmcs = session.exec(statement).all()

        return [
            {
                "id": pmc.id,
                "project_name": pmc.project_name,
                "pmc_members": pmc.pmc_members,
                "committers": pmc.committers,
                "release_managers": pmc.release_managers,
            }
            for pmc in pmcs
        ]


@APP.route("/pmc/<project_name>")
async def pmc_arg(project_name: str) -> dict:
    """Get a specific PMC by project name."""
    with Session(current_app.config["engine"]) as session:
        statement = select(PMC).where(PMC.project_name == project_name)
        pmc = session.exec(statement).first()

        if not pmc:
            raise ASFQuartException("PMC not found", errorcode=404)

        return {
            "id": pmc.id,
            "project_name": pmc.project_name,
            "pmc_members": pmc.pmc_members,
            "committers": pmc.committers,
            "release_managers": pmc.release_managers,
        }
