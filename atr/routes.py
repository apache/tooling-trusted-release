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

"routes.py"

import hashlib
import json
from pathlib import Path
from typing import List, Tuple

from asfquart import APP
from asfquart.auth import Requirements as R, require
from asfquart.base import ASFQuartException
from asfquart.session import read as session_read
from quart import current_app, render_template, request
from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError
import httpx

from .models import (
    DistributionChannel,
    PMC,
    PMCKeyLink,
    Package,
    ProductLine,
    PublicSigningKey,
    Release,
    ReleasePhase,
    ReleaseStage,
    VotePolicy,
)

if APP is ...:
    raise ValueError("APP is not set")

ALLOWED_USERS = {"cwells", "fluxo", "gmcdonald", "humbedooh", "sbp", "tn", "wave"}


def compute_sha3_256(file_data: bytes) -> str:
    "Compute SHA3-256 hash of file data."
    return hashlib.sha3_256(file_data).hexdigest()


def compute_sha512(file_path: Path) -> str:
    "Compute SHA-512 hash of a file."
    sha512 = hashlib.sha512()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha512.update(chunk)
    return sha512.hexdigest()


async def save_file_by_hash(file, base_dir: Path) -> Tuple[Path, str]:
    """
    Save a file using its SHA3-256 hash as the filename.
    Returns the path where the file was saved and its hash.
    """
    # FileStorage.read() returns bytes directly, no need to await
    data = file.read()
    file_hash = compute_sha3_256(data)

    # Create path with hash as filename
    path = base_dir / file_hash
    path.parent.mkdir(parents=True, exist_ok=True)

    # Only write if file doesn't exist
    # If it does exist, it'll be the same content anyway
    if not path.exists():
        path.write_bytes(data)

    return path, file_hash


@APP.route("/add-release-candidate", methods=["GET", "POST"])
@require(R.committer)
async def add_release_candidate() -> str:
    "Add a release candidate to the database."
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # For POST requests, handle the file upload
    if request.method == "POST":
        form = await request.form

        project_name = form.get("project_name")
        if not project_name:
            raise ASFQuartException("Project name is required", errorcode=400)

        # Verify user is a PMC member of the project
        if project_name not in session.committees:
            raise ASFQuartException(
                f"You must be a PMC member of {project_name} to submit a release candidate", errorcode=403
            )

        # Get all uploaded files
        files = await request.files

        # Get the release artifact and signature files
        artifact_file = files.get("release_artifact")
        signature_file = files.get("release_signature")

        if not artifact_file:
            raise ASFQuartException("Release artifact file is required", errorcode=400)
        if not signature_file:
            raise ASFQuartException("Detached GPG signature file is required", errorcode=400)
        if not signature_file.filename.endswith(".asc"):
            # TODO: Could also check that it's artifact name + ".asc"
            # And at least warn if it's not
            raise ASFQuartException("Signature file must have .asc extension", errorcode=400)

        # Save files using their hashes as filenames
        storage_dir = Path(current_app.config["RELEASE_STORAGE_DIR"]) / project_name
        artifact_path, artifact_hash = await save_file_by_hash(artifact_file, storage_dir)
        # TODO: Do we need to do anything with the signature hash?
        # These should be identical, but path might be absolute?
        # TODO: Need to check, ideally. Could have a data browser
        signature_path, _ = await save_file_by_hash(signature_file, storage_dir)

        # Compute SHA-512 checksum of the artifact for the package record
        # We're using SHA-3-256 for the filename, so we need to use SHA-3-512 for the checksum
        checksum_512 = compute_sha512(artifact_path)

        # Store in database
        with Session(current_app.config["engine"]) as db_session:
            # Get PMC
            statement = select(PMC).where(PMC.project_name == project_name)
            pmc = db_session.exec(statement).first()
            if not pmc:
                raise ASFQuartException("PMC not found", errorcode=404)

            # Create release record using artifact hash as storage key
            # At some point this presumably won't work, because we can have many artifacts
            # But meanwhile it's fine
            # TODO: Extract version from filename or add to form
            release = Release(
                storage_key=artifact_hash,
                stage=ReleaseStage.CANDIDATE,
                phase=ReleasePhase.RELEASE_CANDIDATE,
                pmc_id=pmc.id,
                version="",
            )
            db_session.add(release)

            # Create package record
            package = Package(
                file=str(artifact_path.relative_to(current_app.config["RELEASE_STORAGE_DIR"])),
                signature=str(signature_path.relative_to(current_app.config["RELEASE_STORAGE_DIR"])),
                checksum=checksum_512,
                release_key=release.storage_key,
            )
            db_session.add(package)

            db_session.commit()

            return f"Successfully uploaded release candidate for {project_name}"

    # For GET requests, show the form
    return await render_template(
        "add-release-candidate.html",
        asf_id=session.uid,
        pmc_memberships=session.committees,
        committer_projects=session.projects,
    )


@APP.route("/admin/data-browser")
@APP.route("/admin/data-browser/<model>")
@require(R.committer)
async def admin_data_browser(model: str = "PMC") -> str:
    "Browse all records in the database."
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    if session.uid not in ALLOWED_USERS:
        raise ASFQuartException("You are not authorized to browse data", errorcode=403)

    # Map of model names to their classes
    models = {
        "PMC": PMC,
        "Release": Release,
        "Package": Package,
        "VotePolicy": VotePolicy,
        "ProductLine": ProductLine,
        "DistributionChannel": DistributionChannel,
        "PublicSigningKey": PublicSigningKey,
        "PMCKeyLink": PMCKeyLink,
    }

    if model not in models:
        # Default to PMC if invalid model specified
        model = "PMC"

    with Session(current_app.config["engine"]) as db_session:
        # Get all records for the selected model
        statement = select(models[model])
        records = db_session.exec(statement).all()

        # Convert records to dictionaries for JSON serialization
        records_dict = []
        for record in records:
            if hasattr(record, "dict"):
                record_dict = record.dict()
            else:
                # Fallback for models without dict() method
                record_dict = {
                    "id": getattr(record, "id", None),
                    "storage_key": getattr(record, "storage_key", None),
                }
                for key in record.__dict__:
                    if not key.startswith("_"):
                        record_dict[key] = getattr(record, key)
            records_dict.append(record_dict)

        return await render_template("data-browser.html", models=list(models.keys()), model=model, records=records_dict)


@APP.route("/admin/update-pmcs", methods=["GET", "POST"])
async def admin_update_pmcs() -> str:
    "Update PMCs from remote, authoritative committee-info.json."
    # Check authentication
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    if session.uid not in ALLOWED_USERS:
        raise ASFQuartException("You are not authorized to update PMCs", errorcode=403)

    if request.method == "POST":
        # TODO: We should probably lift this branch
        # Or have the "GET" in a branch, and then we can happy path this POST branch
        # Fetch committee-info.json from Whimsy
        WHIMSY_URL = "https://whimsy.apache.org/public/committee-info.json"
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(WHIMSY_URL)
                response.raise_for_status()
                data = response.json()
            except (httpx.RequestError, json.JSONDecodeError) as e:
                raise ASFQuartException(f"Failed to fetch committee data: {str(e)}", errorcode=500)

        committees = data.get("committees", {})
        updated_count = 0

        with Session(current_app.config["engine"]) as db_session:
            for committee_id, info in committees.items():
                # Skip non-PMC committees
                if not info.get("pmc", False):
                    continue

                # Get or create PMC
                statement = select(PMC).where(PMC.project_name == committee_id)
                pmc = db_session.exec(statement).first()
                if not pmc:
                    pmc = PMC(project_name=committee_id)
                    db_session.add(pmc)

                # Update PMC data
                roster = info.get("roster", {})
                # All roster members are PMC members
                pmc.pmc_members = list(roster.keys())
                # All PMC members are also committers
                pmc.committers = list(roster.keys())

                # Mark chairs as release managers
                # TODO: Who else is a release manager? How do we know?
                chairs = [m["id"] for m in info.get("chairs", [])]
                pmc.release_managers = chairs

                updated_count += 1

            # Add special entry for Tooling PMC
            # Not clear why, but it's not in the Whimsy data
            statement = select(PMC).where(PMC.project_name == "tooling")
            tooling_pmc = db_session.exec(statement).first()
            if not tooling_pmc:
                tooling_pmc = PMC(project_name="tooling")
                db_session.add(tooling_pmc)
                updated_count += 1

            # Update Tooling PMC data
            # Could put this in the "if not tooling_pmc" block, perhaps
            tooling_pmc.pmc_members = ["wave", "tn", "sbp"]
            tooling_pmc.committers = ["wave", "tn", "sbp"]
            tooling_pmc.release_managers = ["wave"]

            db_session.commit()

        return f"Successfully updated {updated_count} PMCs from Whimsy"

    # For GET requests, show the update form
    return await render_template("update-pmcs.html")


@APP.route("/pmc/create/<project_name>")
async def pmc_create_arg(project_name: str) -> dict:
    "Create a new PMC with some sample data."
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
                f"PMC with name '{project_name}' already exists",
                errorcode=409,  # HTTP 409 Conflict
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
    "List all PMCs in the database."
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
    "Get a specific PMC by project name."
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


@APP.route("/")
async def root() -> str:
    "Main PMC directory page."
    with Session(current_app.config["engine"]) as session:
        # Get all PMCs and their latest releases
        statement = select(PMC)
        pmcs = session.exec(statement).all()
        return await render_template("root.html", pmcs=pmcs)


@APP.route("/user/uploads")
@require(R.committer)
async def user_uploads() -> str:
    "Show all release candidates uploaded by the current user."
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    with Session(current_app.config["engine"]) as db_session:
        # Get all releases where the user is a PMC member of the associated PMC
        # TODO: We don't actually record who uploaded the release candidate
        # We should probably add that information!
        statement = select(Release).join(PMC).where(Release.stage == ReleaseStage.CANDIDATE)
        releases = db_session.exec(statement).all()

        # Filter to only show releases for PMCs where the user is a member
        user_releases = []
        for r in releases:
            if r.pmc is None:
                continue
            if session.uid in r.pmc.pmc_members:
                user_releases.append(r)

        return await render_template("user-uploads.html", releases=user_releases)
