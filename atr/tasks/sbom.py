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

import asyncio
import json
import os
import pathlib
from typing import Any, Final

import aiofiles
import aiofiles.os
import yyjson

import atr.archives as archives
import atr.config as config
import atr.log as log
import atr.models.results as results
import atr.models.schema as schema
import atr.sbom as sbom
import atr.storage as storage
import atr.tasks.checks as checks
import atr.tasks.checks.targz as targz
import atr.util as util

_CONFIG: Final = config.get()


class GenerateCycloneDX(schema.Strict):
    """Arguments for the task to generate a CycloneDX SBOM."""

    artifact_path: str = schema.description("Absolute path to the artifact")
    output_path: str = schema.description("Absolute path where the generated SBOM JSON should be written")


class SBOMGenerationError(Exception):
    """Custom exception for SBOM generation failures."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


class SBOMScoringError(Exception):
    """Raised on a failure to score an SBOM."""

    def __init__(self, msg: str, context: dict[str, Any] | None = None) -> None:
        super().__init__(msg)
        self.context = context if context is not None else {}


class FileArgs(schema.Strict):
    project_name: str = schema.description("Project name")
    version_name: str = schema.description("Version name")
    revision_number: str = schema.description("Revision number")
    file_path: str = schema.description("Relative path to the SBOM file")
    asf_uid: str | None = None


@checks.with_model(FileArgs)
async def augment(args: FileArgs) -> results.Results | None:
    base_dir = util.get_unfinished_dir() / args.project_name / args.version_name / args.revision_number
    if not os.path.isdir(base_dir):
        raise SBOMScoringError("Revision directory does not exist", {"base_dir": str(base_dir)})
    full_path = os.path.join(base_dir, args.file_path)
    if not (full_path.endswith(".cdx.json") and os.path.isfile(full_path)):
        raise SBOMScoringError("SBOM file does not exist", {"file_path": args.file_path})
    # Read from the old revision
    bundle = sbom.utilities.path_to_bundle(pathlib.Path(full_path))
    patch_ops = sbom.utilities.bundle_to_patch(bundle)
    new_full_path: str | None = None
    if patch_ops:
        patch_data = sbom.utilities.patch_to_data(patch_ops)
        merged = bundle.doc.patch(yyjson.Document(patch_data))
        description = "SBOM augmentation through web interface"
        async with storage.write(args.asf_uid) as write:
            wacp = await write.as_project_committee_participant(args.project_name)
            async with wacp.revision.create_and_manage(
                args.project_name, args.version_name, args.asf_uid or "unknown", description=description
            ) as creating:
                new_full_path = os.path.join(str(creating.interim_path), args.file_path)
                # Write to the new revision
                log.info(f"Writing augmented SBOM to {new_full_path}")
                await aiofiles.os.remove(new_full_path)
                async with aiofiles.open(new_full_path, "w", encoding="utf-8") as f:
                    await f.write(merged.dumps())

            if creating.new is None:
                raise RuntimeError("Internal error: New revision not found")

    return results.SBOMAugment(
        kind="sbom_augment",
        path=(new_full_path if new_full_path is not None else full_path),
    )


@checks.with_model(GenerateCycloneDX)
async def generate_cyclonedx(args: GenerateCycloneDX) -> results.Results | None:
    """Generate a CycloneDX SBOM for the given artifact and write it to the output path."""
    try:
        result_data = await _generate_cyclonedx_core(args.artifact_path, args.output_path)
        log.info(f"Successfully generated CycloneDX SBOM for {args.artifact_path}")
        msg = result_data["message"]
        if not isinstance(msg, str):
            raise SBOMGenerationError(f"Invalid message type: {type(msg)}")
        return results.SBOMGenerateCycloneDX(
            kind="sbom_generate_cyclonedx",
            msg=msg,
        )
    except (archives.ExtractionError, SBOMGenerationError) as e:
        log.error(f"SBOM generation failed for {args.artifact_path}: {e}")
        raise


@checks.with_model(FileArgs)
async def score_qs(args: FileArgs) -> results.Results | None:
    base_dir = util.get_unfinished_dir() / args.project_name / args.version_name / args.revision_number
    if not os.path.isdir(base_dir):
        raise SBOMScoringError("Revision directory does not exist", {"base_dir": str(base_dir)})
    full_path = os.path.join(base_dir, args.file_path)
    if not (full_path.endswith(".cdx.json") and os.path.isfile(full_path)):
        raise SBOMScoringError("SBOM file does not exist", {"file_path": args.file_path})
    proc = await asyncio.create_subprocess_exec(
        "sbomqs",
        "score",
        os.path.basename(full_path),
        "--json",
        cwd=os.path.dirname(full_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    # TODO: Timeout should probably be a lot shorter
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
    if proc.returncode != 0:
        raise SBOMScoringError(
            "sbomqs command failed",
            {"returncode": proc.returncode, "stderr": stderr.decode("utf-8", "ignore")},
        )
    report_obj = results.SbomQsReport.model_validate(json.loads(stdout.decode("utf-8")))
    return results.SBOMQsScore(
        kind="sbom_qs_score",
        project_name=args.project_name,
        version_name=args.version_name,
        revision_number=args.revision_number,
        file_path=args.file_path,
        report=report_obj,
    )


@checks.with_model(FileArgs)
async def score_tool(args: FileArgs) -> results.Results | None:
    base_dir = util.get_unfinished_dir() / args.project_name / args.version_name / args.revision_number
    if not os.path.isdir(base_dir):
        raise SBOMScoringError("Revision directory does not exist", {"base_dir": str(base_dir)})
    full_path = os.path.join(base_dir, args.file_path)
    if not (full_path.endswith(".cdx.json") and os.path.isfile(full_path)):
        raise SBOMScoringError("SBOM file does not exist", {"file_path": args.file_path})
    bundle = sbom.utilities.path_to_bundle(pathlib.Path(full_path))
    warnings, errors = sbom.conformance.ntia_2021_issues(bundle.bom)
    outdated = sbom.maven.plugin_outdated_version(bundle.bom)
    cli_errors = sbom.cyclonedx.validate_cli(bundle)
    return results.SBOMToolScore(
        kind="sbom_tool_score",
        project_name=args.project_name,
        version_name=args.version_name,
        revision_number=args.revision_number,
        file_path=args.file_path,
        warnings=[w.model_dump_json() for w in warnings],
        errors=[e.model_dump_json() for e in errors],
        outdated=outdated.model_dump_json() if outdated else None,
        cli_errors=cli_errors,
    )


async def _generate_cyclonedx_core(artifact_path: str, output_path: str) -> dict[str, Any]:
    """Core logic to generate CycloneDX SBOM on failure."""
    log.info(f"Generating CycloneDX SBOM for {artifact_path} -> {output_path}")

    # TODO: Should create a new revision here rather than in the caller
    async with util.async_temporary_directory(prefix="cyclonedx_sbom_") as temp_dir:
        log.info(f"Created temporary directory: {temp_dir}")

        # Find and validate the root directory
        try:
            root_dir = await asyncio.to_thread(targz.root_directory, artifact_path)
        except targz.RootDirectoryError as e:
            raise SBOMGenerationError(f"Archive root directory issue: {e}", {"artifact_path": artifact_path}) from e
        except Exception as e:
            raise SBOMGenerationError(
                f"Failed to determine archive root directory: {e}", {"artifact_path": artifact_path}
            ) from e

        extract_dir = os.path.join(temp_dir, root_dir)

        # Extract the archive to the temporary directory
        # TODO: Ideally we'd have task dependencies or archive caching
        log.info(f"Extracting {artifact_path} to {temp_dir}")
        extracted_size, _extracted_paths = await asyncio.to_thread(
            archives.extract,
            artifact_path,
            str(temp_dir),
            max_size=_CONFIG.MAX_EXTRACT_SIZE,
            chunk_size=_CONFIG.EXTRACT_CHUNK_SIZE,
        )
        log.info(f"Extracted {extracted_size} bytes into {extract_dir}")

        # Run syft to generate the CycloneDX SBOM
        syft_command = ["syft", extract_dir, "-o", "cyclonedx-json"]
        log.info(f"Running syft: {' '.join(syft_command)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *syft_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)

            stdout_str = stdout.decode("utf-8").strip() if stdout else ""
            stderr_str = stderr.decode("utf-8").strip() if stderr else ""

            if process.returncode != 0:
                log.error(f"syft command failed with code {process.returncode}")
                log.error(f"syft stderr: {stderr_str}")
                log.error(f"syft stdout: {stdout_str[:1000]}...")
                raise SBOMGenerationError(
                    f"syft command failed with code {process.returncode}",
                    {"returncode": process.returncode, "stderr": stderr_str, "stdout": stdout_str[:1000]},
                )

            # Parse the JSON output from syft
            try:
                sbom_data = json.loads(stdout_str)
                log.info(f"Successfully parsed syft output for {artifact_path}")

                # Write the SBOM data to the specified output path
                try:
                    async with aiofiles.open(output_path, "w", encoding="utf-8") as f:
                        await f.write(json.dumps(sbom_data, indent=2))
                    log.info(f"Successfully wrote SBOM to {output_path}")
                except Exception as write_err:
                    log.exception(f"Failed to write SBOM JSON to {output_path}: {write_err}")
                    raise SBOMGenerationError(f"Failed to write SBOM to {output_path}: {write_err}") from write_err

                return {
                    "message": "Successfully generated and saved CycloneDX SBOM",
                    "sbom": sbom_data,
                    "format": "CycloneDX",
                    "components": len(sbom_data.get("components", [])),
                }
            except json.JSONDecodeError as e:
                log.error(f"Failed to parse syft output as JSON: {e}")
                raise SBOMGenerationError(
                    f"Failed to parse syft output: {e}",
                    {"error": str(e), "syft_output": stdout_str[:1000]},
                ) from e

        except TimeoutError:
            log.error("syft command timed out after 5 minutes")
            raise SBOMGenerationError("syft command timed out after 5 minutes")
        except FileNotFoundError:
            log.error("syft command not found. Is it installed and in PATH?")
            raise SBOMGenerationError("syft command not found")
