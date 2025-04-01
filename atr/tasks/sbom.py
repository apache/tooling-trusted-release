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
import logging
import os
import tarfile
from typing import Any, Final

import aiofiles
import pydantic

import atr.config as config
import atr.tasks.checks as checks
import atr.tasks.checks.archive as archive
import atr.util as util

_CONFIG: Final = config.get()
_LOGGER: Final = logging.getLogger(__name__)


class SBOMGenerationError(Exception):
    """Custom exception for SBOM generation failures."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


class GenerateCycloneDX(pydantic.BaseModel):
    """Arguments for the task to generate a CycloneDX SBOM."""

    artifact_path: str = pydantic.Field(..., description="Absolute path to the artifact")
    output_path: str = pydantic.Field(..., description="Absolute path where the generated SBOM JSON should be written")


def _archive_extract_safe_process_file(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    extract_dir: str,
    total_extracted: int,
    max_size: int,
    chunk_size: int,
) -> int:
    """Process a single file member during safe archive extraction."""
    target_path = os.path.join(extract_dir, member.name)
    if not os.path.abspath(target_path).startswith(os.path.abspath(extract_dir)):
        _LOGGER.warning(f"Skipping potentially unsafe path: {member.name}")
        return 0

    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    source = tf.extractfile(member)
    if source is None:
        # Should not happen if member.isreg() is true
        _LOGGER.warning(f"Could not extract file object for member: {member.name}")
        return 0

    extracted_file_size = 0
    try:
        with open(target_path, "wb") as target:
            while chunk := source.read(chunk_size):
                target.write(chunk)
                extracted_file_size += len(chunk)

                # Check size limits during extraction
                if (total_extracted + extracted_file_size) > max_size:
                    # Clean up the partial file before raising
                    target.close()
                    os.unlink(target_path)
                    raise SBOMGenerationError(
                        f"Extraction exceeded maximum size limit of {max_size} bytes",
                        {"max_size": max_size, "current_size": total_extracted},
                    )
    finally:
        source.close()

    return extracted_file_size


def _archive_extract_safe(
    archive_path: str,
    extract_dir: str,
    max_size: int,
    chunk_size: int,
) -> int:
    """Safe archive extraction."""
    total_extracted = 0

    try:
        with tarfile.open(archive_path, mode="r|gz") as tf:
            for member in tf:
                # Skip anything that's not a file or directory
                if not (member.isreg() or member.isdir()):
                    continue

                # Check whether extraction would exceed the size limit
                if member.isreg() and ((total_extracted + member.size) > max_size):
                    raise SBOMGenerationError(
                        f"Extraction would exceed maximum size limit of {max_size} bytes",
                        {"max_size": max_size, "current_size": total_extracted, "file_size": member.size},
                    )

                # Extract directories directly
                if member.isdir():
                    # Ensure the path is safe before extracting
                    target_path = os.path.join(extract_dir, member.name)
                    if not os.path.abspath(target_path).startswith(os.path.abspath(extract_dir)):
                        _LOGGER.warning(f"Skipping potentially unsafe path: {member.name}")
                        continue
                    tf.extract(member, extract_dir, numeric_owner=True)
                    continue

                if member.isreg():
                    extracted_size = _archive_extract_safe_process_file(
                        tf, member, extract_dir, total_extracted, max_size, chunk_size
                    )
                    total_extracted += extracted_size

                # TODO: Add other types here

    except tarfile.ReadError as e:
        raise SBOMGenerationError(f"Failed to read archive: {e}", {"archive_path": archive_path}) from e

    return total_extracted


@checks.with_model(GenerateCycloneDX)
async def generate_cyclonedx(args: GenerateCycloneDX) -> str | None:
    """Generate a CycloneDX SBOM for the given artifact and write it to the output path."""
    try:
        result_data = await _generate_cyclonedx_core(args.artifact_path, args.output_path)
        _LOGGER.info(f"Successfully generated CycloneDX SBOM for {args.artifact_path}")
        msg = result_data["message"]
        if not isinstance(msg, str):
            raise SBOMGenerationError(f"Invalid message type: {type(msg)}")
        return msg
    except SBOMGenerationError as e:
        _LOGGER.error(f"SBOM generation failed for {args.artifact_path}: {e.details}")
        raise


async def _generate_cyclonedx_core(artifact_path: str, output_path: str) -> dict[str, Any]:
    """Core logic to generate CycloneDX SBOM, raising SBOMGenerationError on failure."""
    _LOGGER.info(f"Generating CycloneDX SBOM for {artifact_path} -> {output_path}")

    async with util.async_temporary_directory(prefix="cyclonedx_sbom_") as temp_dir:
        _LOGGER.info(f"Created temporary directory: {temp_dir}")

        # Find and validate the root directory
        try:
            root_dir = await asyncio.to_thread(archive.root_directory, artifact_path)
        except ValueError as e:
            raise SBOMGenerationError(f"Archive root directory issue: {e}", {"artifact_path": artifact_path}) from e
        except Exception as e:
            raise SBOMGenerationError(
                f"Failed to determine archive root directory: {e}", {"artifact_path": artifact_path}
            ) from e

        extract_dir = os.path.join(temp_dir, root_dir)

        # Extract the archive to the temporary directory
        # TODO: Ideally we'd have task dependencies or archive caching
        _LOGGER.info(f"Extracting {artifact_path} to {temp_dir}")
        extracted_size = await asyncio.to_thread(
            _archive_extract_safe,
            artifact_path,
            str(temp_dir),
            max_size=_CONFIG.MAX_EXTRACT_SIZE,
            chunk_size=_CONFIG.EXTRACT_CHUNK_SIZE,
        )
        _LOGGER.info(f"Extracted {extracted_size} bytes into {extract_dir}")

        # Run syft to generate the CycloneDX SBOM
        syft_command = ["syft", extract_dir, "-o", "cyclonedx-json"]
        _LOGGER.info(f"Running syft: {' '.join(syft_command)}")

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
                _LOGGER.error(f"syft command failed with code {process.returncode}")
                _LOGGER.error(f"syft stderr: {stderr_str}")
                _LOGGER.error(f"syft stdout: {stdout_str[:1000]}...")
                raise SBOMGenerationError(
                    f"syft command failed with code {process.returncode}",
                    {"returncode": process.returncode, "stderr": stderr_str, "stdout": stdout_str[:1000]},
                )

            # Parse the JSON output from syft
            try:
                sbom_data = json.loads(stdout_str)
                _LOGGER.info(f"Successfully parsed syft output for {artifact_path}")

                # Write the SBOM data to the specified output path
                try:
                    async with aiofiles.open(output_path, "w", encoding="utf-8") as f:
                        await f.write(json.dumps(sbom_data, indent=2))
                    _LOGGER.info(f"Successfully wrote SBOM to {output_path}")
                except Exception as write_err:
                    _LOGGER.exception(f"Failed to write SBOM JSON to {output_path}: {write_err}")
                    raise SBOMGenerationError(f"Failed to write SBOM to {output_path}: {write_err}") from write_err

                return {
                    "message": "Successfully generated and saved CycloneDX SBOM",
                    "sbom": sbom_data,
                    "format": "CycloneDX",
                    "components": len(sbom_data.get("components", [])),
                }
            except json.JSONDecodeError as e:
                _LOGGER.error(f"Failed to parse syft output as JSON: {e}")
                raise SBOMGenerationError(
                    f"Failed to parse syft output: {e}",
                    {"error": str(e), "syft_output": stdout_str[:1000]},
                ) from e

        except TimeoutError:
            _LOGGER.error("syft command timed out after 5 minutes")
            raise SBOMGenerationError("syft command timed out after 5 minutes")
        except FileNotFoundError:
            _LOGGER.error("syft command not found. Is it installed and in PATH?")
            raise SBOMGenerationError("syft command not found")
