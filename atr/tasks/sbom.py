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

import logging
import os
import tarfile
from typing import Any, Final

import atr.config as config
import atr.db.models as models
import atr.tasks.checks.archive as archive
import atr.tasks.task as task

_CONFIG: Final = config.get()
_LOGGER: Final = logging.getLogger(__name__)


def archive_extract_safe(
    archive_path: str,
    extract_dir: str,
    max_size: int = _CONFIG.MAX_EXTRACT_SIZE,
    chunk_size: int = _CONFIG.EXTRACT_CHUNK_SIZE,
) -> int:
    """Safely extract an archive with size limits."""
    total_extracted = 0

    with tarfile.open(archive_path, mode="r|gz") as tf:
        for member in tf:
            # Skip anything that's not a file or directory
            if not (member.isreg() or member.isdir()):
                continue

            # Check whether extraction would exceed the size limit
            if member.isreg() and ((total_extracted + member.size) > max_size):
                raise task.Error(
                    f"Extraction would exceed maximum size limit of {max_size} bytes",
                    {"max_size": max_size, "current_size": total_extracted, "file_size": member.size},
                )

            # Extract directories directly
            if member.isdir():
                tf.extract(member, extract_dir)
                continue

            target_path = os.path.join(extract_dir, member.name)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            source = tf.extractfile(member)
            if source is None:
                continue

            # For files, extract in chunks to avoid saturating memory
            with open(target_path, "wb") as target:
                extracted_file_size = 0
                while True:
                    chunk = source.read(chunk_size)
                    if not chunk:
                        break
                    target.write(chunk)
                    extracted_file_size += len(chunk)

                    # Check size limits during extraction
                    if (total_extracted + extracted_file_size) > max_size:
                        # Clean up the partial file
                        target.close()
                        os.unlink(target_path)
                        raise task.Error(
                            f"Extraction exceeded maximum size limit of {max_size} bytes",
                            {"max_size": max_size, "current_size": total_extracted},
                        )

            total_extracted += extracted_file_size

    return total_extracted


def generate_cyclonedx(args: list[str]) -> tuple[models.TaskStatus, str | None, tuple[Any, ...]]:
    """Generate a CycloneDX SBOM for the given artifact."""
    # First argument should be the artifact path
    artifact_path = args[0]

    task_results = task.results_as_tuple(_cyclonedx_generate(artifact_path))
    _LOGGER.info(f"Generated CycloneDX SBOM for {artifact_path}")

    # Check whether the generation was successful
    result = task_results[0]
    if not result.get("valid", False):
        return task.FAILED, result.get("message", "SBOM generation failed"), task_results

    return task.COMPLETED, None, task_results


def _cyclonedx_generate(artifact_path: str) -> dict[str, Any]:
    """Generate a CycloneDX SBOM for the given artifact."""
    _LOGGER.info(f"Generating CycloneDX SBOM for {artifact_path}")
    try:
        return _cyclonedx_generate_core(artifact_path)
    except Exception as e:
        _LOGGER.error(f"Failed to generate CycloneDX SBOM: {e}")
        return {
            "valid": False,
            "message": f"Failed to generate CycloneDX SBOM: {e!s}",
        }


def _cyclonedx_generate_core(artifact_path: str) -> dict[str, Any]:
    """Generate a CycloneDX SBOM for the given artifact, raising potential exceptions."""
    import json
    import subprocess
    import tempfile

    # Create a temporary directory for extraction
    with tempfile.TemporaryDirectory(prefix="cyclonedx_sbom_") as temp_dir:
        _LOGGER.info(f"Created temporary directory: {temp_dir}")

        # Find and validate the root directory
        try:
            root_dir = archive.root_directory(artifact_path)
        except task.Error as e:
            _LOGGER.error(f"Archive root directory issue: {e}")
            return {
                "valid": False,
                "message": str(e),
                "errors": [str(e)],
            }

        extract_dir = os.path.join(temp_dir, root_dir)

        # Extract the archive to the temporary directory
        _LOGGER.info(f"Extracting {artifact_path} to {temp_dir}")
        # TODO: We need task dependencies, because we don't want to do this more than once
        extracted_size = archive_extract_safe(
            artifact_path, temp_dir, max_size=_CONFIG.MAX_EXTRACT_SIZE, chunk_size=_CONFIG.EXTRACT_CHUNK_SIZE
        )
        _LOGGER.info(f"Extracted {extracted_size} bytes")

        # Run syft to generate CycloneDX SBOM
        try:
            _LOGGER.info(f"Running syft on {extract_dir}")
            process = subprocess.run(
                ["syft", extract_dir, "-o", "cyclonedx-json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=300,
            )

            # Parse the JSON output from syft
            try:
                sbom_data = json.loads(process.stdout)
                return {
                    "valid": True,
                    "message": "Successfully generated CycloneDX SBOM",
                    "sbom": sbom_data,
                    "format": "CycloneDX",
                    "components": len(sbom_data.get("components", [])),
                }
            except json.JSONDecodeError as e:
                _LOGGER.error(f"Failed to parse syft output as JSON: {e}")
                # Include first 1000 chars of output for debugging
                return {
                    "valid": False,
                    "message": f"Failed to parse syft output: {e}",
                    "errors": [str(e), process.stdout[:1000]],
                }

        except subprocess.CalledProcessError as e:
            _LOGGER.error(f"syft command failed: {e}")
            return {
                "valid": False,
                "message": f"syft command failed with code {e.returncode}",
                "errors": [
                    f"Process error code: {e.returncode}",
                    f"STDOUT: {e.stdout}",
                    f"STDERR: {e.stderr}",
                ],
            }
        except subprocess.TimeoutExpired as e:
            _LOGGER.error(f"syft command timed out: {e}")
            return {
                "valid": False,
                "message": "syft command timed out after 5 minutes",
                "errors": [str(e)],
            }
        except Exception as e:
            _LOGGER.error(f"Unexpected error running syft: {e}")
            return {
                "valid": False,
                "message": f"Unexpected error running syft: {e}",
                "errors": [str(e)],
            }
