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
import logging
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ElementTree
from typing import Any, Final

import pydantic

import atr.config as config
import atr.tasks.checks as checks
import atr.tasks.checks.archive as archive
import atr.tasks.sbom as sbom

_CONFIG: Final = config.get()
_JAVA_MEMORY_ARGS: Final[list[str]] = []
# Use this to set smaller memory limits and use SerialGC which also requires less memory
# We prefer, however, to set this in the container
# _JAVA_MEMORY_ARGS: Final[list[str]] = [
#     "-XX:MaxMetaspaceSize=32m",
#     "-Xmx128m",
#     "-XX:+UseSerialGC",
#     "-XX:MaxRAM=256m",
#     "-XX:CompressedClassSpaceSize=16m"
# ]
_LOGGER: Final = logging.getLogger(__name__)


class Check(pydantic.BaseModel):
    """Parameters for Apache RAT license checking."""

    release_name: str = pydantic.Field(..., description="Release name")
    abs_path: str = pydantic.Field(..., description="Absolute path to the .tar.gz file to check")
    rat_jar_path: str = pydantic.Field(
        default=_CONFIG.APACHE_RAT_JAR_PATH, description="Path to the Apache RAT JAR file"
    )
    max_extract_size: int = pydantic.Field(
        default=_CONFIG.MAX_EXTRACT_SIZE, description="Maximum extraction size in bytes"
    )
    chunk_size: int = pydantic.Field(default=_CONFIG.EXTRACT_CHUNK_SIZE, description="Chunk size for extraction")


@checks.with_model(Check)
async def check(args: Check) -> str | None:
    """Use Apache RAT to check the licenses of the files in the artifact."""
    rel_path = checks.rel_path(args.abs_path)
    check_instance = await checks.Check.create(checker=check, release_name=args.release_name, path=rel_path)
    _LOGGER.info(f"Checking RAT licenses for {args.abs_path} (rel: {rel_path})")

    try:
        result_data = await asyncio.to_thread(
            _check_core_logic,
            artifact_path=args.abs_path,
            rat_jar_path=args.rat_jar_path,
            max_extract_size=args.max_extract_size,
            chunk_size=args.chunk_size,
        )

        if result_data.get("error"):
            # Handle errors from within the core logic
            await check_instance.failure(result_data["message"], result_data)
        elif not result_data["valid"]:
            # Handle RAT validation failures
            await check_instance.failure(result_data["message"], result_data)
        else:
            # Handle success
            await check_instance.success(result_data["message"], result_data)

    except Exception as e:
        # TODO: Or bubble for task failure?
        await check_instance.exception("Error running Apache RAT check", {"error": str(e)})

    return None


def _check_core_logic(
    artifact_path: str,
    rat_jar_path: str = _CONFIG.APACHE_RAT_JAR_PATH,
    max_extract_size: int = _CONFIG.MAX_EXTRACT_SIZE,
    chunk_size: int = _CONFIG.EXTRACT_CHUNK_SIZE,
) -> dict[str, Any]:
    """Verify license headers using Apache RAT."""
    _LOGGER.info(f"Verifying licenses with Apache RAT for {artifact_path}")

    # Log the PATH environment variable
    _LOGGER.info(f"PATH environment variable: {os.environ.get('PATH', 'PATH not found')}")

    # Check that Java is installed
    try:
        java_version = subprocess.check_output(
            ["java", *_JAVA_MEMORY_ARGS, "-version"], stderr=subprocess.STDOUT, text=True
        )
        _LOGGER.info(f"Java version: {java_version.splitlines()[0]}")
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        _LOGGER.error(f"Java is not properly installed or not in PATH: {e}")

        # Try to get some output even if the command failed
        try:
            # Use run instead of check_output to avoid exceptions
            java_result = subprocess.run(
                ["java", *_JAVA_MEMORY_ARGS, "-version"],
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                text=True,
                check=False,
            )
            _LOGGER.info(f"Java command return code: {java_result.returncode}")
            _LOGGER.info(f"Java command output: {java_result.stdout or java_result.stderr}")

            # Try to find where Java might be located
            which_java = subprocess.run(["which", "java"], capture_output=True, text=True, check=False)
            which_java_result = which_java.stdout.strip() if which_java.returncode == 0 else "not found"
            _LOGGER.info(f"Result for which java: {which_java_result}")
        except Exception as inner_e:
            _LOGGER.error(f"Additional error while trying to debug java: {inner_e}")

        return {
            "valid": False,
            "message": "Java is not properly installed or not in PATH",
            "total_files": 0,
            "approved_licenses": 0,
            "unapproved_licenses": 0,
            "unknown_licenses": 0,
            "unapproved_files": [],
            "unknown_license_files": [],
            "errors": [f"Java error: {e}"],
        }

    # Verify RAT JAR exists and is accessible
    rat_jar_path, jar_error = _check_core_logic_jar_exists(rat_jar_path)
    if jar_error:
        return jar_error

    try:
        # Create a temporary directory for extraction
        # TODO: We could extract to somewhere in "state/" instead
        with tempfile.TemporaryDirectory(prefix="rat_verify_") as temp_dir:
            _LOGGER.info(f"Created temporary directory: {temp_dir}")

            # Find and validate the root directory
            try:
                root_dir = archive.root_directory(artifact_path)
            except ValueError as e:
                error_msg = str(e)
                _LOGGER.error(f"Archive root directory issue: {error_msg}")
                return {
                    "valid": False,
                    "message": "No root directory found",
                    "total_files": 0,
                    "approved_licenses": 0,
                    "unapproved_licenses": 0,
                    "unknown_licenses": 0,
                    "unapproved_files": [],
                    "unknown_license_files": [],
                    "errors": [error_msg or "No root directory found"],
                }

            extract_dir = os.path.join(temp_dir, root_dir)

            # Extract the archive to the temporary directory
            _LOGGER.info(f"Extracting {artifact_path} to {temp_dir}")
            extracted_size = sbom.archive_extract_safe(
                artifact_path, temp_dir, max_size=max_extract_size, chunk_size=chunk_size
            )
            _LOGGER.info(f"Extracted {extracted_size} bytes")

            # Execute RAT and get results or error
            error_result, xml_output_path = _check_core_logic_execute_rat(rat_jar_path, extract_dir, temp_dir)
            if error_result:
                return error_result

            # Parse the XML output
            try:
                _LOGGER.info(f"Parsing RAT XML output: {xml_output_path}")
                # Make sure xml_output_path is not None before parsing
                if xml_output_path is None:
                    raise ValueError("XML output path is None")

                results = _check_core_logic_parse_output(xml_output_path, extract_dir)
                _LOGGER.info(f"Successfully parsed RAT output with {results.get('total_files', 0)} files")
                return results
            except Exception as e:
                _LOGGER.error(f"Error parsing RAT output: {e}")
                return {
                    "valid": False,
                    "message": f"Failed to parse Apache RAT output: {e!s}",
                    "total_files": 0,
                    "approved_licenses": 0,
                    "unapproved_licenses": 0,
                    "unknown_licenses": 0,
                    "unapproved_files": [],
                    "unknown_license_files": [],
                    "errors": [f"Parse error: {e}"],
                }

    except Exception as e:
        import traceback

        _LOGGER.exception("Error running Apache RAT")
        return {
            "valid": False,
            "message": f"Failed to run Apache RAT: {e!s}",
            "total_files": 0,
            "approved_licenses": 0,
            "unapproved_licenses": 0,
            "unknown_licenses": 0,
            "unapproved_files": [],
            "unknown_license_files": [],
            "errors": [str(e), traceback.format_exc()],
        }


def _check_core_logic_execute_rat(
    rat_jar_path: str, extract_dir: str, temp_dir: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Execute Apache RAT and process its output."""
    # Define output file path
    xml_output_path = os.path.join(temp_dir, "rat-report.xml")
    _LOGGER.info(f"XML output will be written to: {xml_output_path}")

    # Run Apache RAT on the extracted directory
    # Use -x flag for XML output and -o to specify the output file
    command = [
        "java",
        *_JAVA_MEMORY_ARGS,
        "-jar",
        rat_jar_path,
        "-d",
        extract_dir,
        "-x",
        "-o",
        xml_output_path,
    ]
    _LOGGER.info(f"Running Apache RAT: {' '.join(command)}")

    # Change working directory to temp_dir when running the process
    current_dir = os.getcwd()
    os.chdir(temp_dir)

    _LOGGER.info(f"Executing Apache RAT from directory: {os.getcwd()}")

    try:
        # # First make sure we can run Java
        # java_check = subprocess.run(["java", "-version"], capture_output=True, timeout=10)
        # _LOGGER.info(f"Java check completed with return code {java_check.returncode}")

        # Run the actual RAT command
        # We do check=False because we'll handle errors below
        # The timeout is five minutes
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )

        if process.returncode != 0:
            _LOGGER.error(f"Apache RAT failed with return code {process.returncode}")
            _LOGGER.error(f"STDOUT: {process.stdout}")
            _LOGGER.error(f"STDERR: {process.stderr}")
            os.chdir(current_dir)
            error_dict = {
                "valid": False,
                "message": f"Apache RAT process failed with code {process.returncode}",
                "total_files": 0,
                "approved_licenses": 0,
                "unapproved_licenses": 0,
                "unknown_licenses": 0,
                "unapproved_files": [],
                "unknown_license_files": [],
                "errors": [
                    f"Process error code: {process.returncode}",
                    f"STDOUT: {process.stdout}",
                    f"STDERR: {process.stderr}",
                ],
            }
            return error_dict, None

        _LOGGER.info(f"Apache RAT completed successfully with return code {process.returncode}")
        _LOGGER.info(f"stdout: {process.stdout[:200]}...")
    except subprocess.TimeoutExpired as e:
        os.chdir(current_dir)
        _LOGGER.error(f"Apache RAT process timed out: {e}")
        return {
            "valid": False,
            "message": "Apache RAT process timed out",
            "total_files": 0,
            "approved_licenses": 0,
            "unapproved_licenses": 0,
            "unknown_licenses": 0,
            "unapproved_files": [],
            "unknown_license_files": [],
            "errors": [f"Timeout: {e}"],
        }, None
    except Exception as e:
        # Change back to the original directory before raising
        os.chdir(current_dir)
        _LOGGER.error(f"Exception running Apache RAT: {e}")
        return {
            "valid": False,
            "message": f"Apache RAT process failed: {e}",
            "total_files": 0,
            "approved_licenses": 0,
            "unapproved_licenses": 0,
            "unknown_licenses": 0,
            "unapproved_files": [],
            "unknown_license_files": [],
            "errors": [f"Process error: {e}"],
        }, None

    # Change back to the original directory
    os.chdir(current_dir)

    # Check that the output file exists
    if os.path.exists(xml_output_path):
        _LOGGER.info(f"Found XML output at: {xml_output_path} (size: {os.path.getsize(xml_output_path)} bytes)")
        return None, xml_output_path
    else:
        _LOGGER.error(f"XML output file not found at: {xml_output_path}")
        # List files in the temporary directory
        _LOGGER.info(f"Files in {temp_dir}: {os.listdir(temp_dir)}")
        # Look in the current directory too
        _LOGGER.info(f"Files in current directory: {os.listdir('.')}")
        return {
            "valid": False,
            "message": f"RAT output XML file not found: {xml_output_path}",
            "total_files": 0,
            "approved_licenses": 0,
            "unapproved_licenses": 0,
            "unknown_licenses": 0,
            "unapproved_files": [],
            "unknown_license_files": [],
            "errors": [f"Missing output file: {xml_output_path}"],
        }, None


def _check_core_logic_jar_exists(rat_jar_path: str) -> tuple[str, dict[str, Any] | None]:
    """Verify that the Apache RAT JAR file exists and is accessible."""
    # Check that the RAT JAR exists
    if not os.path.exists(rat_jar_path):
        _LOGGER.error(f"Apache RAT JAR not found at: {rat_jar_path}")
        # Try a few common locations:
        # ./rat.jar
        # ./state/rat.jar
        # ../rat.jar
        # ../state/rat.jar
        # NOTE: We're also doing something like this in task_verify_rat_license
        # Should probably decide one place to do it, and do it well
        alternative_paths = [
            os.path.join(os.getcwd(), os.path.basename(rat_jar_path)),
            os.path.join(os.getcwd(), "state", os.path.basename(rat_jar_path)),
            os.path.join(os.path.dirname(os.getcwd()), os.path.basename(rat_jar_path)),
            os.path.join(os.path.dirname(os.getcwd()), "state", os.path.basename(rat_jar_path)),
        ]

        for alt_path in alternative_paths:
            if os.path.exists(alt_path):
                _LOGGER.info(f"Found alternative RAT JAR at: {alt_path}")
                rat_jar_path = alt_path
                break

        # Double check whether we found the JAR
        if not os.path.exists(rat_jar_path):
            _LOGGER.error("Tried alternative paths but Apache RAT JAR still not found")
            _LOGGER.error(f"Current directory: {os.getcwd()}")
            _LOGGER.error(f"Directory contents: {os.listdir(os.getcwd())}")
            if os.path.exists("state"):
                _LOGGER.error(f"State directory contents: {os.listdir('state')}")

            return rat_jar_path, {
                "valid": False,
                "message": f"Apache RAT JAR not found at: {rat_jar_path}",
                "total_files": 0,
                "approved_licenses": 0,
                "unapproved_licenses": 0,
                "unknown_licenses": 0,
                "unapproved_files": [],
                "unknown_license_files": [],
                "errors": [f"Missing JAR: {rat_jar_path}"],
            }
    else:
        _LOGGER.info(f"Found Apache RAT JAR at: {rat_jar_path}")

    return rat_jar_path, None


def _check_core_logic_parse_output(xml_file: str, base_dir: str) -> dict[str, Any]:
    """Parse the XML output from Apache RAT."""
    try:
        tree = ElementTree.parse(xml_file)
        root = tree.getroot()

        total_files = 0
        approved_licenses = 0
        unapproved_licenses = 0
        unknown_licenses = 0

        unapproved_files = []
        unknown_license_files = []

        # Process each resource
        for resource in root.findall(".//resource"):
            total_files += 1

            # Get the name attribute value
            name = resource.get("name", "")

            # Remove base_dir prefix for cleaner display
            if name.startswith(base_dir):
                name = name[len(base_dir) :].lstrip("/")

            # Get license information
            license_approval = resource.find("license-approval")
            license_family = resource.find("license-family")

            is_approved = license_approval is not None and license_approval.get("name") == "true"
            license_name = license_family.get("name") if license_family is not None else "Unknown"

            # Update counters and lists
            if is_approved:
                approved_licenses += 1
            elif license_name == "Unknown license":
                unknown_licenses += 1
                unknown_license_files.append({"name": name, "license": license_name})
            else:
                unapproved_licenses += 1
                unapproved_files.append({"name": name, "license": license_name})

        # Calculate overall validity
        valid = unapproved_licenses == 0

        # Prepare awkwardly long summary message
        message = f"""\
Found {approved_licenses} files with approved licenses, {unapproved_licenses} \
with unapproved licenses, and {unknown_licenses} with unknown licenses"""

        # We limit the number of files we report to 100
        return {
            "valid": valid,
            "message": message,
            "total_files": total_files,
            "approved_licenses": approved_licenses,
            "unapproved_licenses": unapproved_licenses,
            "unknown_licenses": unknown_licenses,
            "unapproved_files": unapproved_files[:100],
            "unknown_license_files": unknown_license_files[:100],
            "errors": [],
        }

    except Exception as e:
        _LOGGER.error(f"Error parsing RAT output: {e}")
        return {
            "valid": False,
            "message": f"Failed to parse Apache RAT output: {e!s}",
            "total_files": 0,
            "approved_licenses": 0,
            "unapproved_licenses": 0,
            "unknown_licenses": 0,
            "errors": [f"XML parsing error: {e!s}"],
        }
