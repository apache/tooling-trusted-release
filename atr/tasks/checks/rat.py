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
import os
import pathlib
import subprocess
import tempfile
import xml.etree.ElementTree as ElementTree
from typing import Any, Final

import atr.archives as archives
import atr.config as config
import atr.log as log
import atr.models.results as results
import atr.tasks.checks as checks
import atr.util as util

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
_RAT_EXCLUDES_FILENAMES: Final[set[str]] = {".rat-excludes", "rat-excludes.txt"}


async def check(args: checks.FunctionArguments) -> results.Results | None:
    """Use Apache RAT to check the licenses of the files in the artifact."""
    recorder = await args.recorder()
    if not (artifact_abs_path := await recorder.abs_path()):
        return None
    if await recorder.primary_path_is_binary():
        log.info(f"Skipping RAT check for binary artifact {artifact_abs_path} (rel: {args.primary_rel_path})")
        return None

    log.info(f"Checking RAT licenses for {artifact_abs_path} (rel: {args.primary_rel_path})")

    try:
        result_data = await asyncio.to_thread(
            _check_core_logic,
            artifact_path=str(artifact_abs_path),
            rat_jar_path=args.extra_args.get("rat_jar_path", _CONFIG.APACHE_RAT_JAR_PATH),
            max_extract_size=args.extra_args.get("max_extract_size", _CONFIG.MAX_EXTRACT_SIZE),
            chunk_size=args.extra_args.get("chunk_size", _CONFIG.EXTRACT_CHUNK_SIZE),
        )

        if result_data.get("warning"):
            await recorder.warning(result_data["warning"], result_data)
        elif result_data.get("error"):
            # Handle errors from within the core logic
            await recorder.failure(result_data["message"], result_data)
        elif not result_data["valid"]:
            # Handle RAT validation failures
            await recorder.failure(result_data["message"], result_data)
        else:
            # Handle success
            await recorder.success(result_data["message"], result_data)

    except Exception as e:
        # TODO: Or bubble for task failure?
        await recorder.failure("Error running Apache RAT check", {"error": str(e)})

    return None


def _check_core_logic(
    artifact_path: str,
    rat_jar_path: str = _CONFIG.APACHE_RAT_JAR_PATH,
    max_extract_size: int = _CONFIG.MAX_EXTRACT_SIZE,
    chunk_size: int = _CONFIG.EXTRACT_CHUNK_SIZE,
) -> dict[str, Any]:
    """Verify license headers using Apache RAT."""
    log.info(f"Verifying licenses with Apache RAT for {artifact_path}")
    log.info(f"PATH environment variable: {os.environ.get('PATH', 'PATH not found')}")

    java_check = _check_java_installed()
    if java_check is not None:
        return java_check

    # Verify RAT JAR exists and is accessible
    rat_jar_path, jar_error = _check_core_logic_jar_exists(rat_jar_path)
    if jar_error:
        return jar_error

    try:
        # Create a temporary directory for extraction
        # TODO: We could extract to somewhere in "state/" instead
        with tempfile.TemporaryDirectory(prefix="rat_verify_") as temp_dir:
            log.info(f"Created temporary directory: {temp_dir}")

            # # Find and validate the root directory
            # try:
            #     root_dir = targz.root_directory(artifact_path)
            # except targz.RootDirectoryError as e:
            #     error_msg = str(e)
            #     log.error(f"Archive root directory issue: {error_msg}")
            #     return {
            #         "valid": False,
            #         "message": "No root directory found",
            #         "total_files": 0,
            #         "approved_licenses": 0,
            #         "unapproved_licenses": 0,
            #         "unknown_licenses": 0,
            #         "unapproved_files": [],
            #         "unknown_license_files": [],
            #         "warning": error_msg or "No root directory found",
            #         "errors": [],
            #     }

            # extract_dir = os.path.join(temp_dir, root_dir)

            # Extract the archive to the temporary directory
            log.info(f"Extracting {artifact_path} to {temp_dir}")
            extracted_size, extracted_paths = archives.extract(
                artifact_path,
                temp_dir,
                max_size=max_extract_size,
                chunk_size=chunk_size,
                track_files=_RAT_EXCLUDES_FILENAMES,
            )
            log.info(f"Extracted {extracted_size} bytes")

            # Find the root directory
            if (extract_dir := _extracted_dir(temp_dir)) is None:
                log.error("No root directory found in archive")
                return {
                    "valid": False,
                    "message": "No root directory found in archive",
                    "errors": [],
                }

            log.info(f"Using root directory: {extract_dir}")

            # Execute RAT and get results or error
            error_result, xml_output_path = _check_core_logic_execute_rat(
                rat_jar_path, extract_dir, temp_dir, extracted_paths
            )
            if error_result:
                return error_result

            # Parse the XML output
            log.info(f"Parsing RAT XML output: {xml_output_path}")
            # Make sure xml_output_path is not None before parsing
            if xml_output_path is None:
                raise ValueError("XML output path is None")

            results = _check_core_logic_parse_output(xml_output_path, extract_dir)
            log.info(f"Successfully parsed RAT output with {results.get('total_files', 0)} files")
            return results

    except Exception as e:
        import traceback

        log.exception("Error running Apache RAT")
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
    rat_jar_path: str, extract_dir: str, temp_dir: str, excluded_paths: list[str]
) -> tuple[dict[str, Any] | None, str | None]:
    """Execute Apache RAT and process its output."""
    # Define output file path
    xml_output_path = os.path.join(temp_dir, "rat-report.xml")
    log.info(f"XML output will be written to: {xml_output_path}")

    # Run Apache RAT on the extracted directory
    # Use -x flag for XML output and -o to specify the output file
    # TODO: From RAT 0.17, --exclude will become --input-exclude
    # TODO: Check whether --exclude NAME works on inner files
    command = [
        "java",
        *_JAVA_MEMORY_ARGS,
        "-jar",
        rat_jar_path,
        "-x",
        "-o",
        xml_output_path,
        "-d",
        "--",
        ".",
    ]
    if excluded_paths:
        _rat_apply_exclusions(extract_dir, excluded_paths, temp_dir)
    log.info(f"Running Apache RAT: {' '.join(command)}")

    # Change working directory to extract_dir when running the process
    current_dir = os.getcwd()
    os.chdir(extract_dir)

    log.info(f"Executing Apache RAT from directory: {os.getcwd()}")

    try:
        # # First make sure we can run Java
        # java_check = subprocess.run(["java", "-version"], capture_output=True, timeout=10)
        # log.info(f"Java check completed with return code {java_check.returncode}")

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
            log.error(f"Apache RAT failed with return code {process.returncode}")
            log.error(f"STDOUT: {process.stdout}")
            log.error(f"STDERR: {process.stderr}")
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

        log.info(f"Apache RAT completed successfully with return code {process.returncode}")
        log.info(f"stdout: {process.stdout[:200]}...")
    except subprocess.TimeoutExpired as e:
        os.chdir(current_dir)
        log.error(f"Apache RAT process timed out: {e}")
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
        log.error(f"Exception running Apache RAT: {e}")
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
    if not os.path.exists(xml_output_path):
        log.error(f"XML output file not found at: {xml_output_path}")
        # List files in the temporary directory
        log.info(f"Files in {temp_dir}: {os.listdir(temp_dir)}")
        # Look in the current directory too
        log.info(f"Files in current directory: {os.listdir('.')}")
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

    # The XML was found correctly
    log.info(f"Found XML output at: {xml_output_path} (size: {os.path.getsize(xml_output_path)} bytes)")
    return None, xml_output_path


def _check_core_logic_jar_exists(rat_jar_path: str) -> tuple[str, dict[str, Any] | None]:
    """Verify that the Apache RAT JAR file exists and is accessible."""
    # Check that the RAT JAR exists
    if not os.path.exists(rat_jar_path):
        log.error(f"Apache RAT JAR not found at: {rat_jar_path}")
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
                log.info(f"Found alternative RAT JAR at: {alt_path}")
                rat_jar_path = alt_path
                break

        # Double check whether we found the JAR
        if not os.path.exists(rat_jar_path):
            log.error("Tried alternative paths but Apache RAT JAR still not found")
            log.error(f"Current directory: {os.getcwd()}")
            log.error(f"Directory contents: {os.listdir(os.getcwd())}")
            if os.path.exists("state"):
                log.error(f"State directory contents: {os.listdir('state')}")

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
        log.info(f"Found Apache RAT JAR at: {rat_jar_path}")

    return rat_jar_path, None


def _check_core_logic_parse_output(xml_file: str, base_dir: str) -> dict[str, Any]:
    """Parse the XML output from Apache RAT safely."""
    try:
        return _check_core_logic_parse_output_core(xml_file, base_dir)
    except Exception as e:
        log.error(f"Error parsing RAT output: {e}")
        return {
            "valid": False,
            "message": f"Failed to parse Apache RAT output: {e!s}",
            "total_files": 0,
            "approved_licenses": 0,
            "unapproved_licenses": 0,
            "unknown_licenses": 0,
            "errors": [f"XML parsing error: {e!s}"],
        }


def _check_core_logic_parse_output_core(xml_file: str, base_dir: str) -> dict[str, Any]:
    """Parse the XML output from Apache RAT."""
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

        is_approved = True
        if license_approval is not None:
            if license_approval.get("name") == "false":
                is_approved = False
        license_name = license_family.get("name") if (license_family is not None) else "Unknown"

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
    valid = (unapproved_licenses == 0) and (unknown_licenses == 0)

    # Prepare a summary message of just the right length
    message = _summary_message(valid, unapproved_licenses, unknown_licenses)

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


def _check_java_installed() -> dict[str, Any] | None:
    # Check that Java is installed
    # TODO: Run this only once, when the server starts
    try:
        java_version = subprocess.check_output(
            ["java", *_JAVA_MEMORY_ARGS, "-version"], stderr=subprocess.STDOUT, text=True
        )
        log.info(f"Java version: {java_version.splitlines()[0]}")
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        log.error(f"Java is not properly installed or not in PATH: {e}")

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
            log.info(f"Java command return code: {java_result.returncode}")
            log.info(f"Java command output: {java_result.stdout or java_result.stderr}")

            # Try to find where Java might be located
            which_java = subprocess.run(["which", "java"], capture_output=True, text=True, check=False)
            which_java_result = which_java.stdout.strip() if (which_java.returncode == 0) else "not found"
            log.info(f"Result for which java: {which_java_result}")
        except Exception as inner_e:
            log.error(f"Additional error while trying to debug java: {inner_e}")

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


def _extracted_dir(temp_dir: str) -> str | None:
    # Loop through all the dirs in temp_dir
    extract_dir = None
    log.info(f"Checking directories in {temp_dir}: {os.listdir(temp_dir)}")
    for dir_name in os.listdir(temp_dir):
        if dir_name.startswith("."):
            continue
        dir_path = os.path.join(temp_dir, dir_name)
        if not os.path.isdir(dir_path):
            raise ValueError(f"Unknown file type found in temporary directory: {dir_path}")
        if extract_dir is None:
            extract_dir = dir_path
        else:
            raise ValueError(f"Multiple root directories found: {extract_dir}, {dir_path}")
    return extract_dir


def _rat_apply_exclusions(extract_dir: str, excluded_paths: list[str], temp_dir: str) -> None:
    """Apply exclusions to the extracted directory."""
    # Exclusions are difficult using the command line version of RAT
    # Each line is interpreted as a literal AND a glob AND a regex
    # Then, if ANY of those three match a filename, the file is excluded
    # You cannot specify which syntax to use; all three are always tried
    # You cannot specify that you want to match against the whole path
    # Therefore, we take a different approach
    # We interpret the exclusion file as a glob file in .gitignore format
    # Then, we simply remove any files that match the glob
    exclusion_lines = []
    for excluded_path in excluded_paths:
        abs_excluded_path = os.path.join(temp_dir, excluded_path)
        if not os.path.exists(abs_excluded_path):
            log.error(f"Exclusion file not found: {abs_excluded_path}")
            continue
        if not os.path.isfile(abs_excluded_path):
            log.error(f"Exclusion file is not a file: {abs_excluded_path}")
            continue
        with open(abs_excluded_path, encoding="utf-8") as f:
            exclusion_lines.extend(f.readlines())
    matcher = util.create_path_matcher(
        exclusion_lines, pathlib.Path(extract_dir) / ".ignore", pathlib.Path(extract_dir)
    )
    for root, _dirs, files in os.walk(extract_dir):
        for file in files:
            abs_path = os.path.join(root, file)
            if matcher(abs_path):
                log.info(f"Removing {abs_path} because it matches the exclusion")
                os.remove(abs_path)


def _summary_message(valid: bool, unapproved_licenses: int, unknown_licenses: int) -> str:
    message = "All files have approved licenses"
    if not valid:
        message = "Found "
        if unapproved_licenses > 0:
            files = "file" if (unapproved_licenses == 1) else "files"
            message += f"{unapproved_licenses} {files} with unapproved licenses"
            if unknown_licenses > 0:
                message += " and "
        if unknown_licenses > 0:
            files = "file" if (unknown_licenses == 1) else "files"
            message += f"{unknown_licenses} {files} with unknown licenses"
    return message
