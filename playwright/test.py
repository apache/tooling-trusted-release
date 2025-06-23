#!/usr/bin/env python3

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

import argparse
import dataclasses
import getpass
import logging
import os
import re
import socket
import subprocess
import time
import urllib.parse
from collections.abc import Callable
from typing import Any, Final

import netifaces
import rich.logging

import playwright.sync_api as sync_api

_SSH_KEY_COMMENT: Final[str] = "atr-playwright-test@127.0.0.1"
_SSH_KEY_PATH: Final[str] = "/root/.ssh/id_ed25519"
_OPENPGP_TEST_UID: Final[str] = "<apache-tooling@example.invalid>"


@dataclasses.dataclass
class Credentials:
    username: str
    password: str


# If we did this then we'd have to call e.g. test.page, which is verbose
# @dataclasses.dataclass
# class TestArguments:
#     page: sync_api.Page
#     credentials: Credentials


def esc_id(text: str) -> str:
    return re.escape(text)


def get_credentials() -> Credentials | None:
    try:
        username = input("Enter ASF Username: ")
        password = getpass.getpass("Enter ASF Password: ")
    except (EOFError, KeyboardInterrupt):
        print()
        logging.error("EOFError: No credentials provided")
        return None

    if (not username) or (not password):
        logging.error("Username and password cannot be empty")
        return None

    return Credentials(username=username, password=password)


def get_default_gateway_ip() -> str | None:
    gateways = netifaces.gateways()
    default_gateway = gateways.get("default", {})
    if not isinstance(default_gateway, dict):
        logging.error("Could not determine gateway IP: default gateway is not a dictionary")
        return None

    match default_gateway.get(socket.AF_INET):
        case (str(ip_address), _):
            return ip_address
        case _:
            return None


def go_to_path(page: sync_api.Page, path: str, wait: bool = True) -> None:
    gateway_ip = get_default_gateway_ip()
    if gateway_ip is None:
        logging.error("Could not determine gateway IP")
        raise RuntimeError("Could not determine gateway IP")
    page.goto(f"https://{gateway_ip}:8080{path}")
    if wait:
        wait_for_path(page, path)


def lifecycle_01_add_draft(page: sync_api.Page, credentials: Credentials, version_name: str) -> None:
    logging.info("Following link to start a new release")
    go_to_path(page, "/start/tooling-test-example")

    logging.info("Waiting for the start new release page")
    version_name_locator = page.locator("input#version_name")
    sync_api.expect(version_name_locator).to_be_visible()
    logging.info("Start new release page loaded")

    logging.info(f"Filling version '{version_name}'")
    version_name_locator.fill(version_name)

    logging.info("Submitting the start new release form")
    submit_button_locator = page.locator('input[type="submit"][value="Start new release"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info(f"Waiting for navigation to /compose/tooling-test-example/{version_name} after adding draft")
    wait_for_path(page, f"/compose/tooling-test-example/{version_name}")
    logging.info("Add draft actions completed successfully")


def lifecycle_02_check_draft_added(page: sync_api.Page, credentials: Credentials, version_name: str) -> None:
    logging.info(f"Checking for draft 'tooling-test-example {version_name}'")
    go_to_path(page, f"/compose/tooling-test-example/{version_name}")
    h1_strong_locator = page.locator("h1 strong:has-text('Tooling Test Example')")
    sync_api.expect(h1_strong_locator).to_be_visible()
    h1_em_locator = page.locator(f"h1 em:has-text('{esc_id(version_name)}')")
    sync_api.expect(h1_em_locator).to_be_visible()
    logging.info(f"Draft 'tooling-test-example {version_name}' found successfully")


def lifecycle_03_add_file(page: sync_api.Page, credentials: Credentials, version_name: str) -> None:
    logging.info(f"Navigating to the upload file page for tooling-test-example {version_name}")
    go_to_path(page, f"/upload/tooling-test-example/{version_name}")
    logging.info("Upload file page loaded")

    logging.info("Locating the file input")
    file_input_locator = page.locator('input[name="file_data"]')
    sync_api.expect(file_input_locator).to_be_visible()

    logging.info("Setting the input file to /run/tests/example.txt")
    file_input_locator.set_input_files("/run/tests/example.txt")

    logging.info("Locating and activating the add files button")
    submit_button_locator = page.locator('input[type="submit"][value="Add files"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info(f"Waiting for navigation to /compose/tooling-test-example/{version_name} after adding file")
    wait_for_path(page, f"/compose/tooling-test-example/{version_name}")
    logging.info("Add file actions completed successfully")

    logging.info("Navigating back to /compose/tooling-test-example")
    go_to_path(page, f"/compose/tooling-test-example/{version_name}")
    logging.info("Navigation back to /compose/tooling-test-example completed successfully")


def lifecycle_04_start_vote(page: sync_api.Page, credentials: Credentials, version_name: str) -> None:
    logging.info(f"Navigating to the compose/tooling-test-example page for tooling-test-example {version_name}")
    go_to_path(page, f"/compose/tooling-test-example/{version_name}")
    logging.info("Compose/tooling-test-example page loaded successfully")

    logging.info(f"Locating start vote link for tooling-test-example {version_name}")
    start_vote_link_locator = page.locator('a[title="Start a vote on this draft"]')
    sync_api.expect(start_vote_link_locator).to_be_visible()

    logging.info("Follow the start vote link")
    start_vote_link_locator.click()

    logging.info("Waiting for page load after following the start vote link")
    page.wait_for_load_state()
    logging.info("Page loaded after following the start vote link")
    logging.info(f"Current URL: {page.url}")

    logging.info("Locating and activating the button to prepare the vote email")
    submit_button_locator = page.locator('input[type="submit"][value="Send vote email"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info(f"Waiting for navigation to /vote/tooling-test-example/{version_name} after submitting vote email")
    wait_for_path(page, f"/vote/tooling-test-example/{version_name}")
    logging.info("Vote initiation actions completed successfully")


def lifecycle_05_resolve_vote(page: sync_api.Page, credentials: Credentials, version_name: str) -> None:
    logging.info(f"Navigating to the vote page for tooling-test-example {version_name}")
    go_to_path(page, f"/vote/tooling-test-example/{version_name}")
    logging.info("Vote page loaded successfully")

    logging.info(f"Locating the form to resolve the vote for tooling-test-example {version_name}")
    form_locator = page.locator(
        f'form:has(input[name="candidate_name"][value="tooling-test-example-{esc_id(version_name)}"])'
    )
    sync_api.expect(form_locator).to_be_visible()

    logging.info("Locating and selecting the 'Passed' radio button")
    passed_radio_locator = form_locator.locator('input[name="vote_result"][value="passed"]')
    sync_api.expect(passed_radio_locator).to_be_enabled()
    passed_radio_locator.check()

    logging.info("Locating and activating the button to resolve the vote")
    submit_button_locator = form_locator.locator('input[type="submit"][value="Resolve vote"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info(f"Waiting for navigation to /finish/tooling-test-example/{version_name} after resolving the vote")
    wait_for_path(page, f"/finish/tooling-test-example/{version_name}")
    logging.info("Vote resolution actions completed successfully")


def lifecycle_06_announce_preview(page: sync_api.Page, credentials: Credentials, version_name: str) -> None:
    go_to_path(page, f"/finish/tooling-test-example/{version_name}")
    logging.info("Finish page loaded successfully")

    logging.info(f"Locating the announce link for tooling-test-example {version_name}")
    announce_link_locator = page.locator(f'a[href="/announce/tooling-test-example/{esc_id(version_name)}"]')
    sync_api.expect(announce_link_locator).to_be_visible()
    announce_link_locator.click()

    logging.info(f"Waiting for navigation to /announce/tooling-test-example/{version_name} after announcing preview")
    wait_for_path(page, f"/announce/tooling-test-example/{version_name}")

    logging.info(f"Locating the announcement form for tooling-test-example {version_name}")
    form_locator = page.locator(f'form[action="/announce/tooling-test-example/{esc_id(version_name)}"]')
    sync_api.expect(form_locator).to_be_visible()

    logging.info("Locating the confirmation checkbox within the form")
    checkbox_locator = form_locator.locator('input[name="confirm_announce"]')
    sync_api.expect(checkbox_locator).to_be_visible()

    logging.info("Checking the confirmation checkbox")
    checkbox_locator.check()

    logging.info("Locating and activating the announce button within the form")
    submit_button_locator = form_locator.get_by_role("button", name="Send announcement email")
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info("Waiting for navigation to /releases after submitting announcement")
    wait_for_path(page, "/releases/finished/tooling-test-example")
    logging.info("Preview announcement actions completed successfully")


def lifecycle_07_release_exists(page: sync_api.Page, credentials: Credentials, version_name: str) -> None:
    logging.info(f"Checking for release tooling-test-example {version_name} on /releases/finished/tooling-test-example")
    go_to_path(page, "/releases/finished/tooling-test-example")
    logging.info("Releases finished page loaded successfully")

    release_card_locator = page.locator(f'div.card:has(strong.card-title:has-text("{version_name}"))')
    sync_api.expect(release_card_locator).to_be_visible()
    logging.info(f"Found card for tooling-test-example {version_name} release")
    logging.info(
        f"Release tooling-test-example {version_name} confirmed exists on /releases/finished/tooling-test-example"
    )


def main() -> None:
    # TODO: Only members of ASF Tooling can run these tests
    parser = argparse.ArgumentParser(description="Run Playwright debugging test")
    parser.add_argument(
        "--log",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level, default is INFO",
    )
    parser.add_argument(
        "--skip-slow",
        action="store_true",
        help="Skip slow tests",
    )
    parser.add_argument(
        "--tidy",
        action="store_true",
        help="Run cleanup tasks after tests complete",
    )
    args = parser.parse_args()
    log_level = getattr(logging, args.log.upper(), logging.INFO)

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[rich.logging.RichHandler(rich_tracebacks=True, show_path=False)],
        force=True,
    )

    logging.debug(f"Log level set to {args.log.upper()}")
    run_tests(args.skip_slow, args.tidy)


def poll_for_tasks_completion(page: sync_api.Page, project_name: str, version_name: str, revision: str) -> None:
    gateway_ip = get_default_gateway_ip()
    if not gateway_ip:
        raise RuntimeError("Cannot proceed without gateway IP")

    rev_path = f"{project_name}/{version_name}/{revision}"
    polling_url = f"https://{gateway_ip}:8080/admin/ongoing-tasks/{rev_path}"
    logging.info(f"Polling URL: {polling_url}")

    max_wait_seconds = 12
    poll_interval_seconds = 0.01
    start_time = time.monotonic()

    for attempt in range(int(max_wait_seconds / poll_interval_seconds)):
        if attempt > 0:
            time.sleep(poll_interval_seconds)

        elapsed_time = time.monotonic() - start_time
        if elapsed_time > max_wait_seconds:
            raise TimeoutError(f"Tasks did not complete within {max_wait_seconds} seconds")

        response = page.request.get(polling_url)
        if not response.ok:
            raise RuntimeError(f"Polling request failed with status {response.status}")
        try:
            ongoing_count_str = response.text()
            if not ongoing_count_str:
                raise RuntimeError("Polling request returned empty body")
            ongoing_count = int(ongoing_count_str)
            if ongoing_count == 0:
                elapsed_time = time.monotonic() - start_time
                logging.info(f"All tasks completed in {elapsed_time} seconds")
                return
        except ValueError:
            raise RuntimeError(f"Polling request returned non-integer body: {response.text()}")
        except Exception:
            logging.exception("Unexpected error during polling response processing")
            raise

    raise TimeoutError(f"Tasks did not complete within {max_wait_seconds} seconds")


def ensure_success_results_are_visible(page: sync_api.Page, result_type: str) -> None:
    button_id = f"#btn-toggle-{result_type}-success"
    show_success_btn = page.locator(button_id)

    if show_success_btn.is_visible(timeout=500):
        raw_button_text = show_success_btn.text_content() or ""
        if "Show Success" in " ".join(raw_button_text.split()):
            show_success_btn.click()
            sync_api.expect(show_success_btn).to_contain_text("Hide Success", timeout=2000)
            first_success_row = page.locator(f".atr-result-{result_type}.atr-result-status-success").first
            if first_success_row.is_visible(timeout=500):
                sync_api.expect(first_success_row).not_to_have_class("atr-hide", timeout=1000)


def release_remove(page: sync_api.Page, release_name: str) -> None:
    logging.info(f"Checking whether the {release_name} release exists")
    release_checkbox_locator = page.locator(f'input[name="releases_to_delete"][value="{release_name}"]')

    if release_checkbox_locator.is_visible():
        logging.info(f"Found the {release_name} release, proceeding with deletion")
        logging.info(f"Selecting {release_name} for deletion")
        release_checkbox_locator.check()

        logging.info(f"Filling deletion confirmation for {release_name}")
        page.locator("#confirm_delete").fill("DELETE")

        logging.info(f"Submitting deletion form for {release_name}")
        submit_button_locator = page.locator('input[type="submit"][value="Delete selected releases permanently"]')
        sync_api.expect(submit_button_locator).to_be_enabled()
        submit_button_locator.click()

        logging.info(f"Waiting for page load after deletion submission for {release_name}")
        page.wait_for_load_state()
        logging.info(f"Page loaded after deletion for {release_name}")

        logging.info(f"Checking for success flash message for {release_name}")
        flash_message_locator = page.locator("div.flash-success")
        sync_api.expect(flash_message_locator).to_be_visible()
        sync_api.expect(flash_message_locator).to_contain_text("Successfully deleted 1 release(s)")
        logging.info(f"Deletion successful for {release_name}")
    else:
        logging.info(f"Could not find the {release_name} release, no deletion needed")


def run_tests(skip_slow: bool, tidy_after: bool) -> None:
    if (credentials := get_credentials()) is None:
        logging.error("Cannot run tests: no credentials provided")
        return

    with sync_api.sync_playwright() as p:
        browser = None
        context = None
        try:
            browser = p.chromium.launch()
            context = browser.new_context(ignore_https_errors=True)
            run_tests_in_context(context, credentials, skip_slow, tidy_after)

        except Exception as e:
            logging.error(f"Error during page interaction: {e}", exc_info=True)
        finally:
            if context:
                context.close()
            if browser:
                browser.close()


def run_tests_in_context(
    context: sync_api.BrowserContext, credentials: Credentials, skip_slow: bool, tidy_after: bool
) -> None:
    ssh_keys_generate()
    page = context.new_page()
    test_all(page, credentials, skip_slow)
    logging.info("Tests finished successfully")

    if tidy_after:
        logging.info("Tidying up after the tests")
        test_tidy_up(page)
        logging.info("Tidying up after the tests finished")


def run_tests_skipping_slow(
    tests: list[Callable[..., Any]], page: sync_api.Page, credentials: Credentials, skip_slow: bool
) -> None:
    for test in tests:
        if skip_slow and ("slow" in test.__annotations__):
            logging.info(f"Skipping slow test: {test.__name__}")
            continue
        # if "credentials" in test.__code__.co_varnames:
        test(page, credentials)


def show_default_gateway_ip() -> None:
    match get_default_gateway_ip():
        case str(ip_address):
            logging.info(f"Default gateway IP: {ip_address}")
        case None:
            logging.warning("Could not determine gateway IP")


def slow(func: Callable[..., Any]) -> Callable[..., Any]:
    func.__annotations__["slow"] = True
    return func


def ssh_keys_generate() -> None:
    ssh_key_path = _SSH_KEY_PATH
    ssh_dir = os.path.dirname(ssh_key_path)

    try:
        if os.path.exists(ssh_key_path):
            os.remove(ssh_key_path)
            logging.info(f"Removed existing SSH key at {ssh_key_path}")
        if os.path.exists(f"{ssh_key_path}.pub"):
            os.remove(f"{ssh_key_path}.pub")
            logging.info(f"Removed existing SSH public key at {ssh_key_path}.pub")

        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

        logging.info(f"Generating new SSH key at {ssh_key_path} with comment {_SSH_KEY_COMMENT}")
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", ssh_key_path, "-N", "", "-C", _SSH_KEY_COMMENT],
            check=True,
            capture_output=True,
            text=True,
        )
        logging.info("SSH key generated successfully")

    except (OSError, subprocess.CalledProcessError) as e:
        logging.error(f"Failed to generate SSH key: {e}", exc_info=True)
        if isinstance(e, subprocess.CalledProcessError):
            logging.error(f"ssh-keygen stderr: {e.stderr}")
        raise RuntimeError("SSH key generation failed") from e


def test_all(page: sync_api.Page, credentials: Credentials, skip_slow: bool) -> None:
    start = time.perf_counter()
    test_login(page, credentials)
    test_tidy_up(page)

    # Declare all tests
    # The order here is important
    tests: dict[str, list[Callable[..., Any]]] = {}
    tests["projects"] = [
        test_projects_01_update,
        test_projects_02_check_directory,
        test_projects_03_add_project,
    ]
    tests["lifecycle"] = [
        test_lifecycle_01_add_draft,
        test_lifecycle_02_check_draft_added,
        test_lifecycle_03_add_file,
        test_lifecycle_04_start_vote,
        test_lifecycle_05_resolve_vote,
        test_lifecycle_06_announce_preview,
        test_lifecycle_07_release_exists,
    ]
    tests["openpgp"] = [
        test_openpgp_01_upload,
    ]
    tests["ssh"] = [
        test_ssh_01_add_key,
        test_ssh_02_rsync_upload,
    ]
    tests["checks"] = [
        test_checks_01_hashing_sha512,
        test_checks_02_license_files,
        test_checks_03_license_headers,
        test_checks_04_paths,
        test_checks_05_signature,
        test_checks_06_targz,
    ]

    # Order between our tests must be preserved
    # Insertion order is reliable since Python 3.6
    # Therefore iteration over tests matches the insertion order above
    for key in tests:
        run_tests_skipping_slow(tests[key], page, credentials, skip_slow)

    finish = time.perf_counter()
    logging.info(f"Tests took {round(finish - start, 3)} seconds")


def test_checks_01_hashing_sha512(page: sync_api.Page, credentials: Credentials) -> None:
    project_name = "tooling-test-example"
    version_name = "0.2"
    filename_sha512 = f"apache-{project_name}-{version_name}.tar.gz.sha512"
    compose_path = f"/compose/{project_name}/{version_name}"
    report_file_path = f"/report/{project_name}/{version_name}/{filename_sha512}"

    logging.info(f"Starting hashing check test for {filename_sha512}")

    logging.info(f"Navigating to compose page {compose_path}")
    go_to_path(page, compose_path)

    logging.info(f"Locating 'Show report' link for {filename_sha512}")
    row_locator = page.locator(f"tr:has(:text('{filename_sha512}'))")
    evaluate_link_title = f"Show report for {filename_sha512}"
    evaluate_link_locator = row_locator.locator(f'a[title="{evaluate_link_title}"]')
    sync_api.expect(evaluate_link_locator).to_be_visible()

    logging.info(f"Clicking 'Show report' link for {filename_sha512}")
    evaluate_link_locator.click()

    logging.info(f"Waiting for navigation to {report_file_path}")
    wait_for_path(page, report_file_path)
    logging.info(f"Successfully navigated to {report_file_path}")

    ensure_success_results_are_visible(page, "primary")

    logging.info("Verifying Hashing Check status")
    check_row_locator = page.locator("tr.atr-result-primary:has(th:has-text('Hashing Check'))")
    sync_api.expect(check_row_locator).to_be_visible()
    logging.info("Located Hashing Check row")

    success_badge_locator = check_row_locator.locator("td span.badge.bg-success:text-is('Success')")
    sync_api.expect(success_badge_locator).to_be_visible()
    logging.info("Hashing Check status verified as Success")


def test_checks_02_license_files(page: sync_api.Page, credentials: Credentials) -> None:
    project_name = "tooling-test-example"
    version_name = "0.2"
    filename_targz = f"apache-{project_name}-{version_name}.tar.gz"
    compose_path = f"/compose/{project_name}/{version_name}"
    report_file_path = f"/report/{project_name}/{version_name}/{filename_targz}"

    logging.info(f"Starting License Files check test for {filename_targz}")

    logging.info(f"Navigating to compose page {compose_path}")
    go_to_path(page, compose_path)

    logging.info(f"Locating 'Show report' link for {filename_targz}")
    row_locator = page.locator(f"tr:has(:text('{filename_targz}'))")
    evaluate_link_title = f"Show report for {filename_targz}"
    evaluate_link_locator = row_locator.locator(f'a[title="{evaluate_link_title}"]')
    sync_api.expect(evaluate_link_locator).to_be_visible()

    logging.info(f"Clicking 'Show report' link for {filename_targz}")
    evaluate_link_locator.click()

    logging.info(f"Waiting for navigation to {report_file_path}")
    wait_for_path(page, report_file_path)
    logging.info(f"Successfully navigated to {report_file_path}")

    ensure_success_results_are_visible(page, "primary")

    logging.info("Verifying License Files check status")
    check_row_locator = page.locator("tr.atr-result-primary:has(th:text-is('License Files'))")
    sync_api.expect(check_row_locator).to_have_count(2)
    logging.info("Located 2 License Files check rows")

    success_badge_locator = check_row_locator.locator("td span.badge.bg-success:text-is('Success')")
    sync_api.expect(success_badge_locator).to_have_count(2)
    logging.info("License Files check status verified as Success for 2 rows")


def test_checks_03_license_headers(page: sync_api.Page, credentials: Credentials) -> None:
    project_name = "tooling-test-example"
    version_name = "0.2"
    filename_targz = f"apache-{project_name}-{version_name}.tar.gz"
    report_file_path = f"/report/{project_name}/{version_name}/{filename_targz}"

    logging.info(f"Starting License Headers check test for {filename_targz}")

    # Don't repeat the link test, just go straight there
    logging.info(f"Navigating to report page {report_file_path}")
    go_to_path(page, report_file_path)
    logging.info(f"Successfully navigated to {report_file_path}")

    ensure_success_results_are_visible(page, "primary")

    logging.info("Verifying License Headers check status")
    check_row_locator = page.locator("tr.atr-result-primary:has(th:has-text('License Headers'))")
    sync_api.expect(check_row_locator).to_be_visible()
    logging.info("Located License Headers check row")

    success_badge_locator = check_row_locator.locator("td span.badge.bg-success:text-is('Success')")
    sync_api.expect(success_badge_locator).to_be_visible()
    logging.info("License Headers check status verified as Success")


def test_checks_04_paths(page: sync_api.Page, credentials: Credentials) -> None:
    project_name = "tooling-test-example"
    version_name = "0.2"
    filename_sha512 = f"apache-{project_name}-{version_name}.tar.gz.sha512"
    report_file_path = f"/report/{project_name}/{version_name}/{filename_sha512}"

    logging.info(f"Starting Paths check test for {filename_sha512}")

    logging.info(f"Navigating to report page {report_file_path}")
    go_to_path(page, report_file_path)
    logging.info(f"Successfully navigated to {report_file_path}")

    ensure_success_results_are_visible(page, "primary")

    # TODO: It's a bit strange to have the status in the check name
    # But we have to do this because we need separate Recorder objects
    logging.info("Verifying Paths Check Success status")
    check_row_locator = page.locator("tr.atr-result-primary:has(th:has-text('Paths Check Success'))")
    sync_api.expect(check_row_locator).to_be_visible()
    logging.info("Located Paths Check Success row")

    success_badge_locator = check_row_locator.locator("td span.badge.bg-success:text-is('Success')")
    sync_api.expect(success_badge_locator).to_be_visible()
    logging.info("Paths Check Success status verified as Success")


def test_checks_05_signature(page: sync_api.Page, credentials: Credentials) -> None:
    project_name = "tooling-test-example"
    version_name = "0.2"
    filename_asc = f"apache-{project_name}-{version_name}.tar.gz.asc"
    report_file_path = f"/report/{project_name}/{version_name}/{filename_asc}"

    logging.info(f"Starting Signature check test for {filename_asc}")

    logging.info(f"Navigating to report page {report_file_path}")
    go_to_path(page, report_file_path)
    logging.info(f"Successfully navigated to {report_file_path}")

    ensure_success_results_are_visible(page, "primary")

    logging.info("Verifying Signature Check status")
    check_row_locator = page.locator("tr.atr-result-primary:has(th:has-text('Signature Check'))")
    sync_api.expect(check_row_locator).to_be_visible()
    logging.info("Located Signature Check row")

    success_badge_locator = check_row_locator.locator("td span.badge.bg-success:text-is('Success')")
    sync_api.expect(success_badge_locator).to_be_visible()
    logging.info("Signature Check status verified as Success")


def test_checks_06_targz(page: sync_api.Page, credentials: Credentials) -> None:
    project_name = "tooling-test-example"
    version_name = "0.2"
    filename_targz = f"apache-{project_name}-{version_name}.tar.gz"
    report_file_path = f"/report/{project_name}/{version_name}/{filename_targz}"

    logging.info(f"Starting Targz checks for {filename_targz}")

    logging.info(f"Navigating to report page {report_file_path}")
    go_to_path(page, report_file_path)
    logging.info(f"Successfully navigated to {report_file_path}")

    ensure_success_results_are_visible(page, "primary")

    logging.info("Verifying Targz Integrity status")
    integrity_row_locator = page.locator("tr.atr-result-primary:has(th:has-text('Targz Integrity'))")
    sync_api.expect(integrity_row_locator).to_be_visible()
    logging.info("Located Targz Integrity row")
    integrity_success_badge = integrity_row_locator.locator("td span.badge.bg-success:text-is('Success')")
    sync_api.expect(integrity_success_badge).to_be_visible()
    logging.info("Targz Integrity status verified as Success")

    logging.info("Verifying Targz Structure status")
    structure_row_locator = page.locator("tr.atr-result-primary:has(th:has-text('Targz Structure'))")
    sync_api.expect(structure_row_locator).to_be_visible()
    logging.info("Located Targz Structure row")
    structure_success_badge = structure_row_locator.locator("td span.badge.bg-success:text-is('Success')")
    sync_api.expect(structure_success_badge).to_be_visible()
    logging.info("Targz Structure status verified as Success")


def test_openpgp_01_upload(page: sync_api.Page, credentials: Credentials) -> None:
    key_fingerprint_lower = "e35604dd9e2892e5465b3d8a203f105a7b33a64f"
    key_fingerprint_upper = key_fingerprint_lower.upper()
    key_path = f"/run/tests/{key_fingerprint_lower.upper()}.asc"

    logging.info("Starting OpenPGP key upload test")
    go_to_path(page, "/keys")

    logging.info("Following link to add OpenPGP key")
    add_key_link_locator = page.locator('a:has-text("Add your OpenPGP key")')
    sync_api.expect(add_key_link_locator).to_be_visible()
    add_key_link_locator.click()

    logging.info("Waiting for Add OpenPGP key page")
    wait_for_path(page, "/keys/add")

    try:
        logging.info(f"Reading public key from {key_path}")
        with open(key_path, encoding="utf-8") as f:
            public_key_content = f.read().strip()
        logging.info("Public key read successfully")
    except OSError as e:
        logging.error(f"Failed to read public key file {key_path}: {e}")
        raise RuntimeError("Failed to read public key file") from e

    logging.info("Filling public key textarea")
    public_key_textarea_locator = page.locator('textarea[name="public_key"]')
    sync_api.expect(public_key_textarea_locator).to_be_visible()
    public_key_textarea_locator.fill(public_key_content)

    logging.info("Clicking Select all committees button")
    select_all_button_locator = page.locator("#toggleCommitteesBtn")
    sync_api.expect(select_all_button_locator).to_be_visible()
    select_all_button_locator.click()

    logging.info("Submitting the Add OpenPGP key form")
    submit_button_locator = page.locator('input[type="submit"][value="Add OpenPGP key"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info("Waiting for navigation back to /keys page")
    wait_for_path(page, "/keys/add")

    logging.info("Checking for success flash message on /keys/add page")
    flash_message_locator = page.locator("div.flash-success")
    sync_api.expect(flash_message_locator).to_be_visible()
    sync_api.expect(flash_message_locator).to_contain_text(f"OpenPGP key {key_fingerprint_upper} added successfully.")
    logging.info("OpenPGP key upload successful message shown")

    logging.info("Navigating back to /keys to verify key presence")
    go_to_path(page, "/keys")

    logging.info(f"Verifying OpenPGP key with fingerprint {key_fingerprint_upper} is visible")
    key_row_locator = page.locator(f'tr.page-user-openpgp-key:has(a[href="/keys/details/{key_fingerprint_lower}"])')
    sync_api.expect(key_row_locator).to_be_visible()
    logging.info("OpenPGP key fingerprint verified successfully on /keys page")


def test_lifecycle_01_add_draft(page: sync_api.Page, credentials: Credentials) -> None:
    lifecycle_01_add_draft(page, credentials, version_name="0.1+draft")
    lifecycle_01_add_draft(page, credentials, version_name="0.1+candidate")
    lifecycle_01_add_draft(page, credentials, version_name="0.1+preview")
    lifecycle_01_add_draft(page, credentials, version_name="0.1+release")


def test_lifecycle_02_check_draft_added(page: sync_api.Page, credentials: Credentials) -> None:
    lifecycle_02_check_draft_added(page, credentials, version_name="0.1+draft")
    lifecycle_02_check_draft_added(page, credentials, version_name="0.1+candidate")
    lifecycle_02_check_draft_added(page, credentials, version_name="0.1+preview")
    lifecycle_02_check_draft_added(page, credentials, version_name="0.1+release")


def test_lifecycle_03_add_file(page: sync_api.Page, credentials: Credentials) -> None:
    lifecycle_03_add_file(page, credentials, version_name="0.1+draft")
    lifecycle_03_add_file(page, credentials, version_name="0.1+candidate")
    lifecycle_03_add_file(page, credentials, version_name="0.1+preview")
    lifecycle_03_add_file(page, credentials, version_name="0.1+release")


def test_lifecycle_04_start_vote(page: sync_api.Page, credentials: Credentials) -> None:
    lifecycle_04_start_vote(page, credentials, version_name="0.1+candidate")
    lifecycle_04_start_vote(page, credentials, version_name="0.1+preview")
    lifecycle_04_start_vote(page, credentials, version_name="0.1+release")


def test_lifecycle_05_resolve_vote(page: sync_api.Page, credentials: Credentials) -> None:
    lifecycle_05_resolve_vote(page, credentials, version_name="0.1+preview")
    lifecycle_05_resolve_vote(page, credentials, version_name="0.1+release")


def test_lifecycle_06_announce_preview(page: sync_api.Page, credentials: Credentials) -> None:
    lifecycle_06_announce_preview(page, credentials, version_name="0.1+release")


def test_lifecycle_07_release_exists(page: sync_api.Page, credentials: Credentials) -> None:
    lifecycle_07_release_exists(page, credentials, version_name="0.1+release")


def test_login(page: sync_api.Page, credentials: Credentials) -> None:
    debugging = False

    def remove_debugging() -> None:
        pass

    if debugging:
        remove_debugging = test_logging_debug(page, credentials)

    go_to_path(page, "/")
    logging.info(f"Initial page title: {page.title()}")

    logging.info("Following link to log in")
    login_link_locator = page.get_by_role("link", name="Login")
    sync_api.expect(login_link_locator).to_be_visible()
    login_link_locator.click()

    logging.info("Waiting for the login page")
    username_field_locator = page.locator('input[name="username"]')
    sync_api.expect(username_field_locator).to_be_visible()
    logging.info("Login page loaded")

    logging.info("Filling credentials")
    username_field_locator.fill(credentials.username)
    page.locator('input[name="password"]').fill(credentials.password)

    logging.info("Submitting the login form")
    submit_button_locator = page.locator('input[type="submit"][value="Authenticate"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info("Waiting for the page to load")
    page.wait_for_load_state()
    logging.info("Page loaded after login")
    logging.info(f"Initial URL after login: {page.url}")

    logging.info("Waiting for the redirect to /")
    # We can't use wait_for_path here because it goes through /auth
    page.wait_for_url("https://*/")
    logging.info("Redirected to /")
    logging.info(f"Page URL: {page.url}")
    logging.info("Login actions completed successfully")

    if debugging:
        remove_debugging()


def test_logging_debug(page: sync_api.Page, credentials: Credentials) -> Callable[[], None]:
    def log_request(request: sync_api.Request) -> None:
        logging.info(f">> REQUEST: {request.method} {request.url}")
        for key, value in request.headers.items():
            logging.info(f"  REQ HEADER: {key}: {value}")

    def log_response(response: sync_api.Response) -> None:
        logging.info(f"<< RESPONSE: {response.status} {response.url}")
        headers = response.headers
        for key, value in headers.items():
            logging.info(f"  RESP HEADER: {key}: {value}")
        if "location" in headers:
            logging.info(f"  >> REDIRECTING TO: {headers['location']}")
        if response.status == 500:
            logging.info(f"  BODY: {response.text()}")

    page.on("request", log_request)
    page.on("response", log_response)

    def remove_debugging() -> None:
        page.remove_listener("request", log_request)
        page.remove_listener("response", log_response)

    return remove_debugging


@slow
def test_projects_01_update(page: sync_api.Page, credentials: Credentials) -> None:
    logging.info("Navigating to the admin update projects page")
    go_to_path(page, "/admin/projects/update")
    logging.info("Admin update projects page loaded")

    logging.info("Locating and activating the button to update projects")
    update_button_locator = page.get_by_role("button", name="Update projects")
    sync_api.expect(update_button_locator).to_be_enabled()
    update_button_locator.click()

    logging.info("Waiting for project update completion message")
    success_message_locator = page.locator("div.status-message.success")
    sync_api.expect(success_message_locator).to_contain_text(
        re.compile(
            r"Successfully added \d+ and updated \d+ committees and projects \(PMCs and PPMCs\) with membership data"
        )
    )
    logging.info("Project update completed successfully")


def test_projects_02_check_directory(page: sync_api.Page, credentials: Credentials) -> None:
    logging.info("Navigating to the project directory page")
    go_to_path(page, "/projects")
    logging.info("Project directory page loaded")

    logging.info("Checking for the Apache Tooling project card")
    h3_locator = page.get_by_text("Apache Tooling", exact=True)
    tooling_card_locator = h3_locator.locator("xpath=ancestor::div[contains(@class, 'project-card')]")
    sync_api.expect(tooling_card_locator).to_be_visible()
    logging.info("Apache Tooling project card found successfully")


def test_projects_03_add_project(page: sync_api.Page, credentials: Credentials) -> None:
    base_project_label = "tooling"
    project_name = "Apache Tooling Test Example"
    project_label = "tooling-test-example"

    logging.info("Navigating to the add derived project page")
    go_to_path(page, f"/project/add/{base_project_label}")
    logging.info("Add a new project page loaded")

    logging.info(f"Filling display name '{project_name}'")
    page.locator('input[name="display_name"]').fill(project_name)

    logging.info(f"Filling label '{project_label}'")
    page.locator('input[name="label"]').fill(project_label)

    logging.info("Submitting the add derived project form")
    submit_button_locator = page.locator('input[type="submit"][value="Add project"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info(f"Waiting for navigation to project view page for {project_label}")
    wait_for_path(page, f"/projects/{project_label}")
    logging.info("Navigated to project view page successfully")

    logging.info(f"Checking for project title '{project_name}' on view page")
    title_locator = page.locator(f'h1:has-text("{project_name}")')
    sync_api.expect(title_locator).to_be_visible()
    logging.info("Project title confirmed on view page")


def test_ssh_01_add_key(page: sync_api.Page, credentials: Credentials) -> None:
    logging.info("Starting SSH key addition test")
    go_to_path(page, "/committees")

    logging.info("Navigating to Your Public Keys page")
    page.locator('a[href="/keys"]:has-text("Manage keys")').click()
    wait_for_path(page, "/keys")
    logging.info("Navigated to Your Public Keys page")

    logging.info("Clicking Add your SSH key button")
    # There can be two buttons with the same text if the user did not upload an SSH key yet
    page.locator('a[href="/keys/ssh/add"]:has-text("Add your SSH key")').first.click()
    wait_for_path(page, "/keys/ssh/add")
    logging.info("Navigated to Add your SSH key page")

    public_key_path = f"{_SSH_KEY_PATH}.pub"
    try:
        logging.info(f"Reading public key from {public_key_path}")
        with open(public_key_path, encoding="utf-8") as f:
            public_key_content = f.read().strip()
        logging.info("Public key read successfully")
    except OSError as e:
        logging.error(f"Failed to read public key file {public_key_path}: {e}")
        raise RuntimeError("Failed to read public key file") from e

    logging.info("Pasting public key into textarea")
    page.locator('textarea[name="key"]').fill(public_key_content)

    logging.info("Submitting the Add SSH key form")
    page.locator('input[type="submit"][value="Add SSH key"]').click()

    logging.info("Waiting for navigation back to /keys page")
    wait_for_path(page, "/keys")
    logging.info("Navigated back to /keys page")

    try:
        logging.info("Calculating expected SSH key fingerprint using ssh-keygen -lf")
        result = subprocess.run(
            ["ssh-keygen", "-lf", public_key_path],
            check=True,
            capture_output=True,
            text=True,
        )
        fingerprint_output = result.stdout.strip()
        match = re.search(r"SHA256:([\w\+/=]+)", fingerprint_output)
        if not match:
            logging.error(f"Could not parse fingerprint from ssh-keygen output: {fingerprint_output}")
            raise RuntimeError("Failed to parse SSH key fingerprint")
        expected_fingerprint = f"SHA256:{match.group(1)}"
        logging.info(f"Expected fingerprint: {expected_fingerprint}")

    except (subprocess.CalledProcessError, FileNotFoundError, RuntimeError) as e:
        logging.error(f"Failed to get SSH key fingerprint: {e}")
        if isinstance(e, subprocess.CalledProcessError):
            logging.error(f"ssh-keygen stderr: {e.stderr}")
        raise RuntimeError("Failed to get SSH key fingerprint") from e

    logging.info("Verifying that the added SSH key fingerprint is visible")
    key_card_locator = page.locator(f'div.card:has(td:has-text("{expected_fingerprint}"))')
    sync_api.expect(key_card_locator).to_be_visible()
    logging.info("SSH key fingerprint verified successfully on /keys page")


def test_ssh_02_rsync_upload(page: sync_api.Page, credentials: Credentials) -> None:
    project_name = "tooling-test-example"
    version_name = "0.2"
    source_dir_rel = f"apache-{project_name}-{version_name}"
    source_dir_abs = f"/run/tests/{source_dir_rel}"
    file1 = f"apache-{project_name}-{version_name}.tar.gz"
    file2 = f"{file1}.sha512"

    logging.info(f"Starting rsync upload test for {project_name}-{version_name}")

    gateway_ip = get_default_gateway_ip()
    if not gateway_ip:
        raise RuntimeError("Cannot proceed without gateway IP")

    username = credentials.username
    ssh_command = "ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    source_path = f"{source_dir_abs}/"
    destination = f"{username}@{gateway_ip}:/{project_name}/{version_name}/"

    rsync_cmd = [
        "rsync",
        "-av",
        "-e",
        ssh_command,
        source_path,
        destination,
    ]

    logging.info(f"Executing rsync command: {' '.join(rsync_cmd)}")
    try:
        result = subprocess.run(rsync_cmd, check=True, capture_output=True, text=True)
        logging.info(f"rsync completed successfully. stdout:\n{result.stdout}")
        if result.stderr:
            logging.warning(f"rsync stderr:\n{result.stderr}")
    except subprocess.CalledProcessError as e:
        logging.error(f"rsync command failed with exit code {e.returncode}")
        logging.error(f"rsync stdout:\n{e.stdout}")
        logging.error(f"rsync stderr:\n{e.stderr}")
        raise RuntimeError("rsync upload failed") from e
    except FileNotFoundError:
        logging.error("rsync command not found. Is rsync installed in the container?")
        raise RuntimeError("rsync command not found")

    logging.info(f"Navigating to compose page for {project_name}-{version_name}")
    compose_path = f"/compose/{project_name}/{version_name}"
    go_to_path(page, compose_path)
    logging.info(f"Checking for uploaded files on {compose_path}")

    # Check for the existence of the files in the table using exact match
    file1_locator = page.get_by_role("cell", name=file1, exact=True)
    file2_locator = page.get_by_role("cell", name=file2, exact=True)

    sync_api.expect(file1_locator).to_be_visible()
    logging.info(f"Found file: {file1}")
    sync_api.expect(file2_locator).to_be_visible()
    logging.info(f"Found file: {file2}")
    logging.info("rsync upload test completed successfully")

    logging.info(f"Extracting latest revision from {compose_path}")
    revision_link_locator = page.locator(f'a[href^="/revisions/{project_name}/{version_name}#"]')
    sync_api.expect(revision_link_locator).to_be_visible()
    revision_href = revision_link_locator.get_attribute("href")
    if not revision_href:
        raise RuntimeError("Could not find revision link href")
    revision = revision_href.split("#", 1)[-1]
    logging.info(f"Found revision: {revision}")

    logging.info(f"Polling for task completion for revision {revision}")
    poll_for_tasks_completion(page, project_name, version_name, revision)


def test_tidy_up(page: sync_api.Page) -> None:
    # Projects cannot be deleted if they have associated releases
    # Therefore, we need to delete releases first
    test_tidy_up_releases(page)
    test_tidy_up_project(page)
    test_tidy_up_ssh_keys(page)
    test_tidy_up_openpgp_keys(page)


def test_tidy_up_openpgp_keys(page: sync_api.Page) -> None:
    logging.info("Starting OpenPGP key tidy up")
    go_to_path(page, "/keys")
    logging.info("Navigated to /keys page for OpenPGP key cleanup")

    openpgp_key_section_locator = page.locator("h3:has-text('OpenPGP keys')")
    table_locator = openpgp_key_section_locator.locator("xpath=following-sibling::div//table")
    key_rows_locator = table_locator.locator("tbody tr.page-user-openpgp-key")

    key_rows = key_rows_locator.all()
    logging.info(f"Found {len(key_rows)} OpenPGP key rows to check")

    fingerprints_to_delete = []

    for row in key_rows:
        link_locator = row.locator('a[href^="/keys/details/"]')
        href = link_locator.get_attribute("href")
        if not href:
            logging.warning("Could not find href for key details link in a row, skipping")
            continue
        fingerprint = href.split("/")[-1]

        go_to_path(page, href, wait=False)

        pre_locator = page.locator("pre")
        sync_api.expect(pre_locator).to_be_visible()
        key_content = pre_locator.inner_text()

        if _OPENPGP_TEST_UID in key_content:
            logging.info(f"Found test OpenPGP key with fingerprint {fingerprint} for deletion")
            fingerprints_to_delete.append(fingerprint)

        go_to_path(page, "/keys")

    # For the complexity linter only
    test_tidy_up_openpgp_keys_continued(page, fingerprints_to_delete)


def test_tidy_up_openpgp_keys_continued(page: sync_api.Page, fingerprints_to_delete: list[str]) -> None:
    if not fingerprints_to_delete:
        logging.info("No test OpenPGP keys found to delete")
        return

    # Delete identified keys
    logging.info(f"Attempting to delete {len(fingerprints_to_delete)} test OpenPGP keys")
    for fingerprint in fingerprints_to_delete:
        logging.info(f"Locating delete form for fingerprint: {fingerprint}")
        # Locate again by fingerprint for robustness
        row_to_delete_locator = page.locator(f'tr:has(a[href="/keys/details/{fingerprint}"])')
        delete_button_locator = row_to_delete_locator.locator(
            'form[action="/keys/delete"] input[type="submit"][value="Delete key"]'
        )

        if delete_button_locator.is_visible():
            logging.info(f"Delete button found for {fingerprint}, proceeding with deletion")

            def handle_dialog(dialog: sync_api.Dialog) -> None:
                logging.info(f"Accepting dialog for OpenPGP key deletion: {dialog.message}")
                dialog.accept()

            page.once("dialog", handle_dialog)
            delete_button_locator.click()

            logging.info(f"Waiting for page reload after deleting OpenPGP key {fingerprint}")
            page.wait_for_load_state()
            wait_for_path(page, "/keys")

            flash_message_locator = page.locator("div.flash-success")
            sync_api.expect(flash_message_locator).to_contain_text("OpenPGP key deleted successfully")
            logging.info(f"Deletion successful for OpenPGP key {fingerprint}")

        else:
            logging.warning(f"Could not find delete button for OpenPGP fingerprint {fingerprint} after re-locating")

    logging.info("OpenPGP key tidy up finished")


def test_tidy_up_project(page: sync_api.Page) -> None:
    project_name = "Apache Tooling Test Example"
    logging.info(f"Checking for project '{project_name}' at /projects")
    go_to_path(page, "/projects")
    logging.info("Project directory page loaded")

    h3_locator = page.get_by_text(project_name, exact=True)
    example_card_locator = h3_locator.locator("xpath=ancestor::div[contains(@class, 'project-card')]")

    if example_card_locator.is_visible():
        logging.info(f"Found project card for '{project_name}'")
        delete_button_locator = example_card_locator.get_by_role("button", name="Delete Project")

        if delete_button_locator.is_visible():
            logging.info(f"Delete button found for '{project_name}', proceeding with deletion")

            def handle_dialog(dialog: sync_api.Dialog) -> None:
                logging.info(f"Accepting dialog: {dialog.message}")
                dialog.accept()

            page.once("dialog", handle_dialog)
            delete_button_locator.click()

            logging.info("Waiting for navigation back to /projects after deletion")
            wait_for_path(page, "/projects")

            logging.info(f"Verifying project card for '{project_name}' is no longer visible")
            h3_locator_check = page.get_by_text(project_name, exact=True)
            card_locator_check = h3_locator_check.locator("xpath=ancestor::div[contains(@class, 'project-card')]")
            sync_api.expect(card_locator_check).not_to_be_visible()
            logging.info(f"Project '{project_name}' deleted successfully")
        else:
            logging.info(f"Delete button not visible for '{project_name}', no deletion performed")
    else:
        logging.info(f"Project card for '{project_name}' not found, no deletion needed")


def test_tidy_up_ssh_keys(page: sync_api.Page) -> None:
    logging.info("Starting SSH key tidy up")
    go_to_path(page, "/keys")
    logging.info("Navigated to /keys page for SSH key cleanup")

    ssh_key_section_locator = page.locator("h3:has-text('SSH keys')")
    key_cards_container_locator = ssh_key_section_locator.locator(
        "xpath=following-sibling::div[contains(@class, 'mb-5')]//div[contains(@class, 'd-grid')]"
    )
    key_cards_locator = key_cards_container_locator.locator("> div.card")

    key_cards = key_cards_locator.all()
    logging.info(f"Found {len(key_cards)} potential SSH key cards to check")

    fingerprints_to_delete = []

    for card in key_cards:
        details_element = card.locator("details").first
        summary_element = details_element.locator("summary").first

        if not details_element.is_visible(timeout=500):
            logging.warning("SSH key card: <details> element not found or not visible, skipping")
            continue
        if not summary_element.is_visible(timeout=500):
            logging.warning("SSH key card: <summary> element not found or not visible, skipping")
            continue

        is_already_open = details_element.evaluate("el => el.hasAttribute('open')")

        if not is_already_open:
            logging.info("SSH key card: details is not open, clicking summary to open")
            summary_element.click()
            try:
                sync_api.expect(details_element).to_have_attribute("open", "", timeout=2000)
                logging.info("SSH key card: details successfully opened")
            except Exception as e:
                logging.warning(
                    f"SSH key card: failed to confirm details opened after clicking summary: {e}, skipping card"
                )
                continue
        else:
            logging.info("SSH key card: details already open")

        details_pre_locator = details_element.locator("pre").first
        try:
            sync_api.expect(details_pre_locator).to_be_visible(timeout=1000)
        except Exception as e:
            logging.warning(
                f"SSH key card: <pre> tag not visible even after attempting to open details: {e}, skipping card"
            )
            continue

        key_content = details_pre_locator.inner_text()
        if _SSH_KEY_COMMENT in key_content:
            fingerprint_td_locator = card.locator('td:has-text("SHA256:")')
            if fingerprint_td_locator.is_visible(timeout=500):
                fingerprint = fingerprint_td_locator.inner_text().strip()
                if fingerprint:
                    logging.info(f"Found test SSH key with fingerprint {fingerprint} for deletion")
                    fingerprints_to_delete.append(fingerprint)
                else:
                    logging.warning("Found test SSH key card but could not extract fingerprint text from td")
            else:
                logging.warning("Could not locate fingerprint td for a test key card")
        else:
            logging.debug(f"SSH key card: test comment '{_SSH_KEY_COMMENT}' not found in key content")

    # For the complexity linter only
    test_tidy_up_ssh_keys_continued(page, fingerprints_to_delete)


def test_tidy_up_ssh_keys_continued(page: sync_api.Page, fingerprints_to_delete: list[str]) -> None:
    if not fingerprints_to_delete:
        logging.info("No test SSH keys found to delete")
        return

    # Delete identified keys
    logging.info(f"Attempting to delete {len(fingerprints_to_delete)} test SSH keys")
    for fingerprint in fingerprints_to_delete:
        logging.info(f"Locating delete form for fingerprint: {fingerprint}")
        # Locate again by fingerprint for robustness in case of changes
        card_to_delete_locator = page.locator(f"div.card:has(td:has-text('{fingerprint}'))")
        delete_button_locator = card_to_delete_locator.locator(
            'form[action="/keys/delete"] input[type="submit"][value="Delete key"]'
        )

        if delete_button_locator.is_visible():
            logging.info(f"Delete button found for {fingerprint}, proceeding with deletion")

            def handle_dialog(dialog: sync_api.Dialog) -> None:
                logging.info(f"Accepting dialog for key deletion: {dialog.message}")
                dialog.accept()

            page.once("dialog", handle_dialog)
            delete_button_locator.click()

            logging.info(f"Waiting for page reload after deleting key {fingerprint}")
            page.wait_for_load_state()
            wait_for_path(page, "/keys")

            flash_message_locator = page.locator("div.flash-success")
            sync_api.expect(flash_message_locator).to_contain_text("SSH key deleted successfully")
            logging.info(f"Deletion successful for key {fingerprint}")

        else:
            logging.warning(f"Could not find delete button for fingerprint {fingerprint} after re-locating")

    logging.info("SSH key tidy up finished")


def test_tidy_up_releases(page: sync_api.Page) -> None:
    logging.info("Navigating to the admin delete release page")
    go_to_path(page, "/admin/delete-release")
    logging.info("Admin delete release page loaded")

    # TODO: Get these names automatically
    release_remove(page, "tooling-test-example-0.1+draft")
    release_remove(page, "tooling-test-example-0.1+candidate")
    release_remove(page, "tooling-test-example-0.1+preview")
    release_remove(page, "tooling-test-example-0.1+release")
    release_remove(page, "tooling-test-example-0.2")


def wait_for_path(page: sync_api.Page, path: str) -> None:
    page.wait_for_load_state()
    parsed_url = urllib.parse.urlparse(page.url)
    if parsed_url.path != path:
        logging.error(f"Expected URL path '{path}', but got '{parsed_url.path}'")
        logging.error(f"Page content:\\n{page.content()}")
        raise RuntimeError(f"Expected URL path '{path}', but got '{parsed_url.path}'")
    logging.info(f"Current URL: {page.url}")


if __name__ == "__main__":
    main()
