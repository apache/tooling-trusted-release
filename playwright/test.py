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
import urllib.parse
from collections.abc import Callable
from typing import Any, Final

import netifaces
import rich.logging

import playwright.sync_api as sync_api

_SSH_KEY_COMMENT: Final[str] = "atr-playwright-test@127.0.0.1"
_SSH_KEY_PATH: Final[str] = "/root/.ssh/id_ed25519"


@dataclasses.dataclass
class Credentials:
    username: str
    password: str


# If we did this then we'd have to call e.g. test.page, which is verbose
# @dataclasses.dataclass
# class TestArguments:
#     page: sync_api.Page
#     credentials: Credentials


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
    run_tests(args.skip_slow)


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


def run_tests(skip_slow: bool) -> None:
    if (credentials := get_credentials()) is None:
        logging.error("Cannot run tests: no credentials provided")
        return

    with sync_api.sync_playwright() as p:
        browser = None
        context = None
        try:
            browser = p.chromium.launch()
            context = browser.new_context(ignore_https_errors=True)
            run_tests_in_context(context, credentials, skip_slow)

        except Exception as e:
            logging.error(f"Error during page interaction: {e}", exc_info=True)
        finally:
            if context:
                context.close()
            if browser:
                browser.close()


def run_tests_in_context(context: sync_api.BrowserContext, credentials: Credentials, skip_slow: bool) -> None:
    ssh_keys_generate()
    page = context.new_page()
    test_all(page, credentials, skip_slow)
    logging.info("Tests finished successfully")


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
        test_lifecycle_04_promote_to_candidate,
        test_lifecycle_05_vote_on_candidate,
        test_lifecycle_06_resolve_vote,
        test_lifecycle_07_promote_preview,
        test_lifecycle_08_release_exists,
    ]
    tests["ssh"] = [
        test_ssh_01_add_key,
        test_ssh_02_rsync_upload,
    ]

    # Order between our tests must be preserved
    # Insertion order is reliable since Python 3.6
    # Therefore iteration over tests matches the insertion order above
    for key in tests:
        run_tests_skipping_slow(tests[key], page, credentials, skip_slow)


def test_lifecycle_01_add_draft(page: sync_api.Page, credentials: Credentials) -> None:
    logging.info("Following link to add draft")
    add_draft_link_locator = page.get_by_role("link", name="Add draft")
    sync_api.expect(add_draft_link_locator).to_be_visible()
    add_draft_link_locator.click()

    logging.info("Waiting for the add draft page")
    project_select_locator = page.locator('select[name="project_name"]')
    sync_api.expect(project_select_locator).to_be_visible()
    logging.info("Add draft page loaded")

    logging.info("Selecting project 'tooling-test-example'")
    project_select_locator.select_option(label="Apache Tooling Test Example")

    logging.info("Filling version '0.1'")
    page.locator('input[name="version_name"]').fill("0.1")

    logging.info("Submitting the add draft form")
    submit_button_locator = page.locator('input[type="submit"][value="Create candidate draft"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info("Waiting for navigation to /drafts after adding draft")
    wait_for_path(page, "/drafts")
    logging.info("Add draft actions completed successfully")


def test_lifecycle_02_check_draft_added(page: sync_api.Page, credentials: Credentials) -> None:
    logging.info("Checking for draft 'tooling-test-example-0.1'")
    draft_card_locator = page.locator(r"#tooling-test-example-0\.1")
    sync_api.expect(draft_card_locator).to_be_visible()
    logging.info("Draft 'tooling-test-example-0.1' found successfully")


def test_lifecycle_03_add_file(page: sync_api.Page, credentials: Credentials) -> None:
    logging.info("Navigating to the add file page for tooling-test-example-0.1")
    go_to_path(page, "/draft/add/tooling-test-example/0.1")
    logging.info("Add file page loaded")

    logging.info("Locating the file input")
    file_input_locator = page.locator('input[name="file_data"]')
    sync_api.expect(file_input_locator).to_be_visible()

    logging.info("Setting the input file to /run/tests/example.txt")
    file_input_locator.set_input_files("/run/tests/example.txt")

    logging.info("Locating and activating the add files button")
    submit_button_locator = page.locator('input[type="submit"][value="Add files"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info("Waiting for navigation to /draft/evaluate/tooling-test-example/0.1 after adding file")
    wait_for_path(page, "/draft/evaluate/tooling-test-example/0.1")
    logging.info("Add file actions completed successfully")

    logging.info("Navigating back to /drafts")
    go_to_path(page, "/drafts")
    logging.info("Navigation back to /drafts completed successfully")


def test_lifecycle_04_promote_to_candidate(page: sync_api.Page, credentials: Credentials) -> None:
    logging.info("Locating draft promotion link for tooling-test-example-0.1")
    draft_card_locator = page.locator(r"#tooling-test-example-0\.1")
    promote_link_locator = draft_card_locator.locator('a[title="Promote draft for Apache Tooling Test Example 0.1"]')
    sync_api.expect(promote_link_locator).to_be_visible()

    logging.info("Follow the draft promotion link")
    promote_link_locator.click()

    logging.info("Waiting for page load after following the promote link")
    page.wait_for_load_state()
    logging.info("Page loaded after following the promote link")
    logging.info(f"Current URL: {page.url}")

    logging.info("Locating the promotion form for tooling-test-example-0.1")
    form_locator = page.locator('form:has(input[name="candidate_draft_name"][value="tooling-test-example-0.1"])')
    sync_api.expect(form_locator).to_be_visible()

    logging.info("Locating the confirmation checkbox within the form")
    checkbox_locator = form_locator.locator('input[name="confirm_promote"]')
    sync_api.expect(checkbox_locator).to_be_visible()

    logging.info("Checking the confirmation checkbox")
    checkbox_locator.check()

    logging.info("Locating and activating the promote button within the form")
    submit_button_locator = form_locator.get_by_role("button", name="Promote candidate draft")
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info("Waiting for navigation to /candidate/vote after submitting promotion")
    wait_for_path(page, "/candidate/vote")
    logging.info("Promote draft actions completed successfully")


def test_lifecycle_05_vote_on_candidate(page: sync_api.Page, credentials: Credentials) -> None:
    logging.info("Locating the link to start a vote for tooling-test-example-0.1")
    card_locator = page.locator('div.card:has(input[name="candidate_name"][value="tooling-test-example-0.1"])')
    start_vote_link_locator = card_locator.locator('a[title="Start vote for Apache Tooling Test Example 0.1"]')
    sync_api.expect(start_vote_link_locator).to_be_visible()

    logging.info("Following the link to start the vote")
    start_vote_link_locator.click()

    logging.info("Waiting for navigation to /candidate/vote/tooling-test-example/0.1")
    wait_for_path(page, "/candidate/vote/tooling-test-example/0.1")
    logging.info("Vote start page loaded successfully")

    logging.info("Locating and activating the button to prepare the vote email")
    submit_button_locator = page.locator('input[type="submit"][value="Prepare vote email"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info("Waiting for navigation to /candidate/resolve after submitting vote email")
    wait_for_path(page, "/candidate/resolve")
    logging.info("Vote initiation actions completed successfully")


def test_lifecycle_06_resolve_vote(page: sync_api.Page, credentials: Credentials) -> None:
    logging.info("Locating the form to resolve the vote for tooling-test-example-0.1")
    form_locator = page.locator('form:has(input[name="candidate_name"][value="tooling-test-example-0.1"])')
    sync_api.expect(form_locator).to_be_visible()

    logging.info("Locating and selecting the 'Passed' radio button")
    passed_radio_locator = form_locator.locator('input[name="vote_result"][value="passed"]')
    sync_api.expect(passed_radio_locator).to_be_enabled()
    passed_radio_locator.check()

    logging.info("Locating and activating the button to resolve the vote")
    submit_button_locator = form_locator.locator('input[type="submit"][value="Resolve vote"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info("Waiting for navigation to /previews after resolving the vote")
    wait_for_path(page, "/previews")
    logging.info("Vote resolution actions completed successfully")


def test_lifecycle_07_promote_preview(page: sync_api.Page, credentials: Credentials) -> None:
    logging.info("Locating the link to promote the preview for tooling-test-example-0.1")
    promote_link_locator = page.locator('a[title="Promote Apache Tooling Test Example 0.1 to release"]')
    sync_api.expect(promote_link_locator).to_be_visible()

    logging.info("Following the link to promote the preview")
    promote_link_locator.click()

    logging.info("Waiting for navigation to /preview/promote")
    wait_for_path(page, "/preview/promote")
    logging.info("Promote preview navigation completed successfully")

    logging.info("Locating the promotion form for tooling-test-example-0.1")
    form_locator = page.locator(r'#tooling-test-example-0\.1 form[action="/preview/promote"]')
    sync_api.expect(form_locator).to_be_visible()

    logging.info("Locating the confirmation checkbox within the form")
    checkbox_locator = form_locator.locator('input[name="confirm_promote"]')
    sync_api.expect(checkbox_locator).to_be_visible()

    logging.info("Checking the confirmation checkbox")
    checkbox_locator.check()

    logging.info("Locating and activating the promote button within the form")
    submit_button_locator = form_locator.get_by_role("button", name="Promote to release")
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info("Waiting for navigation to /releases after submitting promotion")
    wait_for_path(page, "/releases")
    logging.info("Preview promotion actions completed successfully")


def test_lifecycle_08_release_exists(page: sync_api.Page, credentials: Credentials) -> None:
    logging.info("Checking for release tooling-test-example-0.1 on the /releases page")

    release_card_locator = page.locator('div.card:has(h3:has-text("Apache Tooling Test Example 0.1"))')
    sync_api.expect(release_card_locator).to_be_visible()
    logging.info("Found card for tooling-test-example-0.1 release")
    logging.info("Release tooling-test-example-0.1 confirmed exists on /releases page")

    logging.info("Locating the announcement marking button for tooling-test-example-0.1")
    mark_announced_button_locator = page.locator('button[title="Mark Apache Tooling Test Example 0.1 as announced"]')
    sync_api.expect(mark_announced_button_locator).to_be_visible()

    logging.info("Activating the button to mark the release as announced")
    mark_announced_button_locator.click()

    logging.info("Waiting for navigation back to /releases after marking as announced")
    wait_for_path(page, "/releases")
    logging.info("Navigation back to /releases completed successfully")

    logging.info("Verifying release tooling-test-example-0.1 phase is now RELEASE_AFTER_ANNOUNCEMENT")
    release_card_locator = page.locator('div.card:has(h3:has-text("Apache Tooling Test Example 0.1"))')
    sync_api.expect(release_card_locator).to_be_visible()
    phase_locator = release_card_locator.locator('span.release-meta-item:has-text("Phase: RELEASE_AFTER_ANNOUNCEMENT")')
    sync_api.expect(phase_locator).to_be_visible()
    logging.info("Phase confirmed as RELEASE_AFTER_ANNOUNCEMENT")


def test_login(page: sync_api.Page, credentials: Credentials) -> None:
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
    project_name = "Apache Tooling Test Example"
    project_label = "tooling-test-example"
    base_project_option_label = "Apache Tooling"
    derived_project_input_value = "Test Example"

    logging.info("Navigating to the add derived project page")
    go_to_path(page, "/project/add")
    logging.info("Add derived project page loaded")

    logging.info(f"Selecting base project '{base_project_option_label}'")
    page.locator('select[name="project_name"]').select_option(label=base_project_option_label)

    logging.info(f"Filling derived project name '{derived_project_input_value}'")
    page.locator('input[name="derived_project_name"]').fill(derived_project_input_value)

    logging.info("Submitting the add derived project form")
    submit_button_locator = page.locator('input[type="submit"][value="Add derived project"]')
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
    go_to_path(page, "/")

    logging.info("Navigating to Your Public Keys page")
    page.locator('a[href="/keys"]:has-text("Your public keys")').click()
    wait_for_path(page, "/keys")
    logging.info("Navigated to Your Public Keys page")

    logging.info("Clicking Add an SSH key button")
    page.locator('a[href="/keys/ssh/add"]:has-text("Add an SSH key")').click()
    wait_for_path(page, "/keys/ssh/add")
    logging.info("Navigated to Add SSH Key page")

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

    logging.info(f"Navigating to evaluate page for {project_name}-{version_name}")
    evaluate_path = f"/draft/evaluate/{project_name}/{version_name}"
    go_to_path(page, evaluate_path)
    logging.info(f"Checking for uploaded files on {evaluate_path}")

    # Check for the existence of the files in the table using exact match
    file1_locator = page.get_by_role("cell", name=file1, exact=True)
    file2_locator = page.get_by_role("cell", name=file2, exact=True)

    sync_api.expect(file1_locator).to_be_visible()
    logging.info(f"Found file: {file1}")
    sync_api.expect(file2_locator).to_be_visible()
    logging.info(f"Found file: {file2}")
    logging.info("rsync upload test completed successfully")


def test_tidy_up(page: sync_api.Page) -> None:
    # Projects cannot be deleted if they have associated releases
    # Therefore, we need to delete releases first
    test_tidy_up_releases(page)
    test_tidy_up_project(page)
    test_tidy_up_ssh_keys(page)


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

    ssh_key_section_locator = page.locator("h2:has-text('SSH keys')")
    key_cards_locator = ssh_key_section_locator.locator("xpath=following-sibling::div//div[contains(@class, 'card')]")

    key_cards = key_cards_locator.all()
    logging.info(f"Found {len(key_cards)} potential SSH key cards to check")

    fingerprints_to_delete = []

    # Identify keys with the test comment
    for card in key_cards:
        # Ensure that the details section is open by clicking the summary
        # TODO: We should consider always displaying the key content instead
        summary_locator = card.locator("details > summary")
        # Check that summary exists before clicking
        if summary_locator.is_visible():
            # Open the details
            summary_locator.click()
        else:
            logging.warning("Could not find summary element in key card, skipping")
            continue

        # Check the content of the pre element
        details_locator = card.locator("details > pre")
        # Even after clicking summary, wait for visibility just in case
        sync_api.expect(details_locator).to_be_visible(timeout=1000)

        if details_locator.is_visible():
            key_content = details_locator.inner_text()
            if _SSH_KEY_COMMENT in key_content:
                fingerprint_locator = card.locator('td:has-text("SHA256:")')
                fingerprint = fingerprint_locator.inner_text()
                if fingerprint:
                    logging.info(f"Found test SSH key with fingerprint {fingerprint} for deletion")
                    fingerprints_to_delete.append(fingerprint)
                else:
                    logging.warning("Found test key card but could not extract fingerprint")
        else:
            logging.warning("Key details <pre> not visible even after clicking summary")

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

    release_remove(page, "tooling-test-example-0.1")
    release_remove(page, "tooling-test-example-0.2")


def wait_for_path(page: sync_api.Page, path: str) -> None:
    page.wait_for_load_state()
    parsed_url = urllib.parse.urlparse(page.url)
    if parsed_url.path != path:
        logging.error(f"Expected URL path '{path}', but got '{parsed_url.path}'")
        raise RuntimeError(f"Expected URL path '{path}', but got '{parsed_url.path}'")
    logging.info(f"Current URL: {page.url}")


if __name__ == "__main__":
    main()
