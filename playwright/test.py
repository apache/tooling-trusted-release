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

import netifaces
import rich.logging

import playwright.sync_api as sync_api


@dataclasses.dataclass
class Credentials:
    username: str
    password: str


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
    run_tests()


def run_tests() -> None:
    if (credentials := get_credentials()) is None:
        logging.error("Cannot run tests: no credentials provided")
        return

    with sync_api.sync_playwright() as p:
        browser = None
        context = None
        try:
            browser = p.chromium.launch()
            context = browser.new_context(ignore_https_errors=True)
            run_tests_in_context(context, credentials)

        except Exception as e:
            logging.error(f"Error during page interaction: {e}", exc_info=True)
        finally:
            if context:
                context.close()
            if browser:
                browser.close()


def run_tests_in_context(context: sync_api.BrowserContext, credentials: Credentials) -> None:
    ssh_keys_generate()
    page = context.new_page()
    test_all(page, credentials)
    logging.info("Tests finished successfully")


def show_default_gateway_ip() -> None:
    match get_default_gateway_ip():
        case str(ip_address):
            logging.info(f"Default gateway IP: {ip_address}")
        case None:
            logging.warning("Could not determine gateway IP")


def ssh_keys_generate() -> None:
    ssh_key_path = "/root/.ssh/id_ed25519"
    ssh_dir = os.path.dirname(ssh_key_path)

    try:
        if os.path.exists(ssh_key_path):
            os.remove(ssh_key_path)
            logging.info(f"Removed existing SSH key at {ssh_key_path}")
        if os.path.exists(f"{ssh_key_path}.pub"):
            os.remove(f"{ssh_key_path}.pub")
            logging.info(f"Removed existing SSH public key at {ssh_key_path}.pub")

        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

        logging.info(f"Generating new SSH key at {ssh_key_path}")
        result = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", ssh_key_path, "-N", ""],
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

    if result.returncode != 0:
        logging.error(f"ssh-keygen returned {result.returncode}")
        logging.error(f"ssh-keygen stdout: {result.stdout}")
        logging.error(f"ssh-keygen stderr: {result.stderr}")
        raise RuntimeError("SSH key generation failed")


def test_all(page: sync_api.Page, credentials: Credentials) -> None:
    test_login(page, credentials)
    test_tidy_up(page)
    test_lifecycle(page)
    test_projects(page)


def test_lifecycle(page: sync_api.Page) -> None:
    test_lifecycle_01_add_draft(page)
    test_lifecycle_02_check_draft_added(page)
    test_lifecycle_03_add_file(page)
    test_lifecycle_04_promote_to_candidate(page)
    test_lifecycle_05_vote_on_candidate(page)
    test_lifecycle_06_resolve_vote(page)
    test_lifecycle_07_promote_preview(page)
    test_lifecycle_08_release_exists(page)


def test_lifecycle_01_add_draft(page: sync_api.Page) -> None:
    logging.info("Following link to add draft")
    add_draft_link_locator = page.get_by_role("link", name="Add draft")
    sync_api.expect(add_draft_link_locator).to_be_visible()
    add_draft_link_locator.click()

    logging.info("Waiting for the add draft page")
    project_select_locator = page.locator('select[name="project_name"]')
    sync_api.expect(project_select_locator).to_be_visible()
    logging.info("Add draft page loaded")

    logging.info("Selecting project 'tooling'")
    project_select_locator.select_option(label="Apache Tooling")

    logging.info("Filling version '0.1'")
    page.locator('input[name="version_name"]').fill("0.1")

    logging.info("Submitting the add draft form")
    submit_button_locator = page.locator('input[type="submit"][value="Create candidate draft"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info("Waiting for navigation to /drafts after adding draft")
    wait_for_path(page, "/drafts")
    logging.info("Add draft actions completed successfully")


def test_lifecycle_02_check_draft_added(page: sync_api.Page) -> None:
    logging.info("Checking for draft 'tooling-0.1'")
    draft_card_locator = page.locator(r"#tooling-0\.1")
    sync_api.expect(draft_card_locator).to_be_visible()
    logging.info("Draft 'tooling-0.1' found successfully")


def test_lifecycle_03_add_file(page: sync_api.Page) -> None:
    logging.info("Navigating to the add file page for tooling-0.1")
    go_to_path(page, "/draft/add/tooling/0.1")
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

    logging.info("Waiting for navigation to /draft/evaluate/tooling/0.1 after adding file")
    wait_for_path(page, "/draft/evaluate/tooling/0.1")
    logging.info("Add file actions completed successfully")

    logging.info("Navigating back to /drafts")
    go_to_path(page, "/drafts")
    logging.info("Navigation back to /drafts completed successfully")


def test_lifecycle_04_promote_to_candidate(page: sync_api.Page) -> None:
    logging.info("Locating draft promotion link for tooling-0.1")
    draft_card_locator = page.locator(r"#tooling-0\.1")
    promote_link_locator = draft_card_locator.locator('a[title="Promote draft for Apache Tooling 0.1"]')
    sync_api.expect(promote_link_locator).to_be_visible()

    logging.info("Follow the draft promotion link")
    promote_link_locator.click()

    logging.info("Waiting for page load after following the promote link")
    page.wait_for_load_state()
    logging.info("Page loaded after following the promote link")
    logging.info(f"Current URL: {page.url}")

    logging.info("Locating the promotion form for tooling-0.1")
    form_locator = page.locator('form:has(input[name="candidate_draft_name"][value="tooling-0.1"])')
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


def test_lifecycle_05_vote_on_candidate(page: sync_api.Page) -> None:
    logging.info("Locating the link to start a vote for tooling-0.1")
    card_locator = page.locator('div.card:has(input[name="candidate_name"][value="tooling-0.1"])')
    start_vote_link_locator = card_locator.locator('a[title="Start vote for Apache Tooling 0.1"]')
    sync_api.expect(start_vote_link_locator).to_be_visible()

    logging.info("Following the link to start the vote")
    start_vote_link_locator.click()

    logging.info("Waiting for navigation to /candidate/vote/tooling/0.1")
    wait_for_path(page, "/candidate/vote/tooling/0.1")
    logging.info("Vote start page loaded successfully")

    logging.info("Locating and activating the button to prepare the vote email")
    submit_button_locator = page.locator('input[type="submit"][value="Prepare vote email"]')
    sync_api.expect(submit_button_locator).to_be_enabled()
    submit_button_locator.click()

    logging.info("Waiting for navigation to /candidate/resolve after submitting vote email")
    wait_for_path(page, "/candidate/resolve")
    logging.info("Vote initiation actions completed successfully")


def test_lifecycle_06_resolve_vote(page: sync_api.Page) -> None:
    logging.info("Locating the form to resolve the vote for tooling-0.1")
    form_locator = page.locator('form:has(input[name="candidate_name"][value="tooling-0.1"])')
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


def test_lifecycle_07_promote_preview(page: sync_api.Page) -> None:
    logging.info("Locating the link to promote the preview for tooling-0.1")
    promote_link_locator = page.locator('a[title="Promote Apache Tooling 0.1 to release"]')
    sync_api.expect(promote_link_locator).to_be_visible()

    logging.info("Following the link to promote the preview")
    promote_link_locator.click()

    logging.info("Waiting for navigation to /preview/promote")
    wait_for_path(page, "/preview/promote")
    logging.info("Promote preview navigation completed successfully")

    logging.info("Locating the promotion form for tooling-0.1")
    form_locator = page.locator(r'#tooling-0\.1 form[action="/preview/promote"]')
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


def test_lifecycle_08_release_exists(page: sync_api.Page) -> None:
    logging.info("Checking for release tooling-0.1 on the /releases page")

    release_card_locator = page.locator('div.card:has(h3:has-text("Apache Tooling 0.1"))')
    sync_api.expect(release_card_locator).to_be_visible()
    logging.info("Found card for tooling-0.1 release")
    logging.info("Release tooling-0.1 confirmed exists on /releases page")

    logging.info("Locating the announcement marking button for tooling-0.1")
    mark_announced_button_locator = page.locator('button[title="Mark Apache Tooling 0.1 as announced"]')
    sync_api.expect(mark_announced_button_locator).to_be_visible()

    logging.info("Activating the button to mark the release as announced")
    mark_announced_button_locator.click()

    logging.info("Waiting for navigation back to /releases after marking as announced")
    wait_for_path(page, "/releases")
    logging.info("Navigation back to /releases completed successfully")

    logging.info("Verifying release tooling-0.1 phase is now RELEASE_AFTER_ANNOUNCEMENT")
    release_card_locator = page.locator('div.card:has(h3:has-text("Apache Tooling 0.1"))')
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


def test_projects(page: sync_api.Page) -> None:
    test_projects_01_update(page)
    test_projects_02_check_directory(page)
    test_projects_03_add_project(page)


def test_projects_01_update(page: sync_api.Page) -> None:
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


def test_projects_02_check_directory(page: sync_api.Page) -> None:
    logging.info("Navigating to the project directory page")
    go_to_path(page, "/projects")
    logging.info("Project directory page loaded")

    logging.info("Checking for the Apache Tooling project card")
    h3_locator = page.get_by_text("Apache Tooling", exact=True)
    tooling_card_locator = h3_locator.locator("xpath=ancestor::div[contains(@class, 'project-card')]")
    sync_api.expect(tooling_card_locator).to_be_visible()
    logging.info("Apache Tooling project card found successfully")


def test_projects_03_add_project(page: sync_api.Page) -> None:
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


def test_tidy_up(page: sync_api.Page) -> None:
    test_tidy_up_release(page)
    test_tidy_up_project(page)


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


def test_tidy_up_release(page: sync_api.Page) -> None:
    logging.info("Navigating to the admin delete release page")
    go_to_path(page, "/admin/delete-release")
    logging.info("Admin delete release page loaded")

    logging.info("Checking whether the tooling-0.1 release exists")
    release_checkbox_locator = page.locator('input[name="releases_to_delete"][value="tooling-0.1"]')

    if release_checkbox_locator.is_visible():
        logging.info("Found the tooling-0.1 release, proceeding with deletion")
        logging.info("Selecting tooling-0.1 for deletion")
        release_checkbox_locator.check()

        logging.info("Filling deletion confirmation")
        page.locator("#confirm_delete").fill("DELETE")

        logging.info("Submitting deletion form")
        submit_button_locator = page.locator('input[type="submit"][value="Delete selected releases permanently"]')
        sync_api.expect(submit_button_locator).to_be_enabled()
        submit_button_locator.click()

        logging.info("Waiting for page load after deletion submission")
        page.wait_for_load_state()
        logging.info("Page loaded after deletion")

        logging.info("Checking for success flash message")
        flash_message_locator = page.locator("div.flash-success")
        sync_api.expect(flash_message_locator).to_be_visible()
        sync_api.expect(flash_message_locator).to_contain_text("Successfully deleted 1 release(s)")
        logging.info("Deletion successful")
    else:
        logging.info("Could not find the tooling-0.1 release, no deletion needed")


def wait_for_path(page: sync_api.Page, path: str) -> None:
    page.wait_for_load_state()
    parsed_url = urllib.parse.urlparse(page.url)
    if parsed_url.path != path:
        logging.error(f"Expected URL path '{path}', but got '{parsed_url.path}'")
        raise RuntimeError(f"Expected URL path '{path}', but got '{parsed_url.path}'")
    logging.info(f"Current URL: {page.url}")


if __name__ == "__main__":
    main()
