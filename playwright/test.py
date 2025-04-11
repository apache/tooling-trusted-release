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
import socket
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


def main() -> None:
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
    page = context.new_page()
    test_all(page, credentials)
    logging.info("Tests finished successfully")


def show_default_gateway_ip() -> None:
    match get_default_gateway_ip():
        case str(ip_address):
            logging.info(f"Default gateway IP: {ip_address}")
        case None:
            logging.warning("Could not determine gateway IP")


def test_all(page: sync_api.Page, credentials: Credentials) -> None:
    test_login(page, credentials)
    test_tidy_up(page)
    test_lifecycle(page)


def test_lifecycle(page: sync_api.Page) -> None:
    test_lifecycle_01_add_draft(page)
    test_lifecycle_02_check_draft_added(page)
    test_lifecycle_03_promote_to_candidate(page)
    test_lifecycle_04_vote_on_candidate(page)
    test_lifecycle_05_resolve_vote(page)


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


def test_lifecycle_03_promote_to_candidate(page: sync_api.Page) -> None:
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


def test_lifecycle_04_vote_on_candidate(page: sync_api.Page) -> None:
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


def test_lifecycle_05_resolve_vote(page: sync_api.Page) -> None:
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


def test_login(page: sync_api.Page, credentials: Credentials) -> None:
    gateway_ip = get_default_gateway_ip()
    if gateway_ip is None:
        logging.error("Could not determine gateway IP")
        raise RuntimeError("Could not determine gateway IP")

    start_url = f"https://{gateway_ip}:8080/"
    logging.info(f"Navigating to {start_url}")
    page.goto(start_url)
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
    page.wait_for_url("https://*/")
    logging.info("Redirected to /")
    logging.info(f"Page URL: {page.url}")
    logging.info("Login actions completed successfully")


def test_tidy_up(page: sync_api.Page) -> None:
    logging.info("Navigating to the admin delete release page")
    gateway_ip = get_default_gateway_ip()
    if gateway_ip is None:
        logging.error("Could not determine gateway IP for tidy up")
        raise RuntimeError("Could not determine gateway IP for tidy up")
    delete_url = f"https://{gateway_ip}:8080/admin/delete-release"
    page.goto(delete_url)
    wait_for_path(page, "/admin/delete-release")
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
