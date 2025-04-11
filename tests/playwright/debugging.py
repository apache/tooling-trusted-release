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

import netifaces
import playwright.sync_api as sync_api
import rich.logging


@dataclasses.dataclass
class Credentials:
    username: str
    password: str


def add_draft(page: sync_api.Page) -> None:
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

    logging.info("Waiting for page load after adding draft")
    page.wait_for_load_state()
    logging.info("Page loaded after add draft submission")
    logging.info(f"Current URL: {page.url}")
    logging.info("Add draft actions completed successfully")


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
    match gateways.get("default", {}).get(socket.AF_INET):
        case (ip_address, _):
            return ip_address
        case _:
            return None


def perform_login(page: sync_api.Page, start_url: str, credentials: Credentials) -> None:
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

    show_default_gateway_ip()
    gateway_ip = get_default_gateway_ip()
    if gateway_ip:
        run_tests(gateway_ip)


def run_tests(ip_address: str | None) -> None:
    if ip_address is None:
        logging.error("Cannot run tests: no site IP address provided")
        return

    if (credentials := get_credentials()) is None:
        logging.error("Cannot run tests: no credentials provided")
        return

    with sync_api.sync_playwright() as p:
        browser = None
        context = None
        try:
            browser = p.chromium.launch()
            context = browser.new_context(ignore_https_errors=True)
            run_tests_in_context(context, ip_address, credentials)

        except Exception as e:
            logging.error(f"Error during page interaction: {e}", exc_info=True)
        finally:
            if context:
                context.close()
            if browser:
                browser.close()


def run_tests_in_context(context: sync_api.BrowserContext, ip_address: str, credentials: Credentials) -> None:
    page = context.new_page()
    start_url = f"https://{ip_address}:8080/"
    # Tests go here
    perform_login(page, start_url, credentials)
    add_draft(page)
    logging.info("Tests finished successfully")


def show_default_gateway_ip() -> None:
    match get_default_gateway_ip():
        case str(ip_address):
            logging.info(f"Default gateway IP: {ip_address}")
        case None:
            logging.warning("Could not determine gateway IP")


if __name__ == "__main__":
    main()
