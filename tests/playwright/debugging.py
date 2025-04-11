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

import getpass
import socket

import netifaces
import playwright.sync_api as sync_api


def get_default_gateway_ip() -> str | None:
    gateways = netifaces.gateways()
    match gateways.get("default", {}).get(socket.AF_INET):
        case (ip_address, _):
            return ip_address
        case _:
            return None


def show_default_gateway_ip() -> None:
    match get_default_gateway_ip():
        case str(ip_address):
            print(f"Default gateway IP: {ip_address}")
        case None:
            print("Could not determine gateway IP")


def login_and_check(ip_address: str | None) -> None:
    if ip_address is None:
        print("Cannot login: no IP address provided")
        return

    username = input("Enter ASF Username: ")
    password = getpass.getpass("Enter ASF Password: ")

    if (not username) or (not password):
        print("Error: Username and password cannot be empty")
        return

    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        try:
            start_url = f"https://{ip_address}:8080/"
            print(f"Navigating to {start_url}")
            page.goto(start_url)
            print("Initial page title:", page.title())

            print("Following link to log in")
            login_link_locator = page.get_by_role("link", name="Login")
            sync_api.expect(login_link_locator).to_be_visible()
            login_link_locator.click()

            print("Waiting for the login page")
            username_field_locator = page.locator('input[name="username"]')
            sync_api.expect(username_field_locator).to_be_visible()
            print("Login page loaded")

            print("Filling credentials")
            username_field_locator.fill(username)
            page.locator('input[name="password"]').fill(password)

            print("Submitting the login form")
            submit_button_locator = page.locator('input[type="submit"][value="Authenticate"]')
            sync_api.expect(submit_button_locator).to_be_enabled()
            submit_button_locator.click()

            print("Waiting for the page to load")
            page.wait_for_load_state()
            print("Page loaded after login")
            print("Initial URL after login:", page.url)

            print("Waiting for the redirect to /")
            page.wait_for_url("https://*/")
            print("Redirected to / ")
            print("Page URL:", page.url)
            print("Okay!")

        except Exception as e:
            print(f"Error during page interaction: {e}")
        finally:
            context.close()
            browser.close()


if __name__ == "__main__":
    show_default_gateway_ip()
    gateway_ip = get_default_gateway_ip()
    if gateway_ip:
        login_and_check(gateway_ip)
