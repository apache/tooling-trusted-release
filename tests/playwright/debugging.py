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

import socket

import netifaces
from playwright.sync_api import sync_playwright


def get_default_gateway_ip() -> str | None:
    """Gets the default IPv4 gateway IP address."""
    gateways = netifaces.gateways()
    match gateways.get("default", {}).get(socket.AF_INET):
        case (ip_address, _):
            return ip_address
        case _:
            return None


def show_default_gateway_ip():
    match get_default_gateway_ip():
        case str(ip_address):
            print(f"Default gateway IP: {ip_address}")
        case None:
            print("Could not determine gateway IP")


def show_title(ip_address: str | None) -> None:
    if ip_address is None:
        print("Cannot show title: no IP address provided")
        return

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        try:
            page.goto(f"https://{ip_address}:8080/")
            print("Title:", page.title())

            links_locator = page.locator("a[href]")
            link_count = links_locator.count()
            print(f"Found {link_count} hyperlinks:")

            link_texts = links_locator.all_text_contents()
            for i, text in enumerate(link_texts):
                normalised_text = " ".join(text.split())
                if normalised_text:
                    print(f"  {i + 1}: {normalised_text}")

        except Exception as e:
            print(f"Error during page interaction: {e}")
        finally:
            context.close()
            browser.close()


if __name__ == "__main__":
    show_default_gateway_ip()
    gateway_ip = get_default_gateway_ip()
    if gateway_ip:
        show_title(gateway_ip)
