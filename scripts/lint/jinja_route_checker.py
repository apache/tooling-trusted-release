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

"""Script to check whether routes used in Jinja2 templates with as_url() actually exist."""

import argparse
import glob
import json
import os
import re
import sys
from typing import Final

_AS_URL_PATTERN: Final = re.compile(r"as_url\(routes\.([a-zA-Z0-9_.]+)")


class JinjaRouteChecker:
    """Check whether routes used in Jinja2 templates actually exist."""

    def __init__(self) -> None:
        self.available_routes: set[str] = set()
        self.errors: list[tuple[str, str, int]] = []

    def find_project_root(self) -> str:
        """Find the project root directory."""
        # Assume we're in a subdirectory somewhere
        current_dir = os.path.dirname(os.path.abspath(__file__))
        while current_dir != "/":
            if os.path.exists(os.path.join(current_dir, "atr")):
                return current_dir
            current_dir = os.path.dirname(current_dir)
        raise RuntimeError("Could not find project root")

    def collect_available_routes(self) -> None:
        """Collect all available routes from the routes.json file."""
        project_root = self.find_project_root()
        routes_file = os.path.join(project_root, "state", "routes.json")

        if not os.path.exists(routes_file):
            print(f"Note: routes file not found at {routes_file}", file=sys.stderr)
            print("Run the application at least once locally to generate the routes file", file=sys.stderr)

            # Raise no error, to avoid making this script mandatory
            sys.exit()

        with open(routes_file, encoding="utf-8") as f:
            route_paths = json.load(f)
        self.available_routes = set(route_paths)

    def check_template_routes(self, template_file: str) -> None:
        """Check whether routes used in a template exist."""
        rel_path = os.path.relpath(template_file, self.find_project_root())

        try:
            with open(template_file, encoding="utf-8") as f:
                content = f.read()

            # Find all as_url calls with routes
            for match in _AS_URL_PATTERN.finditer(content):
                route_path = match.group(1)
                if route_path not in self.available_routes:
                    # Get approximate line number
                    line_number = content[: match.start()].count("\n") + 1
                    self.errors.append((route_path, rel_path, line_number))
        except Exception as e:
            print(f"Error checking {template_file}: {e}", file=sys.stderr)
            sys.exit(1)

    def check_all_templates(self) -> None:
        """Check all Jinja2 templates for route usage."""
        project_root = self.find_project_root()

        # Find all Jinja2 templates
        template_dir = os.path.join(project_root, "atr", "templates")
        if not os.path.exists(template_dir):
            raise RuntimeError(f"Template directory not found at {template_dir}")

        template_files = glob.glob(os.path.join(template_dir, "**", "*.html"), recursive=True)
        for template_file in template_files:
            self.check_template_routes(template_file)

    def report_errors(self) -> None:
        """Report all errors found."""
        if not self.errors:
            print("No errors found")
            return

        for route_path, template_file, line_number in self.errors:
            print(f"{template_file}:{line_number}: Route '{route_path}' does not exist")
        print(f"\nTotal errors: {len(self.errors)}")


def main() -> None:
    """Run the checker."""
    parser = argparse.ArgumentParser(description="Check whether routes used in Jinja2 templates exist")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show verbose output")
    args = parser.parse_args()

    checker = JinjaRouteChecker()
    checker.collect_available_routes()

    if args.verbose:
        print(f"Found {len(checker.available_routes)} available routes")
        for route in sorted(checker.available_routes):
            print(f"  - {route}")

    checker.check_all_templates()
    checker.report_errors()

    if checker.errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
