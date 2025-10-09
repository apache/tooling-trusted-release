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

import json
import re
import sys
from html.parser import HTMLParser


class SPDXLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.category_a = set()
        self.category_b = set()
        self.category_x = set()

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            attrs_dict = dict(attrs)
            title = attrs_dict.get("title") or ""

            match = re.match(r"Category\s+([ABX]):\s+(.+)", title, re.IGNORECASE)
            if match:
                category = match.group(1).upper()
                spdx_identifiers = match.group(2).strip()

                for spdx_identifier in spdx_identifiers.split(","):
                    spdx_identifier = spdx_identifier.strip()

                    if category == "A":
                        self.category_a.add(spdx_identifier)
                    elif category == "B":
                        self.category_b.add(spdx_identifier)
                    elif category == "X":
                        self.category_x.add(spdx_identifier)


def main():
    if len(sys.argv) != 2:
        print("Usage: extract_spdx_identifiers.py <html_file>", file=sys.stderr)
        sys.exit(1)

    filename = sys.argv[1]

    try:
        with open(filename, encoding="utf-8") as f:
            html_content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    parser = SPDXLinkParser()
    parser.feed(html_content)

    result = {
        "CATEGORY_A_LICENSES": sorted(parser.category_a),
        "CATEGORY_B_LICENSES": sorted(parser.category_b),
        "CATEGORY_X_LICENSES": sorted(parser.category_x),
    }

    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()
