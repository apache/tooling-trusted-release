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

from __future__ import annotations

from typing import Final

LICENSES: Final[dict[str, list[str]]] = {
    "CATEGORY_A_LICENSES": [
        "0BSD",
        "AFL-3.0",
        "APAFML",
        "Apache-1.1",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSD-3-Clause-LBNL",
        "BSL-1.0",
        "Bitstream-Vera",
        "BlueOak-1.0.0",
        "CC-PDDC",
        "CC-PDM-1.0",
        "CC0-1.0",
        "DOC",
        "EPICS",
        "FSFAP",
        "HPND",
        "ICU",
        "ISC",
        "Libpng",
        "LicenseRef-COLT-CERN",
        "LicenseRef-CupPG",
        "LicenseRef-DOM4J",
        "LicenseRef-ECMA-OOXML-XSD",
        "LicenseRef-Google-AIPG",
        "LicenseRef-MX4J",
        "LicenseRef-Open-Grid-Forum",
        "LicenseRef-PIL",
        "LicenseRef-Romantic-WTFPL",
        "LicenseRef-SCA-Spec",
        "LicenseRef-W3C-CCLA",
        "MIT",
        "MIT-0",
        "MS-PL",
        "MulanPSL-2.0",
        "NCSA",
        "OGL-UK-3.0",
        "PHP-3.01",
        "PostgreSQL",
        "Python-2.0",
        "SMLNJ",
        "TCL",
        "UPL-1.0",
        "Unicode-DFS-2016",
        "Unlicense",
        "W3C",
        "WTFPL",
        "Xnet",
        "ZPL-2.0",
        "Zlib",
    ],
    "CATEGORY_B_LICENSES": [
        "CC-BY-2.5",
        "CC-BY-3.0",
        "CC-BY-4.0",
        "CC-BY-SA-2.5",
        "CC-BY-SA-3.0",
        "CC-BY-SA-4.0",
        "CDDL-1.0",
        "CDDL-1.1",
        "CPL-1.0",
        "EPL-1.0",
        "EPL-2.0",
        "ErlPL-1.1",
        "IPA",
        "IPL-1.0",
        "LicenseRef-CMaps-Fonts",
        "LicenseRef-JARs-Additional",
        "LicenseRef-JCR-API",
        "LicenseRef-UnRAR",
        "LicenseRef-WSDL-SFL",
        "MPL-1.0",
        "MPL-1.1",
        "MPL-2.0",
        "OFL-1.1",
        "OSL-3.0",
        "Ruby",
        "SPL-1.0",
        "Ubuntu-font-1.0",
    ],
    "CATEGORY_X_LICENSES": [
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "BSD-4-Clause",
        "BSD-4-Clause-UC",
        "BUSL-1.1",
        "CC-BY-NC-4.0",
        "CPOL-1.02",
        "GPL-1.0-only",
        "GPL-1.0-or-later",
        "GPL-2.0-only",
        "GPL-2.0-only WITH Classpath-exception-2.0",
        "GPL-2.0-or-later",
        "GPL-2.0-or-later WITH Classpath-exception-2.0",
        "GPL-3.0-only",
        "GPL-3.0-only WITH Classpath-exception-2.0",
        "GPL-3.0-or-later",
        "GPL-3.0-or-later WITH Classpath-exception-2.0",
        "JSON",
        "LGPL-2.0-only",
        "LGPL-2.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "LicenseRef-Amazon-Software-License",
        "LicenseRef-BCL",
        "LicenseRef-Booz-Allen-Public-License",
        "LicenseRef-Commons-Clause-1.0",
        "LicenseRef-Confluent-Community-1.0",
        "LicenseRef-DBAD",
        "LicenseRef-Facebook-BSD-Patents",
        "LicenseRef-Intel-SSL",
        "LicenseRef-JSR-275",
        "LicenseRef-Java-SDK-for-Satori-RTM",
        "LicenseRef-Redis-Source-Available",
        "LicenseRef-Solipsistic-Eclipse-Public-License",
        "LicenseRef-Sun-Community-Source-3.0",
        "MS-LPL",
        "NPL-1.0",
        "NPL-1.1",
        "QPL-1.0",
        "SSPL-1.0",
        "Sleepycat",
    ],
}

CATEGORY_A_LICENSES_FOLD: Final[frozenset[str]] = frozenset(
    value.casefold() for value in LICENSES["CATEGORY_A_LICENSES"]
)

CATEGORY_B_LICENSES_FOLD: Final[frozenset[str]] = frozenset(
    value.casefold() for value in LICENSES["CATEGORY_B_LICENSES"]
)

CATEGORY_X_LICENSES_FOLD: Final[frozenset[str]] = frozenset(
    value.casefold() for value in LICENSES["CATEGORY_X_LICENSES"]
)
