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

KNOWN_PURL_PREFIXES: Final[dict[str, tuple[str, str]]] = {
    "pkg:maven/com.atlassian.": ("Atlassian", "https://www.atlassian.com/"),
    "pkg:maven/concurrent/concurrent@": (
        "Dough Lea",
        "http://gee.cs.oswego.edu/dl/classes/EDU/oswego/cs/dl/util/concurrent/intro.html",
    ),
    "pkg:maven/net.shibboleth.": ("The Shibboleth Consortium", "https://www.shibboleth.net/"),
}

KNOWN_PURL_SUPPLIERS: Final[dict[tuple[str, str], tuple[str, str]]] = {
    ("pkg:maven", "jakarta-regexp"): ("The Apache Software Foundation", "https://apache.org/"),
    ("pkg:maven", "javax.servlet.jsp"): ("Sun Microsystems", "https://sun.com/"),
    ("pkg:maven", "org.opensaml"): ("The Shibboleth Consortium", "https://www.shibboleth.net/"),
    ("pkg:maven", "org.osgi"): ("OSGi Working Group, The Eclipse Foundation", "https://www.osgi.org/"),
}

THE_APACHE_SOFTWARE_FOUNDATION: Final[str] = "The Apache Software Foundation"
