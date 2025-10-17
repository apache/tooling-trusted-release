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

import os
from typing import Any

import aiohttp

from . import models

_DEBUG: bool = os.environ.get("DEBUG_SBOM_TOOL") == "1"
_OSV_API_BASE: str = "https://api.osv.dev/v1"


async def scan_bundle(bundle: models.bundle.Bundle) -> tuple[list[models.osv.ComponentVulnerabilities], int]:
    components = bundle.bom.components or []
    queries, ignored_count = _scan_bundle_build_queries(components)
    if _DEBUG:
        print(f"[DEBUG] Scanning {len(queries)} components for vulnerabilities")
        if ignored_count > 0:
            print(f"[DEBUG] {ignored_count} components ignored (missing purl or version)")
    async with aiohttp.ClientSession() as session:
        component_vulns_map = await _scan_bundle_fetch_vulnerabilities(session, queries, 1000)
        if _DEBUG:
            print(f"[DEBUG] Total components with vulnerabilities: {len(component_vulns_map)}")
        await _scan_bundle_populate_vulnerabilities(session, component_vulns_map)
    result: list[models.osv.ComponentVulnerabilities] = []
    for purl, vulns in component_vulns_map.items():
        result.append(models.osv.ComponentVulnerabilities(purl=purl, vulnerabilities=vulns))
    return result, ignored_count


def _component_purl_with_version(component: models.bom.Component) -> str | None:
    if component.purl is None:
        return None
    if component.version is None:
        return None
    version = component.version.strip()
    if not version:
        return None
    purl = component.purl
    split_index = len(purl)
    question_index = purl.find("?")
    if (question_index != -1) and (question_index < split_index):
        split_index = question_index
    hash_index = purl.find("#")
    if (hash_index != -1) and (hash_index < split_index):
        split_index = hash_index
    if "@" in purl[:split_index]:
        return purl
    base = purl[:split_index]
    suffix = purl[split_index:]
    return f"{base}@{version}{suffix}"


async def _fetch_vulnerabilities_for_batch(
    session: aiohttp.ClientSession,
    queries: list[dict[str, Any]],
) -> list[models.osv.QueryResult]:
    if _DEBUG:
        print(f"[DEBUG] Sending querybatch with {len(queries)} queries")
    payload = {"queries": queries}
    async with session.post(f"{_OSV_API_BASE}/querybatch", json=payload) as response:
        # TODO: Should we retry?
        response.raise_for_status()
        data = await response.json()
    results_data = data.get("results", [])
    if _DEBUG:
        print(f"[DEBUG] Received {len(results_data)} results")
    return [models.osv.QueryResult.model_validate(result) for result in results_data]


async def _fetch_vulnerability_details(
    session: aiohttp.ClientSession,
    vuln_id: str,
) -> dict[str, Any]:
    if _DEBUG:
        print(f"[DEBUG] Fetching details for {vuln_id}")
    async with session.get(f"{_OSV_API_BASE}/vulns/{vuln_id}") as response:
        response.raise_for_status()
        return await response.json()


async def _paginate_query(
    session: aiohttp.ClientSession,
    query: dict[str, Any],
    page_token: str,
) -> list[dict[str, Any]]:
    all_vulns: list[dict[str, Any]] = []
    current_query = query.copy()
    current_query["page_token"] = page_token
    page = 0
    while True:
        page += 1
        if _DEBUG and page > 1:
            print(f"[DEBUG] Paginating query (page {page})")
        results = await _fetch_vulnerabilities_for_batch(session, [current_query])
        if not results:
            break
        result = results[0]
        if result.vulns:
            all_vulns.extend(result.vulns)
        next_page_token = result.next_page_token
        if next_page_token is None:
            break
        current_query["page_token"] = next_page_token
    return all_vulns


def _scan_bundle_build_queries(
    components: list[models.bom.Component],
) -> tuple[list[tuple[str, dict[str, Any]]], int]:
    queries: list[tuple[str, dict[str, Any]]] = []
    ignored_count = 0
    for component in components:
        purl_with_version = _component_purl_with_version(component)
        if purl_with_version is None:
            ignored_count += 1
            continue
        query = {"package": {"purl": purl_with_version}}
        queries.append((purl_with_version, query))
    return queries, ignored_count


async def _scan_bundle_fetch_vulnerabilities(
    session: aiohttp.ClientSession,
    queries: list[tuple[str, dict[str, Any]]],
    batch_size: int,
) -> dict[str, list[dict[str, Any]]]:
    component_vulns_map: dict[str, list[dict[str, Any]]] = {}
    for batch_start in range(0, len(queries), batch_size):
        batch_end = min(batch_start + batch_size, len(queries))
        batch = queries[batch_start:batch_end]
        if _DEBUG:
            batch_num = batch_start // batch_size + 1
            print(f"[DEBUG] Processing batch {batch_num} ({batch_start + 1}-{batch_end}/{len(queries)})")
        batch_queries = [query for _purl, query in batch]
        batch_results = await _fetch_vulnerabilities_for_batch(session, batch_queries)
        if _DEBUG and (len(batch_results) != len(batch)):
            print(f"[DEBUG] count mismatch (expected {len(batch)}, got {len(batch_results)})")
        for i, (purl, query) in enumerate(batch):
            if i >= len(batch_results):
                break
            query_result = batch_results[i]
            if query_result.vulns:
                existing_vulns = component_vulns_map.setdefault(purl, [])
                existing_vulns.extend(query_result.vulns)
                if _DEBUG:
                    print(f"[DEBUG] {purl}: {len(query_result.vulns)} vulnerabilities")
            if query_result.next_page_token:
                if _DEBUG:
                    print(f"[DEBUG] {purl}: has pagination, fetching remaining pages")
                existing_vulns = component_vulns_map.setdefault(purl, [])
                paginated = await _paginate_query(session, query, query_result.next_page_token)
                existing_vulns.extend(paginated)
    return component_vulns_map


async def _scan_bundle_populate_vulnerabilities(
    session: aiohttp.ClientSession,
    component_vulns_map: dict[str, list[dict[str, Any]]],
) -> None:
    details_cache: dict[str, dict[str, Any]] = {}
    for vulns in component_vulns_map.values():
        for vuln in vulns:
            vuln_id = vuln.get("id")
            if not vuln_id:
                continue
            details = details_cache.get(vuln_id)
            if details is None:
                details = await _fetch_vulnerability_details(session, vuln_id)
                details_cache[vuln_id] = details
            vuln.clear()
            vuln.update(details)
    if _DEBUG:
        print(f"[DEBUG] Fetched details for {len(details_cache)} unique vulnerabilities")
