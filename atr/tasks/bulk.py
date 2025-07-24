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

import asyncio
import dataclasses
import html.parser
import json
import os
import urllib.parse
from typing import Any

import aiofiles
import aiohttp
import sqlalchemy
import sqlalchemy.ext.asyncio

import atr.config as config
import atr.log as log
import atr.models.sql as sql
import atr.tasks.task as task

global_db_connection: sqlalchemy.ext.asyncio.async_sessionmaker | None = None
global_task_id: int | None = None


# TODO: Use a Pydantic model instead
@dataclasses.dataclass
class Args:
    release_name: str
    base_url: str
    file_types: list[str]
    require_sigs: bool
    max_depth: int
    max_concurrent: int

    @staticmethod
    def from_dict(args: dict[str, Any]) -> "Args":
        """Parse command line arguments."""
        log.debug(f"Parsing arguments: {args}")

        if len(args) != 6:
            log.error(f"Invalid number of arguments: {len(args)}, expected 6")
            raise ValueError("Invalid number of arguments")

        release_name = args["release_name"]
        base_url = args["base_url"]
        file_types = args["file_types"]
        require_sigs = args["require_sigs"]
        max_depth = args["max_depth"]
        max_concurrent = args["max_concurrent"]

        log.debug(
            f"Extracted values - release_name: {release_name}, base_url: {base_url}, "
            f"file_types: {file_types}, require_sigs: {require_sigs}, "
            f"max_depth: {max_depth}, max_concurrent: {max_concurrent}"
        )

        if not isinstance(release_name, str):
            log.error(f"Release key must be a string, got {type(release_name)}")
            raise ValueError("Release key must be a string")
        if not isinstance(base_url, str):
            log.error(f"Base URL must be a string, got {type(base_url)}")
            raise ValueError("Base URL must be a string")
        if not isinstance(file_types, list):
            log.error(f"File types must be a list, got {type(file_types)}")
            raise ValueError("File types must be a list")
        for arg in file_types:
            if not isinstance(arg, str):
                log.error(f"File types must be a list of strings, got {type(arg)}")
                raise ValueError("File types must be a list of strings")
        if not isinstance(require_sigs, bool):
            log.error(f"Require sigs must be a boolean, got {type(require_sigs)}")
            raise ValueError("Require sigs must be a boolean")
        if not isinstance(max_depth, int):
            log.error(f"Max depth must be an integer, got {type(max_depth)}")
            raise ValueError("Max depth must be an integer")
        if not isinstance(max_concurrent, int):
            log.error(f"Max concurrent must be an integer, got {type(max_concurrent)}")
            raise ValueError("Max concurrent must be an integer")

        log.debug("All argument validations passed")

        args_obj = Args(
            release_name=release_name,
            base_url=base_url,
            file_types=file_types,
            require_sigs=require_sigs,
            max_depth=max_depth,
            max_concurrent=max_concurrent,
        )

        log.info(f"Args object created: {args_obj}")
        return args_obj


class LinkExtractor(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            for attr, value in attrs:
                if attr == "href" and value:
                    self.links.append(value)


async def artifact_download(url: str, semaphore: asyncio.Semaphore) -> bool:
    log.debug(f"Starting download of artifact: {url}")
    try:
        success = await artifact_download_core(url, semaphore)
        if success:
            log.info(f"Successfully downloaded artifact: {url}")
        else:
            log.warning(f"Failed to download artifact: {url}")
        return success
    except Exception as e:
        log.exception(f"Error downloading artifact {url}: {e}")
        return False


async def artifact_download_core(url: str, semaphore: asyncio.Semaphore) -> bool:
    log.debug(f"Starting core download process for {url}")
    async with semaphore:
        log.debug(f"Acquired semaphore for {url}")
        # TODO: We flatten the hierarchy to get the filename
        # We should preserve the hierarchy
        filename = url.split("/")[-1]
        if filename.startswith("."):
            raise ValueError(f"Invalid filename: {filename}")
        local_path = os.path.join("downloads", filename)

        # Create download directory if it doesn't exist
        # TODO: Check whether local_path itself exists first
        os.makedirs("downloads", exist_ok=True)
        log.debug(f"Downloading {url} to {local_path}")

        try:
            async with aiohttp.ClientSession() as session:
                log.debug(f"Created HTTP session for {url}")
                async with session.get(url) as response:
                    if response.status != 200:
                        log.warning(f"Failed to download {url}: HTTP {response.status}")
                        return False

                    total_size = int(response.headers.get("Content-Length", 0))
                    if total_size:
                        log.info(f"Content-Length: {total_size} bytes for {url}")

                    chunk_size = 8192
                    downloaded = 0
                    log.debug(f"Writing file to {local_path} with chunk size {chunk_size}")

                    async with aiofiles.open(local_path, "wb") as f:
                        async for chunk in response.content.iter_chunked(chunk_size):
                            await f.write(chunk)
                            downloaded += len(chunk)
                            # if total_size:
                            #     progress = (downloaded / total_size) * 100
                            #     if downloaded % (chunk_size * 128) == 0:
                            #         log.debug(
                            #             f"Download progress for {filename}:"
                            #             f" {progress:.1f}% ({downloaded}/{total_size} bytes)"
                            #         )

            log.info(f"Download complete: {url} -> {local_path} ({downloaded} bytes)")
            return True

        except Exception as e:
            log.exception(f"Error during download of {url}: {e}")
            # Remove partial download if an error occurred
            if os.path.exists(local_path):
                log.debug(f"Removing partial download: {local_path}")
                try:
                    os.remove(local_path)
                except Exception as del_err:
                    log.error(f"Error removing partial download {local_path}: {del_err}")
            return False


async def artifact_urls(args: Args, queue: asyncio.Queue, semaphore: asyncio.Semaphore) -> tuple[list[str], list[str]]:
    log.info(f"Starting URL crawling from {args.base_url}")
    await database_message(f"Crawling artifact URLs from {args.base_url}")
    signatures: list[str] = []
    artifacts: list[str] = []
    seen: set[str] = set()

    log.debug(f"Adding base URL to queue: {args.base_url}")
    await queue.put(args.base_url)

    log.debug("Starting crawl loop")
    depth = 0
    # Start with just the base URL
    urls_at_current_depth = 1
    urls_at_next_depth = 0

    while (not queue.empty()) and (depth < args.max_depth):
        log.debug(f"Processing depth {depth + 1}/{args.max_depth}, queue size: {queue.qsize()}")

        # Process all URLs at the current depth before moving to the next
        for _ in range(urls_at_current_depth):
            if queue.empty():
                break

            url = await queue.get()
            log.debug(f"Processing URL: {url}")

            if url_excluded(seen, url, args):
                continue

            seen.add(url)
            log.debug(f"Checking URL for file types: {args.file_types}")

            # If not a target file type, try to parse HTML links
            if not check_matches(args, url, artifacts, signatures):
                log.debug(f"URL is not a target file, parsing HTML: {url}")
                try:
                    new_urls = await download_html(url, semaphore)
                    log.debug(f"Found {len(new_urls)} new URLs in {url}")
                    for new_url in new_urls:
                        if new_url not in seen:
                            log.debug(f"Adding new URL to queue: {new_url}")
                            await queue.put(new_url)
                            urls_at_next_depth += 1
                except Exception as e:
                    log.warning(f"Error parsing HTML from {url}: {e}")
        # Move to next depth
        depth += 1
        urls_at_current_depth = urls_at_next_depth
        urls_at_next_depth = 0

        # Update database with progress message
        progress_msg = f"Crawled {len(seen)} URLs, found {len(artifacts)} artifacts (depth {depth}/{args.max_depth})"
        await database_message(progress_msg, progress=(30 + min(50, depth * 10), 100))
        log.debug(f"Moving to depth {depth + 1}, {urls_at_current_depth} URLs to process")

    log.info(f"URL crawling complete. Found {len(artifacts)} artifacts and {len(signatures)} signatures")
    return signatures, artifacts


async def artifacts_download(artifacts: list[str], semaphore: asyncio.Semaphore) -> list[str]:
    """Download artifacts with progress tracking."""
    size = len(artifacts)
    log.info(f"Starting download of {size} artifacts")
    downloaded = []

    for i, artifact in enumerate(artifacts):
        progress_percent = int((i / size) * 100) if (size > 0) else 100
        progress_msg = f"Downloading {i + 1}/{size} artifacts"
        log.info(f"{progress_msg}: {artifact}")
        await database_message(progress_msg, progress=(progress_percent, 100))

        success = await artifact_download(artifact, semaphore)
        if success:
            log.debug(f"Successfully downloaded: {artifact}")
            downloaded.append(artifact)
        else:
            log.warning(f"Failed to download: {artifact}")

    log.info(f"Download complete. Successfully downloaded {len(downloaded)}/{size} artifacts")
    await database_message(f"Downloaded {len(downloaded)} artifacts", progress=(100, 100))
    return downloaded


def check_matches(args: Args, url: str, artifacts: list[str], signatures: list[str]) -> bool:
    for type in args.file_types:
        if url.endswith(type):
            log.info(f"Found artifact: {url}")
            artifacts.append(url)
            return True
        elif url.endswith(type + ".asc"):
            log.info(f"Found signature: {url}")
            signatures.append(url)
            return True
    return False


async def database_message(msg: str, progress: tuple[int, int] | None = None) -> None:
    """Update database with message and progress."""
    log.debug(f"Updating database with message: '{msg}', progress: {progress}")
    try:
        task_id = await database_task_id_get()
        if task_id:
            log.debug(f"Found task_id: {task_id}, updating with message")
            await database_task_update(task_id, msg, progress)
        else:
            log.warning("No task ID found, skipping database update")
    except Exception as e:
        # We don't raise here
        # We continue even if database updates fail
        # But in this case, the user won't be informed on the update page
        log.exception(f"Failed to update database: {e}")
        log.info(f"Continuing despite database error. Message was: '{msg}'")


def database_progress_percentage_calculate(progress: tuple[int, int] | None) -> int:
    """Calculate percentage from progress tuple."""
    log.debug(f"Calculating percentage from progress tuple: {progress}")
    if progress is None:
        log.debug("Progress is None, returning 0%")
        return 0

    current, total = progress

    # Avoid division by zero
    if total == 0:
        log.warning("Total is zero in progress tuple, avoiding division by zero")
        return 0

    percentage = min(100, int((current / total) * 100))
    log.debug(f"Calculated percentage: {percentage}% ({current}/{total})")
    return percentage


async def database_task_id_get() -> int | None:
    """Get current task ID asynchronously with caching."""
    global global_task_id
    log.debug("Attempting to get current task ID")

    # Return cached ID if available
    if global_task_id is not None:
        log.debug(f"Using cached task ID: {global_task_id}")
        return global_task_id

    try:
        process_id = os.getpid()
        log.debug(f"Current process ID: {process_id}")
        task_id = await database_task_pid_lookup(process_id)

        if task_id:
            log.info(f"Found task ID: {task_id} for process ID: {process_id}")
            # Cache the task ID for future use
            global_task_id = task_id
        else:
            log.warning(f"No task found for process ID: {process_id}")

        return task_id
    except Exception as e:
        log.exception(f"Error getting task ID: {e}")
        return None


async def database_task_pid_lookup(process_id: int) -> int | None:
    """Look up task ID by process ID asynchronously."""
    log.debug(f"Looking up task ID for process ID: {process_id}")

    try:
        async with await get_db_session() as session:
            log.debug(f"Executing SQL query to find task for PID: {process_id}")
            # Look for ACTIVE task with our PID
            result = await session.execute(
                sqlalchemy.text("""
                    SELECT id FROM task
                    WHERE pid = :pid AND status = 'ACTIVE'
                    LIMIT 1
                """),
                {"pid": process_id},
            )
            log.debug("SQL query executed, fetching results")
            row = result.fetchone()
            if row:
                log.info(f"Found task ID: {row[0]} for process ID: {process_id}")
                row_one = row[0]
                if not isinstance(row_one, int):
                    log.error(f"Task ID is not an integer: {row_one}")
                    raise ValueError("Task ID is not an integer")
                return row_one
            else:
                log.warning(f"No ACTIVE task found for process ID: {process_id}")
                return None
    except Exception as e:
        log.exception(f"Error looking up task by PID: {e}")
        return None


async def database_task_update(task_id: int, msg: str, progress: tuple[int, int] | None) -> None:
    """Update task in database with message and progress."""
    log.debug(f"Updating task {task_id} with message: '{msg}', progress: {progress}")
    # Convert progress to percentage
    progress_pct = database_progress_percentage_calculate(progress)
    log.debug(f"Calculated progress percentage: {progress_pct}%")
    await database_task_update_execute(task_id, msg, progress_pct)


async def database_task_update_execute(task_id: int, msg: str, progress_pct: int) -> None:
    """Execute database update with message and progress."""
    log.debug(f"Executing database update for task {task_id}, message: '{msg}', progress: {progress_pct}%")

    try:
        async with await get_db_session() as session:
            log.debug(f"Executing SQL UPDATE for task ID: {task_id}")

            # Store progress info in the result column as JSON
            result_data = json.dumps({"message": msg, "progress": progress_pct})

            await session.execute(
                sqlalchemy.text("""
                    UPDATE task
                    SET result = :result
                    WHERE id = :task_id
                """),
                {
                    "result": result_data,
                    "task_id": task_id,
                },
            )
            await session.commit()
            log.info(f"Successfully updated task {task_id} with progress {progress_pct}%")
    except Exception as e:
        # Continue even if database update fails
        log.exception(f"Error updating task {task_id} in database: {e}")


async def download(args: dict[str, Any]) -> tuple[sql.TaskStatus, str | None, tuple[Any, ...]]:
    """Download bulk package from URL."""
    # Returns (status, error, result)
    # This is the main task entry point, called by worker.py
    # This function should probably be called artifacts_download
    log.info(f"Starting bulk download task with args: {args}")
    try:
        log.debug("Delegating to download_core function")
        status, error, result = await download_core(args)
        log.info(f"Download completed with status: {status}")
        return status, error, result
    except Exception as e:
        log.exception(f"Error in download function: {e}")
        # Return a tuple with a dictionary that matches what the template expects
        return task.FAILED, str(e), ({"message": f"Error: {e}", "progress": 0},)


async def download_core(args_dict: dict[str, Any]) -> tuple[sql.TaskStatus, str | None, tuple[Any, ...]]:
    """Download bulk package from URL."""
    log.info("Starting download_core")
    try:
        log.debug(f"Parsing arguments: {args_dict}")
        args = Args.from_dict(args_dict)
        log.info(f"Args parsed successfully: release_name={args.release_name}, base_url={args.base_url}")

        # Create async resources
        log.debug("Creating async queue and semaphore")
        queue: asyncio.Queue[str] = asyncio.Queue()
        semaphore = asyncio.Semaphore(args.max_concurrent)

        # Start URL crawling
        await database_message(f"Crawling URLs from {args.base_url}")

        log.info("Starting artifact_urls coroutine")
        signatures, artifacts = await artifact_urls(args, queue, semaphore)
        log.info(f"Found {len(signatures)} signatures and {len(artifacts)} artifacts")

        # Update progress for download phase
        await database_message(f"Found {len(artifacts)} artifacts to download")

        # Download artifacts
        log.info("Starting artifacts_download coroutine")
        artifacts_downloaded = await artifacts_download(artifacts, semaphore)
        files_downloaded = len(artifacts_downloaded)

        # Return a result dictionary
        # This matches what we have in templates/release-bulk.html
        return (
            task.COMPLETED,
            None,
            (
                {
                    "message": f"Successfully downloaded {files_downloaded} artifacts",
                    "progress": 100,
                    "url": args.base_url,
                    "file_types": args.file_types,
                    "files_downloaded": files_downloaded,
                },
            ),
        )

    except Exception as e:
        log.exception(f"Error in download_core: {e}")
        base_url = args_dict["base_url"] if len(args_dict) > 1 else "unknown URL"
        return (
            task.FAILED,
            str(e),
            (
                {
                    "message": f"Failed to download from {base_url}",
                    "progress": 0,
                },
            ),
        )


async def download_html(url: str, semaphore: asyncio.Semaphore) -> list[str]:
    """Download HTML and extract links."""
    log.debug(f"Downloading HTML from: {url}")
    try:
        return await download_html_core(url, semaphore)
    except Exception as e:
        log.error(f"Error downloading HTML from {url}: {e}")
        return []


async def download_html_core(url: str, semaphore: asyncio.Semaphore) -> list[str]:
    """Core HTML download and link extraction logic."""
    log.debug(f"Starting HTML download core for {url}")
    async with semaphore:
        log.debug(f"Acquired semaphore for {url}")

        urls = []
        async with aiohttp.ClientSession() as session:
            log.debug(f"Created HTTP session for {url}")

            async with session.get(url) as response:
                if response.status != 200:
                    log.warning(f"HTTP {response.status} for {url}")
                    return []

                log.debug(f"Received HTTP 200 for {url}, content type: {response.content_type}")
                if not response.content_type.startswith("text/html"):
                    log.debug(f"Not HTML content: {response.content_type}, skipping link extraction")
                    return []

                log.debug(f"Reading HTML content from {url}")
                html = await response.text()

                urls = extract_links_from_html(html, url)
                log.debug(f"Extracted {len(urls)} processed links from {url}")

                return urls


def extract_links_from_html(html: str, base_url: str) -> list[str]:
    """Extract links from HTML content using html.parser."""
    parser = LinkExtractor()
    parser.feed(html)
    raw_links = parser.links
    log.debug(f"Found {len(raw_links)} raw links in {base_url}")

    processed_urls = []
    for link in raw_links:
        processed_url = urllib.parse.urljoin(base_url, link)
        # Filter out URLs that don't start with the base URL
        # We also check this elsewhere amongst other checks
        # But it's good to filter them early
        if processed_url.startswith(base_url):
            processed_urls.append(processed_url)
        else:
            log.debug(f"Skipping URL outside base URL scope: {processed_url}")

    return processed_urls


async def get_db_session() -> sqlalchemy.ext.asyncio.AsyncSession:
    """Get a reusable database session."""
    global global_db_connection

    try:
        # Create connection only if it doesn't exist already
        if global_db_connection is None:
            conf = config.get()
            absolute_db_path = os.path.join(conf.STATE_DIR, conf.SQLITE_DB_PATH)
            # Three slashes are required before either a relative or absolute path
            db_url = f"sqlite+aiosqlite://{absolute_db_path}"
            log.debug(f"Creating database engine: {db_url}")

            engine = sqlalchemy.ext.asyncio.create_async_engine(db_url)
            global_db_connection = sqlalchemy.ext.asyncio.async_sessionmaker(
                engine, class_=sqlalchemy.ext.asyncio.AsyncSession, expire_on_commit=False
            )

        connection: sqlalchemy.ext.asyncio.AsyncSession = global_db_connection()
        return connection
    except Exception as e:
        log.exception(f"Error creating database session: {e}")
        raise


def url_excluded(seen: set[str], url: str, args: Args) -> bool:
    # Filter for sorting URLs to avoid redundant crawling
    sorting_patterns = ["?C=N;O=", "?C=M;O=", "?C=S;O=", "?C=D;O="]

    if not url.startswith(args.base_url):
        log.debug(f"Skipping URL outside base URL scope: {url}")
        return True

    if url in seen:
        log.debug(f"Skipping already seen URL: {url}")
        return True

    # Skip sorting URLs to avoid redundant crawling
    if any(pattern in url for pattern in sorting_patterns):
        log.debug(f"Skipping sorting URL: {url}")
        return True

    return False
