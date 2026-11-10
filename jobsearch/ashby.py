"""Bounded ingestion of Ashby's public posting format."""

import json
import re
import signal
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from http.client import HTTPException, HTTPSConnection

REQUEST_TIMEOUT = 15
MAX_BYTES = 16 * 1024 * 1024
BOARD = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}")
POSTING = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}")


@dataclass(frozen=True)
class Board:
    slug: str
    company: str
    startup: bool

    def __post_init__(self):
        if (
            not isinstance(self.slug, str)
            or not BOARD.fullmatch(self.slug)
            or not isinstance(self.company, str)
            or not self.company.strip()
            or len(self.company) > 120
            or any(unicodedata.category(char) in ("Cc", "Cs") for char in self.company)
        ):
            raise ValueError("invalid board")
        if type(self.startup) is not bool:
            raise ValueError("startup must be a boolean")


def read_bounded(stream):
    data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("input exceeds size limit")
    return data


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _invalid_constant(_):
    raise ValueError("non-finite JSON number")


def decode(data):
    if len(data) > MAX_BYTES:
        raise ValueError("input exceeds size limit")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_object, parse_constant=_invalid_constant)
    except (ValueError, RecursionError) as exc:
        raise ValueError("invalid JSON") from exc


def _text(obj, key, maximum, default=None):
    value = obj.get(key, default)
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError(f"invalid {key}")
    if any(unicodedata.category(char) in ("Cc", "Cs") and char not in "\t\n\r" for char in value):
        raise ValueError(f"invalid characters in {key}")
    return " ".join(value.split())


def parse(board, data):
    """Validate the whole snapshot before returning any listed postings."""
    payload = decode(data)
    if (
        not isinstance(payload, dict)
        or payload.get("apiVersion") != "1"
        or not isinstance(payload.get("jobs"), list)
        or len(payload["jobs"]) > 5000
        or payload.get("partial", False) is not False
        or payload.get("nextCursor") is not None
    ):
        raise ValueError("invalid or incomplete Ashby snapshot")
    jobs = []
    seen = set()
    prefix = f"https://jobs.ashbyhq.com/{board.slug}/"
    for item in payload["jobs"]:
        if not isinstance(item, dict) or type(item.get("isListed")) is not bool:
            raise ValueError("invalid posting")
        if not item["isListed"]:
            continue
        url = item.get("jobUrl")
        # Board names are case-insensitive in links; the feed uses the canonical case.
        if not isinstance(url, str) or not url.lower().startswith(prefix.lower()):
            raise ValueError("invalid posting URL")
        external_id = url[len(prefix) :]
        if not POSTING.fullmatch(external_id) or external_id in seen:
            raise ValueError("invalid or repeated posting ID")
        seen.add(external_id)
        title = _text(item, "title", 250)
        description = _text(item, "descriptionPlain", 100_000)
        location = _text(item, "location", 250, "")
        # An unset workplace type carries no remote or onsite evidence.
        workplace = "" if item.get("workplaceType") is None else _text(item, "workplaceType", 20)
        if not title or not description or workplace not in ("", "Remote", "Hybrid", "OnSite"):
            raise ValueError("invalid posting content")
        secondary = item.get("secondaryLocations", [])
        if (
            not isinstance(secondary, list)
            or len(secondary) > 50
            or any(not isinstance(entry, dict) for entry in secondary)
        ):
            raise ValueError("invalid secondary locations")
        published = _text(item, "publishedAt", 40, "")
        if published:
            try:
                dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    raise ValueError
                published = dt.astimezone(timezone.utc).isoformat()
            except (ValueError, OverflowError) as exc:
                raise ValueError("invalid publication timestamp") from exc
        jobs.append(
            dict(
                external_id=external_id,
                url=url,
                title=title,
                description=description,
                location=location,
                workplace=workplace,
                published=published,
                employment=_text(item, "employmentType", 30, ""),
                secondary=sorted({_text(entry, "location", 250) for entry in secondary}),
            )
        )
    return jobs


class Ashby:
    """Network capability defaults to disabled. The fixture CLI never enables it."""

    def __init__(self, boards, *, network_enabled=False):
        self.boards = {board.slug: board for board in boards}
        self.network_enabled = network_enabled

    def fixture(self, slug, data):
        return parse(self.boards[slug], data)

    def fetch(self, slug):
        board = self.boards.get(slug)
        if board is None or not self.network_enabled:
            raise ValueError("network disabled or board outside the allowlist")
        deadline = time.monotonic() + REQUEST_TIMEOUT
        returncode, body = _fetch_worker(board.slug, deadline)
        if time.monotonic() >= deadline or returncode in (2, -signal.SIGALRM):
            raise TimeoutError("Ashby request deadline exceeded")
        if returncode:
            raise ValueError("Ashby request failed or returned an invalid response")
        return parse(board, body)


def _fetch_worker(slug, deadline):
    interrupted = False

    def defer_interrupt(signum, frame):
        nonlocal interrupted
        interrupted = True

    # Record signals without throwing during Popen or cleanup. Once ownership
    # is established, bounded waits let the parent act on that flag promptly.
    handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        for signum in handlers:
            signal.signal(signum, defer_interrupt)
        if interrupted:
            raise KeyboardInterrupt
        with subprocess.Popen(
            [sys.executable, "-I", "-B", __file__, "--fetch-worker", slug],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={},
        ) as worker:
            try:
                while not interrupted:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("Ashby request deadline exceeded")
                    try:
                        body, _ = worker.communicate(timeout=min(remaining, 0.1))
                    except subprocess.TimeoutExpired:
                        continue
                    break
            finally:
                if worker.poll() is None:
                    try:
                        worker.kill()
                    finally:
                        worker.wait()
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
    if interrupted:
        raise KeyboardInterrupt
    return worker.returncode, body


def _download(slug):
    if not BOARD.fullmatch(slug):
        raise ValueError("invalid board")
    # Direct HTTPS uses certificate validation and ignores environment proxies.
    # HTTPConnection never follows redirects or negotiates compression.
    connection = HTTPSConnection("api.ashbyhq.com", timeout=5)
    try:
        connection.request(
            "GET",
            f"/posting-api/job-board/{slug}",
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
        )
        response = connection.getresponse()
        with response:
            if response.status != 200 or response.headers.get_content_type() != "application/json":
                raise ValueError("unexpected Ashby response")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise ValueError("unexpected response encoding")
            length = response.length
            if length is not None and length > MAX_BYTES:
                raise ValueError("response exceeds size limit")
            body = bytearray()
            while True:
                chunk = response.read1(min(65536, MAX_BYTES + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > MAX_BYTES:
                    raise ValueError("response exceeds size limit")
            if length is not None and len(body) != length:
                raise ValueError("truncated response")
    finally:
        connection.close()
    return bytes(body)


if __name__ == "__main__":
    # The parent checks the board allowlist and bounds this short-lived worker.
    if len(sys.argv) != 3 or sys.argv[1] != "--fetch-worker":
        raise SystemExit(1)
    signal.alarm(REQUEST_TIMEOUT)
    try:
        sys.stdout.buffer.write(_download(sys.argv[2]))
    except TimeoutError:
        raise SystemExit(2)
    except (OSError, HTTPException, ValueError):
        raise SystemExit(1)
