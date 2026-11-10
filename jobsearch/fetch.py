"""Bounded HTTPS GET for public job sources."""

import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

TIMEOUT = 20
MAX_BYTES = 16 * 1024 * 1024
AGENT = "arcturus-radar/0.1 (personal job search; one request per board per run)"
NEVER_FETCH = re.compile(r"ycombinator\.com|workatastartup\.com")  # YC's terms ban robots


class SourceError(Exception):
    pass


class NotFound(SourceError):
    pass


def allowed(url):
    return url.startswith("https://") and not NEVER_FETCH.search(url)


class Redirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed(newurl):
            raise SourceError("redirect to a site we don't fetch")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = build_opener(Redirects)


def get(url):
    if not allowed(url):
        raise SourceError("https only, and never YC's sites")
    request = Request(url, headers={"User-Agent": AGENT, "Accept": "application/json, text/html;q=0.9"})
    try:
        with OPENER.open(request, timeout=TIMEOUT) as response:
            body = response.read(MAX_BYTES + 1)
    except HTTPError as exc:
        if exc.code == 404:
            raise NotFound(url) from exc
        raise SourceError(f"HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise SourceError(type(exc).__name__) from exc
    if len(body) > MAX_BYTES:
        raise SourceError("response too large")
    return body


def get_json(url):
    try:
        return json.loads(get(url))
    except ValueError as exc:
        raise SourceError("invalid JSON") from exc
