"""Find where a company lists its jobs: links we already have, its own careers page, or its name on a job API.

Every hiring tool we can recognise is recorded, even ones we can't read yet, so a lead is never dropped.
"""

import json
import re
import unicodedata
from urllib.parse import urljoin, urlsplit

from .fetch import NotFound, SourceError, allowed, get

SLUG = r"(?P<slug>[A-Za-z0-9_-]+)"
BOARD_LINKS = {
    "greenhouse": [
        rf"(?:boards|job-boards)(?:\.eu)?\.greenhouse\.io/(?:embed/job_board(?:/js)?\?for=)?{SLUG}",
        rf"boards-api\.greenhouse\.io/v1/boards/{SLUG}",
    ],
    "lever": [rf"jobs\.lever\.co/{SLUG}"],
    "ashby": [rf"jobs\.ashbyhq\.com/{SLUG}", rf"api\.ashbyhq\.com/posting-api/job-board/{SLUG}"],
    "workable": [rf"apply\.workable\.com/{SLUG}"],
    "rippling": [rf"ats\.rippling\.com/{SLUG}"],
    "recruitee": [rf"{SLUG}\.recruitee\.com"],
    "smartrecruiters": [rf"(?:jobs|careers)\.smartrecruiters\.com/{SLUG}"],
    "breezy": [rf"{SLUG}\.breezy\.hr"],
    "bamboohr": [rf"{SLUG}\.bamboohr\.com/(?:careers|jobs)"],
    "teamtailor": [rf"{SLUG}\.teamtailor\.com"],
    "dover": [rf"app\.dover\.com/(?:apply|jobs)/{SLUG}"],
    "pinpoint": [rf"{SLUG}\.pinpointhq\.com"],
    "jazzhr": [rf"{SLUG}\.applytojob\.com"],
    "gem": [rf"jobs\.gem\.com/{SLUG}"],
    "wellfound": [rf"wellfound\.com/company/{SLUG}"],
    "waas": [rf"ycombinator\.com/companies/{SLUG}/jobs", rf"workatastartup\.com/companies/{SLUG}"],
}
PATTERNS = [(kind, re.compile(p)) for kind, patterns in BOARD_LINKS.items() for p in patterns]
NOT_BOARDS = {"embed", "v1", "api", "jobs", "careers", "www", "app"}
PROBES = {
    "greenhouse": "https://boards-api.greenhouse.io/v1/boards/{}/jobs",
    "lever": "https://api.lever.co/v0/postings/{}?mode=json&limit=1",
    "ashby": "https://api.ashbyhq.com/posting-api/job-board/{}",
}
NAME_PROBES = tuple(PROBES)  # small tools only when linked: name guesses there cost many requests
READABLE = {*PROBES, "gem", "workable", "recruitee", "pinpoint", "rippling", "jazzhr", "careers"}
EMPTY_LIST = re.compile(rb'"jobs":\s*\[\]')
CAREERS_LINK = re.compile(r'href="([^"#]*(?:careers|jobs|join|hiring|work-with-us)[^"#]*)"', re.I)
CAREERS_TITLE = re.compile(r"<title[^>]*>[^<]*(?:careers|jobs|join|hiring|work with us)", re.I)
ASSET = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|webp|ico|pdf|xml|json|woff2?)$", re.I)
NOTION_HOST = re.compile(r"(?:^|\.)notion\.(?:site|so)$")
JSON_LD = re.compile(r'<script[^>]+application/ld\+json[^>]*>(.*?)</script>', re.I | re.S)


def boards_in(text):
    found = []
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(text or ""):
            slug = match.group("slug")
            if slug.lower() not in NOT_BOARDS and (kind, slug.lower()) not in {(k, s.lower()) for k, s in found}:
                found.append((kind, slug))
    return found


def job_postings_ld(page):
    """schema.org JobPosting objects embedded in a page (the company's own structured data)."""
    found = []
    for block in JSON_LD.findall(page):
        try:
            data = json.loads(block)
        except ValueError:
            continue
        stack = data if isinstance(data, list) else [data]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                if item.get("@type") == "JobPosting":
                    found.append(item)
                stack.extend(v for v in item.values() if isinstance(v, (dict, list)))
            elif isinstance(item, list):
                stack.extend(item)
    return found


def slugs(name):
    folded = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().casefold()
    words = re.findall(r"[a-z0-9]+", re.sub(r"\b(inc|llc|ltd|corp|co|ai|labs|hq|technologies|the)\b\.?", " ", folded))
    full = re.findall(r"[a-z0-9]+", folded)
    return list(dict.fromkeys(filter(None, ["".join(full), "".join(words), "-".join(full)])))


def exists(kind, slug):
    try:
        body = get(PROBES[kind].format(slug))
    except NotFound:
        return False
    return body not in (b"[]", b"") and not EMPTY_LIST.search(body)


def page(url):
    try:
        return get(url).decode("utf-8", "replace")
    except (SourceError, ValueError):
        return ""


def careers_links(html, link):
    """Careers/jobs links on the company's domain, any subdomain of it, or a hosted Notion page."""
    root = (urlsplit(link).hostname or "").removeprefix("www.")
    urls = dict.fromkeys(urljoin(link, href) for href in CAREERS_LINK.findall(html))
    return [
        u
        for u in urls
        if u != link
        and allowed(u)
        and not ASSET.search(urlsplit(u).path)
        and (urlsplit(u).hostname == root or (urlsplit(u).hostname or "").endswith(f".{root}") or hosted(u))
    ]


def hosted(url):
    return bool(NOTION_HOST.search(urlsplit(url).hostname or ""))


def feed_in(html, link):
    found = [(kind, slug, "careers page") for kind, slug in boards_in(html)]
    if not found and job_postings_ld(html):
        found = [("careers", link, "JobPosting data on careers page")]
    return found


def from_site(links):
    """Read the company's own pages: hiring-tool links, JobPosting data, else a careers page to check by hand."""
    hand = []
    for link in links[:2]:
        if not allowed(link):
            continue
        html = page(link)
        found = feed_in(html, link)
        followed = [] if found else careers_links(html, link)[:1]
        if followed:
            link = followed[0]
            html = page(link)
            found = feed_in(html, link)
        if found:
            return found
        if not hand and html and (followed or hosted(link) or CAREERS_TITLE.search(html)):
            hand = [("careers-hand", link, "careers page without a feed: check by hand")]
    return hand


def find_boards(name, links=(), probe=True, extra_slugs=()):
    """Return (kind, slug, how) for every board found, best evidence first."""
    found = [(kind, slug, "linked") for kind, slug in boards_in(" ".join(links))]
    if not any(kind in READABLE for kind, _, _ in found):
        found += from_site(links)
    if not any(kind in READABLE for kind, _, _ in found) and probe:
        for slug in list(dict.fromkeys([*extra_slugs, *slugs(name)]))[:2]:
            for kind in NAME_PROBES:
                try:
                    if exists(kind, slug):
                        found.append((kind, slug, "name probe"))
                except SourceError:
                    continue
            if any(how == "name probe" for _, _, how in found):
                break
    return found
