"""HN job posts: "Ask HN: Who is hiring?" comments (Algolia HN API) and the YC job ads on /jobs (official HN API)."""

import html
import re

from .boards import plain, posting
from .fetch import SourceError, get_json

SEARCH = "https://hn.algolia.com/api/v1/search_by_date?tags=story,author_whoishiring&hitsPerPage=10"
HREF = re.compile(r'href="([^"]+)"')
JOB_ADS = "https://hacker-news.firebaseio.com/v0/jobstories.json"
ITEM = "https://hacker-news.firebaseio.com/v0/item/{}.json"
AD_TITLE = re.compile(r"^(?P<company>.+?) \((?P<batch>YC [A-Z]\d{2,4})\) (?:is )?hiring", re.I)


def latest_thread():
    hits = get_json(SEARCH)["hits"]
    return next(hit for hit in hits if hit["title"].startswith("Ask HN: Who is hiring?"))


def links(markup):
    return [html.unescape(link) for link in HREF.findall(markup or "")]


def parse_comment(item):
    """Return (posting, company, links), or None for deleted or unstructured comments."""
    markup = item.get("text") or ""
    if not markup or item.get("author") is None:
        return None
    header = plain(re.split(r"<p>", markup, maxsplit=1)[0])
    parts = [part.strip() for part in header.split("|")]
    if len(parts) < 2 or not parts[0] or len(parts[0]) > 80:
        return None
    url = f"https://news.ycombinator.com/item?id={item['id']}"
    remote = "Remote" if re.search(r"\bremote\b", header, re.I) else ""
    job = posting(
        "hn", item["id"], url, header[:250], plain(markup), " | ".join(parts[2:4])[:250], remote, item["created_at"]
    )
    return job, parts[0], links(markup)


def thread_postings(story_id):
    thread = get_json(f"https://hn.algolia.com/api/v1/items/{story_id}")
    return [parsed for parsed in map(parse_comment, thread["children"]) if parsed]


def parse_ad(item):
    """Return (posting, company, links) for a "Company (YC S24) is hiring ..." ad, or None."""
    match = AD_TITLE.match((item or {}).get("title", ""))
    if not match or item.get("type") != "job":
        return None
    url = item.get("url") or f"https://news.ycombinator.com/item?id={item['id']}"
    text = plain(item.get("text"))
    remote = "Remote" if re.search(r"\bremote\b", f"{item['title']} {text}", re.I) else ""
    job = posting("hn", item["id"], url, item["title"][:250], text, "", remote, (item.get("time") or 0) * 1000 or "")
    return job, match["company"].strip(), [url, *links(item.get("text"))]


def ad(item_id):
    try:
        return parse_ad(get_json(ITEM.format(item_id)))
    except SourceError:
        return None


def job_ads():
    return [parsed for parsed in map(ad, get_json(JOB_ADS)) if parsed]
