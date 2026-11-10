"""Public job-board adapters. Each returns the posting dicts the registry stores.

`date_kind` says what `published` means for that source, because the sources differ:
Greenhouse `first_published` is the original post date, Lever `createdAt` is the creation date (undocumented),
Ashby `publishedAt` is the last publication date, so a re-publish can make an old job look new.
"none" means the source gives no date at all, so `published` is empty.
"""

import hashlib
import html
import re
from datetime import datetime, timezone

from . import ashby
from .discover import job_postings_ld
from .fetch import get, get_json

DATE_KINDS = {
    "greenhouse": "original",
    "lever": "created",
    "ashby": "last_published",
    "hn": "original",
    "careers": "site_listing",
    "gem": "original",
    "workable": "created",
    "recruitee": "created",
    "rippling": "created",
    "jazzhr": "last_published",
    "pinpoint": "none",
}
TAG = re.compile(r"<[^>]+>")
PLACES = {
    "remote": "Remote",
    "hybrid": "Hybrid",
    "on-site": "OnSite",
    "on_site": "OnSite",
    "onsite": "OnSite",
    "in_office": "OnSite",
}
MAX_DETAIL_JOBS = 40
JAZZ_LINK = re.compile(r"applytojob\.com/apply/([A-Za-z0-9]+)/[^\"'\s<>#?]*")


def plain(markup):
    text = TAG.sub(" ", html.unescape(markup or ""))
    return " ".join(html.unescape(text).split())


def iso(value):
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat()
    parsed = datetime.fromisoformat(re.sub(r"(Z| UTC)$", "+00:00", value.strip()))
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()


def workplace(*texts):
    joined = " ".join(t for t in texts if t).casefold()
    if "remote" in joined:
        return "Remote"
    if "hybrid" in joined:
        return "Hybrid"
    return ""


def posting(source, external_id, url, title, description, location, place, published, employment="", secondary=()):
    return dict(
        external_id=str(external_id),
        url=url,
        title=" ".join(title.split()),
        description=description,
        location=location or "",
        workplace=place,
        published=iso(published),
        employment=employment or "",
        secondary=sorted(set(secondary) - {location}),
        date_kind=DATE_KINDS[source],
    )


def greenhouse(slug, url=""):
    data = get_json(f"https://boards-api.greenhouse.io/v1/boards/{slug}/jobs?content=true")
    jobs = []
    for item in data["jobs"]:
        location = (item.get("location") or {}).get("name", "")
        offices = [o["name"] for o in item.get("offices", []) if o.get("name")]
        jobs.append(
            posting(
                "greenhouse",
                item["id"],
                item["absolute_url"],
                item["title"],
                plain(item.get("content")),
                location,
                workplace(location),
                item.get("first_published") or "",
                secondary=offices,
            )
        )
    return jobs


def lever(slug, url=""):
    data = get_json(f"https://api.lever.co/v0/postings/{slug}?mode=json")
    jobs = []
    for item in data:
        categories = item.get("categories") or {}
        lists = " ".join(f"{entry.get('text', '')}: {plain(entry.get('content'))}" for entry in item.get("lists", []))
        description = " ".join(filter(None, (item.get("descriptionPlain"), lists, item.get("additionalPlain"))))
        place = PLACES.get(item.get("workplaceType"), "")
        location = categories.get("location", "")
        jobs.append(
            posting(
                "lever",
                item["id"],
                item["hostedUrl"],
                item["text"],
                description,
                location,
                place or workplace(location),
                item.get("createdAt"),
                categories.get("commitment", ""),
                categories.get("allLocations", []),
            )
        )
    return jobs


def ashby_board(slug, url=""):
    board = ashby.Board(slug, slug, True)
    body = get(f"https://api.ashbyhq.com/posting-api/job-board/{slug}")
    return [job | {"date_kind": DATE_KINDS["ashby"]} for job in ashby.parse(board, body)]


def ld_location(item):
    places = item.get("jobLocation") or []
    places = places if isinstance(places, list) else [places]
    names = []
    for place in places:
        address = (place or {}).get("address") or {}
        if isinstance(address, dict):
            country = address.get("addressCountry")
            country = country.get("name", "") if isinstance(country, dict) else country or ""
            names.append(
                ", ".join(filter(None, (address.get("addressLocality"), address.get("addressRegion"), country)))
            )
    return " / ".join(filter(None, names))


def ld_posting(source, item, url):
    """A registry posting from one schema.org JobPosting; None when it has no title."""
    title = item.get("title") or ""
    if not title:
        return None
    identifier = item.get("identifier")
    identifier = identifier.get("value") if isinstance(identifier, dict) else identifier
    link = item.get("url") or url
    external = str(identifier or hashlib.sha256(f"{link}|{title}".encode()).hexdigest()[:24])
    remote = "Remote" if item.get("jobLocationType") == "TELECOMMUTE" else ""
    location = ld_location(item)
    return posting(
        source,
        external,
        link,
        title,
        plain(item.get("description")),
        location,
        remote or workplace(location),
        item.get("datePosted") or "",
        str(item.get("employmentType") or ""),
    )


def careers(slug, url):
    """JobPosting structured data the company publishes on its own careers page."""
    items = job_postings_ld(get(url).decode("utf-8", "replace"))
    return [job for job in (ld_posting("careers", item, url) for item in items) if job]


def gem(slug, url=""):
    jobs = []
    for item in get_json(f"https://api.gem.com/job_board/v0/{slug}/job_posts/"):
        location = (item.get("location") or {}).get("name", "")
        offices = [o["location"]["name"] for o in item.get("offices", []) if (o.get("location") or {}).get("name")]
        jobs.append(
            posting(
                "gem",
                item["id"],
                item["absolute_url"],
                item["title"],
                plain(item.get("content")),
                location,
                PLACES.get(item.get("location_type")) or workplace(location),
                item.get("first_published_at"),
                item.get("employment_type"),
                offices,
            )
        )
    return jobs


def workable(slug, url=""):
    jobs = []
    for item in get_json(f"https://apply.workable.com/api/v1/widget/accounts/{slug}?details=true")["jobs"]:
        location = ", ".join(filter(None, (item.get("city"), item.get("state"), item.get("country"))))
        jobs.append(
            posting(
                "workable",
                item["shortcode"],
                item["application_url"],
                item["title"],
                plain(item.get("description")),
                location,
                "Remote" if item.get("telecommuting") else workplace(location),
                item.get("created_at"),
                item.get("employment_type"),
            )
        )
    return jobs


def recruitee(slug, url=""):
    jobs = []
    for item in get_json(f"https://{slug}.recruitee.com/api/offers/")["offers"]:
        place = next(
            (
                name
                for flag, name in (("remote", "Remote"), ("hybrid", "Hybrid"), ("on_site", "OnSite"))
                if item.get(flag)
            ),
            "",
        )
        jobs.append(
            posting(
                "recruitee",
                item["id"],
                item["careers_apply_url"],
                item["title"],
                plain(" ".join(filter(None, (item.get("description"), item.get("requirements"))))),
                item.get("location"),
                place,
                item.get("created_at"),
                item.get("employment_type_code"),
            )
        )
    return jobs


def pinpoint(slug, url=""):
    jobs = []
    for item in get_json(f"https://{slug}.pinpointhq.com/postings.json")["data"]:
        sections = (item.get(k) for k in ("description", "key_responsibilities", "skills_knowledge_expertise"))
        jobs.append(
            posting(
                "pinpoint",
                item["id"],
                item["url"],
                item["title"],
                plain(" ".join(filter(None, sections))),
                (item.get("location") or {}).get("name"),
                PLACES.get(item.get("workplace_type"), ""),
                "",
                item.get("employment_type_text"),
            )
        )
    return jobs


def rippling(slug, url=""):
    base = f"https://ats.rippling.com/api/v2/board/{slug}/jobs"
    items = {}
    for item in get_json(f"{base}?pageSize=100")["items"]:  # one row per location, all with the same job id
        items.setdefault(item["id"], {**item, "locations": []})["locations"] += item.get("locations") or []
    detail = len(items) <= MAX_DETAIL_JOBS
    jobs = []
    for item in items.values():
        extra = get_json(f"{base}/{item['id']}") if detail else {}
        places = item["locations"] or [{}]
        names = list(dict.fromkeys(p["name"] for p in places if p.get("name")))
        jobs.append(
            posting(
                "rippling",
                item["id"],
                item["url"],
                item["name"],
                plain((extra.get("description") or {}).get("role")),
                names[0] if names else "",
                PLACES.get(str(places[0].get("workplaceType")).lower(), ""),
                extra.get("createdOn"),
                (extra.get("employmentType") or {}).get("id"),
                names,
            )
        )
    return jobs


def jazzhr(slug, url=""):
    """JazzHR has no feed: read the job links on its public board, then each job's JobPosting data."""
    ids = list(dict.fromkeys(JAZZ_LINK.findall(get(f"https://{slug}.applytojob.com/apply").decode("utf-8", "replace"))))
    jobs = []
    for job_id in ids[:MAX_DETAIL_JOBS]:
        link = f"https://{slug}.applytojob.com/apply/{job_id}"
        for item in job_postings_ld(get(link).decode("utf-8", "replace")):
            if job := ld_posting("jazzhr", item | {"identifier": job_id}, link):
                jobs.append(job)
    return jobs


ADAPTERS = {
    "greenhouse": greenhouse,
    "lever": lever,
    "ashby": ashby_board,
    "careers": careers,
    "gem": gem,
    "workable": workable,
    "recruitee": recruitee,
    "pinpoint": pinpoint,
    "rippling": rippling,
    "jazzhr": jazzhr,
}
