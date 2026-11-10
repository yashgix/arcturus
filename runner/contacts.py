"""Public contact points in a run's captured pages, found by pattern matching. Nothing is generated or guessed."""

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from research_sources import Retriever

EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])")
PROFILE = re.compile(r"https://(?:www\.)?(?:linkedin\.com/in/[\w%-]+|github\.com/[\w-]+|(?:x|twitter)\.com/\w+)")
NOT_EMAIL = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp)$|@(?:\d+x|example\.|sentry|wixpress|domain\.|"
    r"users\.noreply\.github\.com|ycombinator\.com)|^(?:noreply|no-reply)@",
    re.I,
)
NOT_PROFILES = {"https://github.com/HackerNews", "https://x.com/ycombinator", "https://twitter.com/ycombinator"}


def published_by_company(url, site):
    """Pages the company itself publishes: its own site and its job board. Commit metadata doesn't count."""
    host = urlsplit(url).hostname or ""
    return (
        host == site
        or host.endswith("." + site)
        or host == "api.ashbyhq.com"
        or host.endswith(("greenhouse.io", "lever.co"))
        or host == "news.ycombinator.com"
    )


def contact_points(source_dirs, site):
    """Each email or profile link with the page it was published on."""
    found = {}
    for directory in source_dirs:
        store = Retriever(directory, {}, 0)
        for item in store.state["captures"]:
            if item["http_status"] != 200 or not published_by_company(item["url"], site):
                continue
            raw = (Path(directory) / f"{item['id']}.body").read_bytes().decode("utf-8", "replace")
            values = [("email", e.lower()) for e in EMAIL.findall(raw) if not NOT_EMAIL.search(e)]
            values += [
                ("profile", p.rstrip("/"))
                for p in PROFILE.findall(raw + " " + " ".join(item["links"]))
                if p.rstrip("/") not in NOT_PROFILES
            ]
            for kind, value in values:
                found.setdefault(
                    value,
                    {
                        "kind": kind,
                        "value": value,
                        "source": item["url"],
                        "checked": item["retrieved_at"],
                        "company_domain": kind == "email"
                        and value.endswith("@" + site)
                        or kind == "email"
                        and value.split("@")[1].endswith("." + site),
                    },
                )
    return sorted(found.values(), key=lambda c: (c["kind"], not c["company_domain"], c["value"]))


def main(argv=None):
    run = Path((argv or sys.argv[1:])[0])
    manifest = json.loads((run / "run.json").read_text())
    for company in manifest["companies"]:
        site = urlsplit(f"https://{company['site']}").hostname.removeprefix("www.")
        points = contact_points(company["source_dirs"], site)
        (run / f"contacts-{company['id']}.json").write_text(json.dumps(points, indent=1) + "\n")
        print(
            f"{company['id']}: {sum(p['kind'] == 'email' for p in points)} emails, "
            f"{sum(p['kind'] == 'profile' for p in points)} profile links"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
