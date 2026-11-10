"""Free public evidence for each company in a run: site, job board, company GitHub, search discovery.

YC and h1bdata.info pages are not fetched: their terms ban automated collection. H-1B history comes from the
USCIS exports in the job-search registry instead.

No model is called and nothing is spent. Captures are content-hashed and reused by the staged research steps.
"""

import json
import re
from pathlib import Path
import sys
from urllib.parse import urlencode, urlsplit

from research_sources import SEARCH_PATHS, Retriever
from workers import WorkerFailure

SEARCH = "https://html.duckduckgo.com/html/?"
PRIORITY = (
    "career",
    "job",
    "blog",
    "engineering",
    "doc",
    "about",
    "team",
    "customer",
    "case",
    "changelog",
    "product",
    "security",
    "pricing",
)
SEARCHES = (
    "{name} startup founders",
    "{name} raises funding",
    "{name} engineering blog",
    "{name} {site} launch",
    "{name} founder technical post",
    "{name} {site} docs API integrations",
    "{name} news roadmap",
)
SITE_PAGES = 12
REPOS = 3
NOT_ORGS = {"features", "enterprise", "pricing", "about", "login", "sponsors", "topics", "orgs", "apps", "marketplace"}


def ranked(links, host):
    """Same-site pages about the company and its engineering, not catalog or listing pages."""
    same = {link for link in links if urlsplit(link).hostname in (host, "www." + host)}
    return sorted((link for link in same if any(word in urlsplit(link).path.lower() for word in PRIORITY)), key=len)


def github_orgs(pages, company):
    """Orgs listed in the run, or linked orgs whose name contains the company's name (not any linked repo)."""
    found = set(company.get("github_orgs", []))
    name = "".join(ch for ch in company["name"].casefold() if ch.isalnum())
    for page in pages:
        for link in page["links"]:
            parts = urlsplit(link)
            segments = [s for s in parts.path.split("/") if s]
            if (
                parts.hostname == "github.com"
                and segments
                and segments[0].lower() not in NOT_ORGS
                and name in segments[0].casefold().replace("-", "")
            ):
                found.add(segments[0])
    return sorted(found)


class Store(Retriever):
    """Skips URLs outside the company's public origins instead of failing the whole collection."""

    def fetch(self, url, category, *, fresh=False):
        try:
            return super().fetch(url, category, fresh=fresh)
        except ValueError:
            return {"links": [], "text": "", "gap": "outside origins", "kind": "skipped"}

    def search(self, query, category):
        """Keyless public search; result pages are fetched later as separate, cited documents."""
        page = self.fetch(SEARCH + urlencode({"q": query}), category)
        return page, [
            link for link in page["links"] if urlsplit(link).hostname not in (*SEARCH_PATHS, "duckduckgo.com")
        ]


NEVER_FETCH = re.compile(r"(^|\.)(ycombinator\.com|workatastartup\.com|h1bdata\.info)$")


class AnyPublicHost(dict):
    """Search results may lead to any public HTTPS page except YC and h1bdata.info (also on redirects); the
    connection still refuses private addresses."""

    def __contains__(self, host):
        return host == "news.ycombinator.com" or not NEVER_FETCH.search(host)

    def __missing__(self, host):
        return ["/"]


def collect(company, root, limit=150):
    store = Store(root, AnyPublicHost(), limit)
    pages = [store.fetch(seed["url"], seed["category"]) for seed in company.get("seeds", [])]
    home = store.fetch(f"https://{company['site']}/", "company")
    sitemap = store.fetch(f"https://{company['site']}/sitemap.xml", "company")
    pages += [home]
    for link in ranked(home["links"] + sitemap["links"], company["site"])[:SITE_PAGES]:
        pages.append(store.fetch(link, "company"))
    orgs = github_orgs(pages, company)
    for org in orgs:
        listing = store.fetch(f"https://api.github.com/orgs/{org}/repos?sort=pushed&per_page=30", "code")
        try:
            repos = [r for r in json.loads(listing["text"]) if not r.get("fork")][:REPOS]
        except (ValueError, TypeError, AttributeError):
            repos = []
        for repo in repos:
            name, branch = repo["full_name"], repo.get("default_branch", "main")
            store.fetch(f"https://raw.githubusercontent.com/{name}/{branch}/README.md", "code")
            for path in (
                "issues?state=all&per_page=30",
                "pulls?state=all&per_page=30",
                "commits?per_page=30",
                "releases?per_page=10",
            ):
                store.fetch(f"https://api.github.com/repos/{name}/{path}", "code")
    for query in SEARCHES:
        _, links = store.search(query.format(name=company["name"], site=company["site"]), "discovery")
        for link in links[:3]:
            store.fetch(link, "discovery")
    documents = [c for c in store.state["captures"] if c["kind"] == "document" and not c["gap"]]
    return {
        "company": company["id"],
        "attempts": store.state["attempts"],
        "captures": len(store.state["captures"]),
        "documents_with_text": len(documents),
        "github_orgs": orgs,
    }


def main(argv=None):
    run = Path((argv or sys.argv[1:])[0])
    manifest = json.loads((run / "run.json").read_text())
    for company in manifest["companies"]:
        root = run / "sources" / company["id"]
        try:
            print(json.dumps(collect(company, root)))
        except WorkerFailure as exc:
            print(json.dumps({"company": company["id"], "stopped": str(exc)}))
        if str(root) not in company["source_dirs"]:
            company["source_dirs"].append(str(root))
    (run / "run.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
