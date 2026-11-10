"""Startup leads from VC portfolio pages and portfolio job pages whose robots.txt and terms don't ban reading them.

Checked 7 Nov 2026. Bessemer, Initialized, Techstars, YC, EF careers and the Getro and Consider job
APIs ban automated reading, so they stay hand-only and are not listed here.
"""

import re
from urllib.parse import urlsplit

from .discover import PATTERNS
from .fetch import get

SOURCES = {
    "spc": "https://www.southparkcommons.com/jobs",
    "greylock": "https://greylock.com/jobs/portfolio-jobs/",
    "khosla": "https://www.khoslaventures.com/portfolio",
    "village-global": "https://www.villageglobal.com/portfolio",
    "conviction": "https://www.conviction.com/",
    "ai-grant": "https://aigrant.com/",
}
SECOND_LEVEL = {"co", "com", "org", "net", "ac", "gov"}
HREF = re.compile(r'(?:href=|"(?:website|external_url)":\s*)"(https://[^"\\]+)"')
NOT_COMPANIES = re.compile(
    r"^x\.com$|(^|\.)(linkedin|twitter|facebook|instagram|youtube|youtu|medium|substack|github|google|apple|tiktok|"
    r"wikipedia|bloomberg|techcrunch|forbes|nytimes|wsj|reuters|cnbc|businessinsider|axios|theinformation|"
    r"podcasts|spotify|vimeo|calendly|typeform|notion|webflow|wordpress|cloudflare|gstatic|googleapis|"
    r"ashbyhq|greenhouse|lever|getro|consider|ycombinator|crunchbase|pitchbook|figma|googletagmanager|clarity|"
    r"typekit|jsdelivr|cloudfront|amazonaws|website-files|hubspot|hsforms|sentry|stanford|mit|harvard|"
    r"rippling|gem|dover|workable|comeet|recruitee|bamboohr|breezy|pinpointhq|applytojob)\.[a-z.]+$"
    r"|^(cdn|static|assets|fonts|images|img|media)\."
)


def company_sites(page, own_host):
    """Company homepages linked from a portfolio page: one per domain, outside the VC's own site and known noise."""
    sites = {}
    for url in HREF.findall(page.replace("\\/", "/")):
        host = (urlsplit(url).hostname or "").removeprefix("www.")
        if host and own_host not in host and not NOT_COMPANIES.search(host):
            sites.setdefault(host, f"https://{host}")
    return list(sites.values())


def company_name(host):
    """The domain's own label: gamma from app.gamma.ai, acme from acme.co.uk."""
    labels = host.split(".")
    return labels[-3] if len(labels) > 2 and labels[-2] in SECOND_LEVEL else labels[-2]


def board_links(page):
    """(slug, link) for each hiring-tool board linked on the page, one per board."""
    links = {}
    for kind, pattern in PATTERNS:
        if kind not in ("waas", "wellfound"):
            for match in pattern.finditer(page):
                links.setdefault((kind, match["slug"].casefold()), (match["slug"], "https://" + match.group(0)))
    return list(links.values())


def leads(url):
    """(company name, links to check) for one portfolio page: linked boards first, then company homepages."""
    page = get(url).decode("utf-8", "replace")
    own = (urlsplit(url).hostname or "").removeprefix("www.").split(".")[0]
    found = [(slug, [link]) for slug, link in board_links(page)]
    linked = {slug.casefold() for slug, _ in found}
    for site in company_sites(page, own):
        name = company_name(urlsplit(site).hostname or "")
        if name.casefold() not in linked:
            found.append((name, [site, site + "/careers"]))
    return found
