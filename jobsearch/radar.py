"""Fresh radar: discover startups, read their public job boards, keep every sighting in the registry.

python3 -m jobsearch.radar run           # discover, poll and report in one go (the daily command)
python3 -m jobsearch.radar discover      # HN "Who is hiring" + YC hiring companies -> companies and boards
python3 -m jobsearch.radar poll          # read every known board once; dates, reposts, absences recorded
python3 -m jobsearch.radar report        # write the shortlist
python3 -m jobsearch.radar h1b-load      # load USCIS H-1B employer exports
python3 -m jobsearch.radar worklog FILE [--apply]
"""

import argparse
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from . import h1b, hn, portfolios, shortlist, worklog
from .ashby import BOARD, Board
from .boards import ADAPTERS
from .discover import find_boards
from .fetch import SourceError, get_json
from .store import Store, stamp, utcnow

HOME = Path.home() / "arcturus-runs" / "radar"
YC_HIRING = "https://yc-oss.github.io/api/companies/hiring.json"
YC_REGIONS = {"United States of America", "Remote", "America / Canada"}
WORKERS = 8
COMMON = {"www", "com", "app", "the", "careers", "jobs", "job", "boards", "org", "net", "inc", "hq"}


def add_company(db, name, lead_source, lead_url, note=""):
    key = h1b.employer_key(name) or name.casefold()
    # The first lead source is kept; a later YC record still adds its batch note.
    db.execute(
        """INSERT INTO companies VALUES (?,?,?,?,?,?)
                  ON CONFLICT(key) DO UPDATE SET note=excluded.note WHERE excluded.note<>''""",
        (key, name, lead_source, lead_url, note, stamp(utcnow())),
    )
    return key


def matches(name, board, site=""):
    """A board found on a careers page must look like the company's own, not a VC's shared board."""
    words = set(re.findall(r"[a-z0-9]{3,}", f"{h1b.employer_key(name)} {urlsplit(site).hostname or ''}")) - COMMON
    flat = re.sub(r"[^a-z0-9]", "", board.casefold())
    return any(word in flat for word in words) or flat in re.sub(r"[^a-z0-9]", "", name.casefold())


def add_boards(db, key, found, name="", site=""):
    for source, board, how in found:
        if how == "careers page" and not matches(name, board, site):
            how = "careers page, board name differs from company: not read"
            source = f"unmatched-{source}"
        url = ""
        if source in ("careers", "careers-hand"):
            url, board = board, re.sub(r"[^a-z0-9]+", "-", urlsplit(board).hostname or "site").strip("-")[:80]
        db.execute("INSERT OR IGNORE INTO company_boards VALUES (?,?,?,?,?)", (key, source, board, url, how))


def record(store, source, board, jobs, slot):
    token = store.begin(slot, source, board.slug, utcnow())
    if token is None:
        return "already recorded"
    now = utcnow()
    return store.complete(token, board, jobs, now, live=True, observed_at=now)


def yc_leads(batch_from=2024):
    """yc-oss is an unofficial daily copy of YC's public company index: discovery leads only."""
    for company in get_json(YC_HIRING):
        year = re.search(r"\d{4}", company.get("batch") or "")
        if year and int(year.group()) >= batch_from and YC_REGIONS & set(company.get("regions", [])):
            yield company


def portfolio_leads():
    for source, url in portfolios.SOURCES.items():
        try:
            found = portfolios.leads(url)
        except SourceError as exc:
            print(f"{source}: portfolio page not read ({exc})")
            continue
        yield from ((name, url, links, [], f"vc:{source}", "") for name, links in found)


def discover(store):
    db, slot = store.db, f"discover-{uuid4().hex[:8]}"
    thread = hn.latest_thread()
    comments = hn.thread_postings(thread["objectID"])
    leads = [
        (company, job["url"], links, [], "hn", "YC (per HN post)" if re.search(r"\(YC ", job["title"]) else "")
        for job, company, links in comments
    ]
    ads = hn.job_ads()
    leads += [
        (company, job["url"], links, [], "hn-jobs", f"YC (per HN job ad): {job['title']}"[:200])
        for job, company, links in ads
    ]
    for job, company, _ in comments + ads:
        record(store, "hn", Board(f"hn{job['external_id']}", company, True), [job], slot)
    for company in yc_leads():
        site = (company.get("website") or "").rstrip("/")
        note = f"YC {company.get('batch')}, team {company.get('team_size')}: {company.get('one_liner') or ''}"
        leads.append(
            (
                company["name"],
                f"https://www.ycombinator.com/companies/{company['slug']}",
                [site, site + "/careers"] if site.startswith("https://") else [],
                [company["slug"]],
                "yc-oss",
                note[:200],
            )
        )
    leads += portfolio_leads()
    with ThreadPoolExecutor(WORKERS) as pool:
        found = list(pool.map(lambda lead: find_boards(lead[0], lead[2], extra_slugs=lead[3]), leads))
    for (name, url, links, slugs, source, note), boards in zip(leads, found):
        key = add_company(db, name, source, url, note)
        site = links[0] if links else ""
        add_boards(
            db, key, boards or ([("waas", slugs[0], "YC hiring, no public board found")] if slugs else []), name, site
        )
    print(
        f"HN thread {thread['title']}: {len(comments)} postings; HN job ads: {len(ads)}. Leads: {len(leads)}. "
        f"With a public board: {sum(1 for f in found if f)}."
    )


def poll(store):
    rows = store.db.execute(
        """SELECT b.source, b.board, b.url, c.name FROM company_boards b
                               JOIN companies c ON c.key=b.company_key WHERE b.source IN (%s)"""
        % ",".join("?" * len(ADAPTERS)),
        tuple(ADAPTERS),
    ).fetchall()
    rows = list({(r["source"], r["board"]): r for r in rows if BOARD.fullmatch(r["board"])}.values())

    def read(row):
        try:
            jobs = ADAPTERS[row["source"]](row["board"], row["url"])
            if len({job["external_id"] for job in jobs}) < len(jobs):
                raise ValueError("board returned the same job id twice")
            return jobs, None
        except (SourceError, ValueError, KeyError, TypeError) as exc:
            return None, f"{type(exc).__name__}: {exc}"[:200]

    slot, counts = f"poll-{uuid4().hex[:8]}", {}
    with ThreadPoolExecutor(WORKERS) as pool:
        results = list(pool.map(read, rows))
    for row, (jobs, error) in zip(rows, results):
        if error:
            token = store.begin(slot, row["source"], row["board"], utcnow())
            store.fail(token, error, utcnow())
            outcome = "failed"
        else:
            outcome = record(store, row["source"], Board(row["board"], row["name"][:120], True), jobs, slot)
        counts[(row["source"], outcome)] = counts.get((row["source"], outcome), 0) + 1
    for (source, outcome), count in sorted(counts.items()):
        print(f"{source}: {count} boards {outcome}")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="jobsearch.radar")
    parser.add_argument("command", choices=("run", "discover", "poll", "report", "h1b-load", "worklog"))
    parser.add_argument("file", nargs="?")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--registry", default=str(HOME / "registry.sqlite"))
    args = parser.parse_args(argv)
    Path(args.registry).parent.mkdir(parents=True, exist_ok=True)
    with closing(Store(args.registry, live_registry=True)) as store:
        if args.command in ("run", "discover"):
            discover(store)
        if args.command in ("run", "poll"):
            poll(store)
        if args.command in ("run", "report"):
            print(shortlist.write(store, Path(args.registry).parent))
        if args.command == "h1b-load":
            with store.write():
                print(f"{h1b.load(store.db)} USCIS employer rows loaded")
        if args.command == "worklog":
            return run_worklog(store, args.file, args.apply)
    return 0


def run_worklog(store, path, apply):
    if not path:
        raise SystemExit("worklog needs the work log path")
    new, duplicate = worklog.plan(store.db, path)
    for row in new:
        print(
            f"ADD  {row['status']:<10} {row['company']} {('/ ' + row['role']) if row['role'] else ''}  "
            f"[{row['source']}]"
        )
    print(f"{len(new)} to add, {len(duplicate)} already present.")
    if apply:
        with store.write():
            worklog.apply(store.db, new)
        print("Imported.")
    else:
        print("Preview only. Run again with --apply to import.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
