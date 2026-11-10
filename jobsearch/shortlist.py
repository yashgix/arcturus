"""Score role-matching postings and write the shortlist (Markdown), with an honest coverage section."""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from . import h1b
from .boards import ADAPTERS
from .store import normalized, utcnow

PROFILE = Path(__file__).with_name("radar-profile.json")
YEARS = re.compile(r"(\d{1,2})\s*\+?\s*(?:-|–|to)?\s*(?:\d{1,2})?\s*\+?\s*years?(?=[^.]{0,60}experience)", re.I)
SENIOR = re.compile(r"\b(senior|sr\.?|staff|lead)\b", re.I)
HN_VISA = re.compile(r"\bvisa\b", re.I)
HN_NO_VISA = re.compile(r"\bno (?:visa|sponsorship)\b|\bvisa:? no\b", re.I)
DATE_LABELS = {
    "original": "posted",
    "created": "created",
    "last_published": "last published",
    "site_listing": "listed on site",
}
TIER_POINTS = {"<=1 day": 30, "<=14 days": 20, "15-30 days": 8, "unknown": 0, "repost": 0, "older": -10}
PLACE_POINTS = {
    "target city": 12,
    "US remote": 10,
    "US other": 4,
    "remote, region unclear": 2,
    "unknown": 0,
    "non-US": -40,
}
H1B_POINTS = {"explicit support": 15, "historical filings": 8, "unknown": 0, "explicit refusal": -30}
YOE_POINTS = {"fit": 15, "stretch": 5, "reach": -10, "unknown": 0}
SHORTLIST, PER_COMPANY, LARGE_BOARD = 40, 2, 60
BULK_MINUTES, BULK_SIZE = 10, 3
READ = tuple(ADAPTERS)
IN_READ = ",".join("?" * len(READ))
GAPS = [
    "LinkedIn, Wellfound and X: their terms ban automated collection, so nothing is read from them. "
    "Recommended: job-alert emails from each, read from Gmail with your OK, or you browse.",
    "Work at a Startup: roles listed only there are not read (YC's terms ban robots on its site; WaaS isn't named). "
    "YC companies come in through yc-oss and are checked on their own boards and careers pages instead.",
    "VC portfolios and accelerators other than YC (a16z, Sequoia, Lightspeed, speedrun, SPC, Techstars): not in "
    "M1. Recommended next: a company list per portfolio page, then the same board check.",
    "Applicant counts: only LinkedIn shows them; not collected.",
]


def hits(terms, text):
    return [t for t in terms if re.search(r"(?<!\w)" + re.escape(t) + r"(?!\w)", text)]


def when(value):
    return datetime.fromisoformat(value) if value else None


def freshness(posting, first_seen, watching_since, now):
    """Return (tier, basis). Source dates, first-seen dates and unknown dates are never mixed."""
    kind, published = posting.get("date_kind", "last_published"), when(posting["published"])
    if published:
        age = now - published
        basis = f"{DATE_LABELS.get(kind, kind)} {published:%d %b} at source"
        if kind in ("last_published", "site_listing"):
            basis += "; original date unknown"
    elif first_seen > watching_since + timedelta(hours=1):
        age, basis = now - first_seen, f"first seen by us {first_seen:%d %b}"
    else:
        return "unknown", "no date at source; seen on our first read"
    days = age.total_seconds() / 86400
    tier = "<=1 day" if days <= 1 else "<=14 days" if days <= 14 else "15-30 days" if days <= 30 else "older"
    return tier, basis


def not_new(row, posting, first_seen):
    """Why a posting's date must not be read as a new job, or "" if nothing says so."""
    published = when(posting["published"])
    if row["repost"]:
        return "repost: the same job was open here before under another ID"
    if row["bulk"]:
        return "bulk re-publish on this board, so this date is likely not new"
    if published and first_seen and published > first_seen + timedelta(hours=1):
        return f"re-published: we first saw it {first_seen:%d %b}, before this date"
    return ""


def role_title(posting, source):
    """HN headers read "Company | Role | Location ..."; boards give the role title alone."""
    parts = posting["title"].split("|")
    return parts[1].strip() if source == "hn" and len(parts) > 1 else posting["title"]


def place(posting, profile, source):
    header = posting["title"] if source == "hn" else ""
    text = normalized(" / ".join([posting["location"], *posting["secondary"], header]))
    remote = posting["workplace"] == "Remote" or "remote" in text
    if hits(profile["target_locations"], text):
        return "target city"
    us = bool(hits(profile["us_markers"], text))
    if hits(profile["non_us_markers"], text) and not us:
        return "non-US"
    if us:
        return "US remote" if remote else "US other"
    return "remote, region unclear" if remote else "unknown"


def years_asked(description):
    found = [int(m.group(1)) for m in YEARS.finditer(description)]
    return min(found) if found else None


def sponsorship(source, posting, company, db):
    if source == "hn":
        if HN_NO_VISA.search(posting["title"]):
            return {"state": "explicit refusal", "wording": "HN header says no visa", "filings": ""}
        if HN_VISA.search(posting["title"]):
            return {"state": "explicit support", "wording": "HN header lists VISA", "filings": ""}
    return h1b.evidence(posting["description"], h1b.filings(db, company))


def assess(row, posting, profile, db, watching_since, now):
    title = role_title(posting, row["source"])
    if not hits(profile["roles"], normalized(title)) or hits(profile["excluded_titles"], normalized(title)):
        return None
    tier, basis = freshness(posting, when(row["first_seen"]), watching_since, now)
    reason = not_new(row, posting, when(row["first_seen"]))
    if reason:
        tier, basis = tier if tier == "older" else "repost", f"{reason}; {basis}"
    asked = years_asked(posting["description"])
    yoe = (
        "unknown"
        if asked is None
        else "fit"
        if asked <= profile["yoe_fit"]
        else ("stretch" if asked <= profile["yoe_stretch"] else "reach")
    )
    where, visa = place(posting, profile, row["source"]), sponsorship(row["source"], posting, row["company"], db)
    skills = hits(profile["skills"], normalized(posting["description"]))
    score = (
        40
        + TIER_POINTS[tier]
        + PLACE_POINTS[where]
        + H1B_POINTS[visa["state"]]
        + YOE_POINTS[yoe]
        + min(12, 2 * len(skills))
        + 10 * row["yc"]
        - 5 * bool(SENIOR.search(title))
        - 25 * row["large"]
    )
    return dict(
        company=row["company"],
        title=title,
        url=posting["url"],
        source=row["source"],
        tier=tier,
        basis=basis,
        place=where,
        location=posting["location"],
        yoe=yoe,
        asked=asked,
        visa=visa,
        skills=skills,
        score=score,
        repost=row["repost"],
        duplicate=bool(row["possible_duplicate"]),
        note=row["note"],
        yc=row["yc"],
        large=row["large"],
        found_by=row["found_by"],
    )


def bulk_republished(db):
    """Boards where several "last published" dates fall within minutes: a bulk re-publish, not new jobs."""
    dates = defaultdict(list)
    for r in db.execute("""SELECT source, board, json_extract(body,'$.published') FROM postings
                           WHERE active=1 AND json_extract(body,'$.date_kind')='last_published'"""):
        if r[2]:
            dates[(r[0], r[1])].append(when(r[2]))
    flagged = set()
    for key, stamps in dates.items():
        stamps.sort()
        for n in range(len(stamps) - BULK_SIZE + 1):
            if stamps[n + BULK_SIZE - 1] - stamps[n] <= timedelta(minutes=BULK_MINUTES):
                flagged |= {(key, s) for s in stamps[n : n + BULK_SIZE]}
    return flagged


def leads(db):
    return {r["key"]: dict(r) for r in db.execute("SELECT key, name, lead_source, lead_url, note FROM companies")}


def candidates(store, now):
    profile, db = json.loads(PROFILE.read_text()), store.db
    companies = leads(db)
    since = {
        (r[0], r[1]): when(r[2])
        for r in db.execute(
            "SELECT source, board, min(started) FROM attempts WHERE status='complete' GROUP BY source, board"
        )
    }
    reposts = {tuple(r) for r in db.execute("SELECT source, board, external_id FROM history WHERE kind='repost'")}
    sizes = {
        (r[0], r[1]): r[2]
        for r in db.execute("SELECT source, board, count(*) FROM postings WHERE active=1 GROUP BY source, board")
    }
    found_by = {(r[0], r[1]): r[2] for r in db.execute("SELECT source, board, found_by FROM company_boards")}
    bulk = bulk_republished(db)
    found = []
    for row in store.inbox():
        if not row["active"]:
            continue
        lead = companies.get(h1b.employer_key(row["company"]), {})
        row = dict(row) | {
            "repost": (row["source"], row["board"], row["external_id"]) in reposts,
            "note": lead.get("note", ""),
            "yc": lead.get("note", "").startswith("YC "),
            "large": sizes.get((row["source"], row["board"]), 0) > LARGE_BOARD,
            "found_by": found_by.get((row["source"], row["board"]), ""),
            "bulk": ((row["source"], row["board"]), when(json.loads(row["body"])["published"])) in bulk,
        }
        item = assess(row, json.loads(row["body"]), profile, db, since.get((row["source"], row["board"]), now), now)
        if item:
            found.append(item)
    return sorted(same_job_not_new(found), key=lambda item: -item["score"])


def same_job_not_new(items):
    """A job re-published on one board is not new on another (e.g. its careers page copies the board's date)."""
    reposted = {(h1b.employer_key(i["company"]), normalized(i["title"])) for i in items if i["tier"] == "repost"}
    for item in items:
        if (
            item["tier"] not in ("repost", "older")
            and (h1b.employer_key(item["company"]), normalized(item["title"])) in reposted
        ):
            item["score"] -= TIER_POINTS[item["tier"]]
            item["tier"], item["basis"] = "repost", f"same job is a re-publish on another board; {item['basis']}"
    return items


def history_note(db, company):
    rows = db.execute(
        "SELECT status, source FROM applications WHERE company_key=?", (h1b.employer_key(company),)
    ).fetchall()
    return "; ".join(f"Work Log: {r['status']} ({r['source']})" for r in rows)


def write(store, folder, now=None):
    now = now or utcnow()
    items = candidates(store, now)
    path = Path(folder) / f"shortlist-{now:%Y-%m-%d}.md"
    path.write_text("\n".join(table(store.db, items, now) + coverage(store.db, items)) + "\n")
    return path


def row_line(db, n, item, more):
    notes = [
        item["note"].split(":")[0] if item["yc"] else "",
        f"skills: {', '.join(item['skills'][:5])}" if item["skills"] else "",
        "possible duplicate" if item["duplicate"] else "",
        item["visa"]["filings"],
        history_note(db, item["company"]),
        f"+{more} more roles here" if more else "",
        "large company (60+ open roles)" if item["large"] else "",
        "board found by name guess: check" if item["found_by"] == "name probe" else "",
        f"via {item['source']}",
    ]
    yoe = item["yoe"] if item["asked"] is None else f"{item['yoe']} ({item['asked']}+ asked)"
    return (
        f"| {n} | {item['company']} | [{item['title'][:70]}]({item['url']}) | {item['tier']}: {item['basis']} | "
        f"{item['place']} ({item['location'][:40]}) | {yoe} | {item['visa']['state']} | "
        f"{'; '.join(filter(None, notes))} |"
    )


def table(db, items, now):
    per_company = Counter(i["company"] for i in items)
    shown, seen = [], Counter()
    for item in items:
        seen[item["company"]] += 1
        if seen[item["company"]] <= PER_COMPANY:
            shown.append(item)
    lines = [
        f"# Fresh radar shortlist, {now:%d %b %Y %H:%M} UTC",
        "",
        f"{len(items)} open postings match the target roles, at {len(per_company)} companies. Freshness: "
        + ", ".join(f"{k} {v}" for k, v in Counter(i["tier"] for i in items).most_common())
        + ".",
        "",
        f"Top {SHORTLIST}, at most {PER_COMPANY} per company. Scores favour fresh, startup, target city or US "
        "remote, 1-5 YOE and any H-1B evidence; unknown sponsorship is never a reason to drop a job.",
        "",
        "| # | Company | Role | Fresh | Where | YOE | H-1B | Notes |",
        "|---|---|---|---|---|---|---|---|",
    ]
    shown = shown[:SHORTLIST]
    last = {item["company"]: n for n, item in enumerate(shown)}
    for n, item in enumerate(shown):
        more = per_company[item["company"]] - PER_COMPANY if last[item["company"]] == n else 0
        lines.append(row_line(db, n + 1, item, max(more, 0)))
    return lines


def coverage(db, items):
    with_jobs = Counter()
    for company in {h1b.employer_key(i["company"]) for i in items}:
        source = db.execute("SELECT lead_source FROM companies WHERE key=?", (company,)).fetchone()
        with_jobs[source[0] if source else "board only"] += 1
    lines = [
        "",
        "## Coverage: where leads came from and what was verified",
        "",
        "| Lead source | Companies | With a readable board or careers data | With matching open roles |",
        "|---|---|---|---|",
    ]
    for r in db.execute(
        """SELECT c.lead_source, count(DISTINCT c.key) companies,
                                  count(DISTINCT CASE WHEN b.source IN (%s)
                                        THEN c.key END) readable
                           FROM companies c LEFT JOIN company_boards b ON b.company_key=c.key GROUP BY 1"""
        % IN_READ,
        READ,
    ):
        lines.append(f"| {r['lead_source']} | {r['companies']} | {r['readable']} | {with_jobs[r['lead_source']]} |")
    lines += ["", "| Board type | Boards | Read OK | Failed | Not readable yet |", "|---|---|---|---|---|"]
    last = {
        (r[0], r[1]): r[2]
        for r in db.execute(
            "SELECT source, board, status FROM attempts a WHERE id=(SELECT max(id) FROM attempts b "
            "WHERE (b.source,b.board)=(a.source,a.board))"
        )
    }
    for r in db.execute("SELECT source, count(*) n FROM company_boards GROUP BY source ORDER BY n DESC"):
        ok = sum(1 for (s, _), status in last.items() if s == r["source"] and status == "complete")
        failed = sum(1 for (s, _), status in last.items() if s == r["source"] and status == "failed")
        unread = r["n"] if r["source"] not in READ else 0
        lines.append(f"| {r['source']} | {r['n']} | {ok} | {failed} | {unread} |")
    return lines + yc_section(db, items) + ["", "## Gaps (not covered in M1)", ""] + [f"- {g}" for g in GAPS]


def yc_section(db, items):
    roles = defaultdict(list)
    for item in items:
        if item["yc"]:
            roles[item["company"]].append(item)
    lines = ["", f"## YC companies with matching open roles ({len(roles)})", ""]
    for company, found in sorted(roles.items(), key=lambda kv: -kv[1][0]["score"]):
        if all(item["place"] == "non-US" for item in found):
            continue
        best = found[0]
        lines.append(
            f"- **{company}** ({best['note'][:90]}): {len(found)} roles, best "
            f"[{best['title'][:60]}]({best['url']}), {best['tier']}, {best['visa']['state']}"
        )
    unverified = db.execute(
        """SELECT c.name, c.lead_url, c.note FROM companies c
                               WHERE c.lead_source='yc-oss' AND NOT EXISTS(SELECT 1 FROM company_boards b
                                 WHERE b.company_key=c.key AND b.source IN (%s))
                               ORDER BY c.note DESC"""
        % IN_READ,
        READ,
    ).fetchall()
    lines += ["", f"## YC companies hiring, roles not verified yet ({len(unverified)}): leads kept, open by hand", ""]
    lines += [f"- [{r['name']}]({r['lead_url']}/jobs): {r['note'][:110]}" for r in unverified[:60]]
    return lines
