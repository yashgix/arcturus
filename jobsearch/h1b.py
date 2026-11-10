"""H-1B evidence in four separate states: explicit support, explicit refusal, historical filings, unknown.

Historical filings come from USCIS H-1B Employer Data Hub exports (official, by fiscal year). They show the
employer has filed before; they are not a promise for this role. A missing match is "unknown", never "no".
"""

import csv
import io
import re
import unicodedata

from .fetch import get
from .ranking import _sponsorship

EXPORT = "https://www.uscis.gov/sites/default/files/document/data/h1b_datahubexport-{}.csv"
YEARS = (2021, 2022, 2023)
SUFFIX = re.compile(r"\b(inc|llc|l l c|ltd|corp|corporation|co|company|pbc|plc|lp|llp|incorporated|dba .*)\b")


def employer_key(name):
    text = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode().casefold()
    text = SUFFIX.sub(" ", re.sub(r"[^a-z0-9 ]+", " ", re.sub(r"\(.*?\)", " ", text)))
    return " ".join(text.split())


def load(db, years=YEARS):
    db.execute("DELETE FROM h1b_filings WHERE fiscal_year IN (%s)" % ",".join("?" * len(years)), years)
    count = 0
    for year in years:
        rows = csv.DictReader(io.StringIO(get(EXPORT.format(year)).decode("utf-8-sig")))
        batch = [
            (
                int(r["Fiscal Year"]),
                r["Employer"],
                employer_key(r["Employer"]),
                int(r["Initial Approval"] or 0),
                int(r["Continuing Approval"] or 0),
                r["State"],
                r["City"],
            )
            for r in rows
            if r["Employer"]
        ]
        db.executemany("INSERT INTO h1b_filings VALUES (?,?,?,?,?,?,?)", batch)
        count += len(batch)
    return count


def filings(db, company):
    key = employer_key(company)
    if len(key) < 3:
        return []
    return db.execute(
        """SELECT fiscal_year, employer, initial_approvals, continuing_approvals, state, city
                         FROM h1b_filings WHERE employer_key=? ORDER BY fiscal_year""",
        (key,),
    ).fetchall()


def evidence(description, history):
    """Combine the posting's own wording with filing history, keeping the states apart."""
    wording, refused = _sponsorship(description)
    if refused:
        state = "explicit refusal"
    elif "sponsorship wording" in wording and not wording.startswith(("ambiguous", "conflicting", "uncertain")):
        state = "explicit support"
    elif history:
        state = "historical filings"
    else:
        state = "unknown"
    years = sorted({row["fiscal_year"] for row in history})
    total = sum(row["initial_approvals"] + row["continuing_approvals"] for row in history)
    detail = f"USCIS FY{years[0]}-{years[-1]}: {total} approvals ({history[0]['employer']})" if history else ""
    return {"state": state, "wording": wording, "filings": detail}
