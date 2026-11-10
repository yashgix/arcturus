"""Import a job-search work log (Markdown table) into the registry: historical status, verbatim detail, source line.

Statuses are read conservatively: anything unconfirmed stays "researched" or "unknown", never "applied".
"""

import re
from pathlib import Path

from .h1b import employer_key
from .store import stamp, utcnow

DATED = re.compile(r"^- \*\*(\d{4}-\d{2}-\d{2}) \| ([^|]+) \| ([^|]+) \|(.*)$")
OTHERS = re.compile(r"^\*\*Others appearing in earlier research[^:]*:\*\*\s*(.+)$")
UNCONFIRMED = re.compile(
    r"not confirmed|unverified|unknown|unclear|not explicitly|not proof|unconfirmed|"
    r"not applied|not (?:yet )?sent",
    re.I,
)
APPLIED = re.compile(r"\bapplied\b(?! ai)", re.I)
NOT_COMPANIES = re.compile(r"^(arcturus|job search|salus bridge)\b", re.I)


def status(text):
    if UNCONFIRMED.search(text):
        return "drafted" if re.search(r"\bdraft", text, re.I) else "researched"
    if APPLIED.search(text):
        return "applied"
    if re.search(r"\bsent\b|\bemailed\b|\bconnected with\b|outreach", text, re.I):
        return "contacted"
    if re.search(r"\bdraft", text, re.I):
        return "drafted"
    if re.search(r"research|considered|evaluated|tailored|fit", text, re.I):
        return "researched"
    return "unknown"


def dated_target(cell):
    """Dated entries read "Company / role" or "Company, role"."""
    name, _, role = cell.partition("," if "," in cell else " / ")
    return name.strip(), role.strip()


def table_targets(cell):
    """Table cells read "Company, role" or list several companies as "A / B"."""
    name, _, role = re.sub(r"\*\*", "", cell).partition(",")
    return [(part.strip(), role.strip()) for part in name.split(" / ") if part.strip()]


def rows(line):
    """Yield (company, role, status, detail) for one log line."""
    dated, others = DATED.match(line), OTHERS.match(line)
    if dated:
        name, role = dated_target(dated.group(2))
        yield name, role, status(dated.group(3)), line.strip("- *")
    elif others:
        for name in others.group(1).split(". ")[0].split(","):
            yield name.strip(), "", "unknown", "Appeared in earlier research; status unknown"
    elif line.startswith("| ") and not line.startswith(("| Company", "| Label", "|---")):
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) >= 2 and cells[0]:
            for name, role in table_targets(cells[0]):
                yield name, role, status(" ".join(cells[1:])), " | ".join(cells[1:])


def entries(path):
    path = Path(path)
    for number, line in enumerate(path.read_text().splitlines(), 1):
        for name, role, state, detail in rows(line):
            if name and not NOT_COMPANIES.match(name):
                yield dict(company=name, role=role, status=state, detail=detail, source=f"{path.name}:{number}")


def plan(db, path):
    """Split the log into rows to add and rows already present.

    Present means the same company, role and status; a row with no role matches any role at that company."""
    present = {tuple(row) for row in db.execute("SELECT company_key, role, status FROM applications")}
    new, duplicate = [], []
    for entry in entries(path):
        company, role, state = employer_key(entry["company"]), entry["role"].casefold(), entry["status"]
        seen = (company, role, state) in present or (
            not role and any((c, s) == (company, state) for c, _, s in present)
        )
        (duplicate if seen else new).append(entry)
        present.add((company, role, state))
    return new, duplicate


def apply(db, rows):
    now = stamp(utcnow())
    db.executemany(
        """INSERT OR IGNORE INTO applications(company_key,company,role,status,detail,source,recorded_at)
                      VALUES (?,?,?,?,?,?,?)""",
        [
            (employer_key(r["company"]), r["company"], r["role"].casefold(), r["status"], r["detail"], r["source"], now)
            for r in rows
        ],
    )
