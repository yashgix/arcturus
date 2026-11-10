CREATE TABLE companies (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    lead_source TEXT NOT NULL,
    lead_url TEXT NOT NULL,
    note TEXT NOT NULL,
    first_seen TEXT NOT NULL
);
CREATE TABLE company_boards (
    company_key TEXT NOT NULL REFERENCES companies(key),
    source TEXT NOT NULL,
    board TEXT NOT NULL,
    url TEXT NOT NULL,
    found_by TEXT NOT NULL,
    PRIMARY KEY(source, board)
);
CREATE TABLE h1b_filings (
    fiscal_year INTEGER NOT NULL,
    employer TEXT NOT NULL,
    employer_key TEXT NOT NULL,
    initial_approvals INTEGER NOT NULL,
    continuing_approvals INTEGER NOT NULL,
    state TEXT NOT NULL,
    city TEXT NOT NULL
);
CREATE INDEX h1b_employer ON h1b_filings(employer_key);
CREATE TABLE applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_key TEXT NOT NULL,
    company TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('applied','contacted','replied','drafted','researched','unknown')),
    detail TEXT NOT NULL,
    source TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    UNIQUE(company_key, role, source)
);
PRAGMA user_version = 6;
