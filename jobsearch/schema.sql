CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    changed_at TEXT NOT NULL
);
CREATE TABLE identities (
    company_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    job_id TEXT NOT NULL REFERENCES jobs(id),
    PRIMARY KEY(company_key, fingerprint, job_id)
);

CREATE TABLE runs (
    slot TEXT NOT NULL,
    source TEXT NOT NULL,
    board TEXT NOT NULL,
    PRIMARY KEY(slot, source, board)
);
CREATE TABLE attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slot TEXT NOT NULL,
    source TEXT NOT NULL,
    board TEXT NOT NULL,
    started TEXT NOT NULL,
    finished TEXT,
    status TEXT NOT NULL CHECK(status IN ('running','interrupted','failed','complete','stale')),
    error TEXT,
    FOREIGN KEY(slot, source, board) REFERENCES runs(slot, source, board)
);
CREATE INDEX attempt_run ON attempts(slot, source, board, id);
CREATE INDEX attempt_board ON attempts(source, board, status, id);
CREATE UNIQUE INDEX active_attempt ON attempts(slot, source, board) WHERE status = 'running';

CREATE TABLE postings (
    source TEXT NOT NULL,
    board TEXT NOT NULL,
    external_id TEXT NOT NULL,
    job_id TEXT NOT NULL REFERENCES jobs(id),
    company TEXT NOT NULL,
    startup INTEGER NOT NULL CHECK(startup IN (0,1)),
    body TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    PRIMARY KEY(source, board, external_id)
);
CREATE INDEX posting_job ON postings(job_id);
CREATE TABLE history (
    attempt_id INTEGER NOT NULL REFERENCES attempts(id),
    source TEXT NOT NULL,
    board TEXT NOT NULL,
    external_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('new','duplicate','repost','changed','absent','returned')),
    body TEXT NOT NULL,
    PRIMARY KEY(attempt_id, source, board, external_id),
    FOREIGN KEY(source, board, external_id) REFERENCES postings(source, board, external_id)
);
CREATE TABLE selections (
    job_id TEXT PRIMARY KEY REFERENCES jobs(id),
    selected INTEGER NOT NULL CHECK(selected IN (0,1)),
    updated_at TEXT NOT NULL
);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id),
    kind TEXT NOT NULL CHECK(kind IN ('job.selected','job.deselected')),
    created_at TEXT NOT NULL
);
PRAGMA application_id = 0x41524A53;
PRAGMA user_version = 1;
