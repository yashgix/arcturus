CREATE TABLE legacy_postings (
    job_id TEXT PRIMARY KEY REFERENCES jobs(id),
    source TEXT NOT NULL,
    board TEXT NOT NULL,
    external_id TEXT NOT NULL,
    FOREIGN KEY(source, board, external_id) REFERENCES postings(source, board, external_id)
);
PRAGMA user_version = 3;
