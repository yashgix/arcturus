ALTER TABLE attempts ADD COLUMN observed_at TEXT;

CREATE TABLE live_registry (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1)
);
CREATE TABLE pending_absences (
    source TEXT NOT NULL,
    board TEXT NOT NULL,
    external_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    PRIMARY KEY(source,board,external_id),
    FOREIGN KEY(source,board,external_id) REFERENCES postings(source,board,external_id)
);
PRAGMA user_version = 4;
