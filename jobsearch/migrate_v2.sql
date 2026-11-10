ALTER TABLE jobs ADD COLUMN material_changed_at TEXT;
UPDATE jobs SET material_changed_at=coalesce((
    SELECT max(a.started) FROM history h JOIN attempts a ON a.id=h.attempt_id
    JOIN postings p ON (p.source,p.board,p.external_id)=(h.source,h.board,h.external_id)
    WHERE p.job_id=jobs.id AND h.kind='changed'
),first_seen);

ALTER TABLE runs ADD COLUMN generation INTEGER;
UPDATE runs SET generation=rowid;
CREATE UNIQUE INDEX run_generation ON runs(generation);

CREATE TABLE selection_postings (
    job_id TEXT PRIMARY KEY REFERENCES selections(job_id),
    source TEXT NOT NULL,
    board TEXT NOT NULL,
    external_id TEXT NOT NULL,
    FOREIGN KEY(source, board, external_id) REFERENCES postings(source, board, external_id)
);
INSERT INTO selection_postings
SELECT s.job_id, p.source, p.board, p.external_id
FROM selections s JOIN postings p ON p.job_id=s.job_id
WHERE s.selected=1 AND (SELECT count(*) FROM postings q WHERE q.job_id=s.job_id)=1;

CREATE TABLE quarantined_snapshots (
    attempt_id INTEGER PRIMARY KEY REFERENCES attempts(id),
    missing_hash TEXT NOT NULL
);
PRAGMA user_version = 2;
