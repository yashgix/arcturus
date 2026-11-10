CREATE TABLE IF NOT EXISTS research_control (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    state TEXT NOT NULL CHECK(state IN ('running','paused','stopped'))
);
INSERT OR IGNORE INTO research_control VALUES (1,'paused');

CREATE TABLE IF NOT EXISTS research_tasks (
    id INTEGER PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id),
    version TEXT NOT NULL,
    posting_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('queued','running','ready','failed','superseded')),
    due_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    lease_until TEXT,
    claim INTEGER,
    error TEXT,
    packet TEXT,
    deferred INTEGER NOT NULL DEFAULT 0 CHECK(deferred IN (0,1)),
    UNIQUE(job_id, version)
);

CREATE TABLE IF NOT EXISTS research_attempts (
    id INTEGER PRIMARY KEY,
    task_id INTEGER NOT NULL REFERENCES research_tasks(id),
    utc_day TEXT NOT NULL,
    started TEXT NOT NULL,
    reserved_microusd INTEGER NOT NULL,
    charged_microusd INTEGER,
    outcome TEXT NOT NULL CHECK(outcome IN ('running','ready','failed','interrupted'))
);
CREATE INDEX IF NOT EXISTS research_attempts_day ON research_attempts(utc_day);
CREATE INDEX IF NOT EXISTS research_tasks_due ON research_tasks(state,due_at,id);

CREATE TABLE IF NOT EXISTS research_current (
    job_id TEXT PRIMARY KEY REFERENCES jobs(id),
    task_id INTEGER NOT NULL UNIQUE REFERENCES research_tasks(id) ON DELETE CASCADE
);
