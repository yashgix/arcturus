"""SQLite registry. Each source snapshot is committed as a single transaction."""

import hashlib
import json
import os
import re
import sqlite3
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

SLOT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}")


def stamp(now):
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("timestamp needs an explicit offset")
    return now.astimezone(timezone.utc).isoformat(timespec="microseconds")


def utcnow():
    return datetime.now(timezone.utc)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def normalized(text):
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def fingerprint(job):
    return digest([normalized(job[key]) for key in ("title", "location", "description")])


class Store:
    def __init__(self, path, *, live_registry=None):
        if str(path) != ":memory:":
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        try:
            with self.write():
                version = self.db.execute("PRAGMA user_version").fetchone()[0]
                application = self.db.execute("PRAGMA application_id").fetchone()[0]
                fresh = version == 0 and application == 0
                if live_registry is True and not fresh and version < 4:
                    raise ValueError("live discovery requires a fresh or designated live registry")
                if fresh:
                    if self.db.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
                        raise ValueError("database belongs to another application")
                    self._schema("schema.sql")
                    version = 1
                elif version not in (1, 2, 3, 4, 5, 6) or application != 0x41524A53:
                    raise ValueError("unsupported jobsearch schema")
                if version == 1:
                    self._schema("migrate_v2.sql")
                if version < 3:
                    self._schema("migrate_v3.sql")
                    self._separate_legacy_postings()
                if version < 4:
                    self._schema("migrate_v4.sql")
                if version < 5:
                    self._schema("migrate_v5.sql")
                    self._backfill_publication_high_water()
                if version < 6:
                    self._schema("migrate_v6.sql")
                if fresh and live_registry is True:
                    self.db.execute("INSERT INTO live_registry VALUES (1)")
                self.live_registry = bool(self.db.execute("SELECT 1 FROM live_registry").fetchone())
                if live_registry is not None and live_registry != self.live_registry:
                    raise ValueError("fixture and live discovery require separate registries")
        except BaseException:
            self.close()
            raise

    def _schema(self, filename):
        for statement in Path(__file__).with_name(filename).read_text().split(";"):
            if statement.strip():
                self.db.execute(statement)

    def _backfill_publication_high_water(self):
        dates = {}
        for row in self.db.execute(
            """SELECT source,board,external_id,body FROM postings
               UNION ALL SELECT source,board,external_id,body FROM history"""
        ):
            key = (row["source"], row["board"], row["external_id"])
            dates[key] = max(dates.get(key, ""), json.loads(row["body"])["published"])
        self.db.executemany(
            "UPDATE postings SET publication_high_water=? WHERE (source,board,external_id)=(?,?,?)",
            ((published, *key) for key, published in dates.items()),
        )

    def _separate_legacy_postings(self):
        shared = self.db.execute(
            """SELECT p.*, j.changed_at, j.material_changed_at,
                      row_number() OVER (
                        PARTITION BY p.job_id ORDER BY (pin.job_id IS NOT NULL) DESC,
                          p.first_seen,p.source,p.board,p.external_id
                      ) position
               FROM postings p JOIN jobs j ON j.id=p.job_id
               LEFT JOIN selection_postings pin ON pin.job_id=p.job_id
                 AND (pin.source,pin.board,pin.external_id)=(p.source,p.board,p.external_id)
               WHERE p.job_id IN (SELECT job_id FROM postings GROUP BY job_id HAVING count(*)>1)
                  OR (pin.job_id IS NULL AND EXISTS(
                      SELECT 1 FROM selections s WHERE s.job_id=p.job_id AND s.selected=1))
               ORDER BY p.job_id,position"""
        ).fetchall()
        for posting in shared:
            key = (posting["source"], posting["board"], posting["external_id"])
            if posting["position"] == 1:
                self.db.execute(
                    """INSERT INTO legacy_postings
                       SELECT job_id,source,board,external_id FROM selection_postings WHERE job_id=?""",
                    (posting["job_id"],),
                )
                self.db.execute("INSERT OR IGNORE INTO legacy_postings VALUES (?,?,?,?)", (posting["job_id"], *key))
            job_id = uuid4().hex
            self.db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?)",
                (
                    job_id,
                    posting["first_seen"],
                    posting["changed_at"],
                    max(posting["first_seen"], posting["material_changed_at"]),
                ),
            )
            self.db.execute(
                "INSERT INTO identities VALUES (?,?,?)",
                (normalized(posting["company"]), fingerprint(json.loads(posting["body"])), job_id),
            )
            self.db.execute("UPDATE postings SET job_id=? WHERE (source,board,external_id)=(?,?,?)", (job_id, *key))
        self.db.execute(
            """INSERT OR IGNORE INTO legacy_postings
               SELECT pin.job_id,pin.source,pin.board,pin.external_id FROM selection_postings pin
               WHERE NOT EXISTS(SELECT 1 FROM postings p WHERE p.job_id=pin.job_id)"""
        )
        self.db.execute("CREATE UNIQUE INDEX posting_identity ON postings(job_id)")

    def close(self):
        self.db.close()

    @contextmanager
    def write(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def begin(self, slot, source, board, now):
        """Return a fencing token. Explicit retry supersedes an unfinished attempt."""
        if not SLOT.fullmatch(slot):
            raise ValueError("invalid run slot")
        when = stamp(now)
        key = (slot, source, board)
        with self.write():
            self.db.execute(
                """INSERT OR IGNORE INTO runs(slot,source,board,generation)
                   SELECT ?,?,?,coalesce(max(generation),0)+1 FROM runs""",
                key,
            )
            previous = self.db.execute(
                "SELECT status FROM attempts WHERE slot=? AND source=? AND board=? ORDER BY id DESC LIMIT 1", key
            ).fetchone()
            if previous and previous["status"] in ("complete", "stale"):
                return None
            self.db.execute(
                """UPDATE attempts SET status='interrupted', finished=?
                   WHERE slot=? AND source=? AND board=? AND status='running'""",
                (when, *key),
            )
            return self.db.execute(
                "INSERT INTO attempts(slot,source,board,started,status) VALUES (?,?,?,?,'running')", (*key, when)
            ).lastrowid

    def fail(self, token, error, now):
        with self.write():
            self.db.execute(
                "UPDATE attempts SET status='failed', error=?, finished=? WHERE id=? AND status='running'",
                (error, stamp(now), token),
            )

    def observation_revision(self, source, board):
        row = self.db.execute(
            """SELECT r.generation,a.id,coalesce(a.observed_at,a.started) FROM attempts a JOIN runs r USING(slot,source,board)
               WHERE a.source=? AND a.board=? AND (a.status='complete' OR EXISTS(
                   SELECT 1 FROM quarantined_snapshots q WHERE q.attempt_id=a.id))
               ORDER BY r.generation DESC,a.id DESC LIMIT 1""",
            (source, board),
        ).fetchone()
        return tuple(row) if row else (0, 0, "")

    def complete(
        self,
        token,
        board,
        jobs,
        now,
        *,
        live=False,
        expected_revision=None,
        observed_at=None,
        expires_at=None,
        may_apply=None,
    ):
        with self.write():
            if expires_at is not None:
                now = utcnow()
                if observed_at is None or now < observed_at or now >= expires_at:
                    return "expired"
            run = self.db.execute(
                """SELECT a.*, r.generation FROM attempts a JOIN runs r USING(slot,source,board)
                   WHERE a.id=? AND a.status='running'""",
                (token,),
            ).fetchone()
            if run is None:
                return "superseded"
            if may_apply is not None and not may_apply():
                self.db.execute(
                    "UPDATE attempts SET status='interrupted',finished=?,error=? WHERE id=?",
                    (stamp(now), "coordinator paused or stopped", token),
                )
                return "interrupted"
            if run["board"] != board.slug:
                raise ValueError("attempt board mismatch")
            source, slug, seen = run["source"], board.slug, run["started"]
            finished = stamp(now)
            if observed_at is not None:
                seen = stamp(observed_at)
            verified = self.db.execute(
                """SELECT max(r.generation) FROM attempts a JOIN runs r USING(slot,source,board)
                   WHERE a.source=? AND a.board=? AND a.status='complete'""",
                (source, slug),
            ).fetchone()[0]
            generation = run["generation"]
            error = None
            revision = self.observation_revision(source, slug) if live else (verified or 0, 0, "")
            if self.live_registry and not live:
                raise ValueError("fixture ingestion is disabled for a live registry")
            if (
                revision[0] > generation
                or seen < revision[2]
                or (expected_revision is not None and revision != expected_revision)
            ):
                status = "stale"
            else:
                shrinkage = self._shrinkage(token, source, slug, jobs, generation, verified or 0) if live else None
                if shrinkage == "quarantined":
                    status, error = "failed", "suspicious feed shrinkage"
                else:
                    self._snapshot(
                        source,
                        board,
                        jobs,
                        seen,
                        token,
                        generation if live else None,
                        confirmed_shrinkage=shrinkage == "confirmed",
                    )
                    status = "complete"
            self.db.execute(
                "UPDATE attempts SET status=?, finished=?, error=?, observed_at=? WHERE id=?",
                (status, finished, error, seen if live and status != "stale" else None, token),
            )
            return "quarantined" if error else status

    def _shrinkage(self, token, source, board, jobs, generation, verified):
        active = {
            row[0]
            for row in self.db.execute(
                "SELECT external_id FROM postings WHERE source=? AND board=? AND active=1", (source, board)
            )
        }
        missing = active - {job["external_id"] for job in jobs}
        if not missing or len(missing) * 2 < len(active):
            return None
        signature = digest(sorted(missing))
        candidate = self.db.execute(
            """SELECT q.missing_hash, r.generation
               FROM quarantined_snapshots q JOIN attempts a ON a.id=q.attempt_id
               JOIN runs r USING(slot,source,board)
               WHERE a.source=? AND a.board=? AND r.generation>?
               ORDER BY r.generation DESC, a.id DESC LIMIT 1""",
            (source, board, verified),
        ).fetchone()
        if candidate and candidate["generation"] < generation and candidate["missing_hash"] == signature:
            return "confirmed"
        self.db.execute("INSERT INTO quarantined_snapshots VALUES (?,?)", (token, signature))
        # A validated sighting contradicts a prior miss, even when omissions
        # from this observation cannot safely be applied.
        self.db.executemany(
            "DELETE FROM pending_absences WHERE (source,board,external_id)=(?,?,?)",
            ((source, board, job["external_id"]) for job in jobs),
        )
        return "quarantined"

    def _snapshot(self, source, board, jobs, seen, token, generation, *, confirmed_shrinkage):
        prior = {
            row["external_id"]: row
            for row in self.db.execute("SELECT * FROM postings WHERE source=? AND board=?", (source, board.slug))
        }
        # Resolve present source IDs before new ones. When a board changes an ID,
        # classify its replacement using the post-snapshot availability.
        present = {job["external_id"] for job in jobs}
        for external_id, old in prior.items():
            key = (source, board.slug, external_id)
            if external_id not in present and old["active"]:
                if generation is not None and not confirmed_shrinkage:
                    pending = self.db.execute(
                        "SELECT generation FROM pending_absences WHERE (source,board,external_id)=(?,?,?)", key
                    ).fetchone()
                    if pending is None or pending[0] >= generation:
                        self.db.execute("INSERT OR IGNORE INTO pending_absences VALUES (?,?,?,?)", (*key, generation))
                        continue
                self.db.execute(
                    "UPDATE postings SET active=0 WHERE source=? AND board=? AND external_id=?",
                    (source, board.slug, external_id),
                )
                self._history(token, source, board.slug, external_id, "absent", old["body"])
            self.db.execute("DELETE FROM pending_absences WHERE (source,board,external_id)=(?,?,?)", key)
        for job in sorted(jobs, key=lambda item: (item["external_id"] not in prior, item["external_id"])):
            external_id = job["external_id"]
            old = prior.get(external_id)
            identity = fingerprint(job)
            if old and not job["published"]:
                job = {**job, "published": json.loads(old["body"])["published"]}
            body = encoded(job)
            content = digest(
                {key: value for key, value in job.items() if key not in ("url", "external_id", "published")}
            )
            kind = self._record(source, board, job, old, body, content, seen, identity)
            if kind:
                self._history(token, source, board.slug, external_id, kind, body)

    def _record(self, source, board, job, old, body, content, seen, identity):
        company = normalized(board.company)
        publication = job["published"]
        high_water = publication
        if old:
            job_id = old["job_id"]
            high_water = max(publication, old["publication_high_water"])
            kind = None
            previous_publication = old["publication_high_water"]
            if not old["active"]:
                kind = "returned"
            elif old["content_hash"] != content:
                kind = "changed"
            elif previous_publication and publication > previous_publication:
                kind = "repost"
            if kind:
                self.db.execute("INSERT OR IGNORE INTO identities VALUES (?,?,?)", (company, identity, job_id))
        else:
            similar_closed = self.db.execute(
                """SELECT 1 FROM identities i JOIN postings p ON p.job_id=i.job_id
                   WHERE i.company_key=? AND i.fingerprint=? AND p.source=? AND p.board=?
                     AND p.active=0 LIMIT 1""",
                (company, identity, source, board.slug),
            ).fetchone()
            job_id = uuid4().hex
            self.db.execute("INSERT INTO jobs VALUES (?,?,?,?)", (job_id, seen, seen, seen))
            self.db.execute("INSERT INTO identities VALUES (?,?,?)", (company, identity, job_id))
            kind = "repost" if similar_closed else "new"
        if kind:
            self.db.execute("UPDATE jobs SET changed_at=max(changed_at,?) WHERE id=?", (seen, job_id))
        if old and old["content_hash"] != content:
            self.db.execute("UPDATE jobs SET material_changed_at=max(material_changed_at,?) WHERE id=?", (seen, job_id))
        self.db.execute(
            """INSERT INTO postings(source,board,external_id,job_id,company,startup,body,content_hash,
                                    first_seen,last_seen,active,publication_high_water)
               VALUES (?,?,?,?,?,?,?,?,?,?,1,?)
               ON CONFLICT(source,board,external_id) DO UPDATE SET
                 company=excluded.company, startup=excluded.startup, body=excluded.body,
                 content_hash=excluded.content_hash, last_seen=excluded.last_seen, active=1,
                 publication_high_water=excluded.publication_high_water""",
            (
                source,
                board.slug,
                job["external_id"],
                job_id,
                board.company,
                board.startup,
                body,
                content,
                seen,
                seen,
                high_water,
            ),
        )
        return kind

    def _history(self, token, source, board, external_id, kind, body):
        self.db.execute("INSERT INTO history VALUES (?,?,?,?,?,?)", (token, source, board, external_id, kind, body))

    def select(self, job_id, selected, now, *, posting_key=None):
        when = stamp(now)
        with self.write():
            job = self.db.execute(
                """SELECT coalesce(s.selected,0) selected FROM jobs j
                   LEFT JOIN selections s ON s.job_id=j.id WHERE j.id=?""",
                (job_id,),
            ).fetchone()
            if job is None:
                raise ValueError("job is unknown or closed")
            if bool(job["selected"]) == selected:
                return False
            if selected:
                postings = self.db.execute(
                    """SELECT p.source,p.board,p.external_id FROM postings p WHERE p.job_id=? AND p.active=1
                       AND NOT EXISTS(SELECT 1 FROM selection_postings pin
                           WHERE (pin.source,pin.board,pin.external_id)=(p.source,p.board,p.external_id))""",
                    (job_id,),
                )
                key = next((tuple(row) for row in postings if posting_key is None or tuple(row) == posting_key), None)
                if key is None:
                    raise ValueError("job is unknown or closed")
            self.db.execute(
                """INSERT INTO selections VALUES (?,?,?) ON CONFLICT(job_id)
                   DO UPDATE SET selected=excluded.selected, updated_at=excluded.updated_at""",
                (job_id, selected, when),
            )
            if selected:
                self.db.execute("INSERT OR REPLACE INTO selection_postings VALUES (?,?,?,?)", (job_id, *key))
            else:
                self.db.execute("DELETE FROM selection_postings WHERE job_id=?", (job_id,))
            kind = "job.selected" if selected else "job.deselected"
            self.db.execute("INSERT INTO events(job_id,kind,created_at) VALUES (?,?,?)", (job_id, kind, when))
            return True

    def inbox(self):
        return self.db.execute(
            """WITH candidates AS (
                   SELECT p.job_id,p.source,p.board,p.external_id,p.company,p.startup,p.body,p.active,p.last_seen
                   FROM postings p WHERE NOT EXISTS(
                       SELECT 1 FROM selection_postings pin WHERE pin.job_id<>p.job_id
                         AND (pin.source,pin.board,pin.external_id)=(p.source,p.board,p.external_id)
                   )
                   UNION ALL
                   SELECT legacy.job_id,p.source,p.board,p.external_id,p.company,p.startup,p.body,p.active,p.last_seen
                   FROM legacy_postings legacy JOIN selections s ON s.job_id=legacy.job_id AND s.selected=1
                   JOIN postings p ON (legacy.source,legacy.board,legacy.external_id)=(p.source,p.board,p.external_id)
               )
               SELECT j.*, p.company, p.startup, p.body, p.active, p.last_seen,
                      p.source,p.board,p.external_id,coalesce(s.selected,0) selected,
                      EXISTS(SELECT 1 FROM pending_absences pending
                             WHERE (pending.source,pending.board,pending.external_id)=
                                   (p.source,p.board,p.external_id)) pending_absence,
                      s.selected=1 AND pin.job_id IS NULL selection_review,
                      EXISTS(SELECT 1 FROM identities own JOIN identities other
                               USING(company_key,fingerprint)
                             JOIN postings q ON q.job_id=other.job_id
                             WHERE own.job_id=j.id AND q.job_id<>j.id AND q.active=1
                               AND (q.source,q.board)<>(p.source,p.board)) possible_duplicate
               FROM jobs j JOIN candidates p ON p.job_id=j.id
               LEFT JOIN selection_postings pin ON pin.job_id=j.id
                   AND (pin.source,pin.board,pin.external_id)=(p.source,p.board,p.external_id)
               LEFT JOIN selections s ON s.job_id=j.id WHERE p.active=1 OR s.selected=1"""
        ).fetchall()

    def run_status(self):
        return self.db.execute(
            """WITH ranked AS (
                   SELECT a.*, row_number() OVER (
                     PARTITION BY a.source,a.board ORDER BY runs.generation DESC,a.id DESC
                   ) preference FROM attempts a JOIN runs USING(slot,source,board)
               )
               SELECT source,board,slot,
                      CASE WHEN EXISTS(SELECT 1 FROM quarantined_snapshots q WHERE q.attempt_id=r.id)
                           THEN 'quarantined' ELSE status END status,started,finished,error,
                      (SELECT max(coalesce(a.observed_at, a.finished)) FROM attempts a
                       WHERE a.source=r.source AND a.board=r.board
                       AND a.status='complete') last_success
               FROM ranked r WHERE preference=1 ORDER BY source,board"""
        ).fetchall()
