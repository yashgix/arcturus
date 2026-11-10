import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time as wall_clock
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import date, datetime, time, timedelta, timezone
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from jobsearch import ashby, dashboard
from jobsearch.__main__ import FIXTURES, ingest, main
from jobsearch.ashby import Ashby, Board, parse
from jobsearch.ranking import Profile, rank
from jobsearch.schedule import Cadence
from jobsearch.store import Store

NOW = datetime(2026, 11, 4, 14, tzinfo=timezone.utc)
HERE = Path(__file__).resolve().parents[1]
ORBIT = Board("fixture-orbit", "Orbit", True)
ALIAS = Board("fixture-alias", "orbit", True)
VECTOR = Board("fixture-vector", "Vector", False)


def posting(board=ORBIT, key="opening-1", **overrides):
    return {
        "isListed": True,
        "title": "Backend Engineer",
        "location": "New York, NY",
        "workplaceType": "Hybrid",
        "descriptionPlain": "Python and PostgreSQL. Visa sponsorship is available.",
        "jobUrl": f"https://jobs.ashbyhq.com/{board.slug}/{key}",
    } | overrides


def payload(*items, **overrides):
    return json.dumps({"apiVersion": "1", "jobs": list(items)} | overrides).encode()


class AdapterTests(unittest.TestCase):
    def test_unlisted_and_normalization(self):
        (job,) = parse(
            ORBIT,
            payload(
                posting(
                    title="Backend\n Engineer",
                    publishedAt="2026-11-03T10:00:00-05:00",
                    secondaryLocations=[{"location": "USA"}, {"location": "USA"}],
                ),
                {"isListed": False, "descriptionHtml": "<script>ignored</script>"},
            ),
        )
        self.assertEqual(job["title"], "Backend Engineer")
        self.assertEqual(job["published"], "2026-11-03T15:00:00+00:00")
        self.assertEqual(job["secondary"], ["USA"])

    def test_null_workplace_is_unknown(self):
        (job,) = parse(ORBIT, payload(posting(workplaceType=None, isRemote=True)))
        self.assertEqual(job["workplace"], "")

    def test_rejects_invalid_and_partial_feeds(self):
        inputs = [
            b"\xff",
            b"{" * 3000,
            b'{"jobs":[],"jobs":[]}',
            b'{"x":NaN}',
            b"[]",
            payload(partial=True),
            payload(nextCursor="more"),
            payload(apiVersion="2"),
            payload(posting(), posting()),
            payload(posting(title=" ")),
            payload(posting(title="\ud800")),
            payload(posting(isListed="true")),
            payload(posting(location=None)),
            payload(posting(publishedAt="2026-11-03")),
            payload(posting(workplaceType=True)),
            payload(posting(workplaceType="Other")),
            payload(posting(secondaryLocations=["bad"])),
            payload(posting(descriptionPlain="x" * 100001)),
            payload(posting(jobUrl="https://example.org/fixture-orbit/opening-1")),
            payload(posting(jobUrl="https://jobs.ashbyhq.com/fixture-orbit/%2e%2e")),
            payload(posting(jobUrl="https://jobs.ashbyhq.com/fixture-orbit/opening-1?redirect=x")),
        ]
        for data in inputs:
            with self.subTest(data=data[:80]), self.assertRaises(ValueError):
                parse(ORBIT, data)
        with self.assertRaises(ValueError):
            Board("../elsewhere", "Example", False)

    @patch("jobsearch.ashby._fetch_worker")
    def test_network_disabled_and_board_allowlist(self, connect):
        with self.assertRaises(ValueError):
            Ashby([ORBIT]).fetch(ORBIT.slug)
        with self.assertRaises(ValueError):
            Ashby([ORBIT], network_enabled=True).fetch("other")
        connect.assert_not_called()

    def fake_response(self, connect, status, chunks, length=None, encoding="identity"):
        connection = connect.return_value
        response = connection.getresponse.return_value
        response.status = status
        response.headers = Message()
        response.headers["Content-Type"] = "application/json"
        response.headers["Content-Encoding"] = encoding
        response.headers["Location"] = "https://example.org/evil"
        response.read1.side_effect = chunks
        response.length = length
        return connection, response

    @patch("jobsearch.ashby.HTTPSConnection")
    def test_fixed_https_target_and_valid_feed(self, connect):
        data = payload(posting())
        connection, _ = self.fake_response(connect, 200, [data, b""], len(data))
        self.assertEqual(len(parse(ORBIT, ashby._download(ORBIT.slug))), 1)
        connect.assert_called_once_with("api.ashbyhq.com", timeout=5)
        self.assertEqual(connection.request.call_args.args, ("GET", "/posting-api/job-board/fixture-orbit"))
        connection.close.assert_called_once()

    @patch("jobsearch.ashby.HTTPSConnection")
    def test_redirect_oversize_truncation_and_timeout(self, connect):
        cases = [
            (302, [], None, "identity", ValueError),
            (429, [], None, "identity", ValueError),
            (200, [], ashby.MAX_BYTES + 1, "identity", ValueError),
            (200, [b"x" * (ashby.MAX_BYTES + 1)], None, "identity", ValueError),
            (200, [b""], 1, "identity", ValueError),
            (200, [], None, "gzip", ValueError),
            (200, [TimeoutError()], None, "identity", TimeoutError),
        ]
        for status, chunks, length, encoding, error in cases:
            with self.subTest(status=status, length=length, error=error):
                connect.reset_mock()
                connection, _ = self.fake_response(connect, status, chunks, length, encoding)
                with self.assertRaises(error):
                    ashby._download(ORBIT.slug)
                connect.assert_called_once()
                connection.close.assert_called_once()

    def test_process_deadline_covers_slow_headers_and_late_body(self):
        with tempfile.TemporaryDirectory(dir=HERE, prefix=".test-") as directory:
            worker = Path(directory) / "worker.py"
            marker = Path(directory) / "phase"
            for phase in ("headers", "body"):
                worker.write_text(
                    "import time, sys\n"
                    f"open({str(marker)!r}, 'w').write({phase!r})\n"
                    + ("sys.stdout.buffer.write(b'partial'); sys.stdout.flush()\n" if phase == "body" else "")
                    + "time.sleep(10)\n"
                )
                started = wall_clock.monotonic()
                with (
                    patch("jobsearch.ashby.__file__", str(worker)),
                    patch("jobsearch.ashby.REQUEST_TIMEOUT", 1),
                    self.assertRaisesRegex(TimeoutError, "deadline exceeded"),
                ):
                    Ashby([ORBIT], network_enabled=True).fetch(ORBIT.slug)
                self.assertEqual(marker.read_text(), phase)
                self.assertLess(wall_clock.monotonic() - started, 5)

    @patch("jobsearch.ashby._fetch_worker")
    def test_worker_result_is_validated_after_deadline_check(self, run):
        run.return_value = (0, payload(posting()))
        adapter = Ashby([ORBIT], network_enabled=True)
        with patch("jobsearch.ashby.time.monotonic", side_effect=[0, 14]):
            self.assertEqual(len(adapter.fetch(ORBIT.slug)), 1)
        with patch("jobsearch.ashby.time.monotonic", side_effect=[0, 21]):
            with self.assertRaises(TimeoutError):
                adapter.fetch(ORBIT.slug)


class RegistryFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=HERE, prefix=".test-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "jobs.sqlite"
        self.store = Store(self.path)
        self.addCleanup(self.store.close)

    def rows(self, sql):
        return [tuple(row) for row in self.store.db.execute(sql)]

    def commit(self, slot, *items, board=ORBIT, day=0):
        now = NOW + timedelta(days=day)
        token = self.store.begin(slot, "ashby", board.slug, now)
        if token is None:
            return None
        return self.store.complete(token, board, parse(board, payload(*items)), now)


class RegistryTests(RegistryFixture):
    def test_replay_changes_absence_and_return(self):
        self.commit("first", posting())
        (original,) = self.store.inbox()
        self.assertIsNone(self.commit("first", day=1))
        self.assertIsNone(self.commit("first", day=1))
        self.commit("second", posting(), day=1)
        self.assertEqual(self.rows("SELECT kind FROM history"), [("new",)])
        (current,) = self.store.inbox()
        self.assertEqual(current["changed_at"], original["changed_at"])
        self.assertGreater(current["last_seen"], original["last_seen"])
        changed = posting(title="Backend Engineer II")
        self.commit("third", changed, day=2)
        self.commit("missing", day=3)
        self.assertEqual(self.store.inbox(), [])
        self.commit("back", changed, day=4)
        self.assertEqual(self.store.inbox()[0]["id"], original["id"])
        self.assertEqual(
            self.rows("SELECT kind FROM history ORDER BY attempt_id"),
            [("new",), ("changed",), ("absent",), ("returned",)],
        )

    def test_dedupe_repost_and_external_id_namespace(self):
        self.commit("first", posting())
        job_id = self.store.inbox()[0]["id"]
        self.commit("first", posting(ALIAS), board=ALIAS)
        self.commit("first", posting(VECTOR), board=VECTOR)
        self.assertEqual(len(self.store.inbox()), 3)
        self.assertEqual(sum(row["possible_duplicate"] for row in self.store.inbox()), 2)
        self.commit("second", board=ALIAS, day=1)
        self.commit("second", posting(key="replacement"), day=1)
        self.assertNotIn(job_id, [row["id"] for row in self.store.inbox()])
        self.assertEqual(
            self.rows("SELECT kind FROM history ORDER BY attempt_id, external_id"),
            [("new",), ("new",), ("new",), ("absent",), ("absent",), ("repost",)],
        )

    def test_same_board_simultaneous_openings_keep_selection_link(self):
        first = posting(key="a", workplaceType="Remote")
        second = posting(key="b", workplaceType="OnSite")
        self.commit("first", first, second)
        job = next(row for row in self.store.inbox() if json.loads(row["body"])["url"] == first["jobUrl"])
        self.store.select(job["id"], True, NOW)
        self.commit("second", second, day=1)
        (selected,) = [row for row in self.store.inbox() if row["selected"]]
        self.assertEqual(json.loads(selected["body"])["url"], first["jobUrl"])
        self.assertFalse(selected["active"])
        self.assertEqual(self.rows("SELECT count(DISTINCT job_id) FROM postings"), [(2,)])

    def test_repost_keeps_selected_original_link(self):
        self.commit("first", posting(key="old"))
        job = self.store.inbox()[0]
        self.store.select(job["id"], True, NOW)
        self.commit("next", posting(key="new"), day=1)
        (pinned,) = [row for row in self.store.inbox() if row["selected"]]
        self.assertEqual(pinned["external_id"], "old")
        self.assertFalse(pinned["active"])
        (replacement,) = [row for row in self.store.inbox() if row["active"]]
        self.assertNotEqual(replacement["id"], pinned["id"])
        self.assertEqual(
            self.rows("SELECT kind FROM history ORDER BY attempt_id, kind"), [("new",), ("absent",), ("repost",)]
        )

    def test_closed_opening_id_cannot_select_similar_replacement(self):
        self.commit("first", posting(key="a"))
        original_id = self.store.inbox()[0]["id"]
        self.commit("next", posting(key="b"), day=1)
        with redirect_stderr(io.StringIO()):
            result = main(["--db", str(self.path), "select", original_id])
        self.assertEqual(result, 1)
        (replacement,) = self.store.inbox()
        self.assertNotEqual(replacement["id"], original_id)
        self.assertFalse(replacement["selected"])
        self.assertEqual(self.rows("SELECT * FROM selection_postings"), [])
        self.assertEqual(self.rows("SELECT * FROM events"), [])
        self.commit("return", posting(key="a"), posting(key="b"), day=2)
        self.assertEqual(
            {row["external_id"]: row["id"] for row in self.store.inbox()}, {"a": original_id, "b": replacement["id"]}
        )

    def test_v1_ambiguous_selection_is_flagged_and_active_openings_split(self):
        legacy = self.path.parent / "legacy.sqlite"
        with closing(sqlite3.connect(legacy)) as db:
            db.executescript((HERE / "schema.sql").read_text())
            db.execute("INSERT INTO jobs VALUES ('legacy', '2026-11-01T00:00:00+00:00', '2026-11-02T00:00:00+00:00')")
            for key in ("a", "b"):
                (body,) = parse(ORBIT, payload(posting(key=key)))
                db.execute(
                    "INSERT INTO postings VALUES (?,?,?,?,?,?,?,?,?,?,1)",
                    (
                        "ashby",
                        ORBIT.slug,
                        key,
                        "legacy",
                        ORBIT.company,
                        1,
                        json.dumps(body),
                        "hash",
                        "2026-11-01T00:00:00+00:00",
                        "2026-11-02T00:00:00+00:00",
                    ),
                )
            db.execute("INSERT INTO selections VALUES ('legacy', 1, '2026-11-02')")
            db.commit()
        with closing(Store(legacy)) as migrated:
            rows = migrated.inbox()
            self.assertEqual(len(rows), 3)
            (selected,) = [row for row in rows if row["selected"]]
            self.assertTrue(selected["selection_review"])
            selected_items, available = rank(
                rows, Profile.load(json.loads((FIXTURES / "profile.json").read_text())), NOW
            )
            report = dashboard.html(selected_items, available, [])
            selected_section = report.split("<h2>Shortlist</h2>")[0]
            self.assertIn("Selection needs review", selected_section)
            self.assertNotIn("href=", selected_section)
            self.assertTrue(migrated.select("legacy", False, NOW))
            with self.assertRaisesRegex(ValueError, "closed"):
                migrated.select("legacy", True, NOW)
            self.assertEqual(migrated.db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(migrated.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_v2_shared_id_preserves_pinned_posting_and_retires_selection_id(self):
        legacy = self.path.parent / "legacy-v2.sqlite"
        with closing(sqlite3.connect(legacy)) as db:
            for filename in ("schema.sql", "migrate_v2.sql"):
                db.executescript((HERE / filename).read_text())
            now = NOW.isoformat()
            db.execute("INSERT INTO jobs VALUES ('shared', ?, ?, ?)", (now, now, now))
            for key, active in (("a", 0), ("b", 1)):
                (body,) = parse(ORBIT, payload(posting(key=key)))
                db.execute(
                    "INSERT INTO postings VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    ("ashby", ORBIT.slug, key, "shared", ORBIT.company, 1, json.dumps(body), "hash", now, now, active),
                )
            db.execute("INSERT INTO selections VALUES ('shared', 1, ?)", (now,))
            db.execute("INSERT INTO selection_postings VALUES ('shared', 'ashby', ?, 'b')", (ORBIT.slug,))
            db.execute("INSERT INTO events(job_id,kind,created_at) VALUES ('shared','job.selected',?)", (now,))
            db.commit()
        with closing(Store(legacy)) as migrated:
            (selected,) = migrated.inbox()
            self.assertEqual(
                (selected["id"], selected["external_id"], selected["selection_review"]), ("shared", "b", 0)
            )
            self.assertTrue(migrated.select("shared", False, NOW))
            (replacement,) = migrated.inbox()
            self.assertNotEqual(replacement["id"], "shared")
            with self.assertRaisesRegex(ValueError, "closed"):
                migrated.select("shared", True, NOW)
            self.assertEqual(
                [tuple(row) for row in migrated.db.execute("SELECT job_id,kind FROM events ORDER BY id")],
                [("shared", "job.selected"), ("shared", "job.deselected")],
            )
            self.assertEqual(migrated.db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(migrated.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_retry_older_failed_slot_cannot_close_newer_snapshot(self):
        directory = self.path.parent
        fixture = directory / f"{ORBIT.slug}.json"
        boards = directory / "boards.json"
        boards.write_text(json.dumps([ORBIT.__dict__]))
        args = ["--db", str(self.path), "ingest", "--boards", str(boards), "--fixtures", str(directory)]
        for day, snapshot, result in [
            (1, payload(posting()), 0),
            (2, payload(partial=True), 1),
            (3, payload(posting(title="Backend Engineer II")), 0),
            (2, payload(), 0),
        ]:
            fixture.write_bytes(snapshot)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(args + ["--slot", f"2026-11-0{day}"]), result)
        current = self.store.inbox()
        self.assertEqual(len(current), 1)
        self.assertEqual(json.loads(current[0]["body"])["title"], "Backend Engineer II")
        self.assertEqual(
            self.rows("SELECT status FROM attempts ORDER BY id"),
            [("complete",), ("failed",), ("complete",), ("stale",)],
        )

    def test_live_shrinkage_needs_a_second_slot_and_recovery_clears_suspicion(self):
        def live(slot, day, *items):
            now = NOW + timedelta(days=day)
            token = self.store.begin(slot, "ashby", ORBIT.slug, now)
            return self.store.complete(token, ORBIT, parse(ORBIT, payload(*items)), now, live=True)

        first, second = posting(key="a"), posting(key="b", title="Platform Engineer")
        self.assertEqual(live("original", 0, first, second), "complete")
        verified = self.store.run_status()[0]["last_success"]
        self.assertEqual(live("shrink", 1, first), "quarantined")
        self.assertEqual(live("shrink", 1, first), "quarantined")
        self.assertEqual(len(self.store.inbox()), 2)
        self.assertEqual(self.store.run_status()[0]["last_success"], verified)
        self.assertEqual(self.store.run_status()[0]["status"], "quarantined")
        self.assertEqual(live("recovered", 2, first, second), "complete")
        self.assertEqual(live("empty", 3), "quarantined")
        self.assertEqual(len(self.store.inbox()), 2)
        self.assertEqual(live("confirmed", 4), "complete")
        self.assertEqual(self.store.inbox(), [])

    def test_republication_advances_freshness(self):
        self.commit("first", posting(publishedAt="2026-11-01T12:00:00Z"))
        self.commit("second", posting(publishedAt="2026-11-05T12:00:00Z"), day=1)
        self.assertEqual(self.rows("SELECT kind FROM history ORDER BY attempt_id"), [("new",), ("repost",)])
        (current,) = self.store.inbox()
        self.assertGreater(current["changed_at"], current["material_changed_at"])

    def test_failed_snapshot_does_not_mark_absent_and_can_retry(self):
        self.commit("first", posting())
        directory = self.path.parent
        fixture = directory / f"{ORBIT.slug}.json"
        fixture.write_bytes(payload(posting(), partial=True))
        with redirect_stderr(io.StringIO()):
            self.assertEqual(ingest(self.store, [ORBIT, VECTOR], directory, "second"), 1)
        self.assertEqual(len(self.store.inbox()), 1)
        self.assertEqual(self.store.run_status()[0]["status"], "failed")
        self.assertIsNotNone(self.store.run_status()[0]["last_success"])
        fixture.write_bytes(payload())
        (directory / f"{VECTOR.slug}.json").write_bytes(payload(posting(VECTOR)))
        self.assertEqual(ingest(self.store, [ORBIT, VECTOR], directory, "second"), 0)
        self.assertEqual([row["company"] for row in self.store.inbox()], ["Vector"])

    def test_partial_run_keeps_failed_board_and_commits_healthy_board(self):
        self.commit("first", posting())
        directory = self.path.parent
        (directory / f"{ORBIT.slug}.json").write_bytes(payload(partial=True))
        (directory / f"{VECTOR.slug}.json").write_bytes(payload(posting(VECTOR)))
        with redirect_stderr(io.StringIO()):
            self.assertEqual(ingest(self.store, [ORBIT, VECTOR], directory, "partial"), 1)
        self.assertCountEqual([row["company"] for row in self.store.inbox()], ["Orbit", "Vector"])
        self.assertEqual([row["status"] for row in self.store.run_status()], ["failed", "complete"])

    def test_selection_and_atomic_event_are_idempotent(self):
        self.commit("first", posting())
        key = self.store.inbox()[0]["id"]
        with self.assertRaises(ValueError):
            self.store.select("unknown", True, NOW)
        self.store.db.execute(
            "CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'test'); END"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.select(key, True, NOW)
        self.assertEqual(self.rows("SELECT * FROM selections"), [])
        self.assertEqual(self.rows("SELECT * FROM selection_postings"), [])
        self.store.db.execute("DROP TRIGGER fail_event")
        with closing(Store(self.path)) as reopened:
            self.assertTrue(reopened.select(key, True, NOW))
        self.assertFalse(self.store.select(key, True, NOW))
        self.commit("closed", day=1)
        self.assertEqual((self.store.inbox()[0]["selected"], self.store.inbox()[0]["active"]), (1, 0))
        self.assertTrue(self.store.select(key, False, NOW))
        with self.assertRaises(ValueError):
            self.store.select(key, True, NOW)
        self.assertEqual(self.rows("SELECT kind FROM events ORDER BY id"), [("job.selected",), ("job.deselected",)])

    def test_interrupted_process_rolls_back_and_retry_fences(self):
        self.commit("first", posting())
        child_code = """
import os, signal, sys
from jobsearch.ashby import Board
from jobsearch.store import Store, utcnow
store = Store(sys.argv[1])
token = store.begin('retry', 'ashby', 'fixture-orbit', utcnow())
record_history = store._history
def kill_after_history(*args):
    record_history(*args)
    os.kill(os.getpid(), signal.SIGKILL)
store._history = kill_after_history
store.complete(token, Board('fixture-orbit', 'Orbit', True), [], utcnow())
"""
        child = subprocess.run([sys.executable, "-B", "-c", child_code, str(self.path)], cwd=HERE.parent, timeout=10)
        self.assertEqual(child.returncode, -9)
        self.assertEqual(len(self.store.inbox()), 1)
        (old,) = self.rows("SELECT id FROM attempts WHERE status='running'")[0]
        self.commit("retry", posting(), day=1)
        self.assertEqual(self.store.complete(old, ORBIT, [], NOW), "superseded")
        self.assertEqual(
            self.rows("SELECT status FROM attempts ORDER BY id"), [("complete",), ("interrupted",), ("complete",)]
        )
        self.assertEqual(self.rows("PRAGMA integrity_check"), [("ok",)])
        self.assertEqual(self.rows("PRAGMA foreign_key_check"), [])

    def test_concurrent_attempts_allow_one_completion(self):
        barrier = threading.Barrier(2)

        def worker():
            with closing(Store(self.path)) as store:
                token = store.begin("shared", "ashby", ORBIT.slug, NOW)
                barrier.wait(timeout=5)
                return store.complete(token, ORBIT, parse(ORBIT, payload(posting())), NOW)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: worker(), range(2)))
        self.assertCountEqual(outcomes, ["complete", "superseded"])
        self.assertEqual(self.rows("SELECT count(*) FROM runs"), [(1,)])
        self.assertEqual(self.rows("SELECT count(*) FROM jobs"), [(1,)])

    def test_old_snapshot_cannot_reverse_new_board_state(self):
        old = self.store.begin("first", "ashby", ORBIT.slug, NOW)
        self.commit("later", posting(), day=1)
        self.assertEqual(self.store.complete(old, ORBIT, [], NOW + timedelta(days=2)), "stale")
        self.assertEqual(len(self.store.inbox()), 1)

    def test_preserves_other_database_and_enforces_foreign_keys(self):
        foreign = self.path.parent / "foreign.sqlite"
        with closing(sqlite3.connect(foreign)) as db:
            db.execute("CREATE TABLE data (x)")
        with self.assertRaises(ValueError):
            Store(foreign)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.db.execute("INSERT INTO events VALUES (1,'missing','job.selected','now')")


class InboxTests(RegistryFixture):
    def profile(self):
        return Profile.load(json.loads((FIXTURES / "profile.json").read_text()))

    def test_qualification_reason_and_deterministic_ranking(self):
        self.commit(
            "first",
            posting(key="1"),
            posting(key="2", title="Staff Backend Engineer"),
            posting(key="3", location="Berlin"),
            posting(key="4", descriptionPlain="Python. We cannot sponsor visas."),
            posting(key="5", title="Platform Engineer", descriptionPlain="Python."),
            posting(
                key="6", location="", secondaryLocations=[{"location": "United States"}], descriptionPlain="TypeScript."
            ),
        )
        rows = self.store.inbox()
        _, available = rank(rows, self.profile(), NOW)
        self.assertEqual([row["posting"]["external_id"] for row in available], ["1", "6", "5"])
        self.assertEqual(rank(reversed(rows), self.profile(), NOW)[1], available)
        self.assertIn("H-1B: general visa sponsorship wording", available[0]["reasons"])
        self.assertIn("H-1B: no explicit evidence found", available[1]["reasons"])
        old = NOW + timedelta(days=30)
        self.assertEqual(rank(rows, self.profile(), old)[1], [])
        self.assertEqual(len(rank(rows, self.profile(), old, include_older=True)[1]), 3)

    def test_negated_visa_phrase_does_not_count_as_positive_evidence(self):
        self.commit(
            "first",
            posting(descriptionPlain="No visa sponsorship is available."),
            posting(key="supported", descriptionPlain="H-1B visa sponsorship is available."),
        )
        profile = replace(self.profile(), exclude_visa_denials=False)
        _, available = rank(self.store.inbox(), profile, NOW)
        self.assertIn("H-1B: general H-1B sponsorship wording", available[0]["reasons"])
        self.assertIn("H-1B: sponsorship restriction wording", available[1]["reasons"])

    def test_sponsorship_qualifiers_and_publication_retention(self):
        self.commit(
            "first",
            posting(key="negative", descriptionPlain="We do not currently offer visa sponsorship."),
            posting(key="hedged", descriptionPlain="We may offer visa sponsorship."),
            posting(key="conflict", descriptionPlain="No visa sponsorship. We sponsor H-1B visas."),
            posting(key="generic", publishedAt="2026-11-01T12:00:00Z"),
        )
        self.commit(
            "second",
            posting(key="negative", descriptionPlain="We do not currently offer visa sponsorship."),
            posting(key="hedged", descriptionPlain="We may offer visa sponsorship."),
            posting(key="conflict", descriptionPlain="No visa sponsorship. We sponsor H-1B visas."),
            posting(key="generic"),
            day=1,
        )
        profile = replace(self.profile(), exclude_visa_denials=False)
        selected, available = rank(self.store.inbox(), profile, NOW + timedelta(days=1))
        by_key = {item["external_id"]: item for item in available}
        for key, wording in [
            ("negative", "sponsorship restriction wording"),
            ("hedged", "ambiguous sponsorship wording"),
            ("conflict", "conflicting wording"),
            ("generic", "general visa sponsorship wording"),
        ]:
            self.assertIn(f"H-1B: {wording}", by_key[key]["reasons"])
        self.assertEqual(by_key["generic"]["posting"]["published"], "2026-11-01T12:00:00+00:00")
        preview = dashboard.html(selected, available, [])
        self.assertIn("Last published: 2026-11-01", preview)
        self.assertIn("First discovered: 2026-11-04", preview)
        self.assertIn("Last material change: 2026-11-04", preview)

    def test_sponsorship_punctuation_questions_and_affirmations(self):
        cases = [
            ("We don't sponsor H-1B visas.", "sponsorship restriction wording", -20),
            ("We don’t sponsor H‑1B visas.", "sponsorship restriction wording", -20),
            ("Do you require us to sponsor H-1B visas?", "ambiguous sponsorship wording", 0),
            ("Visa sponsorship is not currently available.", "sponsorship restriction wording", -20),
            ("We cannot provide any visa sponsorship.", "sponsorship restriction wording", -20),
            ("We sponsor H-1B visas.", "general H-1B sponsorship wording", 0),
            ("We sponsor H‑1B visas. This role is not eligible for visa sponsorship.", "conflicting wording", 0),
            (
                "We sponsor H‑1B visas. H‑1B sponsorship may not be available for this role.",
                "uncertain role eligibility",
                0,
            ),
            ("H-1B sponsorship is available for this role.", "explicit role-level H-1B sponsorship wording", 0),
            ("This position is eligible for H-1B sponsorship.", "explicit role-level H-1B sponsorship wording", 0),
            ("This role is not eligible for visa sponsorship.", "sponsorship restriction wording", -20),
            ("For this role, work authorization sponsorship is not available.", "sponsorship restriction wording", -20),
            ("We offer visa sponsorship.", "general visa sponsorship wording", 0),
            ("We may sponsor H-1B visas.", "ambiguous sponsorship wording", 0),
            ("We sponsor H-1B visas, but only for current employees.", "ambiguous sponsorship wording", 0),
            ("We sponsor H-1B visas. We don't sponsor H-1B visas.", "conflicting wording", 0),
            ("We sponsor H-1B visas, but visa sponsorship is not currently available.", "conflicting wording", 0),
            ("Visa sponsorship: not currently available.", "sponsorship restriction wording", -20),
            ("The form asks applicants to confirm whether we sponsor H-1B visas.", "ambiguous sponsorship wording", 0),
        ]
        self.commit(
            "first",
            posting(key="unknown", descriptionPlain="Build internal tools."),
            *(posting(key=str(index), descriptionPlain=text) for index, (text, _, _) in enumerate(cases)),
        )
        profile = replace(self.profile(), exclude_visa_denials=False, shortlist_size=20)
        _, available = rank(self.store.inbox(), profile, NOW)
        by_key = {item["posting"]["external_id"]: item for item in available}
        for index, (text, wording, boost) in enumerate(cases):
            with self.subTest(text=text):
                row = by_key[str(index)]
                self.assertIn(f"H-1B: {wording}", row["reasons"])
                self.assertEqual(row["score"] - by_key["unknown"]["score"], boost)
        _, filtered = rank(self.store.inbox(), replace(profile, exclude_visa_denials=True), NOW)
        filtered_keys = {row["posting"]["external_id"] for row in filtered}
        self.assertEqual(
            filtered_keys, {"unknown"} | {str(index) for index, (_, _, boost) in enumerate(cases) if boost == 0}
        )

    def test_qualified_or_unrelated_sponsorship_is_neutral_with_either_filter(self):
        self.commit(
            "first",
            posting(key="baseline", descriptionPlain="Build internal tools."),
            posting(key="exception", descriptionPlain="We don’t sponsor H‑1B visas unless an exception is approved."),
            posting(key="conference", descriptionPlain="We do not sponsor conferences."),
            posting(key="role-conference", descriptionPlain="For this role, conference sponsorship is not available."),
        )
        for exclude in (False, True):
            with self.subTest(exclude_visa_denials=exclude):
                profile = replace(self.profile(), exclude_visa_denials=exclude)
                _, available = rank(self.store.inbox(), profile, NOW)
                by_key = {item["posting"]["external_id"]: item for item in available}
                self.assertEqual(set(by_key), {"baseline", "exception", "conference", "role-conference"})
                self.assertIn("H-1B: ambiguous sponsorship wording", by_key["exception"]["reasons"])
                for key in ("conference", "role-conference"):
                    self.assertIn("H-1B: no explicit evidence found", by_key[key]["reasons"])
                self.assertEqual(len({item["score"] for item in by_key.values()}), 1)

    def test_html_escaping_and_failed_publish_preserves_preview(self):
        self.commit("first", posting(title='Backend Engineer <script>alert(1)</script>'))
        selected, available = rank(self.store.inbox(), self.profile(), NOW)
        content = dashboard.html(selected, available, self.store.run_status())
        self.assertIn("&lt;script&gt;", content)
        self.assertNotIn("<script>", content)
        path = self.path.parent / "preview.html"
        dashboard.publish(path, content)
        with patch("jobsearch.dashboard.os.replace", side_effect=OSError), self.assertRaises(OSError):
            dashboard.publish(path, "replacement")
        self.assertEqual(path.read_text(), content)
        self.assertEqual({file.name for file in self.path.parent.iterdir()}, {"jobs.sqlite", "preview.html"})

    def test_cli_end_to_end(self):
        prefix = ["--db", str(self.path)]
        preview = self.path.parent / "preview.html"
        with patch("builtins.input", return_value="1"), redirect_stdout(io.StringIO()):
            self.assertEqual(main(prefix + ["ingest", "--slot", "demo"]), 0)
            self.assertEqual(main(prefix + ["ingest", "--slot", "demo"]), 0)
            self.assertEqual(main(prefix + ["inbox", "--choose", "--html", str(preview)]), 0)
        self.assertEqual(self.rows("SELECT kind FROM events"), [("job.selected",)])
        self.assertEqual(self.rows("SELECT count(*) FROM attempts"), [(2,)])
        self.assertIn("Selected", preview.read_text())
        self.assertIn("fixture-orbit", preview.read_text())


class ScheduleTests(unittest.TestCase):
    def test_interval_wake_and_before_anchor(self):
        cadence = Cadence("shortlist", "America/New_York", date(2026, 11, 4), time(9), 2)
        self.assertIsNone(cadence.due_slot(NOW - timedelta(seconds=1)))
        self.assertEqual(cadence.due_slot(NOW), "shortlist:2026-11-04")
        self.assertEqual(cadence.due_slot(NOW + timedelta(days=3)), "shortlist:2026-11-06")

    def test_cli_cadence_skips_until_due_and_replays_once_due(self):
        with tempfile.TemporaryDirectory(dir=HERE, prefix=".test-") as name:
            db = Path(name) / "jobs.sqlite"
            args = ["--db", str(db), "ingest", "--cadence", str(FIXTURES / "cadence.json")]
            with patch("jobsearch.__main__.utcnow", return_value=NOW - timedelta(seconds=1)):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main(args), 0)
                self.assertFalse(db.exists())
            with patch("jobsearch.__main__.utcnow", return_value=NOW):
                self.assertEqual(main(args), 0)
                self.assertEqual(main(args), 0)
            with closing(Store(db)) as store:
                self.assertEqual([row["slot"] for row in store.run_status()], ["fixture-shortlist:2026-11-04"] * 2)
                self.assertEqual(store.db.execute("SELECT count(*) FROM attempts").fetchone()[0], 2)

    def test_repeated_clock_hour_does_not_reverse_slot(self):
        cadence = Cadence("shortlist", "America/New_York", date(2026, 11, 1), time(1, 30), 1)
        for hour, minute in [(5, 30), (6, 0), (6, 30)]:
            self.assertEqual(
                cadence.due_slot(datetime(2026, 11, 1, hour, minute, tzinfo=timezone.utc)), "shortlist:2026-11-01"
            )
