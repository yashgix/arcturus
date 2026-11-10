"""Offline coverage of the supervised CLI and its live snapshot policy."""

import io
import json
import os
import signal
import subprocess
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from jobsearch import dashboard
from jobsearch.__main__ import main
from jobsearch.ashby import Ashby
from jobsearch.live import ALLOWED_BOARDS
from jobsearch.ranking import Profile, rank
from jobsearch.store import Store, utcnow

from test_jobsearch import HERE, payload, posting

BOARD = ALLOWED_BOARDS["navigate-ai"]
SAVED = HERE / ".runtime/navigate-ai-live.json"


class LiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=HERE, prefix=".test-live-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "live.sqlite"
        self.cli = ["--db", str(self.path), "discover-live", "--board", BOARD.slug]
        self.feed = [posting(BOARD, key=key) for key in ("one", "two", "three")]

    def parse(self, feed):
        return Ashby([BOARD]).fixture(BOARD.slug, payload(*feed))

    def observe(self, store, slot, feed):
        token = store.begin(slot, "ashby", BOARD.slug, utcnow())
        return store.complete(token, BOARD, self.parse(feed), utcnow(), live=True)

    def command(self, *, response="apply", fetch=None):
        out = io.StringIO()
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("builtins.input", side_effect=lambda _: response) as prompt,
            patch("jobsearch.live.Ashby.fetch", side_effect=fetch) as request,
            redirect_stdout(out),
            redirect_stderr(out),
        ):
            result = main(self.cli)
        request.assert_called_once_with(BOARD.slug)
        return result, out.getvalue(), prompt.call_count

    def test_preview_cancel_and_failed_partial_response_preserve_listings(self):
        self.assertEqual(self.command(fetch=lambda _: self.parse(self.feed))[0], 0)
        changed = self.feed[:2] + [dict(self.feed[2], title="Changed Engineer")]
        result, output, prompts = self.command(response="cancel", fetch=lambda _: self.parse(changed))
        self.assertEqual((result, prompts), (0, 1))
        self.assertIn("changed: Changed Engineer [three]", output)
        adapter = Ashby([BOARD])
        result, _, prompts = self.command(fetch=lambda _: adapter.fixture(BOARD.slug, payload(partial=True)))
        self.assertEqual((result, prompts), (1, 0))
        with closing(Store(self.path)) as store:
            rows = store.inbox()
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(row["active"] for row in rows))
            self.assertNotIn("Changed Engineer", [json.loads(row["body"])["title"] for row in rows])
            self.assertEqual(store.db.execute("SELECT count(*) FROM history").fetchone()[0], 3)
            profile = Profile.load(json.loads((HERE / "live-profile.json").read_text()))
            self.assertIn(
                "current status unverified", dashboard.html(*rank(rows, profile, utcnow()), store.run_status())
            )

    def test_small_shrinkage_needs_independent_success_and_keeps_pinned_posting(self):
        with closing(Store(self.path, live_registry=True)) as store:
            self.assertEqual(self.observe(store, "first", self.feed), "complete")
            original = next(row for row in store.inbox() if row["external_id"] == "three")
            store.select(original["id"], True, utcnow(), posting_key=("ashby", BOARD.slug, "three"))
            self.assertEqual(self.observe(store, "missing", self.feed[:2]), "complete")
            self.assertIsNone(store.begin("missing", "ashby", BOARD.slug, utcnow()))
            retained = next(row for row in store.inbox() if row["id"] == original["id"])
            self.assertTrue(retained["active"] and retained["pending_absence"] and retained["selected"])
            self.assertEqual(retained["last_seen"], original["last_seen"])
            token = store.begin("failed", "ashby", BOARD.slug, utcnow())
            store.fail(token, "invalid response", utcnow())
            self.assertEqual(self.observe(store, "confirmed", self.feed[:2]), "complete")
            closed = next(row for row in store.inbox() if row["id"] == original["id"])
            self.assertFalse(closed["active"] or closed["pending_absence"])
            self.assertEqual((closed["external_id"], closed["selected"]), ("three", 1))
            self.assertEqual(store.db.execute("SELECT count(*) FROM events").fetchone()[0], 1)

    def test_newer_quarantine_fences_older_retry(self):
        with closing(Store(self.path, live_registry=True)) as store:
            self.observe(store, "initial", self.feed)
            old = store.begin("older", "ashby", BOARD.slug, utcnow())
            store.fail(old, "interrupted", utcnow())
            self.assertEqual(self.observe(store, "newer", []), "quarantined")
            changed = [dict(job, title="Stale change") for job in self.feed]
            self.assertEqual(self.observe(store, "older", changed), "stale")
            self.assertEqual(store.run_status()[0]["status"], "quarantined")
            self.assertNotIn("Stale change", [json.loads(row["body"])["title"] for row in store.inbox()])

    def test_reordered_fetch_completion_cannot_move_observation_backwards(self):
        with closing(Store(self.path, live_registry=True)) as store:
            now = utcnow()
            earlier = store.begin("earlier-start", "ashby", BOARD.slug, now)
            later = store.begin("later-start", "ashby", BOARD.slug, now + timedelta(seconds=1))
            jobs = self.parse(self.feed)
            self.assertEqual(
                store.complete(
                    earlier, BOARD, jobs, now + timedelta(seconds=4), live=True, observed_at=now + timedelta(seconds=3)
                ),
                "complete",
            )
            self.assertEqual(
                store.complete(
                    later,
                    BOARD,
                    jobs[:2],
                    now + timedelta(seconds=5),
                    live=True,
                    observed_at=now + timedelta(seconds=2),
                ),
                "stale",
            )
            self.assertTrue(all(not row["pending_absence"] for row in store.inbox()))

    def test_concurrent_apply_invalidates_operator_preview(self):
        self.assertEqual(self.command(fetch=lambda _: self.parse(self.feed))[0], 0)

        def approve(_):
            with closing(Store(self.path, live_registry=True)) as store:
                self.assertEqual(self.observe(store, "other-operator", []), "quarantined")
            return "apply"

        changed = [dict(job, title="Unapproved after race") for job in self.feed]
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("builtins.input", side_effect=approve),
            patch("jobsearch.live.Ashby.fetch", return_value=self.parse(changed)),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(self.cli), 1)
        with closing(Store(self.path)) as store:
            self.assertEqual(store.run_status()[0]["status"], "quarantined")
            self.assertEqual(store.db.execute("SELECT count(*) FROM history").fetchone()[0], 3)

    def test_live_registry_and_allowlist_guards_precede_fetch(self):
        with closing(Store(self.path)):
            pass
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("jobsearch.live.Ashby.fetch") as fetch,
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(self.cli), 1)
            other_path = self.path.with_name("fresh-live.sqlite")
            with patch("sys.stdin.isatty", return_value=False):
                self.assertEqual(main(["--db", str(other_path), *self.cli[2:]]), 1)
            self.assertFalse(other_path.exists())
            with self.assertRaises(SystemExit):
                main(self.cli[:-1] + ["other-board"])
        fetch.assert_not_called()

    def test_fixture_ingestion_cannot_write_to_live_registry(self):
        with closing(Store(self.path, live_registry=True)):
            pass
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--db", str(self.path), "ingest", "--slot", "fixture"]), 1)
        with closing(Store(self.path)) as store:
            self.assertEqual(store.run_status(), [])

    def test_reappearance_clears_a_single_miss_and_sponsorship_is_informational(self):
        with closing(Store(self.path, live_registry=True)) as store:
            modified = [dict(self.feed[0], descriptionPlain="We do not sponsor visas."), *self.feed[1:]]
            self.observe(store, "initial", modified)
            self.observe(store, "first-miss", modified[1:])
            self.observe(store, "reappears", modified)
            self.observe(store, "second-miss", modified[1:])
            profile = Profile.load(json.loads((HERE / "live-profile.json").read_text()))
            _, ranked = rank(store.inbox(), profile, utcnow(), sponsorship_informational=True)
            denied = next(row for row in ranked if row["external_id"] == "one")
            self.assertTrue(denied["pending_absence"] and denied["active"])
            self.assertIn("H-1B: sponsorship restriction wording", denied["reasons"])
            _, penalized = rank(store.inbox(), profile, utcnow())
            self.assertEqual(denied["score"] - next(row["score"] for row in penalized if row["id"] == denied["id"]), 20)

    def test_worker_reaped_on_timeout_and_interruption(self):
        worker = self.path.with_suffix(".py")
        pid_file = self.path.with_suffix(".pid")
        for interrupt in (None, signal.SIGINT, signal.SIGTERM):
            with self.subTest(interrupt=interrupt):
                notify = f"os.kill(os.getppid(), {int(interrupt)})\n" if interrupt else ""
                worker.write_text(
                    f"import os, time\nopen({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
                    + notify
                    + "time.sleep(10)\n"
                )
                with (
                    patch("sys.stdin.isatty", return_value=True),
                    patch("jobsearch.ashby.__file__", str(worker)),
                    patch("jobsearch.ashby.REQUEST_TIMEOUT", 1),
                    patch("builtins.input") as prompt,
                    redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(main(self.cli), 130 if interrupt else 1)
                prompt.assert_not_called()
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pid_file.read_text()), 0)
        with closing(Store(self.path)) as store:
            self.assertEqual(store.inbox(), [])
            self.assertEqual(store.db.execute("SELECT count(*) FROM attempts WHERE status='failed'").fetchone()[0], 3)

    def test_interrupt_between_spawn_and_ownership_reaps_worker(self):
        worker_file = self.path.with_suffix(".py")
        worker_file.write_text("import time\ntime.sleep(30)\n")
        real_popen = subprocess.Popen
        spawned = []

        def interrupt_after_spawn(*args, **kwargs):
            worker = real_popen(*args, **kwargs)
            spawned.append(worker)
            signal.raise_signal(signal.SIGTERM)
            return worker

        try:
            with (
                patch("sys.stdin.isatty", return_value=True),
                patch("jobsearch.ashby.__file__", str(worker_file)),
                patch("jobsearch.ashby.subprocess.Popen", side_effect=interrupt_after_spawn),
                patch("builtins.input") as prompt,
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(self.cli), 130)
            prompt.assert_not_called()
            self.assertEqual(len(spawned), 1)
            with self.assertRaises(ProcessLookupError):
                os.kill(spawned[0].pid, 0)
        finally:
            for worker in spawned:
                if worker.poll() is None:
                    worker.kill()
                worker.wait()

    def test_unexpected_worker_wait_failure_reaps_child(self):
        worker_file = self.path.with_suffix(".py")
        worker_file.write_text("import time\ntime.sleep(30)\n")
        real_popen = subprocess.Popen
        spawned = []

        def fail_wait(*args, **kwargs):
            worker = real_popen(*args, **kwargs)
            spawned.append(worker)

            def fail_communicate(**kwargs):
                raise OSError("injected pipe failure")

            worker.communicate = fail_communicate
            return worker

        try:
            with (
                patch("sys.stdin.isatty", return_value=True),
                patch("jobsearch.ashby.__file__", str(worker_file)),
                patch("jobsearch.ashby.subprocess.Popen", side_effect=fail_wait),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(self.cli), 1)
            self.assertEqual(len(spawned), 1)
            with self.assertRaises(ProcessLookupError):
                os.kill(spawned[0].pid, 0)
        finally:
            for worker in spawned:
                if worker.poll() is None:
                    worker.kill()
                worker.wait()

    def test_expired_preview_leaves_postings_unchanged(self):
        observed = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
        applied = observed + timedelta(days=2)
        with (
            patch("jobsearch.live.utcnow", side_effect=[observed, observed, applied]),
            patch("jobsearch.store.utcnow", return_value=applied),
        ):
            result, output, prompts = self.command(fetch=lambda _: self.parse(self.feed))
        self.assertEqual((result, prompts), (1, 1))
        self.assertIn("expired", output)
        with closing(Store(self.path)) as store:
            self.assertEqual(store.inbox(), [])
            self.assertEqual(store.db.execute("SELECT count(*) FROM history").fetchone()[0], 0)
            self.assertIsNone(store.run_status()[0]["last_success"])

    def test_expiry_checked_after_write_lock_and_observation_time_is_preserved(self):
        observed = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
        expires = observed + timedelta(seconds=120)
        approval = expires - timedelta(seconds=1)
        with closing(Store(self.path, live_registry=True)) as store:
            token = store.begin("first", "ashby", BOARD.slug, observed)
            revision = store.observation_revision("ashby", BOARD.slug)
            before = [tuple(row) for row in store.db.execute("SELECT * FROM attempts")]

            def transaction_clock():
                self.assertTrue(store.db.in_transaction)
                return expires

            with patch("jobsearch.store.utcnow", side_effect=transaction_clock):
                self.assertEqual(
                    store.complete(
                        token,
                        BOARD,
                        self.parse(self.feed),
                        approval,
                        live=True,
                        expected_revision=revision,
                        observed_at=observed,
                        expires_at=expires,
                    ),
                    "expired",
                )
            self.assertEqual([tuple(row) for row in store.db.execute("SELECT * FROM attempts")], before)
            with patch("jobsearch.store.utcnow", return_value=approval):
                self.assertEqual(
                    store.complete(
                        token,
                        BOARD,
                        self.parse(self.feed),
                        approval,
                        live=True,
                        expected_revision=revision,
                        observed_at=observed,
                        expires_at=expires,
                    ),
                    "complete",
                )
            row = store.db.execute("SELECT observed_at,finished FROM attempts").fetchone()
            self.assertEqual(tuple(map(datetime.fromisoformat, row)), (observed, approval))
            self.assertTrue(all(datetime.fromisoformat(row["last_seen"]) == observed for row in store.inbox()))
            statuses = store.run_status()
            (summary,) = statuses
            self.assertEqual(datetime.fromisoformat(summary["last_success"]), observed)
            self.assertEqual(datetime.fromisoformat(summary["finished"]), approval)
            label = f"Last successful observation: {summary['last_success']}"
            self.assertIn(label, dashboard.terminal([], [], statuses))
            self.assertIn(label, dashboard.html([], [], statuses))

    def test_sighting_during_quarantine_resets_pending_closure(self):
        with closing(Store(self.path, live_registry=True)) as store:
            self.observe(store, "initial", self.feed)
            self.assertEqual(self.observe(store, "first-miss", self.feed[:2]), "complete")
            self.assertEqual(self.observe(store, "quarantine-sighting", self.feed[2:]), "quarantined")
            self.assertEqual(self.observe(store, "new-first-miss", self.feed[:2]), "complete")
            (retained,) = [row for row in store.inbox() if row["external_id"] == "three"]
            self.assertTrue(retained["pending_absence"])
            self.assertEqual(self.observe(store, "confirmed", self.feed[:2]), "complete")
            self.assertEqual(len(store.inbox()), 2)

    def test_publication_only_regression_is_previewed_without_lowering_high_water(self):
        original = dict(self.feed[0], publishedAt="2026-10-25T12:00:00Z")
        regressed = dict(original, publishedAt="2026-10-01T12:00:00Z")
        self.assertEqual(self.command(fetch=lambda _: self.parse([original]))[0], 0)
        result, output, _ = self.command(response="cancel", fetch=lambda _: self.parse([regressed]))
        self.assertEqual(result, 0)
        self.assertIn("publication changed:", output)
        self.assertIn("2026-10-25T12:00:00+00:00 -> 2026-10-01T12:00:00+00:00", output)
        self.assertIn("first discovered=", output)
        self.assertIn("last observed=", output)
        self.assertIn("material change=", output)
        with closing(Store(self.path)) as store:
            (first,) = store.inbox()
            self.assertEqual(json.loads(first["body"])["published"], "2026-10-25T12:00:00+00:00")
        self.assertEqual(self.command(fetch=lambda _: self.parse([regressed]))[0], 0)
        with closing(Store(self.path)) as store:
            (stored,) = store.inbox()
            self.assertEqual(json.loads(stored["body"])["published"], "2026-10-01T12:00:00+00:00")
            self.assertEqual(stored["material_changed_at"], first["material_changed_at"])
            self.assertEqual(
                store.db.execute("SELECT publication_high_water FROM postings").fetchone()[0],
                "2026-10-25T12:00:00+00:00",
            )
        self.assertEqual(self.command(fetch=lambda _: self.parse([original]))[0], 0)
        with closing(Store(self.path)) as store:
            self.assertEqual([row[0] for row in store.db.execute("SELECT kind FROM history")], ["new"])

    @unittest.skipUnless(SAVED.is_file(), "operator's saved Navigate AI response is unavailable")
    def test_saved_response_replay_and_dashboard(self):
        adapter = Ashby([BOARD])
        jobs = adapter.fixture(BOARD.slug, SAVED.read_bytes())
        self.assertEqual(len(jobs), 5)
        for _ in range(2):
            result, preview, prompts = self.command(fetch=lambda _: jobs)
            self.assertEqual((result, prompts), (0, 1))
            self.assertIn("5 listed postings received", preview)
        output = self.path.with_suffix(".html")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--db", str(self.path), "inbox", "--html", str(output)]), 0)
        html = output.read_text()
        for title in ("Fullstack Engineer", "Mobile Engineer", "AI Engineer"):
            self.assertIn(title, html)
        self.assertIn("Last published: 2025-", html)
        self.assertIn("Last successfully observed:", html)
        with closing(Store(self.path)) as store:
            for table, count in (("jobs", 5), ("history", 5), ("runs", 2), ("events", 0)):
                self.assertEqual(store.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], count)
            self.assertEqual(store.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(store.db.execute("PRAGMA foreign_key_check").fetchall(), [])
