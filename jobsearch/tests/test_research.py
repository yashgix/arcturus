"""Offline coordinator, restart, and evidence regressions."""

import json
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from jobsearch import research
from jobsearch.candidate import load_profile
from jobsearch.ranking import Profile
from jobsearch.research_model import DeepSeek, ModelResult, fixture_transport

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURES = PACKAGE / "fixtures" / "research"
NOW = datetime(2026, 11, 3, 18, tzinfo=timezone.utc)
DEMO_ID = "offline-demo-engineer"


class ResearchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=PACKAGE, prefix=".test-research-")
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.db = self.folder / "research.sqlite"
        self.feed = research.read(FIXTURES / "navigate-ai.json")
        self.config = research.settings(research.read(FIXTURES / "config.json"))
        self.candidate = load_profile(research.read(FIXTURES / "candidate.json"))
        self.profile = Profile.load(research.read(PACKAGE / "live-profile.json"))
        self.responses = research.read(FIXTURES / "responses.json")
        self.write_feed()
        research.initialize(self.db)
        self.store = research.open_registry(self.db)
        self.addCleanup(self.store.close)

    def write_feed(self):
        (self.folder / "navigate-ai.json").write_text(json.dumps(self.feed))

    def run_tick(self, now=NOW, *, model=None, evidence=None):
        if model is None:
            model = DeepSeek("deepseek-chat", fixture_transport(self.responses))
        research.tick(
            self.store, self.config, self.folder, self.profile, self.candidate, evidence or {}, model, clock=lambda: now
        )

    def rows(self, query):
        return [tuple(row) for row in self.store.db.execute(query)]

    @patch("jobsearch.research.Ashby.fetch", side_effect=AssertionError("unexpected network"))
    def test_due_discovery_replays_and_report_has_separate_review_fields(self, fetch):
        self.run_tick()
        self.assertEqual(self.rows("SELECT count(*) FROM runs"), [(0,)])
        research.change_state(self.store, "running")
        self.run_tick()
        self.run_tick(NOW + timedelta(minutes=1))
        self.assertEqual(self.rows("SELECT count(*) FROM runs"), [(1,)])
        self.assertEqual(self.rows("SELECT count(*) FROM jobs"), [(1,)])
        self.assertEqual(self.rows("SELECT state,attempts FROM research_tasks"), [("ready", 1)])
        self.assertEqual(self.rows("SELECT charged_microusd FROM research_attempts"), [(0,)])
        (packet,) = self.rows("SELECT packet FROM research_tasks")[0]
        packet = json.loads(packet)
        self.assertEqual(packet["candidate"]["mode"], "synthetic")
        self.assertEqual(packet["draft"]["technical_fit"]["score"], 70)
        self.assertEqual(packet["draft"]["seniority_fit"]["score"], 40)
        self.assertEqual(packet["location_constraints"]["matched_terms"], ["nyc"])
        self.assertEqual(packet["sponsorship"]["current"], "unknown")
        self.assertNotIn("Example project A", json.dumps(packet))
        report = self.folder / "report.html"
        research.report(self.db, report)
        html = report.read_text()
        for label in ("Prepared opportunities", "Cost ledger", "synthetic", "draft_answers"):
            self.assertIn(label, html)
        self.assertEqual(self.rows("PRAGMA integrity_check"), [("ok",)])
        self.assertEqual(self.rows("PRAGMA foreign_key_check"), [])
        fetch.assert_not_called()

    def test_changed_posting_gets_new_packet_and_stop_blocks_work(self):
        research.change_state(self.store, "running")
        self.run_tick()
        (original,) = self.rows("SELECT id FROM jobs")
        self.feed["jobs"][0]["descriptionPlain"] += " Build evaluation tooling."
        self.write_feed()
        research.change_state(self.store, "stopped")
        self.run_tick(NOW + timedelta(days=1))
        self.assertEqual(self.rows("SELECT count(*) FROM runs"), [(1,)])
        research.change_state(self.store, "running")
        self.run_tick(NOW + timedelta(days=1))
        self.assertEqual(self.rows("SELECT id FROM jobs"), [original])
        self.assertEqual(self.rows("SELECT count(*) FROM research_tasks WHERE state='ready'"), [(2,)])
        self.assertEqual(self.rows("SELECT kind FROM history ORDER BY attempt_id"), [("new",), ("changed",)])

    def test_failed_job_backs_off_without_stopping_peer(self):
        other = {
            **self.feed["jobs"][0],
            "jobUrl": "https://jobs.ashbyhq.com/navigate-ai/peer",
            "title": "Backend Engineer Peer",
        }
        self.feed["jobs"].append(other)
        self.write_feed()
        self.responses["peer"] = self.responses[DEMO_ID]
        correct = self.responses.pop(DEMO_ID)
        research.change_state(self.store, "running")
        self.run_tick()
        self.assertEqual(
            self.rows("SELECT state,attempts FROM research_tasks ORDER BY state"), [("queued", 1), ("ready", 1)]
        )
        self.responses[DEMO_ID] = correct
        self.run_tick(NOW + timedelta(seconds=29))
        self.assertEqual(self.rows("SELECT count(*) FROM research_attempts"), [(2,)])
        self.run_tick(NOW + timedelta(seconds=30))
        self.assertEqual(self.rows("SELECT count(*) FROM research_tasks WHERE state='ready'"), [(2,)])

    def test_restart_retains_reservation_and_fences_late_worker(self):
        research.change_state(self.store, "running")
        research.discover(self.store, self.config, self.folder, NOW)
        row = self.store.inbox()[0]
        ranked = dict(row) | {"posting": json.loads(row["body"])}
        (task_id,) = research.enqueue(self.store, [ranked], self.candidate, {}, NOW)
        old = research.claim(self.store, task_id, self.config, NOW)
        self.assertIsNotNone(old)
        with closing(research.open_registry(self.db)) as reopened:
            recovered = NOW + timedelta(seconds=research.LEASE_SECONDS)
            research.recover(reopened, self.config, recovered)
            research.finish(reopened, task_id, old, self.config, recovered, packet={"late": True}, charge=0)
            self.assertIsNone(research.claim(reopened, task_id, self.config, recovered))
            new = research.claim(reopened, task_id, self.config, recovered + timedelta(seconds=30))
            self.assertNotEqual(old, new)
            self.assertIsNotNone(new)
        self.assertEqual(
            self.rows("SELECT outcome,charged_microusd FROM research_attempts ORDER BY id"),
            [("interrupted", 0), ("running", None)],
        )

    def test_daily_spend_and_request_caps_are_enforced_before_dispatch(self):
        for kind in ("requests", "spend"):
            with self.subTest(kind=kind):
                self.store.db.execute("DELETE FROM research_attempts")
                self.store.db.execute("DELETE FROM research_tasks")
                self.config["daily_requests"] = 1 if kind == "requests" else 10
                self.config["daily_microusd"] = 1000 if kind == "spend" else 5000
                research.change_state(self.store, "running")

                class Uncertain:
                    calls = 0

                    def generate(self, context):
                        self.calls += 1
                        raise TimeoutError("uncertain receipt")

                model = Uncertain()
                self.run_tick(model=model)
                self.run_tick(NOW + timedelta(minutes=2), model=model)
                self.assertEqual(model.calls, 1)
                self.assertEqual(
                    self.rows("SELECT reserved_microusd,charged_microusd FROM research_attempts"), [(1000, None)]
                )

    def test_over_ceiling_cost_pauses_and_preserves_actual_charge(self):
        research.change_state(self.store, "running")

        class BrokenReceipt:
            def generate(self, context):
                return ModelResult({}, 1001)

        self.run_tick(model=BrokenReceipt())
        self.assertEqual(research.state(self.store.db), "paused")
        self.assertEqual(self.rows("SELECT charged_microusd FROM research_attempts"), [(1001,)])

    def test_sponsorship_provenance_and_invalid_model_references(self):
        evidence = {
            f"navigate-ai/{DEMO_ID}": [
                {
                    "kind": "verified_role_restriction",
                    "url": "https://example.org/role",
                    "date": "2026-11-03",
                    "excerpt": "This role is not eligible for visa sponsorship.",
                },
                {
                    "kind": "historical_sponsorship",
                    "url": "https://example.org/history",
                    "date": "2025-10-15",
                    "excerpt": "Synthetic historical employer filing.",
                },
            ]
        }
        research.change_state(self.store, "running")
        self.run_tick(evidence=evidence)
        packet = json.loads(self.rows("SELECT packet FROM research_tasks")[0][0])
        self.assertEqual(
            packet["sponsorship"],
            {
                "current": "confirmed_restriction",
                "restriction_sources": ["evidence-1"],
                "historical_sources": ["evidence-2"],
            },
        )
        self.responses[DEMO_ID]["technical_fit"]["fact_ids"] = ["invented-experience"]
        self.feed["jobs"][0]["descriptionPlain"] += " New requirement."
        self.write_feed()
        self.run_tick(NOW + timedelta(days=1), evidence=evidence)
        self.assertEqual(self.rows("SELECT state FROM research_tasks ORDER BY id"), [("ready",), ("queued",)])

    def test_live_gate_and_allowlist_fail_closed(self):
        raw = research.read(FIXTURES / "config.json")
        raw["boards"] = ["unapproved"]
        with self.assertRaisesRegex(ValueError, "allowlisted"):
            research.settings(raw)
        self.candidate["mode"] = "operator_verified"
        research.change_state(self.store, "running")
        with self.assertRaisesRegex(ValueError, "synthetic"):
            self.run_tick()
        self.assertEqual(self.rows("SELECT count(*) FROM runs"), [(0,)])

    def test_only_verified_variant_facts_are_sent_to_the_mock(self):
        self.candidate["facts"]["unverified"] = {
            "claim": "Unverified synthetic claim",
            "verified": False,
            "technologies": [],
            "metrics": [],
            "source_refs": ["demo-swe"],
        }
        self.candidate["variants"]["swe"].append("unverified")
        captured = []
        transport = fixture_transport(self.responses)

        def capture(request):
            captured.append(json.loads(request["messages"][-1]["content"]))
            return transport(request)

        research.change_state(self.store, "running")
        self.run_tick(model=DeepSeek("deepseek-chat", capture))
        (context,) = captured
        self.assertNotIn("unverified", context["resume_facts"])
        self.assertNotIn("unverified", context["candidate"]["variants"]["swe"])
        self.assertNotIn("Example project A", json.dumps(context))
        self.assertEqual(context["resume_facts"]["example-api"]["source_refs"], ["demo-swe"])

    def test_second_coordinator_cannot_run_and_dashboard_does_not_write_registry(self):
        with research.coordinator(self.db):
            with self.assertRaisesRegex(ValueError, "already owns"):
                with research.coordinator(self.db):
                    self.fail("a second coordinator acquired the lock")
        research.change_state(self.store, "running")
        self.run_tick()
        before = self.db.read_bytes()
        research.report(self.db, self.folder / "inbox.html")
        self.assertEqual(self.db.read_bytes(), before)

    def test_queued_work_defers_then_supersedes_on_confirmed_closure(self):
        research.change_state(self.store, "running")
        self.responses.clear()
        self.run_tick()
        self.assertEqual(self.rows("SELECT state,deferred,attempts FROM research_tasks"), [("queued", 0, 1)])
        self.feed["jobs"] = []
        self.write_feed()
        self.run_tick(NOW + timedelta(days=1))
        self.assertEqual(self.store.run_status()[0]["status"], "quarantined")
        self.assertEqual(self.rows("SELECT state,deferred,attempts FROM research_tasks"), [("queued", 1, 1)])
        report = self.folder / "deferred.html"
        research.report(self.db, report)
        self.assertIn("&quot;deferred&quot;: 1", report.read_text())
        self.run_tick(NOW + timedelta(days=2))
        self.assertEqual(self.rows("SELECT active FROM postings"), [(0,)])
        self.assertEqual(self.rows("SELECT state,deferred,attempts FROM research_tasks"), [("superseded", 0, 1)])

    def test_reverted_posting_uses_original_ready_packet_as_current(self):
        research.change_state(self.store, "running")
        original = self.feed["jobs"][0]["descriptionPlain"]
        self.run_tick()
        (first,) = self.rows("SELECT task_id FROM research_current")[0]
        self.feed["jobs"][0]["descriptionPlain"] = original + " New version."
        self.write_feed()
        self.run_tick(NOW + timedelta(days=1))
        (second,) = self.rows("SELECT task_id FROM research_current")[0]
        self.assertNotEqual(first, second)
        self.feed["jobs"][0]["descriptionPlain"] = original
        self.write_feed()
        self.run_tick(NOW + timedelta(days=2))
        self.assertEqual(self.rows("SELECT task_id FROM research_current"), [(first,)])
        self.assertEqual(self.rows("SELECT count(*) FROM research_attempts"), [(2,)])
        report = self.folder / "versions.html"
        research.report(self.db, report)
        original, latest = report.read_text().split("<article>")[1:]
        self.assertIn("Current posting", original)
        self.assertIn("Historical or unverified", latest)

    def test_malformed_unicode_cannot_publish_but_legacy_packet_renders(self):
        research.change_state(self.store, "running")
        self.responses[DEMO_ID]["role"]["text"] = "invalid \ud800"
        self.run_tick()
        self.assertEqual(self.rows("SELECT state,packet FROM research_tasks"), [("queued", None)])
        self.assertEqual(self.rows("SELECT charged_microusd FROM research_attempts"), [(0,)])
        self.responses[DEMO_ID]["role"]["text"] = "valid text"
        self.run_tick(NOW + timedelta(seconds=30))
        packet = json.loads(self.rows("SELECT packet FROM research_tasks")[0][0])
        packet["title"] = "legacy \ud800"
        packet["draft"]["role"]["text"] = "legacy detail \udfff"
        self.store.db.execute("UPDATE research_tasks SET packet=?", (json.dumps(packet),))
        report = self.folder / "legacy.html"
        research.report(self.db, report)
        html = report.read_text()
        self.assertIn("legacy ?", html)
        self.assertIn("Stored draft contains invalid Unicode", html)
        self.assertIn(r"legacy detail \udfff", html)

    def test_known_cost_survives_bad_transport_output_and_packet_validation(self):
        research.change_state(self.store, "running")
        model = DeepSeek("deepseek-chat", lambda request: (b"{broken", 125))
        self.run_tick(model=model)
        self.assertEqual(self.rows("SELECT outcome,charged_microusd FROM research_attempts"), [("failed", 125)])
        self.assertEqual(self.rows("SELECT state,packet FROM research_tasks"), [("queued", None)])

        class InvalidDraft:
            def generate(self, context):
                return ModelResult({"invalid": True}, 350)

        self.run_tick(NOW + timedelta(seconds=30), model=InvalidDraft())
        self.assertEqual(
            self.rows("SELECT outcome,charged_microusd FROM research_attempts ORDER BY id"),
            [("failed", 125), ("failed", 350)],
        )
        self.assertEqual(self.rows("SELECT state,packet FROM research_tasks"), [("queued", None)])

    def test_current_role_support_conflicts_with_denial_and_keeps_evidence(self):
        self.feed["jobs"][0]["descriptionPlain"] += " H-1B sponsorship is available for this role."
        self.write_feed()
        research.change_state(self.store, "running")
        evidence = {
            f"navigate-ai/{DEMO_ID}": [
                {
                    "kind": "verified_role_restriction",
                    "url": "https://example.org/older",
                    "date": "2026-10-15",
                    "excerpt": "This role is not eligible for visa sponsorship.",
                },
                {
                    "kind": "verified_role_restriction",
                    "url": "https://example.org/current",
                    "date": "2026-11-03",
                    "excerpt": "This role is not eligible for visa sponsorship.",
                },
            ]
        }
        self.run_tick(evidence=evidence)
        packet = json.loads(self.rows("SELECT packet FROM research_tasks")[0][0])
        self.assertEqual(packet["sponsorship"]["current"], "unknown")
        self.assertEqual(packet["sponsorship"]["restriction_sources"], ["evidence-1", "evidence-2"])
        self.assertEqual(len(packet["sources"]), 3)

    def test_unclear_denial_applicability_preserves_source_without_confirmation(self):
        research.change_state(self.store, "running")
        self.run_tick(
            evidence={
                f"navigate-ai/{DEMO_ID}": [
                    {
                        "kind": "verified_role_restriction",
                        "url": "https://example.org/company",
                        "date": "2026-11-03",
                        "excerpt": "We do not sponsor visas unless an exception is approved.",
                    },
                ]
            }
        )
        packet = json.loads(self.rows("SELECT packet FROM research_tasks")[0][0])
        self.assertEqual(packet["sponsorship"]["current"], "unknown")
        self.assertEqual(packet["sponsorship"]["restriction_sources"], ["evidence-1"])

    def test_restart_reconciles_abandoned_attempt_across_cadence_boundary(self):
        research.change_state(self.store, "running")
        previous_slot = self.config["cadence"].due_slot(NOW)
        self.store.begin(previous_slot, "ashby", "navigate-ai", NOW)
        next_day = NOW + timedelta(days=1)
        real_tick = research.tick
        with (
            patch("jobsearch.research.utcnow", return_value=next_day),
            patch("jobsearch.research.tick", side_effect=lambda *args: real_tick(*args, clock=lambda: next_day)),
        ):
            self.assertEqual(
                research.main(
                    [
                        "--db",
                        str(self.db),
                        "run",
                        "--config",
                        str(FIXTURES / "config.json"),
                        "--fixtures",
                        str(self.folder),
                        "--candidate",
                        str(FIXTURES / "candidate.json"),
                        "--responses",
                        str(FIXTURES / "responses.json"),
                    ]
                ),
                0,
            )
        self.assertEqual(self.rows("SELECT status FROM attempts ORDER BY id"), [("interrupted",), ("complete",)])

    def test_stop_during_inflight_discovery_abandons_snapshot_and_can_resume(self):
        research.change_state(self.store, "running")
        from jobsearch.ashby import Ashby

        original = Ashby.fixture

        def stop_during_fetch(adapter, slug, raw):
            with closing(research.open_registry(self.db)) as operator:
                research.change_state(operator, "stopped")
            return original(adapter, slug, raw)

        with patch.object(Ashby, "fixture", stop_during_fetch):
            self.run_tick()
        self.assertEqual(self.rows("SELECT status FROM attempts"), [("interrupted",)])
        self.assertEqual(self.rows("SELECT count(*) FROM postings"), [(0,)])
        self.assertEqual(self.rows("SELECT count(*) FROM research_attempts"), [(0,)])
        research.change_state(self.store, "running")
        self.run_tick(NOW + timedelta(seconds=1))
        self.assertEqual(self.rows("SELECT status FROM attempts ORDER BY id"), [("interrupted",), ("complete",)])
        self.assertEqual(self.rows("SELECT count(*) FROM postings"), [(1,)])

    def test_partial_and_stale_discovery_preserve_last_verified_posting(self):
        research.change_state(self.store, "running")
        self.run_tick()
        (original,) = self.rows("SELECT body FROM postings")
        self.feed["partial"] = True
        self.feed["jobs"] = []
        self.write_feed()
        self.run_tick(NOW + timedelta(days=1))
        self.assertEqual(self.store.run_status()[0]["status"], "failed")
        self.assertEqual(self.rows("SELECT body FROM postings"), [original])
        del self.feed["partial"]
        self.run_tick(NOW - timedelta(days=1))
        self.assertEqual(self.rows("SELECT body FROM postings"), [original])
        old = self.store.begin("abandoned-before-quarantine", "ashby", "navigate-ai", NOW)
        research.interrupt_discovery(self.store, NOW, old)
        self.write_feed()
        self.run_tick(NOW + timedelta(days=2))
        self.assertEqual(self.store.run_status()[0]["status"], "quarantined")
        old = self.store.begin("abandoned-before-quarantine", "ashby", "navigate-ai", NOW)
        self.assertEqual(self.store.complete(old, research.ALLOWED_BOARDS["navigate-ai"], [], NOW, live=True), "stale")
        self.assertEqual(self.rows("SELECT body FROM postings"), [original])

    def test_keyboard_interrupt_records_discovery_attempt_before_exit(self):
        research.change_state(self.store, "running")
        with patch("jobsearch.research.Ashby.fixture", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_tick()
        self.assertEqual(self.rows("SELECT status FROM attempts"), [("interrupted",)])
        self.assertEqual(self.rows("SELECT count(*) FROM postings"), [(0,)])
        self.run_tick(NOW + timedelta(seconds=1))
        self.assertEqual(self.rows("SELECT status FROM attempts ORDER BY id"), [("interrupted",), ("complete",)])

    def test_aged_out_retry_stays_deferred_until_eligible_again(self):
        research.change_state(self.store, "running")
        response = self.responses.pop(DEMO_ID)
        self.run_tick()
        self.assertEqual(self.rows("SELECT state,deferred,attempts FROM research_tasks"), [("queued", 0, 1)])

        self.responses[DEMO_ID] = response
        aged = NOW + timedelta(days=15)
        for offset in (0, 30, 60):
            self.run_tick(aged + timedelta(seconds=offset))
            self.assertEqual(self.rows("SELECT state,deferred,attempts FROM research_tasks"), [("queued", 1, 1)])
        self.assertEqual(self.store.run_status()[0]["status"], "complete")
        self.assertEqual(self.rows("SELECT count(*) FROM history"), [(1,)])

        self.profile = replace(self.profile, freshness_days=16)
        self.run_tick(aged + timedelta(minutes=2))
        self.assertEqual(self.rows("SELECT state,deferred,attempts FROM research_tasks"), [("ready", 0, 2)])

    def test_reverted_current_packet_survives_dashboard_limit(self):
        research.change_state(self.store, "running")
        posting = self.feed["jobs"][0]
        original = posting["descriptionPlain"]
        self.run_tick()
        (first,) = self.rows("SELECT task_id FROM research_current")[0]
        for offset in range(1, 52):
            posting["descriptionPlain"] = f"{original} Historical version {offset}."
            self.write_feed()
            self.run_tick(NOW + timedelta(days=offset))
        posting["descriptionPlain"] = original
        self.write_feed()
        self.run_tick(NOW + timedelta(days=52))

        self.assertEqual(self.rows("SELECT count(*) FROM research_tasks WHERE state='ready'"), [(52,)])
        self.assertEqual(self.rows("SELECT task_id FROM research_current"), [(first,)])
        report = self.folder / "limited.html"
        research.report(self.db, report)
        articles = report.read_text().split("<article>")[1:]
        self.assertEqual(len(articles), 50)
        self.assertIn("Current posting · draft", articles[0])
        self.assertNotIn("Historical version", articles[0])
        self.assertTrue(all("Historical or unverified" in article for article in articles[1:]))

    def test_large_charge_total_is_exact_and_resume_keeps_daily_gate(self):
        research.change_state(self.store, "running")
        maximum = 2**63 - 1
        for seconds, charge in ((0, 125), (30, maximum)):
            model = DeepSeek("deepseek-chat", lambda request: (b"{broken", charge))
            self.run_tick(NOW + timedelta(seconds=seconds), model=model)
        self.assertEqual(research.state(self.store.db), "paused")
        self.assertEqual(self.rows("SELECT charged_microusd FROM research_attempts ORDER BY id"), [(125,), (maximum,)])

        research.change_state(self.store, "running")
        self.run_tick(NOW + timedelta(minutes=2))
        self.assertEqual(self.rows("SELECT count(*) FROM research_attempts"), [(2,)])
        self.assertEqual(research.state(self.store.db), "running")
        report = self.folder / "ledger.html"
        research.report(self.db, report)
        self.assertIn(f"&quot;charged&quot;: {maximum + 125}", report.read_text())

        self.run_tick(NOW + timedelta(days=1))
        self.assertEqual(self.rows("SELECT state,attempts FROM research_tasks"), [("ready", 3)])
        self.assertEqual(
            self.rows("SELECT charged_microusd FROM research_attempts ORDER BY id"), [(125,), (maximum,), (0,)]
        )
