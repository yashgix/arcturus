import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from jobsearch import boards, discover, h1b, hn, radar, shortlist, worklog
from jobsearch.ashby import Board
from jobsearch.fetch import SourceError
from jobsearch.store import Store

NOW = datetime(2026, 11, 7, 12, tzinfo=timezone.utc)
PROFILE = json.loads(shortlist.PROFILE.read_text())


def job(external_id="1", title="Software Engineer", published="", kind="original", location="New York, NY"):
    return dict(
        external_id=external_id,
        url=f"https://example.com/{external_id}",
        title=title,
        description="Build APIs in Python. 3+ years of experience required.",
        location=location,
        workplace="",
        published=published,
        employment="",
        secondary=[],
        date_kind=kind,
    )


def registry():
    return Store(":memory:", live_registry=True)


class Adapters(unittest.TestCase):
    def test_greenhouse_uses_first_published_as_the_original_date(self):
        payload = {
            "jobs": [
                {
                    "id": 7,
                    "title": "Backend Engineer",
                    "absolute_url": "https://x/7",
                    "location": {"name": "Remote - US"},
                    "content": "&lt;p&gt;Python&lt;/p&gt;",
                    "first_published": "2026-11-06T10:00:00-04:00",
                    "updated_at": "2026-11-07T10:00:00Z",
                }
            ]
        }
        with patch.object(boards, "get_json", return_value=payload):
            [posting] = boards.greenhouse("acme")
        self.assertEqual(posting["published"], "2026-11-06T14:00:00+00:00")
        self.assertEqual(
            (posting["date_kind"], posting["description"], posting["workplace"]), ("original", "Python", "Remote")
        )

    def test_lever_created_at_is_milliseconds(self):
        payload = [
            {
                "id": "a",
                "text": "SWE",
                "hostedUrl": "https://jobs.lever.co/acme/a",
                "createdAt": 1786000000000,
                "workplaceType": "hybrid",
                "categories": {"location": "San Francisco"},
            }
        ]
        with patch.object(boards, "get_json", return_value=payload):
            [posting] = boards.lever("acme")
        self.assertEqual(posting["published"][:10], "2026-08-06")
        self.assertEqual((posting["date_kind"], posting["workplace"]), ("created", "Hybrid"))

    def test_careers_page_job_posting_data(self):
        page = (
            '<script type="application/ld+json">{"@type":"JobPosting","title":"Founding Engineer",'
            '"datePosted":"2026-11-01 08:40:01 UTC","jobLocationType":"TELECOMMUTE",'
            '"identifier":{"value":"fe-1"}}</script>'
        ).encode()
        with patch.object(boards, "get", return_value=page):
            [posting] = boards.careers("acme-com", "https://acme.com/careers")
        self.assertEqual(
            (posting["external_id"], posting["workplace"], posting["date_kind"]), ("fe-1", "Remote", "site_listing")
        )
        self.assertEqual(posting["published"], "2026-11-01T08:40:01+00:00")


class Dates(unittest.TestCase):
    def test_original_date_within_a_day(self):
        tier, basis = shortlist.freshness(job(published="2026-11-07T01:00:00+00:00"), NOW, NOW, NOW)
        self.assertEqual(tier, "<=1 day")
        self.assertIn("posted", basis)

    def test_last_published_never_claims_an_original_date(self):
        _, basis = shortlist.freshness(job(published="2026-11-07T01:00:00+00:00", kind="last_published"), NOW, NOW, NOW)
        self.assertIn("original date unknown", basis)

    def test_no_date_on_the_first_read_is_unknown(self):
        self.assertEqual(shortlist.freshness(job(), NOW, NOW, NOW)[0], "unknown")

    def test_no_date_but_appeared_after_we_started_watching(self):
        tier, basis = shortlist.freshness(job(), NOW - timedelta(hours=3), NOW - timedelta(days=5), NOW)
        self.assertEqual(tier, "<=1 day")
        self.assertIn("first seen by us", basis)


class NeverNewWhenReposted(unittest.TestCase):
    def tier(self, published, first_seen, repost=False, bulk=False):
        row = dict(
            source="greenhouse",
            company="Acme",
            first_seen=first_seen.isoformat(),
            repost=repost,
            bulk=bulk,
            possible_duplicate=0,
            note="",
            yc=False,
            large=False,
            found_by="linked",
        )
        with closing(registry()) as store:
            item = shortlist.assess(row, job(published=published), PROFILE, store.db, NOW - timedelta(days=5), NOW)
        return item["tier"], item["basis"]

    def test_fresh_job_seen_before_its_date_is_fresh(self):
        self.assertEqual(self.tier("2026-11-07T01:00:00+00:00", NOW - timedelta(hours=10))[0], "<=1 day")

    def test_registry_repost_is_never_fresh(self):
        tier, basis = self.tier("2026-11-07T01:00:00+00:00", NOW - timedelta(hours=10), repost=True)
        self.assertEqual(tier, "repost")
        self.assertIn("open here before", basis)

    def test_bulk_republish_is_never_fresh(self):
        self.assertEqual(self.tier("2026-11-07T01:00:00+00:00", NOW - timedelta(hours=10), bulk=True)[0], "repost")

    def test_date_that_moved_after_we_first_saw_the_job_is_a_republish(self):
        tier, basis = self.tier("2026-11-07T01:00:00+00:00", NOW - timedelta(days=4))
        self.assertEqual(tier, "repost")
        self.assertIn("re-published", basis)

    def test_reposted_job_without_a_date_says_so_next_to_first_seen(self):
        tier, basis = self.tier("", NOW - timedelta(hours=3), repost=True)
        self.assertEqual(tier, "repost")
        self.assertIn("first seen by us", basis)

    def test_a_copy_of_a_reposted_job_on_another_source_is_not_new(self):
        board = dict(company="Acme Inc", title="Backend Engineer", tier="repost", basis="bulk", score=40)
        careers = dict(company="Acme", title="Backend  engineer", tier="<=14 days", basis="listed", score=60)
        other = dict(company="Acme", title="Designer", tier="<=14 days", basis="listed", score=60)
        shortlist.same_job_not_new([board, careers, other])
        self.assertEqual((careers["tier"], careers["score"]), ("repost", 60 - shortlist.TIER_POINTS["<=14 days"]))
        self.assertEqual(other["tier"], "<=14 days")

    def test_old_repost_stays_older(self):
        self.assertEqual(self.tier("2026-09-01T00:00:00+00:00", NOW - timedelta(days=4), repost=True)[0], "older")


class BulkRepublish(unittest.TestCase):
    def test_several_last_published_dates_within_minutes_are_flagged(self):
        with closing(registry()) as store:
            token = store.begin("slot-1", "ashby", "acme", NOW)
            jobs = [job(str(n), f"Engineer {n}", f"2026-11-02T14:1{n}:00+00:00", "last_published") for n in range(3)]
            jobs.append(job("9", "Engineer 9", "2026-10-01T10:00:00+00:00", "last_published"))
            store.complete(token, Board("acme", "Acme", True), jobs, NOW, live=True, observed_at=NOW)
            flagged = shortlist.bulk_republished(store.db)
        self.assertEqual(len(flagged), 3)


class Registry(unittest.TestCase):
    def snapshot(self, store, jobs, when):
        token = store.begin(f"slot-{when:%Y%m%d}", "greenhouse", "acme", when)
        return store.complete(token, Board("acme", "Acme", True), jobs, when, live=True, observed_at=when)

    def test_same_job_under_a_new_id_after_closing_is_a_repost(self):
        with closing(registry()) as store:
            self.snapshot(store, [job("1")], NOW)
            for day in (1, 2):
                self.snapshot(store, [], NOW + timedelta(days=day))
            self.snapshot(store, [job("2")], NOW + timedelta(days=3))
            kinds = [r[0] for r in store.db.execute("SELECT kind FROM history WHERE external_id='2'")]
        self.assertEqual(kinds, ["repost"])

    def test_one_failing_source_does_not_stop_the_others(self):
        with closing(registry()) as store:
            store.db.execute("INSERT INTO companies VALUES ('acme','Acme','hn','u','', 'now')")
            store.db.executemany(
                "INSERT INTO company_boards VALUES ('acme',?,?,'','linked')", [("greenhouse", "good"), ("lever", "bad")]
            )

            def bad(slug, url):
                raise SourceError("HTTP 503")

            with patch.dict(radar.ADAPTERS, {"greenhouse": lambda slug, url: [job("9")], "lever": bad}):
                radar.poll(store)
            status = dict(store.db.execute("SELECT source, status FROM attempts").fetchall())
            active = store.db.execute("SELECT count(*) FROM postings WHERE active=1").fetchone()[0]
        self.assertEqual(status, {"greenhouse": "complete", "lever": "failed"})
        self.assertEqual(active, 1)

    def test_a_board_with_repeated_job_ids_fails_alone(self):
        with closing(registry()) as store:
            store.db.execute("INSERT INTO companies VALUES ('acme','Acme','hn','u','', 'now')")
            store.db.executemany(
                "INSERT INTO company_boards VALUES ('acme',?,?,'','linked')",
                [("greenhouse", "good"), ("lever", "twice")],
            )
            with patch.dict(
                radar.ADAPTERS,
                {"greenhouse": lambda slug, url: [job("9")], "lever": lambda slug, url: [job("1"), job("1")]},
            ):
                radar.poll(store)
            status = dict(store.db.execute("SELECT source, status FROM attempts").fetchall())
        self.assertEqual(status, {"greenhouse": "complete", "lever": "failed"})


class Sponsorship(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(Path(h1b.__file__).with_name("migrate_v6.sql").read_text())
        self.db.execute("INSERT INTO h1b_filings VALUES (2023,'ACME LABS INC','acme labs',2,1,'CA','SF')")

    def test_four_states_stay_apart(self):
        history = h1b.filings(self.db, "Acme Labs")
        self.assertEqual(h1b.evidence("We do not sponsor visas.", history)["state"], "explicit refusal")
        self.assertEqual(h1b.evidence("We sponsor H-1B visas.", [])["state"], "explicit support")
        self.assertEqual(h1b.evidence("Great team.", history)["state"], "historical filings")
        self.assertEqual(h1b.evidence("Great team.", h1b.filings(self.db, "Other Co"))["state"], "unknown")

    def test_a_refusal_naming_the_company_after_a_lead_in(self):
        text = (
            "Please note: At this time, Acme AI is unable to provide employment visa sponsorship for this "
            "role. We appreciate your interest."
        )
        self.assertEqual(h1b.evidence(text, [])["state"], "explicit refusal")
        self.assertEqual(h1b.evidence("Currently we may sponsor visas.", [])["state"], "unknown")

    def test_hn_visa_header(self):
        header = job(title="Acme | Backend Engineer | NYC | ONSITE | VISA")
        self.assertEqual(shortlist.sponsorship("hn", header, "Acme", self.db)["state"], "explicit support")


class Discovery(unittest.TestCase):
    def test_hn_comment_header(self):
        item = {
            "id": 5,
            "author": "a",
            "created_at": "2026-11-02T16:00:00Z",
            "text": 'Acme | Founding Engineer | SF | REMOTE<p>Apply: <a href="https:&#x2F;&#x2F;'
            'jobs.ashbyhq.com&#x2F;Acme">here</a>',
        }
        posting, company, links = hn.parse_comment(item)
        self.assertEqual((company, posting["workplace"]), ("Acme", "Remote"))
        self.assertEqual(discover.boards_in(" ".join(links)), [("ashby", "Acme")])

    def test_hn_job_ad_keeps_the_exact_post_time_and_link(self):
        item = {
            "id": 9,
            "type": "job",
            "time": 1793984613,
            "url": "https://up.codes/careers",
            "title": "UpCodes (YC S17) is hiring a Founding Engineer (Remote)",
        }
        posting, company, links = hn.parse_ad(item)
        self.assertEqual((company, posting["date_kind"], posting["workplace"]), ("UpCodes", "original", "Remote"))
        self.assertEqual((posting["published"][:10], posting["url"], links), ("2026-11-06", item["url"], [item["url"]]))

    def test_one_unreadable_hn_ad_is_skipped(self):
        ad = {"id": 9, "type": "job", "url": "https://acme.com/jobs", "title": "Acme (YC W25) Is Hiring Engineers"}

        def items(url):
            if url == hn.JOB_ADS:
                return [1, 2]
            if url.endswith("/1.json"):
                raise SourceError("HTTP 503")
            return ad

        with patch.object(hn, "get_json", side_effect=items):
            [(posting, company, _)] = hn.job_ads()
        self.assertEqual((company, posting["published"]), ("Acme", ""))

    def test_hn_ad_without_the_yc_pattern_is_skipped(self):
        self.assertIsNone(hn.parse_ad({"id": 1, "type": "job", "time": 1, "title": "Acme wants people"}))

    def test_a_vc_board_on_a_careers_page_is_not_credited_to_the_company(self):
        self.assertFalse(radar.matches("Spur", "Pear-VC", "https://spur.dev"))
        self.assertTrue(radar.matches("Acme AI", "acme-ai", "https://useacme.ai"))

    def test_years_and_place(self):
        self.assertEqual(shortlist.years_asked("Need 2-4 years of professional experience."), 2)
        self.assertEqual(shortlist.place(job(location="London, UK"), PROFILE, "ashby"), "non-US")
        self.assertEqual(shortlist.place(job(location="Remote - US"), PROFILE, "ashby"), "US remote")


class WorkLog(unittest.TestCase):
    LOG = """| Company / target | Last reported action | Evidence status / caveat |
|---|---|---|
| Example Co, Full-Stack | **Applied**; used Resume A | Confirmed in prior project context. |
| Sample Labs | Confirming onsite | Submission not explicitly established; verify before marking applied. |
| Example Co | **Applied** | Do not treat as new. |
"""

    def test_statuses_are_conservative_and_imports_do_not_repeat(self):
        with closing(registry()) as store, tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "log.md"
            path.write_text(self.LOG)
            new, duplicate = worklog.plan(store.db, path)
            self.assertEqual(
                [(r["company"], r["status"]) for r in new], [("Example Co", "applied"), ("Sample Labs", "researched")]
            )
            self.assertEqual(len(duplicate), 1)
            worklog.apply(store.db, new)
            again, repeated = worklog.plan(store.db, path)
        self.assertEqual((len(again), len(repeated)), (0, 3))

    def test_status_words_that_are_not_applications(self):
        self.assertEqual(worklog.status("Senior Applied AI stretch; connected with recruiter"), "contacted")
        self.assertEqual(worklog.status("Researched + resume tailoring requested, not applied"), "researched")
        self.assertEqual(h1b.employer_key("Salus (YC W26)"), "salus")


if __name__ == "__main__":
    unittest.main()
