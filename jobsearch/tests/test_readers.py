import json
import unittest
from pathlib import Path
from unittest.mock import patch

from jobsearch import boards, discover, fetch
from jobsearch.fetch import NotFound

HAND = "careers page without a feed: check by hand"
FIXTURES = Path(__file__).parent.parent / "fixtures" / "readers"


def fixture(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def read(adapter, *payloads):
    with patch.object(boards, "get_json", side_effect=payloads):
        return adapter("acme", "")


class Readers(unittest.TestCase):
    def test_gem_first_published_is_the_original_date(self):
        remote, hybrid = read(boards.gem, fixture("gem"))[::-1]
        self.assertEqual(
            (hybrid["published"], hybrid["date_kind"], hybrid["workplace"]),
            ("2023-04-17T14:11:41+00:00", "original", "Hybrid"),
        )
        self.assertEqual((remote["workplace"], remote["location"]), ("Remote", "Korea, Republic of - Remote"))
        self.assertTrue(hybrid["description"].startswith("About Rootly At Rootly"))

    def test_workable_uses_created_date_and_application_url(self):
        first, second = read(boards.workable, fixture("workable"))
        self.assertEqual(
            (first["external_id"], first["url"], first["published"], first["date_kind"]),
            ("CD50BEE8FE", "https://apply.workable.com/j/CD50BEE8FE/apply", "2026-09-22T00:00:00+00:00", "created"),
        )
        self.assertEqual(
            (first["location"], first["workplace"], first["employment"]),
            ("Toronto, Ontario, Canada", "Remote", "Full-time"),
        )
        self.assertEqual(second["workplace"], "")

    def test_recruitee_uses_created_not_published_at(self):
        offers = fixture("recruitee")
        offers["offers"][0]["published_at"] = "2026-11-06 09:00:00 UTC"
        [first, _] = read(boards.recruitee, offers)
        self.assertEqual(
            (first["published"], first["date_kind"], first["workplace"]),
            ("2026-10-28T18:47:32+00:00", "created", "Remote"),
        )
        self.assertIn("/o/", first["url"])

    def test_recruitee_without_text_has_an_empty_description(self):
        offers = fixture("recruitee")
        offers["offers"][0].pop("description", None)
        offers["offers"][0].pop("requirements", None)
        self.assertEqual(read(boards.recruitee, offers)[0]["description"], "")

    def test_pinpoint_has_no_date(self):
        first, _ = read(boards.pinpoint, fixture("pinpoint"))
        self.assertEqual(
            (first["published"], first["date_kind"], first["workplace"], first["employment"]),
            ("", "none", "Remote", "Full Time"),
        )
        self.assertIn("sports markets", first["description"])

    def test_rippling_reads_created_date_from_the_detail(self):
        [posting] = read(boards.rippling, fixture("rippling-list"), fixture("rippling-detail"))
        self.assertEqual(
            (posting["published"], posting["date_kind"], posting["workplace"]),
            ("2026-09-20T00:30:26.642000+00:00", "created", "Remote"),
        )
        self.assertEqual((posting["location"], posting["employment"]), ("Los Angeles, CA", "Salaried, full-time"))
        self.assertTrue(posting["description"].startswith("About the role"))

    def test_rippling_skips_details_on_big_boards(self):
        listing = fixture("rippling-list")
        listing["items"] = [listing["items"][0] | {"id": str(n)} for n in range(boards.MAX_DETAIL_JOBS + 1)]
        postings = read(boards.rippling, listing)
        self.assertEqual({(p["description"], p["published"]) for p in postings}, {("", "")})

    def test_rippling_rows_per_location_are_one_job(self):
        listing = fixture("rippling-list")
        first = listing["items"][0]
        listing["items"] = [first, first | {"locations": [{"name": "Austin, TX", "workplaceType": "ON_SITE"}]}]
        [posting] = read(boards.rippling, listing, fixture("rippling-detail"))
        self.assertEqual((posting["location"], posting["secondary"]), ("Los Angeles, CA", ["Austin, TX"]))

    def test_jazzhr_reads_job_pages_listed_on_the_board(self):
        board = b'<a href="https://acme.applytojob.com/apply/Ab12/Engineer">x</a><a href="/apply/Ab12/Engineer">y</a>'
        job = (FIXTURES / "jazzhr-job.html").read_bytes()
        with patch.object(boards, "get", side_effect=[board, job]) as fetched:
            [posting] = boards.jazzhr("acme", "")
        self.assertEqual(fetched.call_count, 2)
        self.assertEqual(
            (posting["external_id"], posting["published"], posting["date_kind"], posting["location"]),
            ("Ab12", "2026-08-31T00:00:00+00:00", "last_published", "Denver, CO"),
        )

    def test_every_new_source_has_a_date_kind_and_a_probe(self):
        new = {"gem", "workable", "recruitee", "pinpoint", "rippling", "jazzhr"}
        self.assertLessEqual(new, set(boards.ADAPTERS))
        self.assertLessEqual(new, set(boards.DATE_KINDS))
        self.assertLessEqual(new, discover.READABLE)
        self.assertEqual(discover.NAME_PROBES, ("greenhouse", "lever", "ashby"))
        self.assertNotIn("dover", boards.ADAPTERS)  # app.dover.com robots.txt disallows /api/


class NeverYC(unittest.TestCase):
    def test_yc_sites_are_refused_directly_and_by_redirect(self):
        self.assertFalse(fetch.allowed("https://www.workatastartup.com/jobs/1"))
        with self.assertRaises(fetch.SourceError):
            fetch.get("https://www.ycombinator.com/companies/acme/jobs")
        with self.assertRaises(fetch.SourceError):
            fetch.Redirects().redirect_request(
                None, None, 302, "Found", {}, "https://www.ycombinator.com/companies/acme/jobs"
            )


class Probes(unittest.TestCase):
    def exists(self, body):
        with patch.object(discover, "get", return_value=body):
            return discover.exists("ashby", "acme")

    def test_empty_shapes_do_not_count(self):
        for body in (b"[]", b"", b'{"jobs":[]}', b'{"apiVersion":"1","jobs": []}'):
            self.assertFalse(self.exists(body), body)

    def test_a_board_with_jobs_counts(self):
        self.assertTrue(self.exists(b'{"jobs":[{"id":1}]}'))

    def test_unknown_slug_does_not_count(self):
        with patch.object(discover, "get", side_effect=NotFound("x")):
            self.assertFalse(discover.exists("lever", "nobody"))


class FromSite(unittest.TestCase):
    def site(self, pages, links=("https://acme.com", "https://acme.com/careers")):
        with patch.object(discover, "page", side_effect=lambda url: pages.get(url, "")) as fetched:
            return discover.from_site(list(links)), [call.args[0] for call in fetched.call_args_list]

    def test_follows_a_careers_subdomain_to_an_ats_link(self):
        found, _ = self.site(
            {
                "https://acme.com": '<a href="https://careers.acme.com/">Careers</a>',
                "https://careers.acme.com/": '<a href="https://apply.workable.com/acme-inc/">x</a>',
            }
        )
        self.assertEqual(found, [("workable", "acme-inc", "careers page")])

    def test_follows_a_relative_link_from_a_www_site(self):
        found, _ = self.site(
            {
                "https://www.acme.com": '<a href="/jobs">Jobs</a>',
                "https://www.acme.com/jobs": '<a href="https://jobs.lever.co/acme">x</a>',
            },
            links=("https://www.acme.com",),
        )
        self.assertEqual(found, [("lever", "acme", "careers page")])

    def test_notion_careers_page_is_kept_for_a_hand_check(self):
        notion = "https://acme.notion.site/Careers-123"
        found, _ = self.site({"https://acme.com": f'<a href="{notion}">Careers</a>', notion: "<html>jobs</html>"})
        self.assertEqual(found, [("careers-hand", notion, HAND)])

    def test_a_careers_path_without_a_careers_title_is_not_a_page(self):
        found, _ = self.site(
            {"https://acme.com": "<html>home</html>", "https://acme.com/careers": "<title>Acme home</title>"}
        )
        self.assertEqual(found, [])

    def test_careers_page_with_a_title_is_kept_for_a_hand_check(self):
        found, _ = self.site({"https://acme.com/careers": "<title>Careers at Acme</title>"})
        self.assertEqual(found, [("careers-hand", "https://acme.com/careers", HAND)])

    def test_a_readable_board_beats_an_earlier_hand_page(self):
        found, _ = self.site(
            {
                "https://acme.com": '<a href="https://acme.notion.site/Join-1">x</a>',
                "https://acme.notion.site/Join-1": "<html>jobs</html>",
                "https://acme.com/careers": '<a href="https://jobs.ashbyhq.com/acme">x</a>',
            }
        )
        self.assertEqual(found, [("ashby", "acme", "careers page")])

    def test_other_domains_and_assets_are_not_followed(self):
        found, fetched = self.site(
            {"https://acme.com": '<a href="https://other.com/careers">x</a><a href="/static/jobs.css">y</a>'}
        )
        self.assertEqual((found, fetched), ([], ["https://acme.com", "https://acme.com/careers"]))

    def test_never_fetches_yc_pages(self):
        found, fetched = self.site(
            {}, links=("https://www.ycombinator.com/companies/acme", "https://www.workatastartup.com/companies/acme")
        )
        self.assertEqual((found, fetched), ([], []))
        found, fetched = self.site({"https://acme.com": '<a href="https://www.ycombinator.com/careers">x</a>'})
        self.assertNotIn("https://www.ycombinator.com/careers", fetched)


if __name__ == "__main__":
    unittest.main()
