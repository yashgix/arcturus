import unittest
from unittest.mock import patch

from jobsearch import portfolios

PAGE = b"""<a href="https://jobs.ashbyhq.com/acme/123">Acme job</a> <a href="https://jobs.ashbyhq.com/acme/456">again</a>
<a href="https://boards.greenhouse.io/beta">Beta</a> <a href="https://www.ycombinator.com/companies/x/jobs">YC</a>
<a href="https://www.gamma.ai/">Gamma</a> <a href="https://app.delta.dev/login">Delta</a>
<a href="https://www.linkedin.com/company/gamma">in</a> <a href="https://x.com/gamma">X</a>
<a href="https://www.zeta.co.uk/">Zeta</a> <a href="https://cdn.prod.website-files.com/a.css">css</a> <a href="https://vc.example/team">us</a>
<script>{"external_url":"https:\\/\\/epsilon.io","url":"https://www.acme.com"}</script>"""


class Portfolios(unittest.TestCase):
    def leads(self):
        with patch.object(portfolios, "get", return_value=PAGE):
            return dict(portfolios.leads("https://vc.example/portfolio"))

    def test_linked_boards_once_each_and_never_yc(self):
        found = self.leads()
        self.assertEqual(found["acme"], ["https://jobs.ashbyhq.com/acme"])
        self.assertEqual(found["beta"], ["https://boards.greenhouse.io/beta"])
        self.assertNotIn("x", found)

    def test_company_homepages_without_social_assets_or_the_vc_itself(self):
        found = self.leads()
        self.assertEqual(found["gamma"], ["https://gamma.ai", "https://gamma.ai/careers"])
        self.assertEqual(found["delta"][0], "https://app.delta.dev")
        self.assertEqual(found["epsilon"][0], "https://epsilon.io")
        self.assertEqual(found["zeta"][0], "https://zeta.co.uk")
        self.assertFalse({"linkedin", "website-files", "example"} & set(found))


if __name__ == "__main__":
    unittest.main()
