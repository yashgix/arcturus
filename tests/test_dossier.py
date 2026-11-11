"""Staged research under one signed grant, with real SSH signatures and offline provider fixtures."""

import fcntl
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))
import dossier
from grant_fixture import keys, sign as sign_grant, signed_root
import grant as grants
import llm
import providers
from research_sources import Page, digest

PAGE = (
    "Acme is hiring a founding backend engineer to build reliable ingestion pipelines in Python and Postgres. "
    "The team ships an audit log product used by fintech customers. "
) * 20


class Provider:
    """Answers each step like a well-behaved model unless a test asks for a specific failure."""

    def __init__(self):
        self.calls, self.truncate, self.interrupt, self.wrong_model, self.reject = [], set(), set(), False, None
        self.packets = []
        self.cutoffs = {}  # (provider, step) -> how many more answers are cut off
        self.cut_models = set()  # (model, step): every answer is cut off
        self.thinking = set()  # (model, step): every answer spends its whole limit on reasoning, no text

    def __call__(self, host, port, timeout, context):
        return Connection(self, host)

    def reply(self, host, body):
        wire = json.loads(body)
        provider = {"api.anthropic.com": "anthropic", "api.openai.com": "openai", "api.deepseek.com": "deepseek"}[host]
        content = {
            "anthropic": lambda: wire["messages"][0]["content"],
            "openai": lambda: wire["input"],
            "deepseek": lambda: wire["messages"][1]["content"],
        }[provider]()
        packet = json.loads(content)
        step = next(name for name, task in dossier.TASKS.items() if task == packet["task"])
        self.calls.append((provider, wire["model"], step))
        self.packets.append(packet)
        key = (provider, step)
        if key in self.interrupt:
            self.interrupt.discard(key)
            raise ConnectionResetError("fixture interruption")
        truncated = key in self.truncate or self.cutoffs.get(key, 0) > 0 or (wire["model"], step) in self.cut_models
        self.truncate.discard(key)
        if self.cutoffs.get(key):
            self.cutoffs[key] -= 1
        answer = json.dumps(getattr(self, step)(packet))
        model = "other-model" if self.wrong_model else wire["model"]
        if provider == "anthropic":
            return {
                "id": "msg_1",
                "model": model,
                "stop_reason": "max_tokens" if truncated else "end_turn",
                "content": [{"type": "text", "text": answer}],
                "usage": {"input_tokens": 1000, "output_tokens": 500},
            }
        if provider == "openai":
            return {
                "id": "resp_1",
                "model": model,
                "status": "incomplete" if truncated else "completed",
                "incomplete_details": {"reason": "max_output_tokens"} if truncated else None,
                "output": [{"type": "message", "content": [{"type": "output_text", "text": answer}]}],
                "usage": {
                    "input_tokens": 1000,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 500,
                    "output_tokens_details": {"reasoning_tokens": 100},
                },
            }
        if (wire["model"], step) in self.thinking:
            limit = wire["max_tokens"]
            return {
                "id": "ds-1",
                "model": model,
                "system_fingerprint": "fixture",
                "choices": [{"index": 0, "finish_reason": "length", "message": {"role": "assistant", "content": ""}}],
                "usage": {
                    "prompt_tokens": 1000,
                    "prompt_cache_hit_tokens": 0,
                    "completion_tokens": limit,
                    "completion_tokens_details": {"reasoning_tokens": limit},
                },
            }
        return {
            "id": "ds-1",
            "model": model,
            "system_fingerprint": "fixture",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "length" if truncated else "stop",
                    "message": {"role": "assistant", "content": answer},
                }
            ],
            "usage": {"prompt_tokens": 1000, "prompt_cache_hit_tokens": 0, "completion_tokens": 500},
        }

    def extract(self, packet):
        source = packet["sources"][0]
        return {
            "findings": [
                {
                    "category": "role",
                    "statement": "Founding backend role",
                    "source_id": source["id"],
                    "quote": source["text"][:60],
                },
                {
                    "category": "code",
                    "statement": "Invented claim",
                    "source_id": source["id"],
                    "quote": "Acme open-sourced its kernel",
                },
            ],
            "gaps": [],
        }

    def dossier(self, packet):
        first = packet["findings"][0]["id"]
        return {
            "summary": "Acme builds audit logs.",
            "open_questions": [],
            "sections": [
                {
                    "category": c,
                    "status": "covered" if c == "role" else "gap",
                    "missing": "none",
                    "points": [{"statement": "Hiring a backend engineer.", "kind": "fact", "findings": [first]}]
                    if c == "role"
                    else [],
                }
                for c in dossier.CATEGORIES
            ],
        }

    def projects(self, packet):
        first = packet["findings"][0]["id"]
        ideas = [
            {
                "title": f"Idea {n}",
                "scope": "focused",
                "problem": "p",
                "why_it_matters": "w",
                "already_solved": "unknown",
                "originality": "o",
                "feasibility": "f",
                "architecture": "a",
                "tradeoffs": "t",
                "test_plan": "t",
                "hiring_impact": "h",
                "origin": "stated_problem",
                "need": "verified",
                "shape": "a diagnostic",
                "real_data": "their public repository",
                "findings": [first],
                "depth": 3,
                "originality_score": 3,
                "relevance": 4,
                "feasibility_score": 4,
                "impact": 4,
            }
            for n in range(3)
        ]
        return {"ideas": ideas, "recommended": "Idea 1", "reasoning": "Best evidence."}

    def judge(self, packet):
        labels = [c["label"] for c in packet["candidates"]]
        scores = [
            {"label": label, "notes": "n", **{c: 5 + n % 3 for c in dossier.CRITERIA}} for n, label in enumerate(labels)
        ]
        return {"scores": scores, "ranking": labels, "best": labels[0], "comparison": "c"}

    def challenge(self, packet):
        return {
            "claims": [],
            "missed": [],
            "overall": "Reasonable.",
            "ideas": [
                {"title": i["title"], "verdict": "strong", "reason": "r"} for i in packet["peer_projects"]["ideas"]
            ],
        }


class Connection:
    def __init__(self, provider, host):
        self.provider, self.host = provider, host

    def request(self, method, path, body, headers):
        self.body = body

    def getresponse(self):
        if self.provider.reject:
            self.provider.calls.append(("rejected", self.host, None))
            return Response(self.provider.reject.encode(), status=400)
        return Response(json.dumps(self.provider.reply(self.host, self.body)).encode())

    def close(self):
        pass


class Response:
    reason, headers = "OK", {}

    def __init__(self, raw, status=200):
        self.raw, self.status = raw, status

    def read(self, limit):
        return self.raw[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class GrantedResearch(unittest.TestCase):
    def setUp(self):
        self.root = signed_root(self)
        self.keys = keys(self.root, ("anthropic", "deepseek"))
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        sources = self.root / "sources"
        sources.mkdir()
        raw = PAGE.encode()
        item = {
            "id": "s1",
            "requested_url": "https://acme.example/jobs",
            "url": "https://acme.example/jobs",
            "category": "hiring",
            "kind": "document",
            "retrieved_at": "2026-11-05T00:00:00+00:00",
            "published_at": None,
            "http_status": 200,
            "raw_sha256": digest(raw),
            "text_sha256": digest(raw),
            "gap": None,
            "links": [],
        }
        (sources / "s1.body").write_bytes(raw)
        (sources / "s1.txt").write_text(PAGE)
        (sources / "index.json").write_text(json.dumps({"attempts": 1, "captures": [item]}))
        manifest = {
            "companies": [
                {"id": "acme", "name": "Acme", "role": "Founding Backend Engineer", "source_dirs": [str(sources)]}
            ],
            "providers": {
                "anthropic": {"cheap": "claude-haiku-5-5", "strong": "claude-sonnet-5-5"},
                "deepseek": {"cheap": "deepseek-flash", "strong": "deepseek-v4-pro"},
            },
            "judges": {"anthropic": "claude-opus-5-5", "deepseek": "deepseek-v4-pro"},
            "keys": self.keys,
            "prior_commitments": {"retained_microusd": 1546650},
        }
        (self.run_dir / "run.json").write_text(json.dumps(manifest))
        self.provider = Provider()

    def grant(self, ceiling=10.0, sign=True):
        self.assertEqual(dossier.main([str(self.run_dir), "grant", "--ceiling", str(ceiling)]), 0)
        draft = json.loads((self.run_dir / "grant.json").read_text())
        if sign:
            sign_grant(self, draft)
        return draft

    def execute(self):
        run = dossier.Run(self.run_dir, connection=self.provider)
        run.run()
        return run

    def lane(self, provider):
        return self.run_dir / "lanes" / "acme" / provider

    def test_one_signature_runs_every_step_and_writes_reports(self):
        self.grant()
        run = self.execute()
        for provider in ("anthropic", "deepseek"):
            lane = self.lane(provider)
            for name in ("dossier-cheap", "projects-cheap", "dossier-strong", "projects-strong", "challenge"):
                self.assertTrue((lane / f"{name}.json").exists(), (provider, name))
            findings = json.loads((lane / "findings.json").read_text())
            self.assertEqual(len(findings["findings"]), 1)
            self.assertEqual(findings["rejected"][0]["reason"], "quote not verbatim")
            self.assertIn("Recommended: **Idea 1**", (lane / "report-strong.md").read_text())
            judged = json.loads((self.run_dir / "lanes" / "acme" / f"judge-{provider}" / "judge.json").read_text())
            self.assertEqual(len(judged["labels"]), 4)
        judging = (self.run_dir / "lanes" / "acme" / "judging.md").read_text()
        self.assertIn("Strong minus cheap", judging)
        self.assertIn("claude-opus-5-5", judging)
        rows = run.ledger.rows()
        self.assertTrue(all(r["state"] == "received" and r["charge"] > 0 for r in rows))
        self.assertIn("1546650", (self.run_dir / "results.md").read_text())
        self.assertIn("Arcturus run", (self.run_dir / "status.html").read_text())

    def test_routed_run_uses_the_chosen_model_for_each_step(self):
        manifest = json.loads((self.run_dir / "run.json").read_text())
        manifest["routing"] = {
            "extract": "deepseek-flash",
            "dossier": "deepseek-flash",
            "projects": "claude-sonnet-5-5",
            "challenge": "claude-haiku-5-5",
        }
        manifest["json_by_instruction"] = ["claude-sonnet-5-5"]
        (self.run_dir / "run.json").write_text(json.dumps(manifest))
        self.grant()
        run = dossier.Run(self.run_dir, connection=self.provider)
        run.run(routed=True)
        self.assertEqual(
            [(model, step) for _, model, step in self.provider.calls],
            [
                ("deepseek-flash", "extract"),
                ("deepseek-flash", "dossier"),
                ("claude-sonnet-5-5", "projects"),
                ("claude-haiku-5-5", "challenge"),
            ],
        )
        report = (self.lane("routed") / "report-routed.md").read_text()
        self.assertIn("## Independent check", report)
        self.assertNotIn("job_posting_context_not_a_source", self.provider.packets[0])

    def test_routed_research_sees_the_admitted_posting_but_extract_does_not(self):
        manifest = json.loads((self.run_dir / "run.json").read_text())
        manifest["routing"] = {
            "extract": "deepseek-flash",
            "dossier": "deepseek-flash",
            "projects": "deepseek-flash",
            "challenge": "deepseek-flash",
        }
        manifest["companies"][0]["job"] = {"title": "Engineer", "description": "Build evals."}
        (self.run_dir / "run.json").write_text(json.dumps(manifest))
        self.grant()
        dossier.Run(self.run_dir, connection=self.provider).run(routed=True)
        seen = [("job_posting_context_not_a_source" in p) for p in self.provider.packets]
        self.assertEqual(seen, [False, True, True, True])
        self.assertEqual(self.provider.packets[1]["job_posting_context_not_a_source"]["description"], "Build evals.")
        self.assertIn("| Acme | routed |", (self.run_dir / "results.md").read_text())

    def test_unsigned_or_changed_grant_is_refused(self):
        self.grant(sign=False)
        with self.assertRaises(grants.GrantError):
            dossier.Run(self.run_dir, connection=self.provider)
        self.grant()
        with patch.object(grants, "enforcement_sha256", return_value="changed"):
            with self.assertRaises(grants.GrantError):
                dossier.Run(self.run_dir, connection=self.provider)
        self.assertEqual(self.provider.calls, [])

    def test_truncation_retries_inside_the_grant_and_other_lanes_continue(self):
        self.grant()
        self.provider.truncate = {("deepseek", "dossier")}
        self.execute()
        self.assertTrue((self.lane("deepseek") / "dossier-cheap.json").exists())
        log = json.loads((self.lane("deepseek") / "dossier-cheap.log.json").read_text())
        self.assertEqual([entry["kind"] for entry in log], ["truncated", "ok"])
        self.assertTrue((self.lane("anthropic") / "challenge.json").exists())

    def test_a_second_cut_off_ends_the_step_instead_of_resending_it(self):
        self.grant()
        self.provider.cutoffs = {("deepseek", "dossier"): 5}
        self.execute()
        log = json.loads((self.lane("deepseek") / "dossier-cheap.log.json").read_text())
        self.assertEqual([entry["kind"] for entry in log], ["truncated", "truncated"])
        self.assertTrue((self.lane("deepseek") / "dossier-cheap.failed.json").exists())
        self.assertEqual(self.provider.calls.count(("deepseek", "deepseek-flash", "dossier")), 2)

    def test_after_a_restart_the_ledger_keeps_the_cut_off_rule(self):
        draft = self.grant()
        ledger = dossier.grants.Ledger(self.run_dir / "ledger.sqlite", draft)
        for _ in range(2):  # two cut-off answers recorded before a crash
            call = ledger.reserve("acme/deepseek", "dossier-cheap", "deepseek-flash", 10)
            ledger.settle(call, "truncated", charge=5)
        self.execute()
        steps = [r["step"] for r in ledger.rows() if r["lane"] == "acme/deepseek"]
        self.assertEqual(steps.count("dossier-cheap"), 2, "never sent a third time")

    def test_interrupted_call_keeps_its_reserve_and_a_new_call_finishes_the_step(self):
        self.grant()
        self.provider.interrupt = {("anthropic", "projects")}
        run = self.execute()
        uncertain = [r for r in run.ledger.rows() if r["state"] == "uncertain"]
        self.assertEqual(len(uncertain), 1)
        self.assertIsNone(uncertain[0]["charge"])
        self.assertGreaterEqual(run.ledger.committed(), uncertain[0]["reserve"])
        self.assertTrue((self.lane("anthropic") / "projects-cheap.json").exists())

    def test_ceiling_stops_lanes_without_crossing_it(self):
        self.grant(ceiling=0.05)
        run = self.execute()
        self.assertLessEqual(run.ledger.committed(), 50_000)
        self.assertFalse((self.lane("anthropic") / "projects-strong.json").exists())
        self.assertIn("INCOMPLETE", (self.lane("anthropic") / "report-strong.md").read_text())

    def test_wrong_model_identity_stops_everything(self):
        self.grant()
        self.provider.wrong_model = True
        with self.assertRaises(llm.SecurityStop):
            self.execute()
        self.assertEqual(
            grants.Ledger(
                self.run_dir / "ledger.sqlite", json.loads((self.run_dir / "grant.json").read_text())
            ).state(),
            "stop",
        )

    def test_a_second_runner_on_the_same_grant_is_refused(self):
        self.grant()
        first = dossier.Run(self.run_dir, connection=self.provider)
        first.lock = open(self.run_dir / "runner.lock", "w")
        fcntl.flock(first.lock, fcntl.LOCK_EX)
        with self.assertRaises(dossier.Stopped):
            dossier.Run(self.run_dir, connection=self.provider).run()
        self.assertEqual(self.provider.calls, [])

    def test_resume_reuses_finished_steps(self):
        self.grant()
        self.execute()
        calls = len(self.provider.calls)
        self.execute()
        self.assertEqual(len(self.provider.calls), calls)

    def test_request_outside_the_grant_is_never_sent(self):
        self.grant()
        build = providers.request
        with patch.object(providers, "request", lambda *a: {**build(*a), "tools": [{"type": "web_search"}]}):
            run = self.execute()
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(run.ledger.rows(), [])

    def test_ledger_refuses_companies_operations_and_limits_outside_the_grant(self):
        draft = self.grant()
        ledger = grants.Ledger(self.run_dir / "ledger.sqlite", draft)
        for lane, step in (("other/anthropic", "dossier-cheap"), ("acme/anthropic", "publish")):
            with self.assertRaises(grants.GrantError):
                ledger.reserve(lane, step, "claude-haiku-5-5", 1)
        settings = {**draft["models"]["claude-haiku-5-5"], "max_output_tokens": 10**6}
        outcome = llm.call(
            ledger,
            "acme/anthropic",
            "dossier-cheap",
            "claude-haiku-5-5",
            settings,
            "s",
            {"task": "t"},
            dossier.SCHEMAS["dossier"],
            "k",
            self.provider,
        )
        self.assertEqual((outcome.kind, ledger.rows(), self.provider.calls), ("rejected", [], []))

    def test_provider_rejection_costs_nothing_and_keeps_the_reason(self):
        self.grant()
        self.provider.reject = '{"error": {"message": "unknown parameter: thinking"}}'
        run = self.execute()
        rows = run.ledger.rows()
        self.assertTrue(rows and all(r["state"] == "rejected" and r["charge"] == 0 for r in rows))
        self.assertIn("unknown parameter: thinking", rows[0]["reason"])
        self.assertEqual(run.ledger.committed(), 0)

    def test_embedded_page_data_keeps_its_context(self):
        page = Page()
        data = {
            "company": {
                "name": "Acme",
                "primary_group_partner": {"full_name": "Partner"},
                "founders": [{"full_name": "Founder", "founder_bio": "<p>Built <b>ledgers</b></p>"}],
            }
        }
        page.feed(f"<div data-page='{json.dumps(data)}'></div>")
        self.assertEqual(
            page.text,
            [
                "company.name: Acme",
                "primary_group_partner.full_name: Partner",
                "founders.full_name: Founder",
                "founders.founder_bio: Built ledgers",
            ],
        )

    def test_pause_and_revoke_controls(self):
        self.grant()
        self.assertEqual(dossier.main([str(self.run_dir), "pause"]), 0)
        run = dossier.Run(self.run_dir, connection=self.provider, verify=False)
        self.assertEqual(run.ledger.state(), "pause")
        self.assertEqual(dossier.main([str(self.run_dir), "revoke"]), 0)
        self.assertEqual(dossier.main([str(self.run_dir), "resume"]), 1)
        self.assertEqual(dossier.main([str(self.run_dir), "run"]), 0)
        self.assertEqual(self.provider.calls, [])


class AsksForApproval(unittest.TestCase):
    def test_dossier_asks_before_run(self):
        for command, asks in (("run", True), ("report", False), ("pause", False)):
            with (
                self.subTest(command),
                patch.object(dossier.approve, "ensure", side_effect=dossier.grants.GrantError("no tap")) as ensure,
                patch("sys.stderr"),
            ):
                self.assertEqual(dossier.main(["/nonexistent-run", command]), 1)
            self.assertEqual(ensure.called, asks)


class JobFeedSources(unittest.TestCase):
    FEED = json.dumps(
        {
            "jobs": [
                {
                    "title": f"Engineer {n}",
                    "location": "New York City",
                    "workplaceType": "OnSite",
                    "publishedAt": "2026-11-02T18:00:00Z",
                    "jobUrl": f"https://jobs.ashbyhq.com/acme/{n}",
                    "descriptionPlain": f"Role {n}. We are unable to provide visa sponsorship."
                    if n == 11
                    else f"Role {n}.",
                }
                for n in range(12)
            ]
        }
    ).encode()

    def test_every_posting_becomes_its_own_source_with_its_own_link(self):
        feed = {
            "id": "a" * 64,
            "url": "https://api.ashbyhq.com/posting-api/job-board/acme",
            "category": "hiring",
            "published_at": None,
            "retrieved_at": "2026-11-07T00:00:00+00:00",
            "text": "raw feed",
        }
        posts = dossier.job_posts(feed, self.FEED)
        self.assertEqual(len(posts), 12)
        self.assertEqual(posts[11]["url"], "https://jobs.ashbyhq.com/acme/11")
        self.assertIn("unable to provide visa sponsorship", posts[11]["text"])
        self.assertIn("original date unknown", posts[0]["text"])
        ids = [piece["id"] for group in dossier.batches(posts) for piece in group]
        self.assertEqual(len(set(ids)), 12)

    def capture(self, folder, n, url, raw, gap):
        text = f"text {n}"
        (folder / f"c{n}.body").write_bytes(raw)
        (folder / f"c{n}.txt").write_text(text)
        return {
            "id": f"c{n}",
            "url": url,
            "kind": "document",
            "gap": gap,
            "http_status": 200,
            "category": "hiring",
            "raw_sha256": digest(raw),
            "text_sha256": digest(text.encode()),
            "published_at": None,
            "retrieved_at": "2026-11-07T00:00:00+00:00",
        }

    def test_a_feed_whose_text_hit_the_limit_is_still_read_from_its_whole_body(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            captures = [
                self.capture(
                    folder, 0, "https://api.ashbyhq.com/posting-api/job-board/acme", self.FEED, dossier.TEXT_LIMIT_GAP
                ),
                self.capture(folder, 1, "https://acme.com/blog", b"<p>long</p>", dossier.TEXT_LIMIT_GAP),
                self.capture(
                    folder,
                    2,
                    "https://api.ashbyhq.com/posting-api/job-board/beta",
                    b"{",
                    "source body exceeded capture limit; incomplete bytes retained",
                ),
            ]
            (folder / "index.json").write_text(json.dumps({"attempts": 3, "captures": captures}))
            sources = dossier.load_sources([folder])
        self.assertEqual(len(sources), 12)
        self.assertTrue(all(s["url"].startswith("https://jobs.ashbyhq.com/acme/") for s in sources))

    def test_a_feed_that_is_not_json_falls_back_to_its_text(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            captures = [
                self.capture(
                    folder, 0, "https://api.ashbyhq.com/posting-api/job-board/acme", b"<html>Error</html>", None
                )
            ]
            (folder / "index.json").write_text(json.dumps({"attempts": 1, "captures": captures}))
            [source] = dossier.load_sources([folder])
        self.assertEqual(source["text"], "text 0")

    def test_projects_task_asks_for_bare_finding_ids(self):
        self.assertIn("one to eight bare finding ids", dossier.TASKS["projects"])


if __name__ == "__main__":
    unittest.main()
