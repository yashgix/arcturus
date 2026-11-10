"""Pipeline queue under one signed grant: fake API providers, fake Max and Plus, real Seatbelt test runs, real git."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))
import build
import dossier
from grant_fixture import keys, sign, signed_root
import grant as grants
import pipeline
import pipeline_steps
import real_data
import routing
import sandbox
import subscriptions
from test_dossier import PAGE, Provider, digest

SPEC = "Package calc: calc/ops.py defines add(a, b) returning a + b. demo.py prints add(2, 3)."
GOOD = "def add(a, b):\n    return a + b\n"
OWN = (
    "import unittest\nfrom calc.ops import add\n\n\nclass T(unittest.TestCase):\n"
    "    def test_add(self):\n        self.assertEqual(add(1, 1), 2)\n"
)
HIDDEN = [
    {
        "name": f"test_p_{n}.py",
        "text": "import unittest\nfrom calc.ops import add\n\n\nclass P(unittest.TestCase):\n"
        f"    def test_{n}(self):\n        self.assertEqual(add({n}, 1), {n + 1})\n",
    }
    for n in (1, 2)
]
FILES = {
    "calc/__init__.py": '"""calc"""\n',
    "calc/ops.py": GOOD,
    "tests/test_ops.py": OWN,
    "README.md": "# calc\n",
    "docs/DESIGN.md": "# Design\n",
    "demo.py": "from calc.ops import add\nprint(add(2, 3))\n",
}
COMPANIES = ("acme", "globex", "initech")
BUGGY = "def add(a, b):\n    return a + b + 1\n"
READS_DATA = {
    "name": "test_p_data.py",
    "text": "import unittest\nfrom pathlib import Path\nimport calc\n\n\n"
    "class D(unittest.TestCase):\n    def test_rows(self):\n        self.assertEqual("
    "Path('real_data/rows/rows.csv').read_text(), 'a,b\\n1,2\\n')\n",
}
CORRECTNESS = {
    "path": "calc/ops.py",
    "severity": "medium",
    "category": "correctness",
    "problem": "add overflows.",
    "why_it_matters": "Wrong totals.",
    "fix": "Fix it.",
}


class Fakes(Provider):
    """The research fixture's models, plus the pipeline's and the build loop's steps."""

    def __init__(self):
        super().__init__()
        self.active = self.peak = 0
        self.lock = threading.Lock()
        self.on_step = {}
        self.findings, self.bad_plans, self.model = [], set(), threading.local()
        self.reviewed_specs, self.bodies, self.bad_parts, self.key_shaped = [], [], set(), 0
        self.fast, self.milestones, self.sources, self.specs = {"Initech"}, ["One night."], [], []
        self.buggy, self.on_repair, self.final_reviewed, self.review_packets = False, {}, False, []

    def reply(self, host, body):
        self.bodies.append(body)
        self.model.name = json.loads(body)["model"]
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(0.05)
            return super().reply(host, body)
        finally:
            with self.lock:
                self.active -= 1

    def answer(self, step, packet):
        self.on_step.pop(step, lambda: None)()
        return getattr(self, step)(packet)

    def decide(self, packet):
        if packet["company"] in self.fast:
            return {
                "decision": "fast",
                "impact": 4,
                "company_priority": 3,
                "reasons": ["Strong fit."],
                "idea_title": "none",
                "scope": "none",
                "demo": "none",
                "alternatives": [],
                "milestones": [],
                **dict.fromkeys(("portfolio_difference", "real_data", *pipeline_steps.FOUR), "none"),
            }
        return {
            "decision": "project",
            "impact": 4,
            "company_priority": 5,
            "reasons": ["Strong fit."],
            "idea_title": "Idea 1",
            "scope": "One night.",
            "demo": "none",
            "why_company": "Their problem.",
            "why_project": "Stronger than Idea 0.",
            "why_implementation": "Their stack.",
            "what_it_proves": "add is right on every input.",
            "portfolio_difference": "A new strength.",
            "alternatives": [{"title": "Idea 0", "why_not": "Weaker evidence."}],
            "real_data": "none",
            "milestones": self.milestones,
        }

    def spec(self, packet):
        self.specs.append(packet)
        hidden = HIDDEN + ([READS_DATA] if packet["real_data"] else [])
        return {"package": "calc", "spec_markdown": SPEC, "acceptance_tests": hidden, "data_paths": []}

    def data_search(self, packet):
        return {"queries": ["calc rows dataset"]}

    def data(self, packet):
        return {"sources": self.sources, "needs_approval": [], "synthetic_reason": "none" if self.sources else "None."}

    def notes(self, packet):
        return {
            **dict.fromkeys(
                (
                    "problem",
                    "why_this_approach",
                    "architecture",
                    "data_flow",
                    "tradeoffs",
                    "results",
                    "limitations",
                    "learned",
                ),
                "Plain words.",
            ),
            "talking_points": ["One.", "Two.", "Three."],
            "questions": [{"question": "Why?", "answer": "Because."}] * 3,
        }

    def outreach(self, packet):
        return {"channel": "email", "to": "none", "subject": "Hello", "body": "A short note.", "why": "Founder."}

    def plan(self, packet):
        self.on_step.pop("plan", lambda: None)()
        if self.model.name in self.bad_plans:
            return {"groups": [{"files": [], "why": "extra key"}], "notes": "n"}
        return {"groups": [{"files": [{"path": p, "purpose": "p"} for p in FILES]}], "notes": "n"}

    def build(self, packet):
        files = [
            {"path": p, "text": BUGGY if self.buggy and p == "calc/ops.py" else FILES[p]} for p in packet["write_now"]
        ]
        if self.key_shaped:
            self.key_shaped -= 1
            files[0]["text"] += "FAKE = 'API_KEY=REDACTED_VALUE'\n"
        return {"files": files, "notes": "n"}

    def repair(self, packet):
        """By default a fix; after the first final review, on_repair maps a model to what it writes instead."""
        code = BUGGY if self.buggy and not self.final_reviewed else GOOD  # buggy: the build loop never fixes it
        return self.on_repair.get(
            self.model.name if self.final_reviewed else None,
            lambda: {"files": [{"path": "calc/ops.py", "text": code}], "notes": "n"},
        )()

    def repair_plan(self, packet):
        return {
            "groups": [
                {"files": [{"path": "calc/ops.py", "purpose": "fix"}]},
                {"files": [{"path": "tests/test_ops.py", "purpose": "cover"}]},
            ],
            "notes": "n",
        }

    def repair_part(self, packet):
        if set(packet["write_now"]) & self.bad_parts:
            return {"files": [{"path": "elsewhere.py", "text": ""}], "notes": "n"}
        return {"files": [{"path": p, "text": FILES[p] + "# repaired\n"} for p in packet["write_now"]], "notes": "n"}

    def packet(self, packet):
        first = packet["bullets"][0]["text"]
        lead = [first.upper() if "fix_these_problems_from_your_last_attempt" not in packet else first]
        lead += [b["text"] for b in packet["bullets"][1:4]]
        return {
            "base_resume": packet["resumes"][0],
            "requirements": [{"requirement": "Python", "level": "STRONG", "evidence": "Every bullet."}],
            "lead_bullets": lead,
            "skills": ["Python, FastAPI"],
            "why_company": "Their product.",
            "confirm": [],
        }

    def review(self, packet):
        return {"verdict": "approve", "summary": "s", "findings": []}

    def final_review(self, packet):
        self.reviewed_specs.append(packet["specification"])
        self.review_packets.append(packet)
        self.final_reviewed = True
        findings = [{"cause": "code", **f} for f in self.findings]
        return {"verdict": "changes" if findings else "approve", "summary": "Reviewed.", "findings": findings}

    recheck = final_review

    def respec(self, packet):
        self.on_step.pop("respec", lambda: None)()
        return self.spec(packet)


def sources(folder):
    folder.mkdir(parents=True)
    raw = PAGE.encode()
    item = {
        "id": "s1",
        "requested_url": "https://acme.example/jobs",
        "url": "https://acme.example/jobs",
        "category": "hiring",
        "kind": "document",
        "retrieved_at": "2026-11-07T00:00:00+00:00",
        "published_at": None,
        "http_status": 200,
        "raw_sha256": digest(raw),
        "text_sha256": digest(raw),
        "gap": None,
        "links": [],
    }
    (folder / "s1.body").write_bytes(raw)
    (folder / "s1.txt").write_text(PAGE)
    (folder / "index.json").write_text(json.dumps({"attempts": 1, "captures": [item]}))
    (folder / "collected.json").write_text("{}")


class Queue(unittest.TestCase):
    def setUp(self):
        root = signed_root(self)
        self.run = root / f"run-{root.name}"
        self.run.mkdir()
        # Never Yash's real resumes: drafting a grant copies the packet sources.
        self.enterContext(patch.object(pipeline_steps, "BANK", self.run / "no-bank.txt"))
        self.enterContext(patch.object(pipeline_steps, "RESUMES", self.run / "no-resumes"))
        self.addCleanup(shutil.rmtree, sandbox.AREA / f"pipeline-{self.run.name}", True)
        companies = []
        for cid in COMPANIES:
            sources(self.run / "sources" / cid)
            companies.append(
                {
                    "id": cid,
                    "name": cid.title(),
                    "site": f"{cid}.example",
                    "role": "Backend Engineer",
                    "seeds": [],
                    "source_dirs": [],
                    "job": {"title": "Backend Engineer", "url": "u"},
                }
            )
        manifest = {
            "companies": companies,
            "keys": keys(root, ("anthropic", "deepseek", "openai")),
            "routing": {},
            "json_by_instruction": ["claude-sonnet-5-5"],
        }
        (self.run / "run.json").write_text(json.dumps(manifest))
        pipeline.init(self.run)
        # No build window, no wait between build starts, and a Mac that always has room, unless a test says so.
        routing.write_json(
            self.run / "routing.json",
            {
                **routing.read(self.run / "routing.json"),
                "build_window": None,
                "build_ramp_seconds": 0,
                "machine": {"min_free_memory_percent": 0, "max_load_per_core": 1000},
            },
        )
        queue = pipeline.Queue(self.run)
        for rank, cid in enumerate(COMPANIES):
            queue.add(cid, rank)
        sign(self, self.draft())
        self.fakes = Fakes()
        self.max_windows = {
            "five_hour": {"used": 30.0, "resets_at": time.time() + 3600},
            "seven_day": {"used": 40.0, "resets_at": time.time() + 86400},
        }
        self.plus_windows = {
            "five_hour": {"used": 10.0, "resets_at": time.time() + 3600},
            "seven_day": {"used": 20.0, "resets_at": time.time() + 86400},
        }
        self.plus_limit = None  # a reset time: the next Plus call is refused until then
        self.plan_calls, self.pages = [], []  # pages: what the free data search captured (none by default)
        # The fixture finds each step by its task text; teach it the build and pipeline tasks too.
        tasks = {**dossier.TASKS, **build.TASKS, **pipeline_steps.TASKS}
        for patcher in (
            patch.dict(dossier.TASKS, tasks),
            patch.object(subscriptions, "claude", self.claude),
            patch.object(subscriptions, "codex", self.codex),
            patch.object(subscriptions, "CODEX_SESSIONS", Path(self.enterContext(tempfile.TemporaryDirectory()))),
            patch.object(pipeline_steps, "PYTHON", sys.executable),
            patch.object(pipeline_steps.Steps, "data_pages", lambda steps, company, queries: self.pages),
            patch.object(pipeline, "SANDBOX_WAIT", 0),
            patch.dict(os.environ, {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}, clear=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def draft(self, ceiling=5.0, standing=None):
        pipeline.draft_grant(self.run, ceiling, 400, 2, standing)
        return json.loads((self.run / "grant.json").read_text())

    def step_of(self, packet):
        return next(name for name, task in dossier.TASKS.items() if task == packet["task"])

    def claude(self, instruction, data, schema, model, cwd):
        packet = json.loads(data)
        self.plan_calls.append(("max", model, self.step_of(packet)))
        return self.fakes.answer(self.step_of(packet), packet), self.max_windows, 0.01

    def codex(self, instruction, data, schema):
        packet = json.loads(data)
        self.plan_calls.append(("codex", None, self.step_of(packet)))
        if self.plus_limit:
            raise subscriptions.LimitReached("Plus limit reached", self.plus_limit)
        return self.fakes.answer(self.step_of(packet), packet), self.plus_windows

    def execute(self):
        run = pipeline.Pipeline(self.run, connection=self.fakes)
        run.run()
        return run

    def states(self):
        return {r["id"]: (r["state"], r["decision"]) for r in pipeline.Queue(self.run).rows()}

    def lane(self, cid, name="pipeline"):
        return self.run / "lanes" / cid / name

    def parked(self, cid):
        """The project parked (its strategies used up); the company itself still goes on to its drafts."""
        return (self.lane(cid) / "project-status.json").exists() and self.states()[cid][0] == "ready"

    def test_three_companies_move_through_the_queue_at_once(self):
        run = self.execute()
        self.assertEqual(
            self.states(), {"acme": ("ready", "project"), "globex": ("ready", "project"), "initech": ("ready", "fast")}
        )
        for cid in ("acme", "globex"):
            project = json.loads((self.lane(cid) / "project.json").read_text())
            self.assertTrue(project["accepted"])
            self.assertEqual((project["builder"], project["final_review"]), ("deepseek-flash", "codex"))
            self.assertIn("Open findings (not blocking)", (Path(project["repo"]) / "docs" / "REVIEW.md").read_text())
            self.assertEqual(Path(project["demo"]["output"]).read_text().strip(), "5")
        self.assertFalse((self.lane("initech") / "project.json").exists())
        self.assertTrue(all((self.lane(c) / "outreach.json").exists() for c in COMPANIES))
        self.assertGreaterEqual(self.fakes.peak, 2, "companies should be in flight at the same time")
        self.assertEqual({s for _, _, s in self.plan_calls}, {"decide", "spec", "outreach", "final_review", "notes"})
        self.assertNotIn("final_review", {step for _, _, step in self.fakes.calls}, "Plus did every final review")
        self.assertTrue(all(r["state"] == "received" for r in run.steps.ledger.rows()))
        report = (self.run / "report.md").read_text()
        self.assertIn("| Acme | 5 | ready | project | Idea 1 | ready |", report)
        self.assertIn("Accepted with no rescue: 2 of 2 projects started", report)
        self.assertIn("# Interview notes", (Path(project["repo"]) / "docs" / "INTERVIEW.md").read_text())
        self.assertIn("Plans:", report)

    def test_plans_over_their_line_hand_over_to_apis(self):
        self.max_windows["seven_day"]["used"] = 90.0  # over the 75% weekly line from the first answer on
        self.plus_windows["seven_day"]["used"] = 96.0  # over Plus's 95% weekly line
        (self.run / "usage.json").write_text(
            json.dumps(
                {
                    "max": {"windows": self.max_windows, "at": time.time()},
                    "codex": {"windows": self.plus_windows, "at": time.time()},
                }
            )
        )
        self.execute()
        self.assertEqual(self.plan_calls, [])
        models = json.loads((self.lane("acme") / "models.json").read_text())
        self.assertEqual(
            (models["decide"], models["spec"], models["outreach"]),
            ("claude-sonnet-5-5", "claude-sonnet-5-5", "claude-sonnet-5-5"),
        )
        project = json.loads((self.lane("acme") / "project.json").read_text())
        self.assertEqual(project["final_review"], "gpt-6-sol")
        self.assertIn(("openai", "gpt-6-sol", "final_review"), self.fakes.calls)

    def test_a_stronger_model_rescues_flashs_plan_and_flash_still_builds(self):
        self.fakes.bad_plans.add("deepseek-flash")
        self.execute()
        calls = [(model, step) for _, model, step in self.fakes.calls if step in ("plan", "build")]
        self.assertIn(("claude-sonnet-5-5", "plan"), calls)
        self.assertEqual({model for model, step in calls if step == "build"}, {"deepseek-flash"})
        self.assertEqual(self.states()["acme"], ("ready", "project"))

    def test_open_coverage_findings_are_documented_after_one_repair(self):
        self.fakes.findings = [
            {
                "path": "calc/ops.py",
                "severity": "medium",
                "category": "coverage",
                "problem": "add has no negative-number test.",
                "why_it_matters": "A reader may doubt it.",
                "fix": "Add one.",
            }
        ]
        self.execute()
        project = json.loads((self.lane("acme") / "project.json").read_text())
        self.assertEqual((project["accepted"], project["open_findings"]), (True, 1))
        notes = (Path(project["repo"]) / "docs" / "REVIEW.md").read_text()
        self.assertIn("add has no negative-number test.", notes)
        self.assertIn("not exercised", notes)
        steps = {
            r["step"] for r in pipeline.Pipeline(self.run, self.fakes).steps.ledger.rows() if r["lane"] == "acme/json"
        }
        self.assertIn("repair-1", steps, "one bounded repair before documenting")

    def test_a_contained_robustness_finding_is_documented_not_blocking(self):
        self.fakes.findings = [
            {
                "path": "calc/ops.py",
                "severity": "medium",
                "category": "robustness",
                "problem": "A 5,000-digit string raises ValueError, not TypeError.",
                "why_it_matters": "A caller sees a different error.",
                "fix": "Check the length.",
            }
        ]
        self.execute()
        project = json.loads((self.lane("acme") / "project.json").read_text())
        self.assertEqual((project["accepted"], project["open_findings"]), (True, 1))

    def test_a_correctness_finding_blocks_acceptance_but_the_company_still_gets_its_drafts(self):
        self.fakes.findings = [CORRECTNESS]
        self.execute()
        self.assertEqual(self.states()["acme"], ("ready", "project"))
        self.assertIn("project parked: final review: add overflows.", pipeline.Queue(self.run).rows()[0]["note"])
        self.assertFalse((self.lane("acme") / "project.json").exists())
        self.assertTrue((self.lane("acme") / "outreach.json").exists(), "applying never waits on the project")
        report = (self.run / "report.md").read_text()
        trouble = report.split("## Good startups whose project is in trouble")[1].split("##")[0]
        self.assertIn("**Acme** (priority 5): final review: add overflows.", trouble)
        self.assertIn("| Acme | 5 | ready | project | Idea 1 | dropped |", report)

    def test_a_blocking_finding_that_comes_back_gets_one_stronger_repair_then_parks(self):
        self.fakes.findings = [CORRECTNESS]
        run = self.execute()
        repairs = [model for _, model, step in self.fakes.calls if step == "repair"]
        self.assertEqual(repairs.count("deepseek-v4-pro"), 2, "one stronger repair each for acme and globex")
        self.assertTrue(self.parked("acme"))
        steps = {r["step"] for r in run.steps.ledger.rows() if r["lane"] == "acme/json"}
        self.assertNotIn("review-final3", steps, "parked once the stronger repair did not clear it")

    def test_the_spec_carries_the_ideas_sourced_evidence_for_company_claims(self):
        self.execute()
        finding = routing.read(self.lane("acme", "routed") / "findings.json")["findings"][0]
        spec = (sandbox.AREA / f"pipeline-{self.run.name}" / "acme" / "SPEC.md").read_text()
        self.assertTrue(spec.startswith(SPEC))
        self.assertIn("## Company evidence", spec)
        self.assertIn(f'Quote: "{finding["quote"]}" Source: <{finding["url"]}>', spec)
        self.assertIn("## Company evidence", self.fakes.reviewed_specs[0], "the final reviewer checks claims")

    def test_an_overridden_project_gets_the_recommended_ideas_evidence(self):
        self.assertEqual(pipeline.main([str(self.run), "override", "initech", "project"]), 0)
        self.execute()
        finding = routing.read(self.lane("initech", "routed") / "findings.json")["findings"][0]
        spec = (sandbox.AREA / f"pipeline-{self.run.name}" / "initech" / "SPEC.md").read_text()
        self.assertIn(f'Quote: "{finding["quote"]}"', spec)

    def test_a_repeated_blocker_is_never_escalated_to_the_same_model(self):
        config = routing.read(self.run / "routing.json")
        config["steps"]["escalate"] = ["deepseek-flash", "claude-sonnet-5-5"]
        routing.write_json(self.run / "routing.json", config)
        self.fakes.findings = [
            {
                "path": "calc/ops.py",
                "severity": "medium",
                "category": "correctness",
                "problem": "add overflows.",
                "why_it_matters": "Wrong totals.",
                "fix": "Fix it.",
            }
        ]
        self.execute()
        repairs = {model for _, model, step in self.fakes.calls if step == "repair"}
        self.assertEqual(repairs, {"deepseek-flash", "claude-sonnet-5-5"}, "Flash builds, so Sonnet escalates")
        self.assertTrue(self.parked("acme"))

    def test_revising_a_parked_project_keeps_its_code(self):
        self.fakes.findings = [
            {
                "path": "calc/ops.py",
                "severity": "high",
                "category": "correctness",
                "problem": "Needs a socket.",
                "why_it_matters": "Untestable.",
                "fix": "In memory.",
            }
        ]
        self.execute()
        self.assertTrue(self.parked("acme"))
        builds_before = [
            r
            for r in grants.Ledger(self.run / "ledger.sqlite", json.loads((self.run / "grant.json").read_text())).rows()
            if r["step"].startswith("build-")
        ]
        self.fakes.findings = []
        self.assertEqual(pipeline.main([str(self.run), "revise", "acme", "globex", "--reason", "sockets blocked"]), 0)
        run = self.execute()
        self.assertEqual(self.states()["acme"], ("ready", "project"))
        self.assertIn(("max", "opus", "respec"), self.plan_calls)
        builds_after = [r for r in run.steps.ledger.rows() if r["step"].startswith("build-")]
        self.assertEqual(len(builds_after), len(builds_before), "the code was kept, not rebuilt")
        self.assertTrue((self.lane("acme", "json") / "attempt-1" / "timeline.json").exists())

    def test_a_second_revision_starts_from_the_latest_spec(self):
        lane = self.lane("acme")
        for folder in (lane, self.lane("acme", "json")):
            folder.mkdir(parents=True)
        routing.write_json(lane / "spec.json", {"package": "calc", "spec_markdown": "first"})
        routing.write_json(lane / "spec-2.json", {"package": "calc", "spec_markdown": "second"})
        self.assertEqual(pipeline.main([str(self.run), "revise", "acme", "--reason", "limits"]), 0)
        self.assertEqual(routing.read(lane / "spec.json")["spec_markdown"], "second")
        self.assertEqual(routing.read(lane / "spec-before-attempt-1.json")["spec_markdown"], "first")
        self.assertFalse((lane / "spec-2.json").exists())

    def test_a_stopped_run_resumes_without_repeating_a_paid_step(self):
        grant = json.loads((self.run / "grant.json").read_text())
        ledger = grants.Ledger(self.run / "ledger.sqlite", grant)
        self.fakes.on_step["plan"] = lambda: ledger.control("stop")
        self.execute()
        self.assertTrue(any(state != "ready" for state, _ in self.states().values()))
        ledger.control("run")
        run = self.execute()
        self.assertEqual({s for s, _ in self.states().values()}, {"ready"})
        answered = [(r["lane"], r["step"]) for r in run.steps.ledger.rows() if r["state"] == "received"]
        self.assertEqual(len(answered), len(set(answered)), "a checkpointed step was paid for twice")

    def test_yashs_override_turns_a_project_into_a_fast_application(self):
        pipeline.main([str(self.run), "override", "globex", "fast"])
        self.execute()
        self.assertEqual(self.states()["globex"], ("ready", "fast"))
        self.assertFalse((self.lane("globex") / "spec.json").exists())

    def test_a_stopped_grant_ends_the_run_with_nothing_parked(self):
        grant = json.loads((self.run / "grant.json").read_text())
        grants.Ledger(self.run / "ledger.sqlite", grant).control("stop")
        self.execute()
        self.assertEqual(self.plan_calls, [])
        self.assertEqual({s for s, _ in self.states().values()}, {"queued"})
        self.assertIn("Paused: ", (self.run / "report.md").read_text())

    def test_running_out_of_budget_pauses_instead_of_parking(self):
        sign(self, self.draft(ceiling=0.30))  # below one Sonnet reserve: the projects step is refused
        self.execute()
        self.assertEqual({s for s, _ in self.states().values()}, {"queued"}, "nothing parked for good")
        self.assertRegex((self.run / "report.md").read_text(), r"Paused: .*spending ceiling reached")

    def test_a_sandbox_still_stopping_is_retried_not_parked(self):
        original, raised = pipeline_steps.Steps.decide, []

        def decide(steps, company):
            if company["id"] == "acme" and not raised:
                raised.append(1)
                raise RuntimeError(pipeline.SANDBOX_RACE)
            return original(steps, company)

        with (
            patch.object(pipeline_steps.Steps, "decide", decide),
            patch.object(pipeline, "POLL_SECONDS", 0.01),
            patch.object(pipeline, "survivors", lambda: ["4242 00:12 /usr/bin/python3 -m stuck"]),
        ):
            self.execute()
        self.assertEqual(self.states()["acme"], ("ready", "project"))
        self.assertIn(
            "still running: 4242 00:12 /usr/bin/python3 -m stuck", (self.lane("acme") / "notes.jsonl").read_text()
        )

    def test_an_unexpected_failure_parks_that_company_once(self):
        calls, original = [], pipeline_steps.Steps.decide

        def decide(steps, company):
            if company["id"] != "acme":
                return original(steps, company)
            calls.append(company["id"])
            raise KeyError("bad answer")

        with patch.object(pipeline_steps.Steps, "decide", decide), patch.object(pipeline, "POLL_SECONDS", 0.01):
            self.execute()
        self.assertEqual(calls, ["acme"])
        self.assertEqual(self.states()["acme"][0], "parked")
        self.assertEqual(self.states()["globex"], ("ready", "project"))

    def test_a_rebuild_revision_sets_the_code_aside_and_builds_fresh(self):
        self.fakes.findings = [
            {
                "path": "calc/ops.py",
                "severity": "high",
                "category": "security",
                "problem": "Runs untrusted code.",
                "why_it_matters": "Unsafe.",
                "fix": "Redesign.",
            }
        ]
        self.execute()
        base = sandbox.AREA / f"pipeline-{self.run.name}" / "acme"
        old_head = build.git(base / "arms" / "json", base / "repo", "rev-parse", "HEAD").strip()
        self.fakes.findings = []
        self.assertEqual(pipeline.main([str(self.run), "revise", "acme", "--rebuild", "--reason", "redesign"]), 0)
        run = self.execute()
        self.assertEqual(self.states()["acme"], ("ready", "project"))
        builds = [r for r in run.steps.ledger.rows() if r["lane"] == "acme/json" and r["step"] == "build-1"]
        self.assertEqual(len(builds), 2, "built again from the revised spec")
        self.assertTrue((base / "attempt-1" / "repo" / "calc" / "ops.py").exists(), "the old code is kept aside")
        with self.assertRaises(subprocess.CalledProcessError, msg="a fresh history, not the old one continued"):
            build.git(base / "arms" / "json", base / "repo", "cat-file", "-e", old_head)

    def test_a_cut_off_repair_is_split_into_file_groups_not_resent(self):
        self.fakes.findings = [
            {
                "path": "calc/ops.py",
                "severity": "medium",
                "category": "coverage",
                "problem": "add has no negative-number test.",
                "why_it_matters": "Doubt.",
                "fix": "Add one.",
            }
        ]
        self.fakes.cutoffs = {("deepseek", "repair"): 10}
        run = self.execute()
        project = json.loads((self.lane("acme") / "project.json").read_text())
        self.assertTrue(project["accepted"])
        steps = [r["step"] for r in run.steps.ledger.rows() if r["lane"] == "acme/json"]
        # Cut off at Flash's whole granted limit, so it is split at once: never sent again unchanged.
        self.assertEqual(steps.count("repair-1"), 1, "a cut-off repair is never sent again unchanged")
        self.assertIn("repair-1-plan", steps)
        self.assertIn("repair-1-part-2", steps)
        self.assertTrue((self.lane("acme", "json") / "repair-1.json").exists())

    def test_a_build_group_cut_off_twice_on_flash_goes_to_v4_pro_first(self):
        self.fakes.cut_models = {("deepseek-flash", "build")}
        self.execute()
        project = json.loads((self.lane("acme") / "project.json").read_text())
        self.assertEqual(
            (project["accepted"], project["builder"], project["final_review"]), (True, "deepseek-v4-pro", "codex")
        )

    def test_an_openai_build_is_never_final_reviewed_by_openai(self):
        self.fakes.cut_models = {("deepseek-flash", "build"), ("deepseek-v4-pro", "build")}
        self.execute()
        project = json.loads((self.lane("acme") / "project.json").read_text())
        self.assertEqual((project["builder"], project["final_review"]), ("gpt-6-sol", "claude-sonnet-5-5"))

    def test_deepseek_builds_get_room_to_think(self):
        self.execute()
        limits = {
            (w["model"], w.get("max_tokens", w.get("max_output_tokens")))
            for w in map(json.loads, self.fakes.bodies)
            if w["model"].startswith("deepseek")
        }
        self.assertIn(("deepseek-flash", pipeline_steps.THINKING_ROOM), limits)
        grant = json.loads((self.run / "grant.json").read_text())
        self.assertEqual(grant["models"]["deepseek-v4-pro"]["max_output_tokens"], 64_000)
        self.assertEqual(grant["models"]["gpt-6-sol"]["max_output_tokens"], 48_000)

    def test_a_plus_limit_hands_the_final_review_to_the_api_until_it_resets(self):
        self.plus_limit = time.time() + 3600
        self.execute()
        project = json.loads((self.lane("acme") / "project.json").read_text())
        self.assertEqual(project["final_review"], "gpt-6-sol")
        self.assertIn(("codex", None, "final_review"), self.plan_calls, "Plus was asked first")
        router = routing.Router(self.run)
        router.mark_down("codex", self.plus_limit)
        self.assertEqual(router.candidates("final_review")[0], "gpt-6-sol")
        router.mark_down("codex", time.time() - 1)  # the window has reset
        self.assertEqual(router.candidates("final_review")[0], "codex")

    def test_key_shaped_text_in_a_builders_answer_is_sent_back_not_a_security_stop(self):
        self.fakes.key_shaped = 1
        run = self.execute()
        self.assertIsNone(run.halted)
        self.assertEqual({s for s, _ in self.states().values()}, {"ready"})
        retried = [b for b in self.fakes.bodies if b"contains credential-like text" in b]
        self.assertTrue(retried, "the model was told to rewrite it")

    def test_a_split_repair_that_fails_is_undone(self):
        self.fakes.findings = [
            {
                "path": "calc/ops.py",
                "severity": "medium",
                "category": "coverage",
                "problem": "add has no negative-number test.",
                "why_it_matters": "Doubt.",
                "fix": "Add one.",
            }
        ]
        self.fakes.cutoffs = {("deepseek", "repair"): 10}
        self.fakes.bad_parts = {"tests/test_ops.py"}
        self.execute()
        base = sandbox.AREA / f"pipeline-{self.run.name}" / "acme"
        before = (self.lane("acme", "json") / "repair-1.split").read_text()
        head = build.git(base / "arms" / "json", base / "repo", "rev-parse", "HEAD").strip()
        self.assertEqual(head, before, "part 1 was committed, then undone when part 2 failed")
        self.assertNotIn("# repaired", (base / "repo" / "calc" / "ops.py").read_text())
        self.assertFalse((self.lane("acme", "json") / "repair-1.json").exists())

    def test_a_standing_allowance_needs_a_fresh_run_folder(self):
        self.execute()
        with self.assertRaisesRegex(ValueError, "new run folder"):
            self.draft(standing=5)

    def test_waiting_for_a_build_slot_ends_when_the_run_halts(self):
        run = pipeline.Pipeline(self.run, connection=self.fakes)
        run.halted = "spending ceiling reached"
        routing.write_json(self.run / "routing.json", {**routing.read(self.run / "routing.json"), "max_builds": 0})
        with self.assertRaisesRegex(pipeline.Stopped, "spending ceiling"):
            with run.build_slot("acme", lambda message: None):
                pass

    def test_a_standing_allowance_covers_the_first_companies_the_queue_admits(self):
        sign(self, self.draft(standing=2))
        run = self.execute()
        self.assertIsNone(run.halted, "the scheduler never sends a company the ledger would refuse")
        self.assertEqual(self.states()["initech"], ("queued", None))
        self.assertEqual({s for c, (s, _) in self.states().items() if c != "initech"}, {"ready"})
        self.assertEqual({r["lane"].split("/")[0] for r in run.steps.ledger.rows()}, {"acme", "globex"})
        self.assertIn("at most 2", grants.describe(run.steps.grant))

    def test_at_most_max_builds_companies_build_at_once(self):
        routing.write_json(self.run / "routing.json", {**routing.read(self.run / "routing.json"), "max_builds": 1})
        original, active, peak = pipeline_steps.build_project, [0], [0]

        def counted(*args, **kwargs):
            active[0] += 1
            peak[0] = max(peak[0], active[0])
            try:
                time.sleep(0.2)
                return original(*args, **kwargs)
            finally:
                active[0] -= 1

        with patch.object(pipeline_steps, "build_project", counted), patch.object(pipeline, "POLL_SECONDS", 0.01):
            self.execute()
        self.assertEqual(peak[0], 1)
        self.assertEqual({s for s, _ in self.states().values()}, {"ready"})

    def test_outside_the_build_window_projects_wait_and_others_go_on(self):
        later = time.localtime(time.time() + 3 * 3600)
        window = [f"{later.tm_hour:02d}:00", f"{(later.tm_hour + 1) % 24:02d}:00"]
        routing.write_json(
            self.run / "routing.json",
            {**routing.read(self.run / "routing.json"), "build_window": window, "max_active": 1},
        )
        grant = json.loads((self.run / "grant.json").read_text())
        ledger = grants.Ledger(self.run / "ledger.sqlite", grant)
        with patch.object(pipeline, "POLL_SECONDS", 0.01):
            worker = threading.Thread(target=self.execute)
            worker.start()
            deadline = time.time() + 60
            while self.states()["initech"][0] != "ready" and time.time() < deadline:
                time.sleep(0.1)
            ledger.control("stop")
            worker.join(60)
        self.assertEqual(self.states()["initech"], ("ready", "fast"), "one active place, yet the fast lane moved")
        self.assertEqual({self.states()[c][0] for c in ("acme", "globex")}, {"decided"}, "waiting, not parked")
        self.assertFalse(any(r["step"].startswith("build") for r in ledger.rows()))

    def test_the_application_packet_uses_only_yashs_exact_bullets_on_a_plan(self):
        bank = self.run / "bank.txt"
        bank.write_text("".join(f"[Example Co] (1) Built system {n} in Python.  <-- salus\n" for n in range(6)))
        resumes = self.run / "resumes"
        for name in ("salus", "joe a16z"):
            (resumes / name).mkdir(parents=True)
        with patch.object(pipeline_steps, "BANK", bank), patch.object(pipeline_steps, "RESUMES", resumes):
            pipeline_steps.copy_packet_sources(self.run)
        self.execute()
        text = (self.lane("acme") / "packet.md").read_text()
        self.assertIn("- Built system 0 in Python.", text)
        self.assertNotIn("BUILT SYSTEM", text, "a reworded bullet is sent back")
        self.assertEqual(len([c for c in self.plan_calls if c[2] == "packet"]), 6, "one free retry each")
        self.assertFalse(any(b"Built system" in body for body in self.fakes.bodies), "resume text never goes to an API")
        self.assertIn("packet.md", (self.run / "report.md").read_text())

    def test_from_launchd_an_unapproved_grant_ends_quietly(self):
        self.draft()  # a new draft, not signed
        with patch.object(pipeline.approve, "ensure", side_effect=AssertionError("no page at night")):
            self.assertEqual(pipeline.main([str(self.run), "run", "--scheduled"]), 1)
        self.assertEqual(self.fakes.calls, [])
        self.assertIn("not started: grant is not signed", (self.run / "last-start.txt").read_text())
        self.assertIn("Last start: ", (self.run / "report.md").read_text())

    def only_acme_builds(self):
        self.fakes.fast |= {"Globex"}  # findings are shared by every lane: one project keeps a test exact

    def fix_and_clear(self):
        self.fakes.findings = []
        return {"files": [{"path": "calc/ops.py", "text": GOOD}], "notes": "n"}

    def test_a_repair_that_breaks_passing_tests_is_undone_and_a_stronger_model_tries(self):
        self.only_acme_builds()
        self.fakes.findings = [CORRECTNESS]
        self.fakes.on_repair = {
            "deepseek-flash": lambda: {"files": [{"path": "calc/ops.py", "text": BUGGY}], "notes": "n"},
            "deepseek-v4-pro": self.fix_and_clear,
        }
        self.execute()
        project = json.loads((self.lane("acme") / "project.json").read_text())
        self.assertTrue(project["accepted"])
        self.assertEqual((Path(project["repo"]) / "calc" / "ops.py").read_text().split("# ")[0], GOOD)
        repairs = [model for _, model, step in self.fakes.calls if step == "repair"]
        self.assertEqual(repairs, ["deepseek-flash", "deepseek-v4-pro"])
        notes = (self.lane("acme") / "notes.jsonl").read_text()
        self.assertIn("repair 1 broke or bent", notes)
        self.assertIn("focused recheck", notes)

    def bend_then_fix(self, bent):
        self.only_acme_builds()
        self.fakes.buggy = True  # add is wrong, so the own test fails when the final gate starts
        self.fakes.findings = [CORRECTNESS]
        self.fakes.on_repair = {
            "deepseek-flash": lambda: {"files": [{"path": "tests/test_ops.py", "text": bent}], "notes": "n"},
            "deepseek-v4-pro": self.fix_and_clear,
        }
        self.execute()
        project = json.loads((self.lane("acme") / "project.json").read_text())
        self.assertEqual((Path(project["repo"]) / "tests" / "test_ops.py").read_text(), OWN)
        self.assertEqual((Path(project["repo"]) / "calc" / "ops.py").read_text().split("# ")[0], GOOD)
        self.assertIn(
            "repair 1 broke or bent 1 tests (test_ops.T.test_add)", (self.lane("acme") / "notes.jsonl").read_text()
        )

    def test_a_failing_test_bent_to_pass_is_undone(self):
        self.bend_then_fix(OWN.replace("add(1, 1), 2", "add(1, 1), 3"))

    def test_a_failing_test_deleted_is_undone(self):
        self.bend_then_fix(OWN.replace("    def test_add", "    def check_add"))

    def test_every_repair_goes_through_the_guarded_final_gate(self):
        self.only_acme_builds()
        self.fakes.buggy = True
        self.fakes.on_repair = {"deepseek-flash": self.fix_and_clear}
        self.execute()
        notes = [json.loads(line)["message"] for line in (self.lane("acme") / "notes.jsonl").read_text().splitlines()]
        repairs = [n for n in notes if n.startswith(("repair", "final repair"))]
        self.assertEqual(repairs[0], "final repair 1", "no build-loop repair before the final review")
        self.assertLess(notes.index("final review 0"), notes.index("final repair 1"))
        self.assertTrue(json.loads((self.lane("acme") / "project.json").read_text())["accepted"])

    def test_a_hidden_test_that_contradicts_the_spec_gets_one_revision_and_the_code_is_kept(self):
        self.only_acme_builds()
        self.fakes.findings = [
            {
                "path": "test_p_1.py",
                "severity": "high",
                "category": "correctness",
                "cause": "test",
                "problem": "test_p_1 expects 3 but the spec says add returns a + b.",
                "why_it_matters": "No code can pass it.",
                "fix": "Correct the test.",
            }
        ]
        self.fakes.on_step["respec"] = lambda: setattr(self.fakes, "findings", [])
        run = self.execute()
        self.assertTrue(json.loads((self.lane("acme") / "project.json").read_text())["accepted"])
        self.assertIn(("max", "opus", "respec"), self.plan_calls)
        self.assertNotIn("repair", {step for _, _, step in self.fakes.calls}, "the code is never bent to the test")
        reasons = [
            json.loads(line)["reason"] for line in (self.lane("acme") / "revisions.jsonl").read_text().splitlines()
        ]
        self.assertTrue(all(r.startswith("auto: test_p_1.py") for r in reasons))
        builds = [r for r in run.steps.ledger.rows() if r["lane"] == "acme/json" and r["step"] == "build-1"]
        self.assertEqual(len(builds), 1, "the code was kept")
        self.assertIn("Accepted with no rescue: 1 of 1", (self.run / "report.md").read_text())

    def test_a_spec_fault_that_comes_back_after_its_revision_parks_the_project(self):
        self.only_acme_builds()
        self.fakes.findings = [
            {
                "path": "SPEC.md",
                "severity": "high",
                "category": "correctness",
                "cause": "spec",
                "problem": "Section 2 contradicts section 3.",
                "why_it_matters": "Unbuildable.",
                "fix": "Pick one.",
            }
        ]
        self.execute()
        self.assertTrue(self.parked("acme"))
        status = json.loads((self.lane("acme") / "project-status.json").read_text())
        self.assertIn("revision used up", status["reason"])
        self.assertEqual([s for _, _, s in self.plan_calls].count("respec"), 1)

    def test_a_revision_decided_before_a_crash_is_made_on_restart(self):
        self.only_acme_builds()
        self.fakes.milestones = ["The core.", "The study."]
        original, crashed = pipeline.revise, []

        def revise(root, company_id, reason, rebuild=False):
            if not crashed:
                crashed.append(reason)
                raise KeyError("crash between deciding the next milestone and revising for it")
            return original(root, company_id, reason, rebuild)

        with patch.object(pipeline, "revise", revise):
            self.execute()
            self.assertFalse((self.lane("acme") / "project.json").exists())
            pipeline.main([str(self.run), "retry", "acme"])
            self.execute()
        self.assertEqual(crashed, ["auto: milestone 2 of 2: The study."])
        self.assertIn("2 of 2: The study.", routing.read(self.lane("acme") / "revise.json")["reason"])
        self.assertTrue(json.loads((self.lane("acme") / "project.json").read_text())["accepted"])
        self.assertEqual([s for _, _, s in self.plan_calls].count("respec"), 1, "milestone 2 was built, once")

    def test_milestones_continue_on_the_same_code_and_the_last_writes_interview_notes(self):
        self.only_acme_builds()
        self.fakes.milestones = ["The core.", "The real-data study."]
        run = self.execute()
        self.assertTrue((self.lane("acme") / "milestone-1.json").exists())
        project = json.loads((self.lane("acme") / "project.json").read_text())
        self.assertTrue(project["accepted"])
        self.assertTrue((Path(project["repo"]) / "docs" / "INTERVIEW.md").exists())
        self.assertIn("2 of 2: The real-data study.", routing.read(self.lane("acme") / "revise.json")["reason"])
        builds = [r for r in run.steps.ledger.rows() if r["lane"] == "acme/json" and r["step"] == "build-1"]
        self.assertEqual(len(builds), 1, "milestone 2 extends milestone 1's code")
        self.assertEqual(self.fakes.specs[0]["milestone"], "1 of 2: The core.")

    def test_real_data_is_fetched_by_the_runner_readable_by_tests_and_kept_out_of_git(self):
        self.only_acme_builds()
        url = "https://huggingface.co/datasets/acme/rows/resolve/main/rows.csv"
        self.pages = [
            {
                "id": "p1",
                "url": "https://huggingface.co/datasets/acme/rows",
                "links": [url],
                "text": "Rows of sums. License: CC-BY-4.0, free to reuse.",
            }
        ]
        self.fakes.sources = [
            {
                "name": "rows",
                "url": url,
                "page": "p1",
                "license": "attribution",
                "license_quote": "License: CC-BY-4.0",
                "why": "Real rows.",
            }
        ]

        def download(source, path, room):
            Path(path).write_text("a,b\n1,2\n")
            return 8

        with patch.object(real_data, "download", download):
            self.execute()
        base = sandbox.AREA / f"pipeline-{self.run.name}" / "acme"
        project = json.loads((self.lane("acme") / "project.json").read_text())
        self.assertEqual((project["accepted"], project["real_data"]), (True, 1))
        self.assertEqual(project["acceptance_tests"]["total"], 3, "the hidden test that reads the data ran and passed")
        self.assertEqual(oct((base / "repo" / "real_data" / "rows" / "rows.csv").stat().st_mode & 0o777), "0o644")
        tracked = build.git(base / "arms" / "json", base / "repo", "ls-files").split()
        self.assertFalse([t for t in tracked if t.startswith("real_data")], "never committed, so never in a packet")
        self.assertEqual(
            set(self.fakes.review_packets[0]["failing_hidden_tests"]),
            {"test_p_1.py", "test_p_2.py", "test_p_data.py"},
            "with real data the reviewer sees them all",
        )
        listing = self.fakes.specs[0]["real_data"][0]
        self.assertEqual((listing["license_quote"], listing["preview"]), ("License: CC-BY-4.0", "a,b\n1,2\n"))

    def test_a_new_build_starts_only_when_measurements_show_room(self):
        run = pipeline.Pipeline(self.run, connection=self.fakes)
        config = {
            **routing.read(self.run / "routing.json"),
            "machine": {"min_free_memory_percent": 20, "max_load_per_core": 1.0},
            "build_ramp_seconds": 60,
        }
        calm = {"free_memory_percent": 50, "load_1m": 2.0, "cores": 12}
        run.machine.latest = calm
        self.assertTrue(run.can_build(config))
        run.machine.latest = {**calm, "free_memory_percent": 10}
        self.assertFalse(run.can_build(config), "memory is short")
        run.machine.latest, run.last_build = calm, time.time()
        self.assertFalse(run.can_build(config), "the last build's load has not shown yet")
        run.last_build, run.building = 0.0, config["max_builds"]
        self.assertFalse(run.can_build(config), "the safety ceiling")


class StandingAllowance(unittest.TestCase):
    def test_the_ledger_takes_the_first_companies_that_spend_and_refuses_more(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        grant = {
            "id": "g",
            "models": {"deepseek-flash": {}},
            "max_calls": 10,
            "ceiling_microusd": 1_000_000,
            "expires_at": time.time() + 600,
            "scope": {"max_companies": 2, "operations": ["dossier"]},
        }
        ledger = grants.Ledger(folder / "ledger.sqlite", grant)
        for lane in ("acme/routed", "globex/routed", "acme/json"):
            ledger.reserve(lane, "dossier", "deepseek-flash", 10)
        with self.assertRaisesRegex(grants.GrantError, "initech is outside the grant"):
            ledger.reserve("initech/routed", "dossier", "deepseek-flash", 10)
        with self.assertRaisesRegex(grants.GrantError, "outside the grant"):
            grants.Ledger(folder / "other.sqlite", grant).reserve("../x/routed", "dossier", "deepseek-flash", 10)


class Schedule(unittest.TestCase):
    def test_the_build_window_wraps_past_midnight(self):
        at = lambda clock: time.mktime(time.strptime(f"2026-11-08 {clock}", "%Y-%m-%d %H:%M"))
        night = ["23:00", "07:00"]
        self.assertEqual(
            [pipeline.in_window(night, at(c)) for c in ("23:00", "02:30", "06:59", "07:00", "12:00")],
            [True, True, True, False, False],
        )
        self.assertTrue(pipeline.in_window(["09:00", "17:00"], at("12:00")))
        self.assertTrue(pipeline.in_window(None))
        self.assertTrue(pipeline.in_window(["23:00", "7:00"], at("02:30")), "an unpadded hour is read as a time")
        with self.assertRaises(ValueError):
            pipeline.in_window(["23:00", "24:00"])

    def test_the_launchd_jobs_run_awake_in_a_clean_environment(self):
        root = Path("/tmp/run")
        self.assertEqual(len(pipeline.JOBS["run"]), 24, "a run starts every hour: work never waits for a slot")
        job = pipeline.agent(root, "run", ["run", "--scheduled"], pipeline.JOBS["run"])
        command = job["ProgramArguments"]
        self.assertEqual(command[:4], ["/usr/bin/caffeinate", "-i", "/usr/bin/env", "-i"])
        self.assertEqual({a.split("=")[0] for a in command if "=" in a}, {"PATH", "HOME", "USER", "LOGNAME", "TMPDIR"})
        self.assertNotIn("KeepAlive", job, "KeepAlive implies RunAtLoad: loading the job would start paid work")
        self.assertNotIn("RunAtLoad", job)
        self.assertIn({"Hour": 23, "Minute": 15}, job["StartCalendarInterval"])


class Machine(unittest.TestCase):
    def test_heavy_steps_wait_while_the_mac_is_busy(self):
        router = type(
            "R", (), {"config": lambda self: {"machine": {"min_free_memory_percent": 20, "max_load_per_core": 1.0}}}
        )()
        machine = pipeline.Machine.__new__(pipeline.Machine)
        machine.router = router
        machine.latest = {"free_memory_percent": 5, "load_1m": 1.0, "cores": 12}
        notes = []
        threading.Timer(0.2, lambda: machine.latest.update(free_memory_percent=60)).start()
        with patch.object(pipeline, "SAMPLE_SECONDS", 0.05):
            machine.wait_for_room(notes.append)
        self.assertTrue(notes and notes[0].startswith("waiting: Mac busy (free memory 5%"))

    def test_a_sample_reads_the_real_machine(self):
        now = pipeline.sample()
        self.assertTrue(0 < now["free_memory_percent"] <= 100 and now["cores"] > 0 and now["ours_rss_mb"] > 0)


class Signals(unittest.TestCase):
    def test_max_usage_and_refusal_come_from_the_stream(self):
        allowed = {
            "type": "rate_limit_event",
            "rate_limit_info": {
                "status": "allowed",
                "unifiedWindows": {
                    "five_hour": {"utilization": 0.3, "resetsAt": 1, "status": "allowed"},
                    "seven_day": {"utilization": 0.37, "resetsAt": 2, "status": "allowed"},
                },
            },
        }
        result = {"type": "result", "is_error": False, "structured_output": {"a": 1}, "total_cost_usd": 0.01}
        stream = "\n".join(json.dumps(e) for e in (allowed, result))
        with (
            patch.object(subscriptions, "bounded", return_value=(0, stream, "")),
            patch.object(subscriptions, "claude_binary", return_value="/bin/false"),
        ):
            value, windows, _ = subscriptions.claude("i", "{}", {}, "opus", "/tmp")
            self.assertEqual(
                (value, windows["five_hour"]["used"], windows["seven_day"]["used"]), ({"a": 1}, 30.0, 37.0)
            )
            refused = {
                **allowed,
                "rate_limit_info": {**allowed["rate_limit_info"], "status": "rejected", "resetsAt": 9},
            }
            with patch.object(subscriptions, "bounded", return_value=(0, json.dumps(refused), "")):
                with self.assertRaises(subscriptions.LimitReached) as caught:
                    subscriptions.claude("i", "{}", {}, "opus", "/tmp")
                self.assertEqual(caught.exception.until, 9)

    def test_plus_usage_comes_from_codexs_session_log(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        day = folder / "2026" / "11" / "07"
        day.mkdir(parents=True)
        event = {
            "payload": {
                "rate_limits": {
                    "primary": {"used_percent": 20.0, "resets_at": 5},
                    "secondary": {"used_percent": 45.0, "resets_at": 6},
                }
            }
        }
        (day / "rollout-x-thread1.jsonl").write_text(json.dumps(event) + "\n")
        with patch.object(subscriptions, "CODEX_SESSIONS", folder):
            self.assertEqual(
                subscriptions.codex_snapshot("thread1"),
                {"five_hour": {"used": 20.0, "resets_at": 5}, "seven_day": {"used": 45.0, "resets_at": 6}},
            )

    def test_the_reserve_line_and_its_reset(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        shutil.copy(pipeline.RUNNER / "routing.json", folder / "routing.json")
        router = routing.Router(folder)
        router.record("max", {"seven_day": {"used": 80.0, "resets_at": time.time() + 60}})
        self.assertEqual(router.candidates("decide"), ["claude-sonnet-5-5", "gpt-6-sol"])
        router.record("max", {"seven_day": {"used": 80.0, "resets_at": time.time() - 1}})
        self.assertEqual(router.candidates("decide")[0], "max:opus")


class Commands(unittest.TestCase):
    def test_claude_runs_with_no_tools_no_mcp_and_no_api_key(self):
        with (
            patch.object(subscriptions, "claude_binary", return_value="claude"),
            patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-x", "OPENAI_API_KEY": "sk-x"}),
        ):
            argv, env = subscriptions.claude_argv("i", {}, "opus"), subscriptions.env()
        self.assertEqual(argv[argv.index("--tools") + 1], "")
        self.assertIn("--strict-mcp-config", argv)
        self.assertIn("--disable-slash-commands", argv)
        self.assertFalse({"ANTHROPIC_API_KEY", "OPENAI_API_KEY"} & set(env))

    def test_claude_on_anything_but_the_plan_login_stops_everything(self):
        init = {"type": "system", "subtype": "init", "apiKeySource": "ANTHROPIC_API_KEY"}
        with self.assertRaises(pipeline_steps.llm.SecurityStop):
            subscriptions.read_claude(json.dumps(init))
        overage = {"type": "rate_limit_event", "rate_limit_info": {"status": "allowed", "isUsingOverage": True}}
        with self.assertRaises(subscriptions.LimitReached):
            subscriptions.read_claude(json.dumps(overage))

    def test_codex_runs_read_only_with_every_tool_off_and_no_user_config(self):
        argv = subscriptions.codex_argv("codex", "s.json", "a.json")
        self.assertEqual(argv[argv.index("--sandbox") + 1], "read-only")
        self.assertTrue({"--ignore-user-config", "--ignore-rules"} <= set(argv))
        self.assertNotIn("--ephemeral", argv)  # its session log is where Plus usage is read
        off = {argv[i + 1] for i, a in enumerate(argv) if a == "--disable"}
        self.assertTrue({"shell_tool", "unified_exec", "code_mode_host", "multi_agent", "view_image"} <= off)
        self.assertIn('web_search="disabled"', argv)

    def test_a_codex_tool_call_is_refused(self):
        started = {"type": "thread.started", "thread_id": "t1"}
        command = {"type": "item.started", "item": {"type": "command_execution", "command": "cat ~/.ssh/id"}}
        with self.assertRaises(subscriptions.ToolUsed):
            subscriptions.read_codex("\n".join(json.dumps(e) for e in (started, command)))
        self.assertEqual(subscriptions.read_codex(json.dumps(started)), ("t1", None))

    def test_a_recovered_codex_error_is_no_failure_and_any_other_item_is_a_tool(self):
        events = [
            {"type": "thread.started", "thread_id": "t1"},
            {"type": "error", "message": "Reconnecting... 1/5"},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "{}"}},
            {"type": "turn.completed", "usage": {}},
        ]
        self.assertEqual(subscriptions.read_codex("\n".join(map(json.dumps, events))), ("t1", None))
        image = {"type": "item.started", "item": {"type": "image_generation"}}
        with self.assertRaises(subscriptions.ToolUsed):
            subscriptions.read_codex(json.dumps(image))

    def codex_call(self, login, stream, code=0, snapshot=None):
        replies = iter([(0, login, ""), (code, stream, "")])
        with (
            patch.object(subscriptions, "codex_binary", return_value="codex"),
            patch.object(subscriptions, "bounded", side_effect=lambda *a, **k: next(replies)),
            patch.object(subscriptions, "codex_snapshot", return_value=snapshot or {}),
        ):
            return subscriptions.codex("i", "{}", {})

    def test_codex_on_anything_but_the_plus_login_stops_everything(self):
        with self.assertRaises(pipeline_steps.llm.SecurityStop):
            self.codex_call("Logged in using an API key", "")

    def test_a_plus_refusal_is_a_limit_with_its_reset_time(self):
        failed = "\n".join(
            json.dumps(e)
            for e in ({"type": "thread.started", "thread_id": "t1"}, {"type": "turn.failed", "error": {"message": "x"}})
        )
        full = {"five_hour": {"used": 100.0, "resets_at": 77}, "seven_day": {"used": 50.0, "resets_at": 99}}
        with self.assertRaises(subscriptions.LimitReached) as caught:
            self.codex_call("Logged in using ChatGPT", failed, 1, full)
        self.assertEqual(caught.exception.until, 77)
        said = json.dumps({"type": "error", "message": "You've hit your usage limit. Try again later."})
        with self.assertRaises(subscriptions.LimitReached):
            self.codex_call("Logged in using ChatGPT", said, 1)
        with self.assertRaises(RuntimeError) as other:
            self.codex_call("Logged in using ChatGPT", json.dumps({"type": "error", "message": "boom"}), 1)
        self.assertNotIsInstance(other.exception, subscriptions.LimitReached)

    def test_overrides_are_checked(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.assertEqual(pipeline.main([str(folder / "run"), "override", "acme", "projct"]), 1)


class Reviewed:
    """Just enough of a ProjectBuild for the final review's own logic."""

    def __init__(self, folder, builder, rows=()):
        self.root, self.company, self.system = folder, {"id": "acme"}, "s"
        self.manifest = {"builder": builder}
        self.ledger = type("Ledger", (), {"rows": lambda _: list(rows)})()

    def lane(self, company, name):
        path = self.root / name
        path.mkdir(exist_ok=True)
        return path

    def known_keys(self):
        return []

    def gate(self):
        pass

    def note(self, *args):
        pass


class FinalReview(unittest.TestCase):
    REVIEW = {"verdict": "approve", "summary": "Fine.", "findings": []}

    def setUp(self):
        self.folder = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def saved(self, builder):
        rows = [{"lane": "acme/json", "step": "review-final0", "state": "received", "model": "gpt-6-sol"}]
        pb = Reviewed(self.folder, builder, rows)
        (pb.lane(None, "json") / "review-final0.json").write_text(json.dumps(self.REVIEW))
        return pipeline_steps.saved_review(pb, "review-final0")

    def test_a_saved_review_by_the_builders_own_provider_is_set_aside(self):
        self.assertEqual(self.saved("gpt-6-sol"), (None, None))
        self.assertTrue((self.folder / "json" / "review-final0.not-independent.json").exists())

    def test_a_saved_independent_review_is_reused_with_its_real_author(self):
        self.assertEqual(self.saved("deepseek-flash"), (self.REVIEW, "gpt-6-sol"))

    def test_code_any_openai_model_wrote_is_never_reviewed_by_openai_after_a_restart(self):
        rows = [
            {"lane": "acme/json", "step": "build-8", "state": "received", "model": "gpt-6-sol"},
            {"lane": "acme/json", "step": "build-9", "state": "truncated", "model": "claude-sonnet-5-5"},
        ]
        pb = Reviewed(self.folder, "deepseek-flash", rows)  # replayed under Flash's name
        self.assertEqual(
            [m for m in ("codex", "gpt-6-sol", "claude-sonnet-5-5") if pipeline_steps.independent(pb, m)],
            ["claude-sonnet-5-5"],
        )

    def plus(self, answer):
        router = routing.Router(self.folder)
        with patch.object(subscriptions, "codex", return_value=(answer, {})):
            return pipeline_steps.plus_review(
                Reviewed(self.folder, "deepseek-flash"), router, "review-final0", {"task": "t"}
            )

    def test_a_credential_shaped_plus_answer_stops_everything(self):
        with self.assertRaises(pipeline_steps.llm.SecurityStop):
            self.plus({**self.REVIEW, "summary": "API_KEY=REDACTED_VALUE"})
        with self.assertRaises(pipeline_steps.llm.SecurityStop):
            self.plus({"not": "a review", "note": "API_KEY=REDACTED_VALUE"})

    def test_a_plus_answer_off_the_schema_falls_back_without_a_checkpoint(self):
        self.assertIsNone(self.plus({"verdict": "approve"}))
        self.assertFalse((self.folder / "json" / "review-final0.json").exists())
        self.assertEqual(self.plus(self.REVIEW), self.REVIEW)
        self.assertEqual((self.folder / "json" / "review-final0.model").read_text(), "codex")


class Recovery(unittest.TestCase):
    def test_a_project_decision_must_answer_the_four_questions(self):
        decision = Fakes().decide({"company": "Acme"})
        self.assertEqual(pipeline_steps.check_decide(decision, {"Idea 0", "Idea 1"}), [])
        problems = pipeline_steps.check_decide(
            {**decision, "what_it_proves": "none", "alternatives": [], "milestones": []}, {"Idea 0", "Idea 1"}
        )
        self.assertEqual(len(problems), 3)
        self.assertEqual(pipeline_steps.check_decide({"decision": "fast"}, set()), [])

    def test_only_a_spec_or_hidden_test_fault_asks_for_a_revision(self):
        finding = {**CORRECTNESS, "cause": "code"}
        self.assertEqual(pipeline.spec_fault({"findings": [finding]}), "")
        own = {**finding, "cause": "test", "path": "tests/test_ops.py"}
        self.assertEqual(pipeline.spec_fault({"findings": [own]}), "", "a wrong own test is the fixer's to fix")
        hidden = {**finding, "cause": "test", "path": "test_p_1.py"}
        self.assertIn("test_p_1.py", pipeline.spec_fault({"findings": [hidden]}))
        low = {**hidden, "severity": "low"}
        self.assertEqual(pipeline.spec_fault({"findings": [low]}), "", "only blockers")

    def test_an_automatic_revision_keeps_every_hidden_test_it_was_not_sent_to_fix(self):
        old = {"acceptance_tests": HIDDEN}
        fixed = [{**HIDDEN[0], "text": HIDDEN[0]["text"].replace("add(1, 1), 2", "add(1, 1), 2 + 0")}, HIDDEN[1]]
        fixable = pipeline_steps.fixable_tests("auto: test_p_1.py: expects the wrong sum")
        self.assertEqual(fixable, {"test_p_1.py"})
        kept = lambda tests, allowed=fixable: pipeline_steps.kept_tests(old, {"acceptance_tests": tests}, allowed)
        self.assertEqual(kept(fixed), [])
        gutted = [HIDDEN[0], {**HIDDEN[1], "text": HIDDEN[1]["text"].replace("self.assertEqual(add(2, 1), 3)", "pass")}]
        self.assertTrue(kept(gutted), "test_p_2 was not named")
        skipped = [
            HIDDEN[0],
            {
                **HIDDEN[1],
                "text": HIDDEN[1]["text"].replace("    def test_2", "    @unittest.skip('x')\n    def test_2"),
            },
        ]
        self.assertTrue(kept(skipped), "a decorator is part of the file")
        self.assertTrue(
            kept(
                [
                    {
                        **fixed[0],
                        "text": fixed[0]["text"].replace("    def test_1", "    @unittest.skip('x')\n    def test_1"),
                    },
                    HIDDEN[1],
                ]
            ),
            "a named file may be corrected, never skipped",
        )
        dropped = [{**HIDDEN[0], "text": HIDDEN[0]["text"].replace("def test_1", "def helper")}, HIDDEN[1]]
        self.assertTrue(kept(dropped), "a method removed")
        milestone = pipeline_steps.fixable_tests("auto: milestone 2 of 2: the study")
        self.assertTrue(kept(fixed, milestone), "milestones keep every file")
        self.assertEqual(kept(HIDDEN + [READS_DATA], milestone), [], "and may add new ones")
        self.assertEqual(kept(gutted, None), [], "Yash's own call")

    def test_a_revision_is_sized_by_what_it_adds(self):
        spec = {"package": "calc", "spec_markdown": "x" * 25_000, "acceptance_tests": HIDDEN, "data_paths": []}
        grown = {**spec, "spec_markdown": "x" * 50_000}
        self.assertTrue(pipeline_steps.size_problems(grown))
        self.assertEqual(pipeline_steps.size_problems(grown, spec), [])

    def test_the_company_cap_leaves_room_for_a_whole_round(self):
        run = type("Run", (), {"budget_left": lambda self, cid: 1.4})()
        limits = {"company_usd": 5.0, "round_usd": 1.5}
        self.assertTrue(pipeline.Pipeline.over_budget(run, "acme", limits, lambda m: None))
        run.budget_left = lambda cid: 1.6
        self.assertFalse(pipeline.Pipeline.over_budget(run, "acme", limits, lambda m: None))

    def test_survivors_leave_out_the_helpers_launchd_starts(self):
        listing = "  101   01:02 /usr/sbin/distnoted agent\n  202 00:05 /usr/bin/python3 -I runner.py\n"
        with patch.object(pipeline.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, listing, "")):
            self.assertEqual(pipeline.survivors(), ["202 00:05 /usr/bin/python3 -I runner.py"])


class RealData(unittest.TestCase):
    PAGE = {
        "id": "p1",
        "url": "https://github.com/acme/data",
        "text": "MIT License. Rows of sums.",
        "links": ["https://github.com/acme/data/archive/refs/heads/main.zip"],
    }
    SOURCE = {
        "name": "rows",
        "url": "https://github.com/acme/data/archive/refs/heads/main.zip",
        "page": "p1",
        "license": "permissive",
        "license_quote": "MIT License",
        "why": "Real rows.",
    }

    def test_only_listed_public_hosts(self):
        self.assertTrue(real_data.approved("https://raw.githubusercontent.com/a/b/main/x.csv"))
        self.assertTrue(real_data.approved("https://cdn-lfs.hf.co/x"))
        for url in (
            "http://github.com/a",
            "https://api.acme.example/data",
            "https://user:pw@github.com/a",
            "https://github.com.evil.example/a",
            "https://github.com:8443/a",
        ):
            self.assertFalse(real_data.approved(url), url)

    def test_a_source_must_come_from_a_captured_page_with_its_license_quoted(self):
        check = lambda **change: real_data.problems({"sources": [{**self.SOURCE, **change}]}, [self.PAGE])
        self.assertEqual(check(), [])
        self.assertTrue(check(license_quote="Apache License"), "not on the page")
        self.assertTrue(check(url="https://github.com/acme/other.zip"), "not a link on the page")
        self.assertTrue(check(url="https://kaggle.com/acme/rows"), "a host that needs an account")
        self.assertTrue(check(page="p9"), "not a captured page")
        self.assertTrue(check(name="../rows"), "a name that is a path")

    def test_a_license_that_may_not_allow_the_use_waits_for_yash(self):
        for license in ("non-commercial", "restrictive", "unknown"):
            found = real_data.problems({"sources": [{**self.SOURCE, "license": license}]}, [self.PAGE])
            self.assertTrue(any("wait for Yash" in f for f in found), license)

    def test_terms_that_limit_the_use_wait_for_yash_whatever_the_class(self):
        for quote in (
            "License: CC BY-NC 4.0. Non-commercial use only.",
            "For non commercial use only",
            "Not-for-commercial use",
            "Research_use_only",
        ):
            page = {**self.PAGE, "text": quote}
            found = real_data.problems({"sources": [{**self.SOURCE, "license_quote": quote}]}, [page])
            self.assertTrue(any("wait for Yash" in f for f in found), quote)
        self.assertTrue(real_data.usable({"license": "attribution", "license_quote": "CC BY 4.0"}))

    def test_hidden_tests_that_would_run_downloaded_files_are_refused(self):
        runs = {
            "name": "test_p_x.py",
            "text": READS_DATA["text"].replace(
                "Path('real_data/rows/rows.csv').read_text()", "exec(Path('real_data/rows/rows.csv').read_text())"
            ),
        }
        spec = {"package": "calc", "spec_markdown": SPEC, "acceptance_tests": [HIDDEN[0], runs], "data_paths": []}
        self.assertTrue(any("never run what they read" in p for p in pipeline_steps.check_spec(spec)))
        self.assertEqual(pipeline_steps.check_spec({**spec, "acceptance_tests": [HIDDEN[0], READS_DATA]}), [])

    def test_a_listing_saved_by_an_earlier_run_is_checked_again(self):
        base = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for name, files in (("rows", ("rows.csv", "pkg.py")), ("nc", ("rows.csv",)), ("code", ("pkg.py",))):
            for f in files:
                (base / "real_data" / name).mkdir(parents=True, exist_ok=True)
                (base / "real_data" / name / f).write_text("a,b\n")
        saved = [
            {"path": "real_data/rows", "license": "permissive", "license_quote": "MIT License"},
            {"path": "real_data/nc", "license": "permissive", "license_quote": "Non-commercial use only"},
            {"path": "real_data/code", "license": "permissive", "license_quote": "MIT License"},
        ]
        kept, refused = real_data.recheck(saved, base)
        self.assertEqual([k["path"] for k in kept], ["real_data/rows"])
        self.assertEqual(list(kept[0]["files"]), ["rows/rows.csv"], "the .py file is gone")
        self.assertEqual(len(refused), 2)
        self.assertFalse((base / "real_data" / "nc").exists())

    def test_only_data_files_are_kept(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for name in ("rows.csv", "setup.py", "run.sh", "lib/native.so", "notes.md"):
            (folder / name).parent.mkdir(parents=True, exist_ok=True)
            (folder / name).write_text("x")
        self.assertTrue(real_data.keep_data(folder))
        self.assertEqual(sorted(p.name for p in folder.rglob("*") if p.is_file()), ["notes.md", "rows.csv"])
        code = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (code / "pkg.py").write_text("import os")
        self.assertFalse(real_data.keep_data(code), "a source of code only is refused")
        self.assertFalse(real_data.approved("https://files.pythonhosted.org/packages/x.tar.gz"), "no packages")

    def test_a_redirect_off_the_list_is_refused(self):
        handler = real_data.OnListedHosts()
        with self.assertRaisesRegex(ValueError, "not listed"):
            handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/x")

    def test_archives_unpack_inside_their_folder_or_not_at_all(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        good, bad = folder / "good.zip", folder / "bad.zip"
        import zipfile

        with zipfile.ZipFile(good, "w") as z:
            z.writestr("data/rows.csv", "a,b\n")
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr("../escape.txt", "x")
        self.assertTrue(real_data.unpack(good, folder / "g"))
        self.assertEqual((folder / "g" / "data" / "rows.csv").read_text(), "a,b\n")
        with self.assertRaisesRegex(ValueError, "outside its folder"):
            real_data.unpack(bad, folder / "b")
        self.assertFalse((folder / "escape.txt").exists())

    def test_a_spec_may_never_make_real_data_writable(self):
        spec = {
            "package": "calc",
            "spec_markdown": SPEC,
            "acceptance_tests": HIDDEN,
            "data_paths": ["real_data/rows/*.csv"],
        }
        self.assertTrue(any("read-only" in p for p in pipeline_steps.check_spec(spec)))
        self.assertTrue(pipeline_steps.check_spec({**spec, "package": "real_data", "data_paths": []}), "as the package")

    def test_data_changed_after_download_is_caught(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (folder / "real_data" / "rows").mkdir(parents=True)
        (folder / "real_data" / "rows" / "rows.csv").write_text("a,b\n")
        listing = [
            {"files": {"rows/rows.csv": {"sha256": real_data.digest(folder / "real_data" / "rows" / "rows.csv")}}}
        ]
        self.assertEqual(real_data.changed(folder, listing), [])
        (folder / "real_data" / "extra.csv").write_text("x")
        self.assertEqual(real_data.changed(folder, listing), ["extra.csv"], "a file nobody approved")
        (folder / "real_data" / "rows" / "rows.csv").write_text("forged\n")
        self.assertEqual(real_data.changed(folder, listing), ["extra.csv", "rows/rows.csv"])

    def test_an_archive_with_a_link_is_refused(self):
        import io
        import tarfile

        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        archive = folder / "rows.tar"
        with tarfile.open(archive, "w") as tarred:
            data = tarfile.TarInfo("payload.csv")
            data.size = 4
            tarred.addfile(data, io.BytesIO(b"a,b\n"))
            loop = tarfile.TarInfo("loop")
            loop.type, loop.linkname = tarfile.SYMTYPE, "."
            tarred.addfile(loop)
        with self.assertRaisesRegex(ValueError, "links"):
            real_data.unpack(archive, folder / "out")
        self.assertFalse((folder / "out").exists())

    def test_the_workspace_holds_exactly_the_approved_files(self):
        base = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (base / "repo" / "real_data" / "refused").mkdir(parents=True)
        (base / "repo" / "real_data" / "refused" / "old.csv").write_text("x")
        (base / "arms" / "json" / "git" / "info").mkdir(parents=True)
        real_data.place(base, base / "arms" / "json")
        self.assertFalse((base / "repo" / "real_data").exists(), "nothing approved: nothing left to read")
        (base / "real_data" / "rows").mkdir(parents=True)
        (base / "real_data" / "rows" / "rows.csv").write_text("a,b\n")
        real_data.place(base, base / "arms" / "json")
        self.assertEqual(
            [str(p.relative_to(base / "repo")) for p in (base / "repo").rglob("*") if p.is_file()],
            ["real_data/rows/rows.csv"],
        )

    def test_a_failed_source_is_left_out_and_said_why(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))

        def download(url, path, room):
            raise ValueError("over the 50 MB cap")

        with patch.object(real_data, "download", download):
            listing, failed = real_data.retrieve([{**self.SOURCE, "page_url": self.PAGE["url"]}], folder)
        self.assertEqual((listing, failed), ([], ["rows: over the 50 MB cap"]))
        self.assertFalse((folder / "real_data" / "rows").exists())


class Specs(unittest.TestCase):
    def test_acceptance_tests_must_define_unittest_methods(self):
        spec = {
            "package": "calc",
            "spec_markdown": "s",
            "acceptance_tests": [
                {
                    "name": "test_p_a.py",
                    "text": "from calc.ops import add\n\ndef test_add():\n    assert add(1, 1) == 2\n",
                },
                HIDDEN[0],
            ],
        }
        self.assertTrue(any("no unittest test methods" in p for p in pipeline_steps.check_spec(spec)))
        self.assertEqual(pipeline_steps.check_spec({**spec, "acceptance_tests": HIDDEN}), [])

    def test_a_spec_with_a_credential_shaped_value_is_rewritten(self):
        spec = {
            "package": "calc",
            "spec_markdown": "- `ACME_API_KEY=<key>`\n- next",
            "acceptance_tests": HIDDEN,
            "data_paths": [],
        }
        self.assertEqual(pipeline_steps.check_spec(spec), [], "a placeholder next to a line break is not a key")
        real = {**spec, "spec_markdown": "Set ACME_API_KEY=abcd1234efgh before running."}
        self.assertTrue(any("placeholders" in p for p in pipeline_steps.check_spec(real)))

    def test_a_spec_too_big_for_one_night_is_sent_back(self):
        spec = {"package": "calc", "spec_markdown": "s" * 30_001, "acceptance_tests": HIDDEN, "data_paths": []}
        self.assertTrue(any("one build" in p for p in pipeline_steps.check_spec(spec)))
        many = "".join(f"    def test_{n}(self):\n        add(1, 1)\n" for n in range(61))
        tests = [
            {
                "name": "test_p_many.py",
                "text": f"import unittest\nfrom calc.ops import add\n\n\nclass P(unittest.TestCase):\n{many}",
            },
            HIDDEN[0],
        ]
        problems = pipeline_steps.check_spec({**spec, "spec_markdown": "s", "acceptance_tests": tests})
        self.assertEqual(problems, ["62 new or changed hidden acceptance tests; keep at most 60 (one build)"])

    def test_a_spec_may_add_data_folders_but_never_code_or_tests(self):
        spec = {"package": "calc", "spec_markdown": "s", "acceptance_tests": HIDDEN, "data_paths": ["tasks/*.json"]}
        self.assertEqual(pipeline_steps.check_spec(spec), [])
        for bad in (
            "../tasks/a.json",
            "/tmp/a.json",
            "setup.py",
            "tasks/a.py",
            "a.json",
            "tests/data.json",
            "tasks/.hidden.json",
            "tasks/*.pth",
        ):
            self.assertTrue(pipeline_steps.check_spec({**spec, "data_paths": [bad]}), bad)
        base = Path(self.enterContext(tempfile.TemporaryDirectory()))
        manifest = pipeline_steps.materialize(base, {"id": "acme", "name": "Acme"}, spec, {}, 2)
        self.assertEqual(
            build.files_problems({"files": [{"path": "tasks/t1.json", "text": "{}"}]}, manifest["allowed"]), []
        )
        self.assertTrue(build.files_problems({"files": [{"path": "tasks/t1.py", "text": ""}]}, manifest["allowed"]))


class Admission(unittest.TestCase):
    def test_the_company_site_comes_from_its_own_post(self):
        item = {"url": "https://jobs.ashbyhq.com/acme/1"}
        self.assertEqual(
            pipeline.site_of("Acme", item, "See https://www.acme.ai/blog and https://acme.ai", None), "acme.ai"
        )
        self.assertEqual(pipeline.clean_name("Acme (YC W25)"), "Acme")
        self.assertEqual(pipeline.domain("resources.acme.dev"), "acme.dev")

    def test_a_searched_site_must_link_to_the_posting_board(self):
        item = {"url": "https://jobs.gem.com/ultra/am9icG9zdDq9"}
        pages = {
            "https://takeultra.com/": ["https://takeultra.com/shop"],
            "https://ultra.tech/careers": ["https://jobs.gem.com/ultra"],
        }
        results = {"Ultra official website": ["https://takeultra.com/"], "Ultra company": ["https://ultra.tech/"]}

        def fetch(store, url, category, fresh=False):
            return {"links": pages.get(url, []), "text": "", "gap": None}

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(pipeline.evidence.Store, "fetch", fetch),
            patch.object(
                pipeline.research_sources.Retriever, "search", lambda store, query, category: ({}, results[query])
            ),
        ):
            self.assertEqual(pipeline.site_of("Ultra", item, "", Path(tmp)), "ultra.tech")
            del pages["https://ultra.tech/careers"]
            self.assertIsNone(pipeline.site_of("Ultra", item, "", Path(tmp)))
        self.assertIsNone(pipeline.board_of("https://news.ycombinator.com/item?id=1"))
        self.assertEqual(pipeline.board_of("https://jobs.ashbyhq.com/acme-jobs/f6d2"), "jobs.ashbyhq.com/acme-jobs")

    def test_large_or_refusing_companies_are_not_admitted(self):
        base = {"company": "Acme", "large": False, "visa": {"state": "unknown"}, "tier": "<=14 days"}
        self.assertTrue(pipeline.admissible(base, set()))
        self.assertFalse(pipeline.admissible({**base, "large": True}, set()))
        self.assertFalse(pipeline.admissible({**base, "visa": {"state": "explicit refusal"}}, set()))
        self.assertFalse(pipeline.admissible(base, {"acme"}))


if __name__ == "__main__":
    unittest.main()
