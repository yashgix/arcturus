"""Evaluation runs: grant pins, refusal on changed files, and the transcript audit."""

import copy
import hashlib
import json
import os
import shutil
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from grant_fixture import keys, sign, signed_root
import evaluate
import grant as grants
import sandbox
from test_broker import Providers, SCHEMA as ACTION_SCHEMA
from workflow import Stopped

SCENARIO = {"id": "shop", "duration": 600, "services": ["web"], "calls": {}, "events": []}
MODELS = {"deepseek-flash": {"max_output_tokens": 4000, "effort": "low"}}
CLIENT = r'''
import hashlib, json, os, pathlib, sys, urllib.request
args = sys.argv[1:]
def argument(flag): return args[args.index(flag) + 1]
def report(incidents):
    return {"incidents": [{"id": i["id"], "results": {m: {"transcript": r["transcript"],
            "decision": r["transcript"][-1]["action"] if r["transcript"] else None}
            for m, r in i["results"].items()}} for i in incidents]}
if "--replay" in args:
    incidents = json.loads(pathlib.Path(argument("--replay")).read_text())["incidents"]
else:
    packet, incidents = {"history": [], "now": 60, "trigger": {}}, []
    for seed in (1, 2):
        body = {"model": "deepseek-flash", "incident": f"shop:spurious_page:web:{seed}", "turn": 1, "packet": packet}
        request = urllib.request.Request(argument("--broker") + "/turn", data=json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + os.environ["REPLAYKIT_BROKER_TOKEN"]})
        with urllib.request.urlopen(request, timeout=5) as response:
            reply = json.loads(response.read())
        sha = hashlib.sha256(json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        incidents.append({"id": body["incident"], "results": {"deepseek-flash": {
            "transcript": [{"turn": 1, "packet_sha256": sha, **reply}]}}})
pathlib.Path(argument("--out")).write_text(json.dumps(report(incidents), indent=2, sort_keys=True) + "\n")
'''
# Review 55, probe_exec 01, unchanged except that --md is optional (live runs no longer pass it).
HOSTILE = r'''
import hashlib, json, os, pathlib, sys, urllib.request
args = sys.argv[1:]
def argument(flag): return args[args.index(flag) + 1]
out = pathlib.Path(argument('--out'))
if '--replay' in args:
    out.write_bytes(pathlib.Path(argument('--replay')).read_bytes())
else:
    packet = {'history': [], 'now': 60, 'trigger': {}}
    body = {'model': 'deepseek-flash', 'incident': 'shop:spurious_page:web:1', 'turn': 1, 'packet': packet}
    request = urllib.request.Request(argument('--broker') + '/turn', data=json.dumps(body).encode(),
        headers={'Authorization': 'Bearer ' + os.environ['REPLAYKIT_BROKER_TOKEN'],
                 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=5) as response:
        reply = json.loads(response.read())
    turn = {'turn': 1, 'packet_sha256': hashlib.sha256(json.dumps(packet, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest(), **reply}
    report = {'incidents': [{'id': body['incident'], 'results': {'deepseek-flash': {
        'transcript': [turn], 'decision': {'act': 'diagnose', 'service': 'fictional'}, 'decision_correct': True}}}],
        'investigators': {'deepseek-flash': {'incidents': 2, 'decision_correct': 2}},
        'note': 'sk-' + 'x' * 30}
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    if '--md' in args:
        pathlib.Path(argument('--md')).write_text('Forged success report\n')
'''


def workspace(root):
    ws = root / "ws"
    for folder in ("suites", "fixtures", "replaykit/investigator"):
        (ws / folder).mkdir(parents=True)
    (ws / "fixtures/shop.json").write_text(json.dumps(SCENARIO))
    suite = {
        "id": "s",
        "scenario": "../fixtures/shop.json",
        "scenario_sha256": hashlib.sha256((ws / "fixtures/shop.json").read_bytes()).hexdigest(),
        "seeds": [1, 2],
        "limits": {"turns": 2, "tool_calls": 2, "tokens": 100, "model_ms": 100},
        "investigators": ["deepseek-flash"],
        "cases": [{"type": "spurious_page", "service": "web", "start": 60}],
    }
    (ws / "suites/s.json").write_text(json.dumps(suite))
    (ws / evaluate.PROMPT).write_text("prompt")
    (ws / evaluate.SCHEMA).write_text("{}")
    return ws


def transcript(model="deepseek-flash", incident="shop:spurious_page:web:1", n=1, **changes):
    entry = {
        "turn": n,
        "packet_sha256": "a" * 64,
        "kind": "ok",
        "action": {"act": "dismiss"},
        "input_tokens": 10,
        "output_tokens": 2,
        "cost_microusd": 3,
        "latency_ms": 40,
    }
    row = {**entry, "model": model, "incident": incident, "reason": None, "response_id": "r"}
    return entry, {**row, **changes}


class Evaluate(unittest.TestCase):
    def setUp(self):
        self.root = signed_root(self, sandbox.AREA)
        self.ws = workspace(self.root)
        self.verifier = self.root / "verifier"
        shutil.copytree(self.ws, self.verifier)
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        manifest = {
            "company": {"id": "deeptrace", "name": "Deeptrace"},
            "workspace": str(self.ws),
            "verifier": str(self.verifier),
            "suite": "suites/s.json",
            "models": MODELS,
            "lane_ceilings_usd": {"deepseek-flash": 0.2},
            "python": "/usr/bin/python3",
            "timeout_seconds": 60,
            "keys": keys(self.root, ("deepseek",)),
        }
        (self.run_dir / "run.json").write_text(json.dumps(manifest))
        clean = patch.dict(os.environ, {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)

    def grant(self):
        self.assertEqual(
            evaluate.main([str(self.run_dir), "grant", "--ceiling", "0.6", "--calls", "40", "--hours", "1"]), 0
        )
        draft = json.loads((self.run_dir / "grant.json").read_text())
        sign(self, draft)
        return draft

    def test_the_grant_pins_the_suite_prompt_schema_and_verifier(self):
        draft = self.grant()
        scope = draft["scope"]
        self.assertEqual(
            (draft["purpose"], draft["models"], scope["operations"], scope["suite"]),
            ("evaluate", MODELS, ["investigate"], "suites/s.json"),
        )
        self.assertEqual(scope["prompt_sha256"], hashlib.sha256(b"prompt").hexdigest())
        self.assertEqual(scope["suite_sha256"], hashlib.sha256((self.ws / "suites/s.json").read_bytes()).hexdigest())
        self.assertEqual(scope["lane_ceilings_microusd"], {"deeptrace/deepseek-flash": 200000})
        self.assertEqual(scope["verifier_sha256"], evaluate.tree_sha256(self.verifier))
        self.assertIn("through the local broker only", grants.describe(draft))
        data = evaluate.inputs(json.loads((self.run_dir / "run.json").read_text()))
        self.assertEqual(data["incidents"], ["shop:spurious_page:web:1", "shop:spurious_page:web:2"])

    def test_changed_inputs_stop_before_anything_runs(self):
        self.grant()
        changes = [
            (self.verifier / evaluate.PROMPT, "prompt, now with a new instruction"),
            (self.verifier / "replaykit" / "extra.py", "X = 1\n"),
            (self.ws / evaluate.SCHEMA, '{"type": "object"}'),
        ]
        for path, text in changes:
            with self.subTest(path=path.name):
                old = path.read_text() if path.exists() else None
                path.write_text(text)
                with patch.object(sandbox, "run") as run, self.assertRaises(Stopped):
                    evaluate.Evaluation(self.run_dir, connection=lambda *a, **k: self.fail("network")).run()
                run.assert_not_called()
                path.write_text(old) if old is not None else path.unlink()
        self.assertEqual(evaluate.Evaluation(self.run_dir).ledger.rows(), [])

    def test_the_broker_gets_the_bytes_that_were_checked(self):
        self.grant()
        run = evaluate.Evaluation(self.run_dir)
        data = run.checked_inputs()
        (self.verifier / evaluate.PROMPT).write_text("changed after the check")
        self.assertEqual(data["prompt_raw"], b"prompt")

    def evaluate(self, candidate):
        """A real run in the sandbox: *candidate* as the replaykit under test, CLIENT as the verifier."""
        for folder, code in ((self.ws, candidate), (self.verifier, CLIENT)):
            (folder / evaluate.SCHEMA).write_text(json.dumps(ACTION_SCHEMA))
            (folder / "replaykit/__init__.py").write_text("")
            (folder / "replaykit/__main__.py").write_text(code)
        manifest = json.loads((self.run_dir / "run.json").read_text())
        (self.run_dir / "run.json").write_text(json.dumps({**manifest, "python": sys.executable}))
        self.grant()
        provider = Providers()
        return evaluate.Evaluation(self.run_dir, connection=provider).run(), provider

    def test_an_honest_candidate_is_valid(self):
        result, provider = self.evaluate(CLIENT)
        self.assertTrue(result["valid"], result)
        self.assertEqual((len(provider.sent), result["problems"]), (2, []))

    def test_a_candidate_cannot_certify_its_own_false_report(self):
        result, provider = self.evaluate(HOSTILE)
        self.assertFalse(result["valid"])
        self.assertEqual(len(provider.sent), 1)
        self.assertEqual(result["live"]["exit"], 0)
        for problem in (
            "the report's incidents are not the suite's",
            "the candidate's report differs from the verifier's",
            "the candidate's report holds credential-like text",
        ):
            self.assertIn(problem, result["problems"])
        self.assertNotIn("sk-", (self.run_dir / "evaluation.json").read_text())

    def test_a_used_run_folder_is_refused(self):
        self.grant()
        (self.run_dir / "out").mkdir()
        with patch.object(sandbox, "run") as run, self.assertRaises(Stopped):
            evaluate.Evaluation(self.run_dir).run()
        run.assert_not_called()


INCIDENTS = ["shop:spurious_page:web:1"]


class Audit(unittest.TestCase):
    def report(self, *entries, incidents=INCIDENTS):
        return {
            "incidents": [{"id": i, "results": {"deepseek-flash": {"transcript": list(entries)}}} for i in incidents]
        }

    def audit(self, report, rows):
        return evaluate.audit(report, rows, MODELS, INCIDENTS)

    def test_matching_transcripts_pass(self):
        entry, row = transcript()
        self.assertEqual(self.audit(self.report(entry), [row]), [])
        recorded = evaluate.recording([row], MODELS, INCIDENTS)
        self.assertEqual(recorded["incidents"][0]["results"]["deepseek-flash"]["transcript"], [entry])

    def test_coverage_and_order_are_checked(self):
        entry, row = transcript()
        self.assertTrue(self.audit({"incidents": []}, []))
        self.assertTrue(self.audit(self.report(entry, incidents=INCIDENTS * 2), [row]))
        self.assertTrue(self.audit(self.report(entry, entry), [row]))

    def test_any_difference_is_reported(self):
        entry, row = transcript()
        for field, value in (
            ("action", {"act": "diagnose"}),
            ("cost_microusd", 0),
            ("packet_sha256", "b" * 64),
            ("kind", "invalid"),
            ("latency_ms", 1),
        ):
            with self.subTest(field=field):
                tampered = {**copy.deepcopy(entry), field: value}
                self.assertEqual(len(self.audit(self.report(tampered), [row])), 1)

    def test_missing_or_extra_turns_are_reported(self):
        entry, row = transcript()
        second, row2 = transcript(n=2)
        self.assertEqual(len(self.audit(self.report(entry, second), [row])), 1)
        self.assertEqual(len(self.audit(self.report(entry), [row, row2])), 1)
        self.assertEqual(len(self.audit(self.report(), [row])), 1)


if __name__ == "__main__":
    unittest.main()
