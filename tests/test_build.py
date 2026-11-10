"""Build loop under one signed grant: offline provider fixtures, real Seatbelt test runs, real git."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from grant_fixture import keys, sign, signed_root
import build
import gateway
import llm
import sandbox

SPEC = "Build package calc with calc/ops.py defining add(a, b) that returns a + b. Tests in tests/."
GOOD = "def add(a, b):\n    return a + b\n"
BUGGY = "def add(a, b):\n    return a - b\n"
OWN_TEST = (
    "import unittest\nfrom calc.ops import add\n\n\nclass T(unittest.TestCase):\n"
    "    def test_add(self):\n        self.assertEqual(add(1, 1), 2)\n"
)
PROTECTED = (
    "import unittest\nfrom calc.ops import add\n\n\nclass P(unittest.TestCase):\n"
    "    def test_secret_case(self):\n        self.assertEqual(add(40, 2), 42)\n"
)
# Executed code tries every channel at once. The marker is built at run time, so it is never in any source text.
HOSTILE = (
    "import __main__, os, socket, sys\n"
    "MARK = 'LEAK' + str(6 * 7) + 'X'\n"
    "print(MARK); print(MARK, file=sys.stderr)\n"
    "__main__.outcome['forged.' + MARK + '.test_x'] = ['fail', MARK]\n"
    "for path in (os.getcwd(), os.path.dirname(__file__)):\n"
    "    try:\n        open(os.path.join(path, MARK + '.txt'), 'w')\n    except OSError:\n        pass\n"
    "try:\n    socket.create_connection(('1.1.1.1', 443), timeout=2)\n"
    "except OSError as exc:\n    NETWORK = repr(exc)\n"
    "def add(a, b):\n"
    "    raise ValueError(MARK + NETWORK + open(sys._getframe(1).f_code.co_filename).read())\n"
)
HOSTILE_TEST = (
    "import unittest\nfrom calc import ops\n\n\nclass T(unittest.TestCase):\n"
    "    def test_add(self):\n        self.fail(ops.MARK)\n\n\n"
    "setattr(T, 'test_' + ops.MARK, lambda self: None)\n"
)
MARK = "LEAK42X"
PINNED_OPENCODE = Path(os.environ.get("ARCTURUS_OPENCODE", Path.home() / ".arcturus" / "bin" / "opencode"))
OPENCODE_SHA256 = "feaafead8cd563af0c2dcb386b0757e4355e327ebb6bd1aaad5440fe2f83596c"


class Response:
    reason = "OK"

    def __init__(self, raw, status=200, kind="application/json"):
        self.raw, self.status, self.headers = raw, status, {"Content-Type": kind}

    def read(self, limit):
        return self.raw[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Upstream:
    """Plays the builder, reviewer and agent providers. Records every packet it was sent."""

    def __init__(self):
        self.packets, self.bug, self.paths, self.agent_replies, self.status = [], False, None, [], 200
        self.ops = self.own_test = None
        self.truncate = {}  # step -> number of answers to cut off

    def __call__(self, host, port, timeout, context):
        upstream = self

        class Connection:
            def request(self, method, path, body, headers):
                self.reply = upstream.reply(host, path, json.loads(body))

            def getresponse(self):
                return self.reply

            def close(self):
                pass

        return Connection()

    def reply(self, host, path, wire):
        if path == "/responses":
            self.packets.append(("agent", wire))
            return Response(self.agent_replies.pop(0), self.status, "text/event-stream")
        provider = "anthropic" if host == "api.anthropic.com" else "deepseek"
        packet = json.loads(wire["messages"][0 if provider == "anthropic" else 1]["content"])
        step = next(name for name, task in build.TASKS.items() if task == packet["task"])
        self.packets.append((step, packet))
        self.wires = getattr(self, "wires", []) + [(step, wire)]
        answer = json.dumps(getattr(self, step)(packet))
        cut = self.truncate.get(step, 0) > 0
        self.truncate[step] = self.truncate.get(step, 0) - 1
        if provider == "anthropic":
            return Response(
                json.dumps(
                    {
                        "id": "msg",
                        "model": wire["model"],
                        "stop_reason": "end_turn",
                        "content": [{"type": "text", "text": answer}],
                        "usage": {"input_tokens": 900, "output_tokens": 300},
                    }
                ).encode()
            )
        return Response(
            json.dumps(
                {
                    "id": "ds",
                    "model": wire["model"],
                    "system_fingerprint": "fx",
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "length" if cut else "stop",
                            "message": {"role": "assistant", "content": answer},
                        }
                    ],
                    "usage": {"prompt_tokens": 2000, "prompt_cache_hit_tokens": 500, "completion_tokens": 1000},
                }
            ).encode()
        )

    def plan(self, packet):
        return {
            "groups": [
                {
                    "files": [
                        {"path": p, "purpose": "p"} for p in ("calc/__init__.py", "calc/ops.py", "tests/test_ops.py")
                    ]
                }
            ],
            "notes": "n",
        }

    def build(self, packet):
        texts = {
            "calc/__init__.py": '"""calc"""\n',
            "calc/ops.py": self.ops or (BUGGY if self.bug else GOOD),
            "tests/test_ops.py": self.own_test or OWN_TEST,
        }
        paths = self.paths or packet["write_now"]
        return {"files": [{"path": p, "text": texts.get(p, "x = 1\n")} for p in paths], "notes": "n"}

    def repair(self, packet):
        return {"files": [{"path": "calc/ops.py", "text": self.ops or GOOD}], "notes": "fixed"}

    def review(self, packet):
        failing = packet["runner_results"]["hidden_acceptance_tests"]["not_ok"]
        findings = (
            [{"path": "calc/ops.py", "severity": "high", "problem": "add subtracts", "fix": "use +"}] if failing else []
        )
        return {"verdict": "changes" if failing else "approve", "summary": "s", "findings": findings}


def sse(*events):
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def agent_reply(item, model="deepseek-flash", output_tokens=40):
    usage = {
        "input_tokens": 3000,
        "input_tokens_details": {"cached_tokens": 1000},
        "output_tokens": output_tokens,
        "total_tokens": 3000 + output_tokens,
        "output_tokens_details": {"reasoning_tokens": 0},
    }
    response = {
        "id": "resp_x",
        "object": "response",
        "created_at": 1,
        "status": "in_progress",
        "model": model,
        "output": [],
    }
    events = [
        {"type": "response.created", "response": dict(response)},
        {"type": "response.output_item.added", "output_index": 0, "item": item},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {
            "type": "response.completed",
            "response": {**response, "status": "completed", "output": [item], "usage": usage},
        },
    ]
    for n, event in enumerate(events):
        event["sequence_number"] = n
    return sse(*events)


def tool_call(name, arguments):
    return agent_reply(
        {
            "type": "function_call",
            "id": "fc_1",
            "call_id": "call_1",
            "name": name,
            "arguments": json.dumps(arguments),
            "status": "completed",
        }
    )


def message(text):
    return agent_reply(
        {
            "type": "message",
            "id": "msg_1",
            "role": "assistant",
            "status": "completed",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        }
    )


class BuildLoop(unittest.TestCase):
    def setUp(self):
        self.root = signed_root(self, sandbox.AREA)
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        protected = self.root / "hidden"
        protected.mkdir()
        (protected / "test_p_calc.py").write_text(PROTECTED)
        (self.root / "SPEC.md").write_text(SPEC)
        self.manifest = {
            "company": {"id": "acme", "name": "Acme"},
            "spec": str(self.root / "SPEC.md"),
            "allowed": ["calc/*.py", "tests/*.py", "README.md"],
            "required": ["calc/__init__.py", "calc/ops.py"],
            "protected": {
                "dir": str(protected),
                "pattern": "test_p_*.py",
                "sha256": {"test_p_calc.py": hashlib.sha256(PROTECTED.encode()).hexdigest()},
            },
            "python": sys.executable,
            "builder": "deepseek-flash",
            "reviewer": "deepseek-v4-pro",
            "repairs": 2,
            "arms": {
                "json": {"workspace": str(self.root / "ws-json"), "ceiling_usd": 1.0},
                "opencode": {
                    "workspace": str(self.root / "ws-opencode"),
                    "ceiling_usd": 1.0,
                    "binary": str(PINNED_OPENCODE),
                    "binary_sha256": OPENCODE_SHA256,
                    "max_steps": 4,
                    "session_seconds": 60,
                },
            },
            "keys": keys(self.root, ("deepseek",)),
        }
        self.write_manifest()
        self.upstream = Upstream()
        clean = patch.dict(os.environ, {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)

    def write_manifest(self):
        (self.run_dir / "run.json").write_text(json.dumps(self.manifest))

    def grant(self, ceiling=4.0):
        self.assertEqual(build.main([str(self.run_dir), "grant", "--ceiling", str(ceiling)]), 0)
        draft = json.loads((self.run_dir / "grant.json").read_text())
        sign(self, draft)
        return draft

    def run_arms(self, arms="json"):
        run = build.Build(self.run_dir, connection=self.upstream)
        run.run(arms.split(","))
        return run, json.loads((self.run_dir / "report.json").read_text())

    def lane(self, arm="json"):
        return self.run_dir / "lanes" / "acme" / arm

    def test_one_signature_builds_tests_reviews_and_reports(self):
        draft = self.grant()
        self.assertIn("Local builds in sandboxed workspaces only", (self.run_dir / "sign-grant.sh").read_text())
        self.assertEqual(draft["scope"]["operations"], ["plan", "build", "repair", "review", "agent"])
        run, report = self.run_arms()
        self.assertEqual([s for s, _ in self.upstream.packets], ["plan", "build", "review"])
        self.assertEqual(report["json"]["final_protected"], "1/1")
        self.assertEqual(report["json"]["repairs"], 0)
        self.assertEqual(report["json"]["builder"]["calls"], 2)
        self.assertEqual(report["json"]["reviewer"]["calls"], 1)
        self.assertEqual((report["json"]["source_lines"], report["json"]["test_lines"]), (3, 5))
        log = build.git(run.arm("json"), run.workspace("json"), "log", "--format=%s")
        self.assertEqual(log.split("\n")[:2], ["Build group 1", "Specification"])

    def test_existing_code_reaches_the_plan_and_is_kept(self):
        workspace = Path(self.manifest["arms"]["json"]["workspace"])
        (workspace / "calc").mkdir(parents=True)
        (workspace / "calc" / "legacy.py").write_text("OLD = 1\n")
        self.grant()
        run, _ = self.run_arms()
        plan = next(packet for step, packet in self.upstream.packets if step == "plan")
        self.assertEqual(plan["files_written"], {"calc/legacy.py": "OLD = 1\n"})
        self.assertIn("plan only the files to add or change", plan["task"])
        self.assertEqual((workspace / "calc" / "legacy.py").read_text(), "OLD = 1\n")
        self.assertIn("calc/legacy.py", build.git(run.arm("json"), workspace, "show", "--name-only", "HEAD~1"))

    def test_hidden_failures_drive_a_repair_without_leaking_the_tests(self):
        self.grant()
        self.upstream.bug = True
        _, report = self.run_arms()
        self.assertEqual([s for s, _ in self.upstream.packets], ["plan", "build", "review", "repair", "review"])
        repair = dict(self.upstream.packets)["repair"]
        self.assertEqual(
            repair["problems"]["hidden_acceptance_tests"],
            {"passed": 0, "total": 1, "not_ok": {"test_p_calc.P.test_secret_case": "fail"}},
        )
        self.assertEqual(
            repair["problems"]["your_tests"], {"passed": 0, "total": 1, "not_ok": {"test_ops.T.test_add": "fail"}}
        )
        self.assertEqual(repair["problems"]["review_findings"][0]["severity"], "high")
        self.assertNotIn("38", json.dumps(repair["problems"]))
        for _, packet in self.upstream.packets:
            self.assertNotIn("add(40, 2)", json.dumps(packet))
        self.assertEqual((report["json"]["repairs"], report["json"]["final_protected"]), (1, "1/1"))

    def test_paths_outside_the_allowlist_are_refused_with_feedback(self):
        self.grant()
        self.upstream.paths = ["calc/__init__.py", "calc/ops.py", "../escape.py"]
        _, report = self.run_arms()
        self.assertFalse((self.root / "escape.py").exists())
        failed = json.loads((self.lane() / "build-1.failed.json").read_text())
        self.assertIn("../escape.py is not an allowed path", failed["last_problems"])
        self.assertIn("build group 1 failed", report["json"]["stopped"])

    def test_arm_share_is_signed_and_never_exceeded(self):
        self.manifest["arms"]["json"]["ceiling_usd"] = 0.03
        self.write_manifest()
        draft = self.grant()
        self.assertEqual(draft["scope"]["lane_ceilings_microusd"], {"acme/json": 30_000, "acme/opencode": 1_000_000})
        run, report = self.run_arms()
        self.assertIn("acme/json reached its share of the grant", report["json"]["stopped"])
        self.assertLessEqual(run.ledger.committed("acme/json"), 30_000)
        self.assertGreater(run.ledger.committed("acme/json"), 0)

    def test_changed_protected_test_stops_the_arm(self):
        self.grant()
        Path(self.manifest["protected"]["dir"], "test_p_calc.py").write_text(PROTECTED + "\n")
        _, report = self.run_arms()
        self.assertIn("protected tests changed", report["json"]["stopped"])

    def test_no_text_from_executed_code_reaches_deepseek(self):
        self.grant()
        self.upstream.ops, self.upstream.own_test = HOSTILE, HOSTILE_TEST
        run, _ = self.run_arms()
        evidence = json.dumps(json.loads((self.lane() / "tests-0.json").read_text())["local_only"])
        self.assertIn(MARK, evidence)  # control: the code ran and wrote the marker into its outcome and messages
        self.assertIn("add(40, 2)", evidence)  # control: it read the hidden test source
        self.assertIn("PermissionError", evidence)  # its network attempt was refused by the sandbox
        scratch = self.run_dir / "arms/json/scratch"
        output = (scratch / "protected.stdout.txt").read_text() + (scratch / "protected.stderr.txt").read_text()
        self.assertIn(MARK, output)
        sent = [json.dumps(packet) for _, packet in self.upstream.packets]
        self.assertEqual(len(sent), 7)
        for packet in sent:
            self.assertNotIn(MARK, packet)
            self.assertNotIn("add(40, 2)", packet)
        repair = dict(self.upstream.packets)["repair"]["problems"]
        self.assertEqual(list(repair["hidden_acceptance_tests"]["not_ok"]), ["test_p_calc.P.test_secret_case"])
        self.assertEqual(list(repair["your_tests"]["not_ok"]), ["test_ops.T.test_add"])
        self.assertFalse(list(run.workspace("json").rglob(f"{MARK}*")))

    def test_ids_come_from_source_and_missing_ones_are_not_run(self):
        self.assertEqual(
            build.outcomes(
                {"m.C.test_a": ["ok", ""], "m.C.test_extra": ["ok", ""], "m.C.test_b": ["odd", ""]},
                {"m.C.test_a", "m.C.test_b", "m.C.test_c"},
            ),
            {"m.C.test_a": "ok", "m.C.test_b": "error", "m.C.test_c": "not run"},
        )

    def test_runner_refuses_an_environment_with_secrets(self):
        self.grant()
        with patch.dict(os.environ, {"SOME_TOKEN": "x"}):
            with self.assertRaisesRegex(build.Stopped, "clean environment"):
                build.Build(self.run_dir, connection=self.upstream).run(["json"])

    def test_symlinks_are_never_followed_when_reading_files(self):
        self.grant()
        run = build.Build(self.run_dir, connection=self.upstream)
        run.prepare("json")
        secret = self.root / "outside.txt"
        secret.write_text("outside secret")
        (run.workspace("json") / "notes.md").symlink_to(secret)
        run.commit("json", "link")
        self.assertEqual(Path(run.workspace("json") / "notes.md").read_text(), "outside secret")  # control
        self.assertEqual(run.files("json"), {"notes.md": "(not a regular file; not read)"})

    def test_credential_shaped_text_from_the_builder_never_leaves_the_mac(self):
        self.grant()
        self.upstream.ops = "TOKEN = 'CLAUDE_CODE_MESSAGING_TOKEN=abcdefgh12345'\ndef add(a, b):\n    return a - b\n"
        run, report = self.run_arms()
        self.assertIn("build group 1 failed", report["json"]["stopped"], "sent back, never written")
        self.assertFalse((run.workspace("json") / "calc" / "ops.py").exists())
        self.assertFalse(any("abcdefgh12345" in json.dumps(p) for _, p in self.upstream.packets))
        self.assertNotIn("review", [s for s, _ in self.upstream.packets])

    def test_credential_in_an_outbound_packet_stops_every_arm(self):
        self.grant()
        run = build.Build(self.run_dir, connection=self.upstream)
        run.prepare("json")
        (run.workspace("json") / "notes.md").write_text("CLAUDE_CODE_MESSAGING_TOKEN=abcdefgh12345\n")
        run.commit("json", "a token from elsewhere")
        run, report = self.run_arms()
        self.assertIn("security stop", report["json"]["stopped"])
        self.assertEqual(run.ledger.state(), "stop")

    def test_only_granted_models_can_be_called(self):
        draft = self.grant()
        self.assertEqual(set(draft["models"]), {"deepseek-flash", "deepseek-v4-pro"})
        run = build.Build(self.run_dir, connection=self.upstream)
        with self.assertRaisesRegex(build.grants.GrantError, "claude-haiku-5-5 is not in the grant"):
            run.ledger.reserve("acme/json", "review-0", "claude-haiku-5-5", 1)

    def test_key_is_never_written_to_the_run_or_workspace(self):
        self.grant()
        self.upstream.bug = True
        self.run_arms()
        key = Path(self.manifest["keys"]["deepseek"]).read_bytes().strip()
        written = [p for p in self.root.rglob("*") if p.is_file() and "keys" not in p.parts and key in p.read_bytes()]
        self.assertEqual(written, [])

    def test_code_under_test_cannot_read_the_key_file(self):
        self.grant()
        path = self.manifest["keys"]["deepseek"]
        self.assertTrue(Path(path).read_text())  # control: readable outside the sandbox
        self.upstream.ops = f"KEY = open({path!r}).read()\ndef add(a, b):\n    return a + b\n"
        self.run_arms()
        raw = json.loads((self.lane() / "tests-0.json").read_text())["local_only"]["protected"]
        self.assertEqual({kind for kind, _ in raw.values()}, {"error"})
        self.assertIn("PermissionError", json.dumps(raw))

    def test_review_gets_its_whole_budget_and_a_reasoning_hint_on_retry(self):
        self.grant()
        self.upstream.truncate = {"review": 1}
        _, report = self.run_arms()
        reviews = [wire for step, wire in self.upstream.wires if step == "review"]
        self.assertEqual([w["max_tokens"] for w in reviews], [48000, 48000])
        retry = json.loads(reviews[1]["messages"][1]["content"])["fix_these_problems_from_your_last_attempt"]
        self.assertIn("Spend less of the answer on reasoning", retry[0])
        self.assertTrue(report["json"]["accepted"])

    def test_failed_review_stops_after_bounded_attempts_without_a_blind_repair(self):
        self.grant()
        self.upstream.bug = True
        self.upstream.truncate = {"review": 99}
        run, report = self.run_arms()
        steps = [s for s, _ in self.upstream.packets]
        self.assertEqual(steps, ["plan", "build", "review", "review"], "a second cut-off ends the step")
        self.assertIn("review 0 failed after its bounded attempts; no repair", report["json"]["stopped"])
        self.assertEqual([r["state"] for r in run.ledger.rows() if r["step"] == "review-0"], ["truncated"] * 2)

    def test_review_only_reviews_the_candidate_as_it_is(self):
        self.grant()
        run, _ = self.run_arms()
        head = build.git(run.arm("json"), run.workspace("json"), "rev-parse", "HEAD")
        review_dir = self.root / "review-run"
        review_dir.mkdir()
        shutil.copytree(self.run_dir / "arms/json", review_dir / "arms/json", ignore=shutil.ignore_patterns("scratch"))
        shutil.copytree(run.workspace("json"), self.root / "ws-review")
        arms = {"json": {"workspace": str(self.root / "ws-review"), "ceiling_usd": 0.5}}
        (review_dir / "run.json").write_text(json.dumps({**self.manifest, "builder": None, "arms": arms}))
        self.assertEqual(build.main([str(review_dir), "grant", "--ceiling", "0.5", "--calls", "6"]), 0)
        draft = json.loads((review_dir / "grant.json").read_text())
        self.assertEqual((list(draft["models"]), draft["scope"]["operations"]), (["deepseek-v4-pro"], ["review"]))
        sign(self, draft)
        self.upstream.packets = []
        result = build.Build(review_dir, connection=self.upstream).review_only("json")
        self.assertEqual([s for s, _ in self.upstream.packets], ["review"])
        self.assertTrue(result["accepted"])
        self.assertEqual(result["hidden"], {"passed": 1, "total": 1, "not_ok": {}})
        self.assertEqual(build.git(run.arm("json"), run.workspace("json"), "rev-parse", "HEAD"), head)
        self.assertEqual(build.git(review_dir / "arms/json", self.root / "ws-review", "rev-parse", "HEAD"), head)
        self.assertTrue((review_dir / "lanes/acme/json/final-review.json").exists())

    def external_mode(self):
        self.manifest["reviewer"] = None
        self.write_manifest()
        return self.grant()

    def test_without_an_in_loop_reviewer_only_tests_drive_repairs(self):
        draft = self.external_mode()
        self.assertEqual(
            (list(draft["models"]), draft["scope"]["operations"]),
            (["deepseek-flash"], ["plan", "build", "repair", "agent"]),
        )
        self.upstream.bug = True
        _, report = self.run_arms()
        self.assertEqual([s for s, _ in self.upstream.packets], ["plan", "build", "repair"])
        repair = dict(self.upstream.packets)["repair"]
        self.assertEqual(repair["problems"]["review_findings"], [])
        self.assertEqual(report["json"]["final_protected"], "1/1")
        self.assertFalse(report["json"]["accepted"])
        self.assertTrue(report["json"]["awaiting_external_review"])

    def write_review(self, verdict="approve", findings=(), candidate=None, run=None):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, True)
        path = folder / "codex-review.json"
        head = candidate or build.git(run.arm("json"), run.workspace("json"), "rev-parse", "HEAD").strip()
        path.write_text(json.dumps({"candidate": head, "verdict": verdict, "summary": "s", "findings": list(findings)}))
        return path

    def test_an_external_review_decides_acceptance_on_a_retested_candidate(self):
        self.external_mode()
        run, _ = self.run_arms()
        head = build.git(run.arm("json"), run.workspace("json"), "rev-parse", "HEAD")
        medium = {"path": "calc/ops.py", "severity": "medium", "problem": "p", "fix": "f"}
        low = {**medium, "severity": "low"}
        self.assertFalse(run.record_review("json", self.write_review("changes", [medium], run=run))["accepted"])
        self.assertFalse(run.record_review("json", self.write_review("approve", [medium], run=run))["accepted"])
        result = run.record_review("json", self.write_review("approve", [low], run=run))
        self.assertTrue(result["accepted"])
        self.assertEqual((result["candidate"], result["hidden"]["passed"]), (head.strip(), 1))
        self.assertEqual(
            result["review_sha256"],
            hashlib.sha256(self.write_review("approve", [low], run=run).read_bytes()).hexdigest(),
        )
        recorded = json.loads((self.lane() / "external-review.json").read_text())
        self.assertTrue(recorded["accepted"])
        self.assertFalse(run.record_review("json", self.write_review("changes", [low], run=run))["accepted"])
        self.assertFalse(run.record_review("json", self.write_review("changes", run=run))["accepted"])
        for bad in (
            {"candidate": head.strip(), "verdict": "approve"},
            {"candidate": head.strip(), "verdict": "ok", "summary": "s", "findings": []},
            {"verdict": "approve", "summary": "s", "findings": []},
            [],
        ):
            path = self.write_review(run=run)
            path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):
                run.record_review("json", path)

    def test_an_external_approval_cannot_accept_failing_tests(self):
        self.external_mode()
        self.upstream.bug = True
        self.upstream.ops = BUGGY
        run, report = self.run_arms()
        self.assertFalse(report["json"]["awaiting_external_review"])
        self.assertFalse(run.record_review("json", self.write_review(run=run))["accepted"])

    def test_tests_rerun_on_the_commit_not_the_working_tree(self):
        self.external_mode()
        self.upstream.bug = True
        self.upstream.ops = BUGGY
        run, _ = self.run_arms()
        (run.workspace("json") / "calc" / "ops.py").write_text(GOOD)
        result = run.record_review("json", self.write_review(run=run))
        self.assertFalse(result["accepted"])
        self.assertEqual(result["hidden"]["passed"], 0)

    def test_the_review_must_be_the_operators_own_file_outside_the_execution_area(self):
        self.external_mode()
        run, _ = self.run_arms()
        good = self.write_review(run=run)
        inside = self.root / "review.json"
        inside.write_bytes(good.read_bytes())
        link = good.with_name("link.json")
        link.symlink_to(good)
        # Review 55, probe_exec 04: generated code writes a matching approval into its own scratch folder.
        scratch = run.arm("json") / "scratch/own"
        forged = scratch / "builder-review.json"
        code, _, _ = sandbox.run(
            [sys.executable, "-B", "-c", f"open({str(forged)!r}, 'w').write({good.read_text()!r})"],
            [run.workspace("json")],
            [scratch],
            {"PATH": "/usr/bin:/bin"},
            run.workspace("json"),
            10,
            self.root / "forgery.stdout",
            self.root / "forgery.stderr",
        )
        self.assertEqual(code, 0)
        self.assertNotEqual(forged.stat().st_uid, os.getuid())
        for path in (inside, link, forged):
            with self.subTest(path=path.name), self.assertRaises((ValueError, OSError)):
                run.record_review("json", path)
        self.assertTrue(run.record_review("json", good)["accepted"])

    def test_an_approval_of_another_candidate_is_refused(self):
        self.external_mode()
        run, _ = self.run_arms()
        old = self.write_review(run=run)
        (run.workspace("json") / "calc" / "extra.py").write_text("X = 1\n")
        run.commit("json", "a later change")
        with self.assertRaises(ValueError):
            run.record_review("json", old)
        with self.assertRaises(ValueError):
            run.record_review("json", self.write_review(candidate="0" * 40, run=run))
        self.assertFalse((self.lane() / "external-review.json").exists())

    def test_git_ignores_config_planted_in_the_workspace(self):
        self.grant()
        run = build.Build(self.run_dir, connection=self.upstream)
        run.prepare("json")
        workspace = run.workspace("json")
        planted = workspace / ".git"
        planted.mkdir()
        (planted / "config").write_text(f"[core]\n\tfsmonitor = touch {self.root / 'pwned'}\n")
        (workspace / "calc").mkdir()
        (workspace / "calc/ops.py").write_text(GOOD)
        run.commit("json", "planted")
        self.assertFalse((self.root / "pwned").exists())
        self.assertIn("calc/ops.py", build.git(run.arm("json"), workspace, "ls-files"))

    @unittest.skipUnless(PINNED_OPENCODE.exists(), "pinned OpenCode binary not on this machine")
    def test_opencode_session_through_the_granted_gateway(self):
        self.manifest["repairs"] = 0
        self.write_manifest()
        self.grant()
        target = Path(self.manifest["arms"]["opencode"]["workspace"]) / "calc/ops.py"
        self.upstream.agent_replies = [tool_call("write", {"filePath": str(target), "content": GOOD}), message("done")]
        with patch.object(build.Build, "review", lambda *a: {"verdict": "approve", "summary": "s", "findings": []}):
            run, report = self.run_arms("opencode")
        self.assertEqual(target.read_text(), GOOD)
        sent = [wire for kind, wire in self.upstream.packets if kind == "agent"]
        self.assertEqual(len(sent), 2)
        self.assertTrue(all(w["max_output_tokens"] == 32000 and w["reasoning"] == {"effort": "high"} for w in sent))
        self.assertTrue(any(i.get("type") == "function_call_output" for i in sent[1]["input"]))
        rows = [r for r in run.ledger.rows() if r["lane"] == "acme/opencode"]
        self.assertEqual(
            [(r["step"], r["state"]) for r in rows], [("agent-0-1", "received"), ("agent-0-2", "received")]
        )
        self.assertEqual(report["opencode"]["final_protected"], "1/1")


class GatewayChecks(unittest.TestCase):
    SETTINGS = {"max_output_tokens": 32000, "effort": "high"}

    def gateway(self, replies, lane_cap=1_000_000):
        root = signed_root(self)
        draft = {
            "id": "g",
            "models": {"deepseek-flash": self.SETTINGS},
            "scope": {
                "company_ids": ["acme"],
                "operations": ["agent"],
                "lane_ceilings_microusd": {"acme/opencode": lane_cap},
            },
            "max_calls": 10,
            "ceiling_microusd": 1_000_000,
            "expires_at": 4e9,
        }
        self.ledger = build.grants.Ledger(root / "ledger.sqlite", draft)
        upstream = Upstream()
        upstream.agent_replies = list(replies)
        self.upstream = upstream
        return gateway.Gateway(
            self.ledger,
            "acme/opencode",
            "agent-0",
            "deepseek-flash",
            self.SETTINGS,
            "sk-secret",
            ["sk-secret", "other-key-value"],
            upstream,
        )

    def body(self, **extra):
        return {
            "model": "deepseek-flash",
            "input": [{"role": "user", "content": "hi"}],
            "stream": True,
            "max_output_tokens": 999999,
            "reasoning": {"effort": "xhigh"},
            "store": True,
            "tools": [{"type": "function", "name": "read"}],
            **extra,
        }

    def test_admit_overwrites_spending_fields_and_refuses_the_rest(self):
        wire = gateway.admit(self.body(include=["x"]), "deepseek-flash", self.SETTINGS)
        self.assertEqual((wire["max_output_tokens"], wire["reasoning"]), (32000, {"effort": "high"}))
        self.assertNotIn("include", wire)
        refused = [
            self.body(model="deepseek-v4-pro"),
            self.body(tools=[{"type": "web_search"}]),
            self.body(input=[{"role": "user", "content": [{"type": "input_image", "image_url": "x"}]}]),
            self.body(background=True),
        ]
        for body in refused:
            with self.subTest(body=body), self.assertRaises(gateway.Refused):
                gateway.admit(body, "deepseek-flash", self.SETTINGS)

    def test_settles_from_provider_usage(self):
        g = self.gateway([message("ok")])
        status, kind, payload = g.forward(self.body())
        self.assertEqual((status, kind), (200, "text/event-stream"))
        (row,) = self.ledger.rows()
        self.assertEqual(
            (row["state"], row["charge"]),
            ("received", llm.cost("deepseek-flash", {"input": 2000, "cached": 1000, "output": 40})),
        )

    def test_wrong_model_or_echoed_key_stops_for_good(self):
        g = self.gateway([agent_reply({"type": "message", "content": []}, model="other"), message("ok")])
        with self.assertRaises(llm.SecurityStop):
            g.forward(self.body())
        with self.assertRaises(gateway.Refused):
            g.forward(self.body())
        self.assertEqual([r["state"] for r in self.ledger.rows()], ["uncertain"])
        g = self.gateway([message("sk-secret")])
        with self.assertRaises(llm.SecurityStop):
            g.forward(self.body())

    def test_server_errors_keep_the_reserve(self):
        g = self.gateway([b"{}"])
        self.upstream.status = 503
        with self.assertRaises(gateway.Refused):
            g.forward(self.body())
        (row,) = self.ledger.rows()
        self.assertEqual((row["state"], row["charge"]), ("uncertain", None))

    def test_budget_refusal_happens_before_sending(self):
        g = self.gateway([message("ok")], lane_cap=10)
        with self.assertRaises(build.grants.GrantError):
            g.forward(self.body())
        self.assertEqual((self.ledger.rows(), self.upstream.packets), ([], []))

    def test_credential_like_request_is_never_sent(self):
        for text_ in ("other-key-value", "export GITHUB_TOKEN=ghp_" + "a" * 36):
            g = self.gateway([message("ok")])
            with self.subTest(text_=text_), self.assertRaises(llm.SecurityStop):
                g.forward(self.body(input=[{"role": "user", "content": text_}]))
            self.assertEqual(self.upstream.packets, [])

    def test_item_references_are_refused(self):
        with self.assertRaises(gateway.Refused):
            gateway.admit(self.body(input=[{"type": "item_reference", "id": "x"}]), "deepseek-flash", self.SETTINGS)
        self.assertIs(gateway.admit(self.body(), "deepseek-flash", self.SETTINGS)["store"], False)

    def test_local_token_required(self):
        g = self.gateway([message("ok")])
        port = g.start()
        self.addCleanup(g.stop)
        result = subprocess.run(
            [
                "/usr/bin/curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "-X",
                "POST",
                "-H",
                "Authorization: Bearer wrong",
                "--data",
                "{}",
                f"http://127.0.0.1:{port}/responses",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout, "400")
        self.assertEqual(self.upstream.packets, [])


class PacketScan(unittest.TestCase):
    def test_the_packet_scan_reads_decoded_text(self):
        self.assertFalse(
            gateway.packet_leaks({"spec": "- `ACME_API_KEY=<key>`\n- next step"}, []),
            "a JSON escape must not join a name and the next line",
        )
        self.assertTrue(gateway.packet_leaks({"spec": ["x", "OPENAI_API_KEY=abcd1234efgh"]}, []))
        self.assertTrue(gateway.packet_leaks({"files": {"sk-" + "a" * 24: "x"}}, []), "keys are scanned too")
        self.assertTrue(gateway.packet_leaks({"note": "the key is fixture-key-1"}, ["fixture-key-1"]))


class Pricing(unittest.TestCase):
    def test_estimates_use_published_rates_and_reserves_still_cover_the_worst_case(self):
        # Published peak rates, 5 Nov 2026: V4 Pro $1.32 / $0.044 / $3.96 per million tokens.
        self.assertEqual(
            llm.cost("deepseek-v4-pro", {"input": 1_000_000, "cached": 1_000_000, "output": 1_000_000}),
            1_320_000 + 44_000 + 3_960_000,
        )
        body = b"x" * 40_000
        worst = llm.cost("deepseek-v4-pro", {"input": len(body) + llm.OVERHEAD_TOKENS, "cached": 0, "output": 48_000})
        self.assertGreaterEqual(llm.reserve("deepseek-v4-pro", body, 48_000), worst)


class Containment(unittest.TestCase):
    PROBE = (
        "import json, os, socket, subprocess, sys\n"
        "def denied(f):\n"
        "    try:\n        f()\n        return False\n"
        "    except (PermissionError, ConnectionRefusedError, OSError) as e:\n"
        "        return isinstance(e, PermissionError) or getattr(e, 'errno', None) in (1, 13)\n"
        "home, ws, port, parent = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])\n"
        "print(json.dumps({\n"
        "  'home': denied(lambda: os.listdir(home)),\n"
        "  'tmp': denied(lambda: os.listdir('/private/tmp')),\n"
        "  'write': denied(lambda: open(os.path.join(ws, 'x'), 'w')),\n"
        "  'network': denied(lambda: socket.create_connection(('1.1.1.1', 443), timeout=2)),\n"
        "  'other_loopback_port': denied(lambda: socket.create_connection(('127.0.0.1', port), timeout=2)),\n"
        "  'signal_parent': denied(lambda: os.kill(parent, 0)),\n"
        "  'open': denied(lambda: subprocess.run(['/usr/bin/open', '-g', '/'], check=True, capture_output=True)),\n"
        "  'keychain': denied(lambda: subprocess.run(['/usr/bin/security', 'list-keychains'], check=True,\n"
        "                                            capture_output=True)),\n"
        "  'other_account': os.getuid() == 490}))\n"
    )

    def setUp(self):
        self.root = signed_root(self, sandbox.AREA)
        self.readable, self.writable = self.root / "ws", self.root / "scratch"
        self.readable.mkdir()
        self.writable.mkdir()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.addCleanup(self.listener.close)

    def probe(self, sandboxed):
        args = [
            sys.executable,
            "-c",
            self.PROBE,
            str(Path.home()),
            str(self.readable),
            str(self.listener.getsockname()[1]),
            str(os.getpid()),
        ]
        if not sandboxed:
            return json.loads(subprocess.run(args, capture_output=True, text=True, timeout=60).stdout)
        out = self.root / "out.txt"
        code, _, _ = sandbox.run(
            args,
            [self.readable],
            [self.writable],
            {"PATH": "/usr/bin:/bin", "TMPDIR": str(self.writable)},
            self.readable,
            60,
            out,
            self.root / "err.txt",
        )
        self.assertEqual(code, 0, (self.root / "err.txt").read_text())
        return json.loads(out.read_text())

    def test_sandbox_blocks_home_network_signals_and_escapes(self):
        unsandboxed = self.probe(False)
        self.assertFalse(
            any(
                unsandboxed[k]
                for k in ("home", "tmp", "write", "other_loopback_port", "signal_parent", "other_account")
            ),
            unsandboxed,
        )  # control: these work without the sandbox, as yashgx
        self.assertEqual(set(self.probe(True).values()), {True})

    def test_detached_child_cannot_hang_the_runner(self):
        script = (
            "import os, subprocess, time\n"
            "subprocess.Popen(['/bin/sleep', '300'], start_new_session=True, cwd=os.environ['TMPDIR'])\n"
            "time.sleep(300)\n"
        )
        started = time.time()
        code, timed_out, strays = sandbox.run(
            [sys.executable, "-c", script],
            [self.readable],
            [self.writable],
            {"PATH": "/usr/bin:/bin", "TMPDIR": str(self.writable)},
            self.writable,
            3,
            self.root / "o",
            self.root / "e",
        )
        self.assertTrue(timed_out)
        self.assertLess(time.time() - started, 30)
        self.assertEqual(len(strays), 1)
        self.assertEqual(sandbox.job_processes(), [])

    def test_job_paths_outside_the_execution_area_are_refused(self):
        with self.assertRaises(ValueError):
            sandbox.run(
                ["/usr/bin/true"],
                [Path.home()],
                [self.writable],
                {},
                self.writable,
                10,
                self.root / "o",
                self.root / "e",
            )

    def test_planted_link_does_not_pass_rights_to_its_target(self):
        target = self.root / "private.txt"
        target.write_text("private")
        (self.writable / "link").symlink_to(target)
        code, _, _ = sandbox.run(
            ["/usr/bin/true"], [self.readable], [self.writable], {}, self.writable, 10, self.root / "o", self.root / "e"
        )
        self.assertEqual(code, 0)
        self.assertNotIn(
            "_arcexec", subprocess.run(["/bin/ls", "-le", str(target)], capture_output=True, text=True).stdout
        )

    def test_planted_hardlink_does_not_pass_rights_to_its_target(self):
        target = self.root / "private.txt"
        target.write_text("private")
        os.link(target, self.writable / "hardlink")
        code, _, _ = sandbox.run(
            ["/usr/bin/true"], [self.readable], [self.writable], {}, self.writable, 10, self.root / "o", self.root / "e"
        )
        self.assertEqual(code, 0)
        self.assertNotIn(
            "_arcexec", subprocess.run(["/bin/ls", "-le", str(target)], capture_output=True, text=True).stdout
        )

    def test_output_files_inside_write_paths_are_refused(self):
        with self.assertRaises(ValueError):
            sandbox.run(
                ["/usr/bin/true"],
                [self.readable],
                [self.writable],
                {},
                self.writable,
                10,
                self.writable / "o",
                self.root / "e",
            )

    def test_job_files_are_read_only_if_the_job_wrote_them(self):
        owner_file = self.root / "private.json"
        owner_file.write_text("{}")
        (self.writable / "link.json").symlink_to(owner_file)
        script = f"open({str(self.writable / 'own.json')!r}, 'w').write('{{}}')"
        sandbox.run(
            [sys.executable, "-I", "-c", script],
            [self.readable],
            [self.writable],
            {},
            self.writable,
            30,
            self.root / "o",
            self.root / "e",
        )
        self.assertEqual(sandbox.read_job_file(self.writable / "own.json"), "{}")
        self.assertIsNone(sandbox.read_job_file(self.writable / "link.json"))
        self.assertIsNone(sandbox.read_job_file(owner_file))

    def test_agent_cannot_create_opencode_home_config(self):
        home = self.writable / "home"
        home.mkdir()
        script = f"import os; os.makedirs({str(home / '.opencode')!r})"
        code, _, _ = sandbox.run(
            [sys.executable, "-c", script],
            [self.readable],
            [self.writable],
            {"PATH": "/usr/bin:/bin"},
            self.writable,
            30,
            self.root / "o",
            self.root / "e",
            deny_write=[home / ".opencode"],
        )
        self.assertNotEqual(code, 0)
        self.assertFalse((home / ".opencode").exists())
        (home / ".opencode").mkdir()
        with self.assertRaises(ValueError):
            build.opencode.prepare(self.writable, "deepseek-flash", {"max_output_tokens": 1, "effort": "high"}, 1)


class AsksForApproval(unittest.TestCase):
    def test_build_asks_before_run_and_review(self):
        for command, asks in (("run", True), ("review", True), ("report", False), ("pause", False)):
            with (
                self.subTest(command),
                patch.object(build.approve, "ensure", side_effect=build.grants.GrantError("no tap")) as ensure,
                patch("sys.stderr"),
            ):
                self.assertEqual(build.main(["/nonexistent-run", command]), 1)
            self.assertEqual(ensure.called, asks)


if __name__ == "__main__":
    unittest.main()
